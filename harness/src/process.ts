import { spawn, type ChildProcess } from "node:child_process";
import { createInterface } from "node:readline";
import { setTimeout as delay } from "node:timers/promises";
import {
  normalizeResponseHeaders,
  type AdapterMessage,
  type ClientRunResult,
  type ReadyMessage,
} from "./contracts";
import {
  expectedReportedImplementation,
  type ImplementationDefinition,
} from "./implementations";

type StderrCapture = {
  append(chunk: Buffer | string): void;
  snapshot(): string;
};

type RunningServer = {
  child: ChildProcess;
  ready: ReadyMessage;
};

const ADAPTER_OUTPUT_TIMEOUT_MS = 120_000;
const STDERR_RING_BUFFER_BYTES = 1024;

const stderrCaptures = new WeakMap<ChildProcess, StderrCapture>();

function createStderrRingBuffer(): StderrCapture {
  let buffer = "";
  return {
    append(chunk) {
      buffer += typeof chunk === "string" ? chunk : chunk.toString("utf8");
      if (buffer.length > STDERR_RING_BUFFER_BYTES) {
        buffer = buffer.slice(buffer.length - STDERR_RING_BUFFER_BYTES);
      }
    },
    snapshot() {
      return buffer;
    },
  };
}

function snapshotStderr(child: ChildProcess): string {
  const capture = stderrCaptures.get(child);
  return capture ? capture.snapshot() : "";
}

// P0 false-green killer: assert the adapter reports the identity the
// harness registered it under. An adapter wired to the wrong language's
// binary (e.g. an x402 adapter that reuses a charge client of a different
// language) would otherwise run silently under the wrong label and the
// matrix would report green while asserting nothing about the intended
// implementation. Only `ready`/`result` messages carry an
// `implementation` field; lines without one (or non-object lines) are
// left to the JSON-shape checks downstream.
function assertAdapterIdentity(
  implementation: ImplementationDefinition,
  message: AdapterMessage,
): void {
  const reported = (message as { implementation?: unknown }).implementation;
  if (typeof reported !== "string") {
    return;
  }
  const expected = expectedReportedImplementation(implementation);
  if (reported !== expected) {
    throw new Error(
      `Adapter identity mismatch: ${implementation.id} (role ${implementation.role}) ` +
        `reported implementation="${reported}" but the harness expects "${expected}". ` +
        `This usually means the adapter is wired to the wrong binary. ` +
        `If the fixture intentionally reports a different language tag, set ` +
        `\`reportsAs\` on the implementation definition.`,
    );
  }
}

async function waitForJsonMessage<T extends AdapterMessage>(
  child: ChildProcess,
  implementation: ImplementationDefinition,
  timeoutMs: number,
): Promise<T> {
  if (!child.stdout) {
    throw new Error("Spawned process does not expose stdout");
  }

  const readline = createInterface({ input: child.stdout });

  try {
    return await Promise.race([
      new Promise<T>((resolve, reject) => {
        readline.on("line", (line) => {
          if (!line.trim()) {
            return;
          }

          let parsed: T;
          try {
            parsed = JSON.parse(line) as T;
          } catch (error) {
            const tail = snapshotStderr(child);
            reject(
              new Error(
                `Failed to parse adapter ${implementation.id} output as JSON: ${line}\n` +
                  `${String(error)}` +
                  (tail ? `\nlast stderr: ${tail}` : ""),
              ),
            );
            return;
          }

          // P0 false-green killer: a label mismatch is a hard, loud
          // failure, never a swallowed parse error. Kill the adapter so
          // it cannot keep running under the wrong identity.
          try {
            assertAdapterIdentity(implementation, parsed);
          } catch (error) {
            child.kill("SIGTERM");
            reject(error instanceof Error ? error : new Error(String(error)));
            return;
          }

          resolve(parsed);
        });

        child.once("exit", (code) => {
          const tail = snapshotStderr(child);
          reject(
            new Error(
              `Adapter ${implementation.id} exited with code ${code ?? -1} before readiness;` +
                ` last stderr: ${tail || "<empty>"}`,
            ),
          );
        });
      }),
      delay(timeoutMs).then(() => {
        const tail = snapshotStderr(child);
        child.kill("SIGTERM");
        throw new Error(
          `Timed out waiting for adapter ${implementation.id} output after ${timeoutMs}ms;` +
            ` last stderr: ${tail || "<empty>"}`,
        );
      }),
    ]);
  } finally {
    readline.close();
  }
}

function spawnAdapter(
  implementation: ImplementationDefinition,
  extraEnv: Record<string, string> = {},
): ChildProcess {
  const [command, ...args] = implementation.command;
  const child = spawn(command, args, {
    cwd: process.cwd(),
    env: {
      ...process.env,
      ...extraEnv,
    },
    // Capture stderr to a ring buffer so adapter failures can attach the
    // last 1 KiB of stderr to the rejection. We also forward to the parent
    // stderr so vitest output keeps its full log.
    stdio: ["ignore", "pipe", "pipe"],
  });

  const capture = createStderrRingBuffer();
  stderrCaptures.set(child, capture);
  if (child.stderr) {
    child.stderr.on("data", (chunk: Buffer | string) => {
      capture.append(chunk);
      process.stderr.write(chunk);
    });
  }
  return child;
}

export async function startServer(
  implementation: ImplementationDefinition,
  extraEnv: Record<string, string> = {},
): Promise<RunningServer> {
  const child = spawnAdapter(implementation, extraEnv);
  const ready = await waitForJsonMessage<ReadyMessage>(
    child,
    implementation,
    ADAPTER_OUTPUT_TIMEOUT_MS,
  );

  if (ready.type !== "ready" || ready.role !== "server" || !ready.port) {
    child.kill("SIGTERM");
    throw new Error(
      `Unexpected server readiness payload from ${implementation.id}`,
    );
  }

  return { child, ready };
}

export async function runClient(
  implementation: ImplementationDefinition,
  targetUrl: string,
  extraEnv: Record<string, string> = {},
): Promise<ClientRunResult> {
  const child = spawnAdapter(implementation, {
    // Inject both protocol-namespaced TARGET_URLs so an MPP client and
    // an x402 client driven by the same matrix loop each find their
    // expected env var.
    MPP_INTEROP_TARGET_URL: targetUrl,
    X402_INTEROP_TARGET_URL: targetUrl,
    ...extraEnv,
  });

  const result = await waitForJsonMessage<ClientRunResult>(
    child,
    implementation,
    ADAPTER_OUTPUT_TIMEOUT_MS,
  );
  await waitForExit(child, "Client adapter");

  if (result.type !== "result" || result.role !== "client") {
    throw new Error(
      `Unexpected client result payload from ${implementation.id}`,
    );
  }

  // P0: normalize header keys to lower-case at the boundary so resubmit /
  // cross-server assertions cannot be fooled by an adapter that emits
  // mixed-case header keys.
  return {
    ...result,
    responseHeaders: normalizeResponseHeaders(result.responseHeaders),
  };
}

async function waitForExit(child: ChildProcess, label: string): Promise<void> {
  if (child.exitCode !== null) {
    if (child.exitCode === 0) {
      return;
    }
    throw new Error(`${label} exited with code ${child.exitCode}`);
  }

  await new Promise<void>((resolve, reject) => {
    child.once("exit", (code) => {
      if (code === 0) {
        resolve();
      } else {
        reject(new Error(`${label} exited with code ${code ?? -1}`));
      }
    });
  });
}

export async function stopServer(server: RunningServer): Promise<void> {
  server.child.kill("SIGTERM");
  await Promise.race([
    new Promise<void>((resolve) => {
      server.child.once("exit", () => resolve());
    }),
    delay(5_000).then(() => {
      server.child.kill("SIGKILL");
    }),
  ]);
}
