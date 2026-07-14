import { spawn } from "node:child_process";
import { once } from "node:events";
import { mkdtempSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { startServer, runClient, stopServer } from "../src/process";
import type { ImplementationDefinition } from "../src/implementations";

// Verify that when an adapter exits before signaling readiness, the harness
// error names the adapter id and includes the last bytes of captured stderr.
// Regression: matrix-2026-05-23 reports cite the unattributed
// `Adapter exited before signaling readiness/result (code 1)` message.
describe("process.startServer error enrichment", () => {
  it("attaches adapter id and stderr tail when the adapter exits early", async () => {
    const impl: ImplementationDefinition = {
      id: "synthetic-fail-server",
      label: "synthetic failing server",
      role: "server",
      command: [
        "sh",
        "-c",
        "printf 'boom: synthetic fixture stderr line\\n' 1>&2; exit 7",
      ],
      enabled: true,
    };

    await expect(startServer(impl)).rejects.toThrow(
      /synthetic-fail-server.*exited with code 7.*last stderr:.*boom: synthetic fixture stderr line/s,
    );
  });

  it("attaches adapter id and stderr tail for client adapters", async () => {
    const impl: ImplementationDefinition = {
      id: "synthetic-fail-client",
      label: "synthetic failing client",
      role: "client",
      command: [
        "sh",
        "-c",
        "printf 'client boom: env=%s\\n' \"$MPP_HARNESS_TARGET_URL\" 1>&2; exit 3",
      ],
      enabled: true,
    };

    await expect(
      runClient(impl, "http://127.0.0.1:65535/missing"),
    ).rejects.toThrow(
      /synthetic-fail-client.*exited with code 3.*last stderr:.*client boom: env=http:\/\/127.0.0.1:65535\/missing/s,
    );
  });

  it("removes an explicitly unset inherited environment variable", async () => {
    const original = process.env.PAY_KIT_ALLOW_INMEMORY_REPLAY_STORE;
    process.env.PAY_KIT_ALLOW_INMEMORY_REPLAY_STORE = "1";

    const impl: ImplementationDefinition = {
      id: "synthetic-unset-env-server",
      label: "synthetic unset environment server",
      role: "server",
      command: [
        process.execPath,
        "-e",
        [
          "if (process.env.PAY_KIT_ALLOW_INMEMORY_REPLAY_STORE !== undefined) {",
          "  process.stderr.write('inherited opt-in was not removed\\n');",
          "  process.exit(9);",
          "}",
          "process.stdout.write(JSON.stringify({ type: 'ready', role: 'server', port: 12345 }) + '\\n');",
          "setInterval(() => {}, 1_000);",
        ].join("\n"),
      ],
      enabled: true,
    };

    try {
      const server = await startServer(impl, {
        PAY_KIT_ALLOW_INMEMORY_REPLAY_STORE: undefined,
      });
      expect(server.ready.port).toBe(12345);
      await stopServer(server);
    } finally {
      if (original === undefined) {
        delete process.env.PAY_KIT_ALLOW_INMEMORY_REPLAY_STORE;
      } else {
        process.env.PAY_KIT_ALLOW_INMEMORY_REPLAY_STORE = original;
      }
    }
  });

  it.skipIf(process.platform === "win32")(
    "removes the run-scoped replay directory on SIGHUP",
    async () => {
      const temporaryRoot = mkdtempSync(
        join(tmpdir(), "pay-kit-harness-sighup-"),
      );
      const child = spawn(
        process.execPath,
        [
          "--import",
          "tsx",
          "--input-type=module",
          "--eval",
          "await import('./src/process.ts'); console.log('ready'); setInterval(() => {}, 1000);",
        ],
        {
          cwd: process.cwd(),
          env: { ...process.env, TMPDIR: temporaryRoot },
          stdio: ["ignore", "pipe", "pipe"],
        },
      );
      const replayDirectories = () =>
        readdirSync(temporaryRoot).filter((entry) =>
          entry.startsWith("pay-kit-harness-replay-"),
        );

      try {
        await Promise.race([
          once(child.stdout!, "data"),
          once(child, "exit").then(([code]) => {
            throw new Error(`cleanup probe exited before ready with code ${code}`);
          }),
        ]);
        expect(replayDirectories()).toHaveLength(1);
        child.kill("SIGHUP");
        const [code, signal] = await once(child, "exit");
        expect({ code, signal }).toEqual({ code: 129, signal: null });
        expect(replayDirectories()).toEqual([]);
      } finally {
        if (child.exitCode === null && child.signalCode === null) {
          child.kill("SIGKILL");
        }
        rmSync(temporaryRoot, { force: true, recursive: true });
      }
    },
  );
});
