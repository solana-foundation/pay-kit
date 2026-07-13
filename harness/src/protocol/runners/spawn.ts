// Manifest-driven, spawned-subprocess protocol adapter.
//
// Each SDK declares its protocol runner in harness/protocol-runners/<lang>.json:
//
//   { "language": "rust",
//     "command": ["cargo", "run", "-q", "--example", "protocol_runner"],
//     "cwd": "rust" }
//
// The runner reads one canonical adapter-ABI request as JSON on stdin
// (`{ "op": ..., "input": ... }`) and writes one response as JSON on stdout
// (`{ "success": ..., ... }`). This mirrors the cross-SDK conformance layer
// in src/conformance/runners.ts exactly, so adding a language is a file drop:
// implement the stdin/stdout runner and drop a manifest. The TypeScript
// reference runner at runners/typescript.ts is the contract every other
// language runner must satisfy.

import { spawn } from "node:child_process";
import { readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import type { AdapterRequest, AdapterResponse, ProtocolAdapter } from "../driver";

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(here, "..", "..", "..", "..");
const manifestsDir = join(here, "..", "..", "..", "protocol-runners");

export type ProtocolRunnerManifest = {
  language: string;
  command: string[];
  cwd?: string;
  reportsAs?: string;
};

export type DiscoveredProtocolRunner = {
  language: string;
  command: string[];
  cwd: string;
  reportsAs?: string;
};

function isManifest(value: unknown): value is ProtocolRunnerManifest {
  if (typeof value !== "object" || value === null) return false;
  const m = value as Record<string, unknown>;
  if (typeof m.language !== "string" || m.language === "") return false;
  if (!Array.isArray(m.command) || m.command.length === 0) return false;
  if (!m.command.every((c) => typeof c === "string")) return false;
  if (m.cwd !== undefined && typeof m.cwd !== "string") return false;
  if (m.reportsAs !== undefined && typeof m.reportsAs !== "string") return false;
  return true;
}

export function discoverProtocolRunners(): DiscoveredProtocolRunner[] {
  const files = readdirSync(manifestsDir)
    .filter((name) => name.endsWith(".json"))
    .sort();
  const runners: DiscoveredProtocolRunner[] = [];
  for (const file of files) {
    const path = join(manifestsDir, file);
    const parsed: unknown = JSON.parse(readFileSync(path, "utf8"));
    if (!isManifest(parsed)) {
      throw new Error(`protocol runner manifest ${file} is malformed`);
    }
    runners.push({
      language: parsed.language,
      command: parsed.command,
      cwd: parsed.cwd ? join(repoRoot, parsed.cwd) : repoRoot,
      ...(parsed.reportsAs ? { reportsAs: parsed.reportsAs } : {}),
    });
  }
  return runners;
}

function validateRunnerIdentity(
  response: AdapterResponse,
  runner: DiscoveredProtocolRunner,
): AdapterResponse {
  const reported = response.language ?? response.implementation;
  const expected = runner.reportsAs ?? runner.language;
  if (reported === undefined || reported === "") {
    return {
      success: false,
      error: `runner identity missing: expected language or implementation ${expected}`,
      error_type: "runner_error",
    };
  }
  if (reported !== expected) {
    return {
      success: false,
      error: `runner identity mismatch: manifest ${runner.language} expected ${expected}, got ${reported}`,
      error_type: "runner_error",
    };
  }
  return response;
}

// Wrap a discovered runner as a ProtocolAdapter that spawns one process per
// request and exchanges a single JSON request/response over stdin/stdout.
export function spawnedProtocolAdapter(runner: DiscoveredProtocolRunner): ProtocolAdapter {
  return {
    name: runner.language,
    runProtocolRequest(request: AdapterRequest): Promise<AdapterResponse> {
      return new Promise<AdapterResponse>((resolve) => {
        const timeoutMs = Number(process.env.MPP_PROTOCOL_RUNNER_TIMEOUT_MS) || 120_000;
        const [bin, ...args] = runner.command;
        const child = spawn(bin, args, { cwd: runner.cwd });
        let stdout = "";
        let stderr = "";
        let settled = false;
        const finish = (response: AdapterResponse): void => {
          if (settled) return;
          settled = true;
          clearTimeout(timer);
          resolve(response);
        };
        // Hard timeout: a hung / unresponsive runner turns RED as a runner_error
        // rather than stalling the job until the CI-level timeout (a hang must NOT
        // read as a silent pass). Generous enough to cover a first-invocation
        // compile (`go run` / `cargo run`, cached after the first case); a genuine
        // hang is SIGKILLed here. Override with MPP_PROTOCOL_RUNNER_TIMEOUT_MS.
        const timer = setTimeout(() => {
          child.kill("SIGKILL");
          finish({
            success: false,
            error: `runner timed out after ${timeoutMs}ms; stderr: ${stderr.slice(0, 512)}`,
            error_type: "runner_error",
          });
        }, timeoutMs);
        child.stdout.on("data", (chunk) => (stdout += chunk.toString()));
        child.stderr.on("data", (chunk) => (stderr += chunk.toString()));
        child.on("error", (err) => {
          finish({ success: false, error: `spawn failed: ${err.message}`, error_type: "runner_error" });
        });
        child.on("close", () => {
          const line = stdout.trim().split("\n").filter(Boolean).pop();
          if (!line) {
            finish({
              success: false,
              error: `runner produced no output; stderr: ${stderr.slice(0, 512)}`,
              error_type: "runner_error",
            });
            return;
          }
          try {
            finish(validateRunnerIdentity(JSON.parse(line) as AdapterResponse, runner));
          } catch (err) {
            finish({
              success: false,
              error: `runner output is not JSON: ${err instanceof Error ? err.message : String(err)} (line: ${line.slice(0, 256)})`,
              error_type: "runner_error",
            });
          }
        });
        child.stdin.write(JSON.stringify(request));
        child.stdin.end();
      });
    },
  };
}
