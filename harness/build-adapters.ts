import { spawnSync } from "node:child_process";
import { cpSync, mkdirSync, readdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { parseArgs } from "node:util";
import { getNativeTarget, type NativeTarget } from "./src/artifacts.js";
import { clientImplementations, serverImplementations } from "./src/implementations.js";
import { discoverRunners } from "./src/conformance/runners.js";

/** Separate role selectors; interpreted adapters are validated but need no build. */
export type AdapterSelection = { clients: readonly string[]; servers: readonly string[]; conformance?: readonly string[] };

/** Validate selections and deduplicate aliases into distinct native build targets. */
export function planAdapterBuilds(selection: AdapterSelection): NativeTarget[] {
  const targets = new Map<string, NativeTarget>();
  for (const [role, ids, implementations] of [
    ["client", selection.clients, clientImplementations],
    ["server", selection.servers, serverImplementations],
    ["conformance", selection.conformance ?? [], discoverRunners().map(({ language }) => ({ id: language }))],
  ] as const) {
    for (const id of ids) {
      if (!implementations.some((implementation) => implementation.id === id)) {
        throw new Error(`Unknown ${role} adapter "${id}"`);
      }
      const target = getNativeTarget(role, id);
      if (target) targets.set(target.key, target);
    }
  }
  return [...targets.values()].sort((a, b) => a.key.localeCompare(b.key));
}

/** Strict command-line selectors for the platform build jobs. */
export function parseBuildArguments(args: string[]): AdapterSelection & { out: string } {
  const { values } = parseArgs({
    args,
    options: {
      clients: { type: "string" },
      servers: { type: "string" },
      conformance: { type: "string" },
      out: { type: "string" },
    },
  });
  if (!values.out?.trim()) throw new Error("--out is required");
  const split = (value?: string) => [...new Set((value ?? "").split(",").map((id) => id.trim()).filter(Boolean))];
  return { clients: split(values.clients), servers: split(values.servers), conformance: split(values.conformance), out: values.out };
}

const harnessDirectory = dirname(fileURLToPath(import.meta.url));

function run(command: string, args: string[], cwd: string, capture = false): string {
  const result = spawnSync(command, args, {
    cwd, encoding: "utf8",
    stdio: capture ? ["ignore", "pipe", "inherit"] : "inherit",
  });
  if (result.error) throw result.error;
  if (result.status !== 0) throw new Error(`${command} ${args.join(" ")} failed (${result.signal ?? result.status})`);
  return result.stdout ?? "";
}

/** Compile each target once and package runnable binaries, resources, and JVM libraries. */
export function buildAdapters(targets: readonly NativeTarget[], outputDirectory: string): void {
  const out = resolve(outputDirectory);
  mkdirSync(out, { recursive: true });
  const rust = targets.filter((target) => target.toolchain === "rust");
  if (rust.length) {
    // A controlled target-dir avoids dependence on CARGO_TARGET_DIR or workspace config.
    const targetDirectory = resolve(harnessDirectory, "../rust/target/harness-artifacts");
    run("cargo", [
      "build", "--manifest-path", "../rust/Cargo.toml",
      "--target-dir", targetDirectory, "-p", "paykit-harness-bins",
      ...rust.flatMap((target) => ["--bin", target.product]),
    ], harnessDirectory);
    for (const target of rust) {
      mkdirSync(resolve(out, target.key), { recursive: true });
      cpSync(resolve(targetDirectory, "debug", target.product), resolve(out, target.executable));
    }
  }
  for (const target of targets.filter((target) => target.toolchain !== "rust")) {
    const cwd = resolve(harnessDirectory, target.directory);
    const destination = resolve(out, target.key);
    mkdirSync(destination, { recursive: true });
    switch (target.toolchain) {
      case "go":
        run("go", ["build", "-o", resolve(out, target.executable), "."], cwd);
        break;
      case "swift": {
        const configuration = target.role === "conformance" ? "release" : "debug";
        run("swift", ["build", "--configuration", configuration, "--product", target.product], cwd);
        const bin = run("swift", ["build", "--configuration", configuration, "--show-bin-path"], cwd, true).trim();
        cpSync(resolve(bin, target.product), resolve(out, target.executable));
        // SwiftPM locates resources beside the executable after relocation.
        for (const entry of readdirSync(bin)) {
          if (/\.(bundle|resources|dylib|so)$/.test(entry)) {
            cpSync(resolve(bin, entry), resolve(destination, entry), { recursive: true, dereference: true });
          }
        }
        break;
      }
      case "kotlin":
        run("gradle", ["--no-daemon", "installDist"], cwd);
        cpSync(resolve(cwd, "build/install", target.product), destination, { recursive: true });
        break;
    }
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const selection = parseBuildArguments(process.argv.slice(2));
  buildAdapters(planAdapterBuilds(selection), selection.out);
}
