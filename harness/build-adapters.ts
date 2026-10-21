import { spawnSync } from "node:child_process";
import { cpSync, mkdirSync, readdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { parseArgs } from "node:util";
import { getNativeTarget, type NativeTarget } from "./src/artifacts.js";
import { discoverRunners } from "./src/conformance/runners.js";

// Builds the compiled offline conformance runners (Swift, Kotlin, Go) once
// per platform. The interop payment adapters are built by
// `pkc adapters build --shard <id> --out <dir>` from the Rust registry.

/** Conformance runner selection; interpreted runners are validated but need no build. */
export type AdapterSelection = { conformance: readonly string[] };

/** Validate selections and deduplicate them into distinct native build targets. */
export function planAdapterBuilds(selection: AdapterSelection): NativeTarget[] {
  const targets = new Map<string, NativeTarget>();
  const known = discoverRunners().map(({ language }) => language);
  for (const id of selection.conformance) {
    if (!known.includes(id)) throw new Error(`Unknown conformance adapter "${id}"`);
    const target = getNativeTarget("conformance", id);
    if (target) targets.set(target.key, target);
  }
  return [...targets.values()].sort((a, b) => a.key.localeCompare(b.key));
}

/** Strict command-line selectors for the platform build jobs. */
export function parseBuildArguments(args: string[]): AdapterSelection & { out: string } {
  const { values } = parseArgs({
    args,
    options: {
      conformance: { type: "string" },
      out: { type: "string" },
      clients: { type: "string" },
      servers: { type: "string" },
    },
  });
  if (values.clients !== undefined || values.servers !== undefined) {
    throw new Error("payment adapters are built by `pkc adapters build`; build-adapters.ts only builds --conformance runners");
  }
  if (!values.out?.trim()) throw new Error("--out is required");
  const split = (value?: string) => [...new Set((value ?? "").split(",").map((id) => id.trim()).filter(Boolean))];
  return { conformance: split(values.conformance), out: values.out };
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
  for (const target of targets) {
    const cwd = resolve(harnessDirectory, target.directory);
    const destination = resolve(out, target.key);
    mkdirSync(destination, { recursive: true });
    switch (target.toolchain) {
      case "go":
        run("go", ["build", "-o", resolve(out, target.executable), "."], cwd);
        break;
      case "swift": {
        run("swift", ["build", "--configuration", "release", "--product", target.product], cwd);
        const bin = run("swift", ["build", "--configuration", "release", "--show-bin-path"], cwd, true).trim();
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
