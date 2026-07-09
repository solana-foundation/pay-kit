// Manifest-driven conformance-runner discovery.
//
// Each SDK declares its conformance runner in harness/runners/<lang>.json:
//
//   { "language": "go", "command": ["go", "run", "./cmd/conformance"],
//     "cwd": "go" }
//
// The driver (test/conformance.test.ts) globs these manifests instead of
// carrying a hardcoded RUNNERS table, so adding a language is a file drop
// with no central edit. `cwd` is the runner's working directory relative to
// the repo root: each non-TypeScript runner must run from its own SDK tree
// so its toolchain resolves the project (go module, uv venv, bundler
// Gemfile, composer autoloader, lua package path); `command` paths are
// resolved relative to that cwd. Mirrors mpp-tools' adapter.json discovery.

import { readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import type { ConformanceVector, VectorMode } from "./schema";

export type ModeCapabilities = Partial<
  Record<ConformanceVector["intent"], VectorMode[]>
>;

export type RunnerManifest = {
  language: string;
  command: string[];
  // Working directory relative to the repo root. Defaults to the repo root.
  cwd?: string;
  // Intents this runner can exercise. When omitted, the runner is assumed to
  // support the original cross-SDK intents ("charge", "x402-exact"); a vector
  // whose intent is not listed is skipped for this runner rather than failed.
  // This lets a new intent (e.g. "session") land with only the SDKs that
  // implement it, without editing every other language's runner.
  intents?: string[];
  // Exact modes backed by a real verifier. Declaring a mode makes every
  // eligible vector mandatory; unsupported-mode is then a conformance error.
  modesByIntent?: ModeCapabilities;
  // Optional explicit identity when the spawned process intentionally reports
  // a shared implementation name instead of the manifest language.
  reportsAs?: string;
};

// The intents every runner is assumed to support when its manifest does not
// declare an explicit `intents` list.
const DEFAULT_INTENTS = ["charge", "x402-exact"];
const KNOWN_INTENTS = new Set(["charge", "x402-exact", "session"]);
const KNOWN_MODES = new Set<VectorMode>([
  "build-transaction",
  "verify-transaction",
  "canonical-bytes",
  "verify-x402-transaction",
]);

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(here, "..", "..", "..");
const manifestsDir = join(here, "..", "..", "runners");

function isRunnerManifest(value: unknown): value is RunnerManifest {
  if (typeof value !== "object" || value === null) return false;
  const m = value as Record<string, unknown>;
  if (typeof m.language !== "string" || m.language === "") return false;
  if (!Array.isArray(m.command) || m.command.length === 0) return false;
  if (!m.command.every((c) => typeof c === "string")) return false;
  if (m.cwd !== undefined && typeof m.cwd !== "string") return false;
  if (
    m.intents !== undefined &&
    (!Array.isArray(m.intents) || !m.intents.every((i) => typeof i === "string"))
  ) {
    return false;
  }
  if (m.modesByIntent !== undefined) {
    if (typeof m.modesByIntent !== "object" || m.modesByIntent === null || Array.isArray(m.modesByIntent)) {
      return false;
    }
    const intents = m.intents ?? DEFAULT_INTENTS;
    for (const [intent, modes] of Object.entries(m.modesByIntent)) {
      if (!KNOWN_INTENTS.has(intent) || !intents.includes(intent)) return false;
      if (!Array.isArray(modes) || modes.length === 0 || !modes.every((mode) => typeof mode === "string" && KNOWN_MODES.has(mode as VectorMode))) {
        return false;
      }
      if (new Set(modes).size !== modes.length) return false;
    }
  }
  if (m.reportsAs !== undefined && typeof m.reportsAs !== "string") return false;
  return true;
}

export type DiscoveredRunner = {
  language: string;
  command: string[];
  // Absolute working directory the driver spawns the runner in.
  cwd: string;
  // Resolved intent capabilities (manifest `intents` or the default set).
  intents: string[];
  modesByIntent?: ModeCapabilities;
  reportsAs?: string;
};

// Discover every runner manifest under harness/runners/, validate it, and
// resolve its cwd to an absolute path. Sorted by language for a stable,
// deterministic suite order across machines. Throws on a malformed manifest
// so a typo fails loudly at load instead of silently dropping a runner.
export function discoverRunners(): DiscoveredRunner[] {
  const files = readdirSync(manifestsDir)
    .filter((name) => name.endsWith(".json"))
    .sort();
  const runners: DiscoveredRunner[] = [];
  for (const file of files) {
    const path = join(manifestsDir, file);
    const parsed: unknown = JSON.parse(readFileSync(path, "utf8"));
    if (!isRunnerManifest(parsed)) {
      throw new Error(`runner manifest ${file} is malformed`);
    }
    runners.push({
      language: parsed.language,
      command: parsed.command,
      cwd: parsed.cwd ? join(repoRoot, parsed.cwd) : repoRoot,
      intents: parsed.intents ?? DEFAULT_INTENTS,
      ...(parsed.modesByIntent ? { modesByIntent: parsed.modesByIntent } : {}),
      ...(parsed.reportsAs ? { reportsAs: parsed.reportsAs } : {}),
    });
  }
  return runners;
}
