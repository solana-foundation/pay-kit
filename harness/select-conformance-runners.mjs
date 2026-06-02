#!/usr/bin/env node
// Path-based conformance-runner selection for CI.
//
// Prints the language allowlist for the conformance matrix given a set of
// changed paths, so a CI job can skip runners whose SDK a PR did not touch.
// A shared-file change (vectors, driver, conformance source, runner
// manifests) forces the full matrix. Mirrors mpp-tools select_ci_adapters.py.
//
// Usage:
//   node harness/select-conformance-runners.mjs <path> [<path> ...]
//   git diff --name-only origin/main... | node harness/select-conformance-runners.mjs
//
// Output (stdout): one line, a comma-separated language list suitable for
//   MPP_CONFORMANCE_LANGUAGES, e.g. "go,python". Empty change set or a
//   shared-file change prints the full set.
//
// The selection logic lives in src/conformance/select.ts so the driver and
// this script share one source of truth.

import { selectConformanceLanguages } from "./src/conformance/select.ts";

async function readStdinPaths() {
  if (process.stdin.isTTY) return [];
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(chunk);
  return Buffer.concat(chunks)
    .toString("utf8")
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean);
}

const argvPaths = process.argv.slice(2);
const changedPaths = argvPaths.length > 0 ? argvPaths : await readStdinPaths();
const languages = selectConformanceLanguages(changedPaths);
process.stdout.write(languages.join(",") + "\n");
