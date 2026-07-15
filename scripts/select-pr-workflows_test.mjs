#!/usr/bin/env node
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { WORKFLOWS, selectWorkflows } from "./select-pr-workflows.mjs";

const none = Object.fromEntries(WORKFLOWS.map((name) => [name, false]));
const all = Object.fromEntries(WORKFLOWS.map((name) => [name, true]));

function expectedSelection(enabled) {
  if (enabled === "all") {
    return all;
  }
  const expected = { ...none };
  for (const name of enabled) {
    expected[name] = true;
  }
  return expected;
}

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..");
const fixture = JSON.parse(
  readFileSync(
    join(repoRoot, "scripts", "fixtures", "select-pr-workflows.json"),
    "utf8",
  ),
);
for (const testCase of fixture.cases) {
  assert.deepEqual(
    selectWorkflows(testCase.files),
    expectedSelection(testCase.enabled),
    testCase.name,
  );
}

const routerWorkflow = readFileSync(
  join(repoRoot, ".github", "workflows", "pr-routing.yml"),
  "utf8",
);
const coreWorkflow = readFileSync(
  join(repoRoot, ".github", "workflows", "ci.yml"),
  "utf8",
);
assert.match(routerWorkflow, /ref: \$\{\{ github\.sha \}\}/);
assert.doesNotMatch(routerWorkflow, /github\.event\.pull_request\.head\.sha/);
assert.match(routerWorkflow, /fetch-depth: 2/);
assert.match(routerWorkflow, /set -o pipefail/);
assert.match(routerWorkflow, /git rev-parse --verify HEAD\^1/);
assert.match(routerWorkflow, /git diff --no-renames --name-only HEAD\^1 HEAD/);
assert.doesNotMatch(routerWorkflow, /github\.event\.pull_request\.base\.sha/);
assert.doesNotMatch(routerWorkflow, /git fetch --no-tags --depth=1 origin/);
assert.match(routerWorkflow, /uses: \.\/\.github\/workflows\/ci\.yml/);
assert.match(routerWorkflow, /docs_only: \$\{\{ steps\.select\.outputs\.docs_only \}\}/);
assert.match(routerWorkflow, /node scripts\/verify-routed-sdk-gate\.mjs/);
assert.match(coreWorkflow, /^  workflow_call:/m);
assert.doesNotMatch(coreWorkflow, /^  pull_request:/m);
assert.doesNotMatch(coreWorkflow, /github\.event_name != 'workflow_call'/);
assert.match(
  coreWorkflow,
  /github\.event_name == 'push' \|\| inputs\.run_typescript/,
);

console.log("select-pr-workflows_test: PASS");
