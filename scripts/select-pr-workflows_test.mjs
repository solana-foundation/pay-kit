#!/usr/bin/env node
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { WORKFLOWS, selectWorkflows } from "./select-pr-workflows.mjs";

const none = Object.fromEntries(WORKFLOWS.map((name) => [name, false]));
const all = Object.fromEntries(WORKFLOWS.map((name) => [name, true]));

function expect(files, enabled) {
  const expected = { ...none };
  for (const name of enabled) {
    expected[name] = true;
  }
  assert.deepEqual(selectWorkflows(files), expected, files.join(", "));
}

expect(["go/protocols/x402/verify.go"], ["go"]);
expect(["typescript/packages/mpp/src/index.ts"], ["typescript"]);
expect(["html/src/index.ts"], ["typescript"]);
expect(["rust/crates/kit/src/mpp/lib.rs"], ["rust"]);
expect(["harness/go-server/main.go"], ["go"]);
expect(["python/src/solana_pay_kit/protocols/mpp/server/session.py"], ["python"]);
expect(["harness/python-server/server.py"], ["python"]);
expect(["scripts/check-python-supply-chain.sh"], ["python"]);
expect(["ruby/lib/pay_kit/protocols/mpp/store.rb"], ["ruby"]);
expect(["lua/pay_kit/protocols/mpp/store.lua"], ["lua"]);
expect(["php/src/Protocol/Mpp/Store.php"], ["php"]);
expect(["swift/Sources/SolanaPayKit/Protocols/Mpp/Core/CanonicalJSON.swift"], ["swift"]);
expect(["kotlin/src/main/kotlin/com/solana/paykit/CanonicalJson.kt"], ["kotlin"]);
expect(["harness/vectors/canonical-bytes.json"], ["harness"]);
expect(["docs/security.md"], []);
assert.deepEqual(selectWorkflows(["scripts/unclassified-security-check.sh"]), all);
assert.deepEqual(selectWorkflows([]), all);

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..");
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
assert.match(routerWorkflow, /git diff --name-only HEAD\^1 HEAD/);
assert.doesNotMatch(routerWorkflow, /github\.event\.pull_request\.base\.sha/);
assert.doesNotMatch(routerWorkflow, /git fetch --no-tags --depth=1 origin/);
assert.match(routerWorkflow, /uses: \.\/\.github\/workflows\/ci\.yml/);
assert.match(coreWorkflow, /^  workflow_call:/m);
assert.doesNotMatch(coreWorkflow, /^  pull_request:/m);
assert.doesNotMatch(coreWorkflow, /github\.event_name != 'workflow_call'/);
assert.match(coreWorkflow, /github\.event_name == 'push' \|\| inputs\.run_typescript/);

console.log("select-pr-workflows_test: PASS");
