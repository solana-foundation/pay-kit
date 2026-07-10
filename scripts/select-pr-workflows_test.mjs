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
expect(["harness/go-server/main.go"], ["go"]);
expect(["python/src/solana_pay_kit/protocols/mpp/server/session.py"], ["python"]);
expect(["harness/python-server/server.py"], ["python"]);
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
assert.match(routerWorkflow, /ref: \$\{\{ github\.sha \}\}/);
assert.doesNotMatch(routerWorkflow, /github\.event\.pull_request\.head\.sha/);

console.log("select-pr-workflows_test: PASS");
