#!/usr/bin/env node
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  getSourceInventory,
  validateLedger,
} from "./validate-pr216-ledger.mjs";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const ledger = JSON.parse(
  readFileSync(resolve(repoRoot, ".github/delivery/pr216-ledger.json"), "utf8"),
);
const inventory = getSourceInventory();
const ciWorkflow = readFileSync(
  resolve(repoRoot, ".github/workflows/ci.yml"),
  "utf8",
);

validateLedger(ledger, inventory);

const lintJob = ciWorkflow.match(
  /\n  lint:\n([\s\S]*?)(?=\n  [a-z][a-z0-9-]*:\n)/,
)?.[1];
assert.ok(lintJob, "ci.yml must define the lint job");
assert.match(
  lintJob,
  /actions\/checkout@[a-f0-9]+[^\n]*\n\s+with:\n(?:\s+#[^\n]*\n)*\s+fetch-depth: 0\n/,
  "the ledger gate needs full Git history in the lint job",
);

function expectFailure(name, mutate, pattern) {
  const candidate = structuredClone(ledger);
  mutate(candidate);
  assert.throws(() => validateLedger(candidate, inventory), pattern, name);
}

expectFailure(
  "same-count commit substitution fails",
  (candidate) => {
    candidate.commits[0].sha = "0000000000000000000000000000000000000000";
  },
  /authoritative set digest mismatch/,
);
expectFailure(
  "same-count path substitution fails",
  (candidate) => {
    candidate.paths[0].path = "substituted/path.txt";
  },
  /authoritative set digest mismatch/,
);
expectFailure(
  "unknown status fails",
  (candidate) => {
    candidate.commits[0].status = "done";
  },
  /status must be one of/,
);
expectFailure(
  "evidence is mandatory",
  (candidate) => {
    candidate.commits[0].evidence = [];
  },
  /evidence must not be empty/,
);
expectFailure(
  "open delivery records require owners",
  (candidate) => {
    delete candidate.commits[0].owner;
  },
  /owner must be a string/,
);
expectFailure(
  "open delivery records require follow-ups",
  (candidate) => {
    delete candidate.paths.find((record) => record.status === "open_pr")
      .followUp;
  },
  /followUp must be a string/,
);
expectFailure(
  "integrated blob substitution fails",
  (candidate) => {
    const integrated = candidate.paths.find(
      (record) => record.status === "integrated",
    );
    integrated.evidence[0].deliveryBlob =
      "0000000000000000000000000000000000000000";
  },
  /delivery blob evidence is stale/,
);
expectFailure(
  "status summaries cannot drift",
  (candidate) => {
    candidate.summary.commits.missing -= 1;
  },
  /commit status summary is stale/,
);

console.log("validate-pr216-ledger_test: PASS");
