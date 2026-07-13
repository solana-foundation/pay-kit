#!/usr/bin/env node
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

export const AUTHORITATIVE_SOURCE = Object.freeze({
  base: "49dc7975c674b34e461bed89d2a1a9e49e9e5920",
  head: "45ad8c9acd7a71d4dd12b87321a9902c71fef865",
  commitCount: 113,
  pathCount: 237,
  commitSetSha256:
    "6db6ba37862590cb07f6d5dfd89a28416424b4946534ba255a90c41c8b0d18fa",
  pathSetSha256:
    "a7d381df019007c3d6f413d2b4377cca00beb27572308c908894e4b8dec835fa",
});

export const ALLOWED_STATUSES = Object.freeze([
  "integrated",
  "open_pr",
  "superseded",
  "obsolete_test_only",
  "missing",
]);

export const PLANNED_BUCKETS = Object.freeze([
  "typescript",
  "rust",
  "go",
  "python",
  "ruby",
  "lua",
  "php",
  "swift",
  "kotlin",
  "harness-ci",
  "cross-sdk",
]);

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const defaultLedgerPath = resolve(
  repoRoot,
  ".github/delivery/pr216-ledger.json",
);

function git(args, cwd = repoRoot) {
  return execFileSync("git", args, { cwd, encoding: "utf8" }).trimEnd();
}

function lines(value) {
  return value === "" ? [] : value.split("\n");
}

export function canonicalSetDigest(values) {
  const canonical = `${[...values].sort().join("\n")}\n`;
  return createHash("sha256").update(canonical).digest("hex");
}

function treeEntries(revision, cwd = repoRoot) {
  const entries = new Map();
  for (const line of lines(
    git(["ls-tree", "-r", "--full-tree", revision], cwd),
  )) {
    const match = line.match(/^\d+\s+\w+\s+([0-9a-f]{40})\t(.+)$/);
    if (match) {
      entries.set(match[2], match[1]);
    }
  }
  return entries;
}

export function getSourceInventory(cwd = repoRoot) {
  const range = `${AUTHORITATIVE_SOURCE.base}..${AUTHORITATIVE_SOURCE.head}`;
  const commits = lines(git(["rev-list", "--reverse", range], cwd));
  const paths = lines(git(["diff", "--name-only", range], cwd));
  const subjects = new Map(
    commits.map((sha) => [sha, git(["show", "-s", "--format=%s", sha], cwd)]),
  );
  const currentHead = git(["rev-parse", "HEAD"], cwd);

  return {
    commits,
    paths,
    subjects,
    sourceBlobs: treeEntries(AUTHORITATIVE_SOURCE.head, cwd),
    currentBlobs: treeEntries("HEAD", cwd),
    currentHead,
  };
}

export function getCommitPaths(sha, cwd = repoRoot) {
  return lines(
    git(["diff-tree", "--no-commit-id", "--name-only", "-r", sha], cwd),
  );
}

function requireString(value, label) {
  assert.equal(typeof value, "string", `${label} must be a string`);
  assert.notEqual(value.trim(), "", `${label} must not be empty`);
}

function validateEvidence(record, label) {
  assert.ok(
    Array.isArray(record.evidence),
    `${label}.evidence must be an array`,
  );
  assert.ok(record.evidence.length > 0, `${label}.evidence must not be empty`);
  for (const [index, item] of record.evidence.entries()) {
    requireString(item?.kind, `${label}.evidence[${index}].kind`);
    requireString(item?.detail, `${label}.evidence[${index}].detail`);
  }
}

function validateRecord(record, label) {
  assert.ok(record && typeof record === "object", `${label} must be an object`);
  assert.ok(
    ALLOWED_STATUSES.includes(record.status),
    `${label}.status must be one of ${ALLOWED_STATUSES.join(", ")}`,
  );
  assert.ok(
    PLANNED_BUCKETS.includes(record.bucket),
    `${label}.bucket must name a planned protocol bucket`,
  );
  validateEvidence(record, label);

  if (record.status === "open_pr" || record.status === "missing") {
    requireString(record.owner, `${label}.owner`);
    requireString(record.followUp, `${label}.followUp`);
  }
}

function validateIdentifiers(records, key, expected, digest, label) {
  assert.equal(records.length, expected.length, `${label} count must be exact`);
  const identifiers = records.map((record) => record[key]);
  for (const [index, identifier] of identifiers.entries()) {
    requireString(identifier, `${label}[${index}].${key}`);
  }
  assert.equal(
    new Set(identifiers).size,
    identifiers.length,
    `${label} contains duplicates`,
  );
  assert.equal(
    canonicalSetDigest(identifiers),
    digest,
    `${label} authoritative set digest mismatch`,
  );
  assert.deepEqual(
    [...identifiers].sort(),
    [...expected].sort(),
    `${label} identifiers differ from the Git source range`,
  );
}

function statusCounts(records) {
  const counts = {};
  for (const record of records) {
    counts[record.status] = (counts[record.status] ?? 0) + 1;
  }
  return counts;
}

function validateIntegratedPath(record, inventory, label) {
  const blobEvidence = record.evidence.find(
    (item) => item.kind === "identical-tree-entry",
  );
  assert.ok(
    blobEvidence,
    `${label} integrated path needs identical-tree-entry evidence`,
  );
  requireString(blobEvidence.sourceBlob, `${label}.evidence.sourceBlob`);
  requireString(blobEvidence.deliveryBlob, `${label}.evidence.deliveryBlob`);

  const sourceBlob = inventory.sourceBlobs.get(record.path);
  const currentBlob = inventory.currentBlobs.get(record.path);
  assert.ok(sourceBlob, `${label} has no blob at the authoritative source tip`);
  assert.ok(currentBlob, `${label} has no blob at the current delivery head`);
  assert.equal(
    blobEvidence.sourceBlob,
    sourceBlob,
    `${label} source blob evidence is stale`,
  );
  assert.equal(
    blobEvidence.deliveryBlob,
    currentBlob,
    `${label} delivery blob evidence is stale`,
  );
  assert.equal(
    sourceBlob,
    currentBlob,
    `${label} source and delivery blobs differ`,
  );
}

export function validateLedger(ledger, inventory) {
  assert.equal(ledger.schemaVersion, 1, "schemaVersion must be 1");
  assert.deepEqual(
    ledger.allowedStatuses,
    ALLOWED_STATUSES,
    "allowedStatuses must exactly match the validator contract",
  );
  assert.deepEqual(
    ledger.plannedBuckets,
    PLANNED_BUCKETS,
    "plannedBuckets must exactly match the validator contract",
  );

  const source = ledger.source;
  assert.ok(
    source && typeof source === "object",
    "source metadata is required",
  );
  assert.equal(
    source.base,
    AUTHORITATIVE_SOURCE.base,
    "source.base is not authoritative",
  );
  assert.equal(
    source.head,
    AUTHORITATIVE_SOURCE.head,
    "source.head is not authoritative",
  );
  assert.equal(
    source.commitCount,
    AUTHORITATIVE_SOURCE.commitCount,
    "source commit count is not authoritative",
  );
  assert.equal(
    source.pathCount,
    AUTHORITATIVE_SOURCE.pathCount,
    "source path count is not authoritative",
  );
  assert.equal(
    source.commitSetSha256,
    AUTHORITATIVE_SOURCE.commitSetSha256,
    "source commit digest is not authoritative",
  );
  assert.equal(
    source.pathSetSha256,
    AUTHORITATIVE_SOURCE.pathSetSha256,
    "source path digest is not authoritative",
  );

  assert.equal(
    inventory.commits.length,
    AUTHORITATIVE_SOURCE.commitCount,
    "Git range commit count changed",
  );
  assert.equal(
    inventory.paths.length,
    AUTHORITATIVE_SOURCE.pathCount,
    "Git range path count changed",
  );
  assert.equal(
    canonicalSetDigest(inventory.commits),
    AUTHORITATIVE_SOURCE.commitSetSha256,
    "Git range commit digest changed",
  );
  assert.equal(
    canonicalSetDigest(inventory.paths),
    AUTHORITATIVE_SOURCE.pathSetSha256,
    "Git range path digest changed",
  );

  assert.ok(Array.isArray(ledger.commits), "commits must be an array");
  assert.ok(Array.isArray(ledger.paths), "paths must be an array");
  validateIdentifiers(
    ledger.commits,
    "sha",
    inventory.commits,
    AUTHORITATIVE_SOURCE.commitSetSha256,
    "commits",
  );
  validateIdentifiers(
    ledger.paths,
    "path",
    inventory.paths,
    AUTHORITATIVE_SOURCE.pathSetSha256,
    "paths",
  );

  for (const [index, record] of ledger.commits.entries()) {
    const label = `commits[${index}]`;
    validateRecord(record, label);
    assert.equal(
      record.subject,
      inventory.subjects.get(record.sha),
      `${label}.subject differs from Git`,
    );
    if (record.status === "integrated") {
      const patchEvidence = record.evidence.find(
        (item) => item.kind === "patch-equivalent",
      );
      assert.ok(
        patchEvidence,
        `${label} integrated commit needs patch-equivalent evidence`,
      );
      requireString(
        patchEvidence.deliveryCommit,
        `${label}.evidence.deliveryCommit`,
      );
    }
  }

  for (const [index, record] of ledger.paths.entries()) {
    const label = `paths[${index}]`;
    validateRecord(record, label);
    if (record.status === "integrated") {
      validateIntegratedPath(record, inventory, label);
    }
  }

  assert.deepEqual(
    ledger.summary?.commits,
    statusCounts(ledger.commits),
    "commit status summary is stale",
  );
  assert.deepEqual(
    ledger.summary?.paths,
    statusCounts(ledger.paths),
    "path status summary is stale",
  );
  return {
    commits: ledger.commits.length,
    paths: ledger.paths.length,
    commitStatuses: statusCounts(ledger.commits),
    pathStatuses: statusCounts(ledger.paths),
  };
}

function main() {
  const ledgerPath = process.argv[2]
    ? resolve(process.argv[2])
    : defaultLedgerPath;
  const ledger = JSON.parse(readFileSync(ledgerPath, "utf8"));
  const result = validateLedger(ledger, getSourceInventory());
  process.stdout.write(`pr216-ledger: OK ${JSON.stringify(result)}\n`);
}

if (
  process.argv[1] &&
  resolve(process.argv[1]) === fileURLToPath(import.meta.url)
) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`pr216-ledger: FAIL ${error.message}\n`);
    process.exitCode = 1;
  }
}
