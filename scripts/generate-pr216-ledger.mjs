#!/usr/bin/env node
import { existsSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  ALLOWED_STATUSES,
  AUTHORITATIVE_SOURCE,
  PLANNED_BUCKETS,
  getCommitPaths,
  getSourceInventory,
} from "./validate-pr216-ledger.mjs";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const ledgerPath = resolve(repoRoot, ".github/delivery/pr216-ledger.json");
const languageRoots = new Set([
  "typescript",
  "rust",
  "go",
  "python",
  "ruby",
  "lua",
  "php",
  "swift",
  "kotlin",
]);

function bucketForPath(path) {
  const root = path.split("/", 1)[0];
  if (languageRoots.has(root)) {
    return root;
  }

  const harnessOwner = path.match(
    /^harness\/(go|python|ruby|lua|php|swift|kotlin)(?:-|\/)/,
  )?.[1];
  if (harnessOwner && languageRoots.has(harnessOwner)) {
    return harnessOwner;
  }
  if (
    path.startsWith("harness/") ||
    path.startsWith(".github/") ||
    path.startsWith("scripts/")
  ) {
    return "harness-ci";
  }
  return "cross-sdk";
}

function bucketForCommit(sha) {
  const buckets = new Set(getCommitPaths(sha).map(bucketForPath));
  return buckets.size === 1 ? [...buckets][0] : "cross-sdk";
}

function unresolvedFields(bucket, subject) {
  return {
    owner: `pr216-${bucket}-lane`,
    followUp: `Reconcile ${subject} in the planned ${bucket} protocol bucket and replace missing only with reviewable delivery evidence.`,
  };
}

const force = process.argv.includes("--force");
if (existsSync(ledgerPath) && !force) {
  throw new Error(`${ledgerPath} already exists; pass --force to rebuild it`);
}

const inventory = getSourceInventory();
const commits = inventory.commits.map((sha) => {
  const bucket = bucketForCommit(sha);
  return {
    sha,
    subject: inventory.subjects.get(sha),
    bucket,
    status: "missing",
    evidence: [
      {
        kind: "not-claimed",
        detail:
          "No patch-equivalent delivery commit was established during ledger initialization; semantic delivery is not claimed.",
      },
    ],
    ...unresolvedFields(bucket, `source commit ${sha}`),
  };
});

const paths = inventory.paths.map((path) => {
  const bucket = bucketForPath(path);
  const sourceBlob = inventory.sourceBlobs.get(path);
  const deliveryBlob = inventory.currentBlobs.get(path);
  if (sourceBlob && sourceBlob === deliveryBlob) {
    return {
      path,
      bucket,
      status: "integrated",
      evidence: [
        {
          kind: "identical-tree-entry",
          sourceBlob,
          deliveryBlob,
          sourceRef: `${AUTHORITATIVE_SOURCE.head}:${path}`,
          deliveryRef: `${inventory.currentHead}:${path}`,
          detail:
            "The authoritative source-tip and delivery-baseline blobs are identical; this claims file-state delivery only.",
        },
      ],
    };
  }

  return {
    path,
    bucket,
    status: "missing",
    evidence: [
      {
        kind: "not-claimed",
        detail:
          "The source path is inventoried, but equivalent PR216 semantics have not been established on the delivery branch.",
      },
    ],
    ...unresolvedFields(bucket, `source path ${path}`),
  };
});

const countStatuses = (records) =>
  Object.fromEntries(
    ALLOWED_STATUSES.map((status) => [
      status,
      records.filter((record) => record.status === status).length,
    ]).filter(([, count]) => count > 0),
  );

const ledger = {
  schemaVersion: 1,
  source: { ...AUTHORITATIVE_SOURCE },
  allowedStatuses: [...ALLOWED_STATUSES],
  plannedBuckets: [...PLANNED_BUCKETS],
  deliveryBaseline: inventory.currentHead,
  summary: {
    commits: countStatuses(commits),
    paths: countStatuses(paths),
  },
  commits,
  paths,
};

writeFileSync(ledgerPath, `${JSON.stringify(ledger, null, 2)}\n`);
process.stdout.write(`generated ${ledgerPath}\n`);
