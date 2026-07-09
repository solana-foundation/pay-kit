#!/usr/bin/env node
// Post-run assertion for the harness release-gate legs.
//
// The workflow legs used to select the assertion by a free-text
// `--testNamePattern "<pair title>"`. Those titles are built dynamically
// (`${scenario.id}: ${client} client pays ${server} server`), so a title
// rename or a selector typo made the pattern match zero tests. With vitest's
// `passWithNoTests` defaulting true that produced a green run with zero payment
// tests executed. The legs now select purely via the validated
// MPP_HARNESS_*/X402_HARNESS_* env selectors and hand vitest's JSON report to
// this script, which fails loud when the number of settlement pair-tests that
// actually EXECUTED does not match the leg's pinned expectation.
//
// Usage:
//   node scripts/assert-run-count.mjs --report <path> --min <n> [--exact <n>]
//
// `--min` is the floor (must be >= 1). `--exact`, when given, pins the count to
// an exact value so a leg's selected pair count cannot silently drift. A
// settlement pair-test is any executed test whose title denotes a client/server
// pairing; the per-scenario "has at least one eligible client/server pair"
// guard tests are NOT counted (they assert eligibility, not settlement).

import { readFileSync } from "node:fs";

function parseArgs(argv) {
  const args = { report: undefined, min: undefined, exact: undefined };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--report") {
      args.report = argv[++i];
    } else if (arg === "--min") {
      args.min = Number(argv[++i]);
    } else if (arg === "--exact") {
      args.exact = Number(argv[++i]);
    } else if (arg.startsWith("--report=")) {
      args.report = arg.slice("--report=".length);
    } else if (arg.startsWith("--min=")) {
      args.min = Number(arg.slice("--min=".length));
    } else if (arg.startsWith("--exact=")) {
      args.exact = Number(arg.slice("--exact=".length));
    } else {
      throw new Error(`Unknown argument: ${arg}`);
    }
  }
  return args;
}

// A settlement pair-test title. The e2e matrix registers three shapes:
//   "<scenario>: <client> client pays <server> server"
//   "<scenario>: <client> client pays <server> server twice"   (idempotent)
//   "<scenario>: <client> client, A=<a> B=<b>"                  (cross-server)
// The per-scenario "has at least one eligible ..." guards are excluded.
const PAIR_TITLE_PATTERNS = [
  / client pays .+ server(?: twice)?$/,
  / client, A=.+ B=.+$/,
];

function isPairTitle(title) {
  return PAIR_TITLE_PATTERNS.some((pattern) => pattern.test(title));
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  if (!args.report) {
    throw new Error("--report <path> is required");
  }
  const min = args.exact !== undefined ? args.exact : args.min;
  if (min === undefined || Number.isNaN(min)) {
    throw new Error("one of --min <n> or --exact <n> is required");
  }
  if (min <= 0) {
    throw new Error(
      `run-count floor must be >= 1 (got ${min}); a floor of 0 would let a zero-execution leg pass`,
    );
  }
  if (args.exact !== undefined && Number.isNaN(args.exact)) {
    throw new Error("--exact must be a number");
  }

  let report;
  try {
    report = JSON.parse(readFileSync(args.report, "utf8"));
  } catch (error) {
    throw new Error(`Could not read vitest JSON report at ${args.report}: ${error.message}`);
  }

  // A run whose overall verdict is not success must never be treated as
  // green here, independent of the pair count.
  if (report.success === false) {
    throw new Error(
      `vitest reported success=false in ${args.report}; the leg did not pass. ` +
        "Fix the failing tests rather than the run-count guard.",
    );
  }

  let executedPairs = 0;
  let skippedPairs = 0;
  for (const file of report.testResults ?? []) {
    for (const assertion of file.assertionResults ?? []) {
      if (!isPairTitle(assertion.title)) {
        continue;
      }
      if (assertion.status === "passed") {
        executedPairs += 1;
      } else if (assertion.status === "skipped" || assertion.status === "pending") {
        skippedPairs += 1;
      }
    }
  }

  if (executedPairs === 0) {
    throw new Error(
      `Zero settlement pair-tests EXECUTED in this leg (report ${args.report}; ` +
        `${skippedPairs} pair-test(s) were skipped/filtered). A leg that asserts no ` +
        "settlement is a false green: check the MPP_HARNESS_*/X402_HARNESS_* selectors.",
    );
  }

  if (args.exact !== undefined && executedPairs !== args.exact) {
    throw new Error(
      `Expected exactly ${args.exact} settlement pair-test(s) to execute in this ` +
        `leg but ${executedPairs} did (report ${args.report}). The leg's pinned pair ` +
        "count drifted: update the workflow's --exact value or fix the selectors.",
    );
  }

  if (args.exact === undefined && executedPairs < min) {
    throw new Error(
      `Expected at least ${min} settlement pair-test(s) to execute in this leg but ` +
        `only ${executedPairs} did (report ${args.report}).`,
    );
  }

  const bound = args.exact !== undefined ? `exactly ${args.exact}` : `>= ${min}`;
  console.log(
    `[assert-run-count] ${executedPairs} settlement pair-test(s) executed (${bound}). OK.`,
  );
}

try {
  main();
} catch (error) {
  console.error(`[assert-run-count] ${error.message}`);
  process.exit(1);
}
