// Maturity gate (bedrock gauge): no harness test may silently go dead in CI.
//
// The multi-agent audit's #1 systemic finding was that ~21 of 25 harness test
// files never ran in any workflow — the safety net existed but was unplugged,
// so real bugs (compute-budget cap gaps, canonical divergences, fund-safety
// defect vectors) shipped green. This gate makes that regression IMPOSSIBLE:
// every harness/test/*.test.ts must be either (a) referenced by name in a CI
// workflow, or (b) listed in CI_EXEMPT with a concrete reason. A new test that
// is neither wired nor exempted turns this RED — you cannot add a radar test and
// forget to run it.
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { describe, expect, it } from "vitest";
import { parse } from "yaml";

const here = dirname(fileURLToPath(import.meta.url)); // harness/test
const testDir = here;
const workflowsDir = join(here, "..", "..", ".github", "workflows");

// Tests that legitimately do NOT run in the standard push/PR legs, each with a
// reason. These are the E2E tier (Testing Trophy: kept minimal) — they need a
// live surfnet + the payment-channels program or multiple running SDK servers,
// so they run in dedicated on-chain / matrix legs (harness.yml, go.yml
// playground) or are opt-in, NOT the fast unit job. Keep this list SMALL and
// justified; prefer wiring a test over exempting it.
interface CiExemption {
  owner: string;
  reason: string;
  lastReviewed: string;
  removalCondition: string;
}

const CI_EXEMPT: Record<string, CiExemption> = {
  "onchain.e2e.test.ts": {
    owner: "harness",
    reason:
      "Needs a live surfnet and payment-channels program; deterministic state-transition coverage lives in the unit and conformance suites.",
    lastReviewed: "2026-07-10",
    removalCondition:
      "Remove when the workflow provisions a deterministic local validator for this file.",
  },
  "x402-upto.e2e.test.ts": {
    owner: "x402",
    reason: "Needs a live surfnet and the deployed payment-channels program.",
    lastReviewed: "2026-07-10",
    removalCondition:
      "Remove when the standard matrix provisions the program and executes this file.",
  },
  // protocol-conformance.test.ts is no longer exempt: it now honors
  // MPP_CONFORMANCE_LANGUAGES (spawn loop filtered) and is wired into ci.yml
  // pinned to `typescript`, running the canonical challenge/receipt vectors
  // against the real TS reference codecs. The 6 divergences it caught are fixed.
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function stripShellComments(run: string): string {
  return run
    .split("\n")
    .map((line) => (/^\s*#/.test(line) ? "" : line.replace(/\s+#.*$/, "")))
    .join("\n");
}

function testsInvokedByRun(run: string): string[] {
  const logical = stripShellComments(run).replace(/\\\s*\n/g, " ");
  const invoked = new Set<string>();
  for (const segment of logical.split(/\n|&&|\|\||;/)) {
    const command = segment.trim();
    if (
      !/^(?:[A-Z_][A-Z0-9_]*=\S+\s+)*(?:pnpm\s+(?:exec\s+)?|npx\s+)?vitest\s+run\b/.test(
        command,
      )
    ) {
      continue;
    }
    for (const match of command.matchAll(
      /\btest\/([A-Za-z0-9._/-]+\.test\.ts)\b/g,
    )) {
      invoked.add(match[1]);
    }
  }
  return [...invoked];
}

function collectExecutedHarnessTests(workflowYaml: string): Set<string> {
  const document = parse(workflowYaml) as unknown;
  const executed = new Set<string>();
  if (!isRecord(document) || !isRecord(document.jobs)) return executed;

  for (const job of Object.values(document.jobs)) {
    if (!isRecord(job) || !Array.isArray(job.steps)) continue;
    for (const step of job.steps) {
      if (!isRecord(step) || typeof step.run !== "string") continue;
      const workingDirectory = step["working-directory"];
      const runsInHarness =
        workingDirectory === "harness" ||
        /(?:^|\n)\s*cd\s+(?:\.\/)?harness(?:\s|$)/.test(step.run);
      if (!runsInHarness) continue;
      for (const test of testsInvokedByRun(step.run)) executed.add(test);
    }
  }
  return executed;
}

const workflowFiles = readdirSync(workflowsDir).filter((name) =>
  /\.ya?ml$/.test(name),
);
const executedTests = new Set<string>();
for (const workflow of workflowFiles) {
  const text = readFileSync(join(workflowsDir, workflow), "utf8");
  for (const test of collectExecutedHarnessTests(text)) executedTests.add(test);
}

const DIRECT_NON_PUBLISH_WORKFLOWS = [
  "android-demo.yml",
  "ci.yml",
  "go-consumer.yml",
  "go.yml",
  "harness.yml",
  "ios-demo.yml",
  "kotlin.yml",
  "lua.yml",
  "php.yml",
  "python.yml",
  "ruby.yml",
  "semgrep.yml",
  "swift.yml",
] as const;

const allTests = readdirSync(testDir)
  .filter((name) => name.endsWith(".test.ts"))
  .sort();

describe("CI coverage gate: every harness test runs in CI (or is documented-exempt)", () => {
  it("finds a non-trivial set of harness tests and workflow files", () => {
    expect(allTests.length).toBeGreaterThan(10);
    expect(workflowFiles.length).toBeGreaterThan(10);
    expect(executedTests.size).toBeGreaterThan(10);
  });

  it("counts only test paths passed to a harness vitest command", () => {
    const fixture = `
jobs:
  fake:
    runs-on: ubuntu-latest
    steps:
      - name: test/dead-name.test.ts
        working-directory: harness
        env:
          UNUSED_TEST: test/dead-env.test.ts
        run: |
          echo test/dead-echo.test.ts
          # pnpm exec vitest run test/dead-comment.test.ts
          pnpm exec vitest run \\
            test/live.test.ts
`;
    expect([...collectExecutedHarnessTests(fixture)]).toEqual(["live.test.ts"]);
  });

  it("does not carry stale CI_EXEMPT entries", () => {
    for (const [f, exemption] of Object.entries(CI_EXEMPT)) {
      expect(
        allTests,
        `CI_EXEMPT names '${f}' but no such harness test exists — remove the stale exemption`,
      ).toContain(f);
      expect(exemption.owner.trim(), `${f}.owner`).not.toBe("");
      expect(exemption.reason.trim(), `${f}.reason`).not.toBe("");
      expect(exemption.lastReviewed, `${f}.lastReviewed`).toMatch(
        /^\d{4}-\d{2}-\d{2}$/,
      );
      expect(
        exemption.removalCondition.trim(),
        `${f}.removalCondition`,
      ).not.toBe("");
    }
  });

  for (const test of allTests) {
    it(`${test} is wired into a workflow or in CI_EXEMPT`, () => {
      const wired = executedTests.has(test);
      const exempt = Object.prototype.hasOwnProperty.call(CI_EXEMPT, test);
      if (!wired && !exempt) {
        throw new Error(
          `harness/test/${test} is not passed to a harness vitest command in any workflow ` +
            `and is not in CI_EXEMPT. Wire it into a CI step, or add it to ` +
            `CI_EXEMPT with a reason. (This gate exists because the audit found ` +
            `~21 harness tests silently dead in CI.)`,
        );
      }
      if (wired && exempt) {
        throw new Error(
          `harness/test/${test} is BOTH wired in a workflow and listed in ` +
            `CI_EXEMPT — the exemption is stale, remove it from CI_EXEMPT.`,
        );
      }
    });
  }
});

describe("workflow hygiene gate: direct non-publish workflows are read-only by default", () => {
  for (const workflow of DIRECT_NON_PUBLISH_WORKFLOWS) {
    it(`${workflow} declares top-level contents: read permissions`, () => {
      const text = readFileSync(join(workflowsDir, workflow), "utf8");
      expect(
        /^permissions:\n(?:[ \t]+[A-Za-z-]+:[^\n]*\n)+/m.test(text),
        `${workflow} has no top-level permissions block; PR CI would inherit repository defaults`,
      ).toBe(true);
      const block =
        text.match(/^permissions:\n((?:[ \t]+[A-Za-z-]+:[^\n]*\n)+)/m)?.[1] ??
        "";
      expect(
        block,
        `${workflow} top-level permissions must include contents: read`,
      ).toMatch(/^[ \t]+contents:[ \t]*read[ \t]*$/m);
      expect(
        block,
        `${workflow} top-level permissions must not grant write scopes; use job-level permissions only where needed`,
      ).not.toMatch(/:[ \t]*write\b|write-all|read-all/);
    });
  }

  it("does not accidentally inspect publish workflows in the direct-workflow guard", () => {
    expect(
      [...DIRECT_NON_PUBLISH_WORKFLOWS].some((name) =>
        name.includes("publish"),
      ),
    ).toBe(false);
  });

  it("pins the Semgrep runtime and reserves blocking enforcement for release gates", () => {
    const source = readFileSync(join(workflowsDir, "semgrep.yml"), "utf8");
    expect(source).toMatch(/semgrep\/semgrep@sha256:[a-f0-9]{64}/);
    expect(source).not.toMatch(/pip install semgrep/);
    expect(source).toMatch(/SEMGREP_ERROR_ON_FINDINGS=1/);
  });

  it("keeps the repaired missing-ATA settlement regression blocking", () => {
    // This harness leaf owns the harness.yml missing-ATA step; python.yml's
    // equivalent step is owned by the Python leaf (#228) and gated there, so
    // this gate only asserts the file this leaf modifies. Both leaves make the
    // step blocking; the step name is the reconciled #216-integration one (deliver-or-reject invariant).
    for (const workflow of ["harness.yml"]) {
      const source = readFileSync(join(workflowsDir, workflow), "utf8");
      const step = source.match(
        /- name: Focused Python session missing-ATA settlement invariant \(deliver-or-reject\)([\s\S]*?)(?=\n\s*- name:|$)/,
      )?.[1];
      expect(step, `${workflow} missing-ATA step`).toBeTruthy();
      expect(step, `${workflow} missing-ATA step must not swallow fund-loss failures`).not.toMatch(
        /continue-on-error:\s*true/,
      );
      expect(step).toMatch(/MPP_HARNESS_SESSION_RED_FAULTS:\s*"1"/);
    }
  });
});

// ---------------------------------------------------------------------------
// Gate self-activation SEAL. The cascade root (ci: gates self-activate with
// their subjects) lets the Rust conformance/coverage steps and the python
// session leg report themselves pending while their subjects are absent, so
// earlier legs of the #216 redelivery chain stay green. This tree is the END
// STATE of that chain: every subject MUST exist here, because a missing one
// means a pending gate silently outlived its purpose and is still off.
// ---------------------------------------------------------------------------
describe("gate self-activation seal: every pending gate's subject exists in the end state", () => {
  const repoRoot = join(here, "..", "..");
  const SUBJECTS = [
    // ci.yml: rust-conformance job + the TS-harness job's Rust vector steps
    "rust/crates/kit/examples/conformance_runner.rs",
    "rust/crates/kit/examples/protocol_runner.rs",
    // ci.yml: the Rust coverage floor step
    "scripts/check-rust-coverage.py",
    // harness.yml: the focused python session leg
    "harness/python-session-client/test_main.py",
  ];
  for (const subject of SUBJECTS) {
    it(`subject exists: ${subject}`, () => {
      expect(
        existsSync(join(repoRoot, subject)),
        `${subject} must exist in the integrated tree; a pending gate is still off without it`,
      ).toBe(true);
    });
  }
});
