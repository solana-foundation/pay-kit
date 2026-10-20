// Run-time half of the expectations system: turn a case execution into an
// `Observed`, reconcile it, and record every (SDK, case) outcome to
// harness/results/<suite>.<language>.json for the coverage report and for
// seeding expectations files.

import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  type CaseRef,
  caseKey,
  type Decision,
  decide,
  type Expectations,
  type Observed,
  reconcile,
  type Suite,
} from "./expectations";

const here = dirname(fileURLToPath(import.meta.url));
export const RESULTS_DIR = join(here, "..", "results");

// HARNESS_REQUIRE=1 (set in every CI job) makes incompleteness fatal: every
// claimed case must have been executed by the end of the file.
export function requireMode(): boolean {
  return process.env.HARNESS_REQUIRE === "1";
}

// HARNESS_EXPECTATIONS_DISCOVER=1 executes every case for every SDK and
// only records outcomes, never failing. Used to seed and audit expectations.
export function discoveryMode(): boolean {
  return process.env.HARNESS_EXPECTATIONS_DISCOVER === "1";
}

function message(error: unknown): string {
  const text = error instanceof Error ? error.message : String(error);
  // vitest assertion messages carry ANSI colour codes and long diffs.
  return text.replace(/\u001b\[[0-9;]*m/g, "").slice(0, 2000);
}

// Run a case body. A thrown error (assertion or runner crash) is a failure;
// a returned `{ unsupported }` is the runner declaring it cannot express it.
export async function observe(
  body: () => Promise<"pass" | { unsupported: string }>,
): Promise<Observed> {
  try {
    const result = await body();
    if (result === "pass") return { kind: "pass" };
    return { kind: "unsupported", detail: result.unsupported };
  } catch (error) {
    return { kind: "fail", detail: message(error) };
  }
}

export type RecordedCase = {
  key: string;
  capability: string;
  decision: Decision["kind"];
  observed?: Observed["kind"];
  detail?: string;
};

export class CaseRecorder {
  private readonly cases = new Map<string, RecordedCase>();

  constructor(
    private readonly suite: Suite,
    private readonly language: string,
  ) {}

  record(ref: CaseRef, decision: Decision, observed: Observed | undefined): void {
    this.cases.set(caseKey(ref), {
      key: caseKey(ref),
      capability: ref.capability,
      decision: decision.kind,
      ...(observed ? { observed: observed.kind } : {}),
      ...(observed && observed.kind !== "pass" ? { detail: observed.detail } : {}),
    });
  }

  // Record, reconcile, and throw if the outcome contradicts the
  // expectations. In discovery mode nothing throws.
  verdict(exp: Expectations, ref: CaseRef, decision: Decision, observed: Observed): void {
    this.record(ref, decision, observed);
    if (discoveryMode()) return;
    const v = reconcile(exp, ref, decision, observed);
    if (!v.ok) throw new Error(v.message);
  }

  // Every claimed case must have been executed. Catches a narrowed run
  // (test-name filters, early aborts) that would otherwise look green.
  assertComplete(refs: readonly CaseRef[], exp: Expectations): void {
    const missing = refs
      .filter((r) => decide(exp, r).kind !== "unclaimed")
      .filter((r) => this.cases.get(caseKey(r))?.observed === undefined)
      .map(caseKey);
    if (missing.length > 0) {
      throw new Error(
        `${this.language}: ${missing.length} claimed ${this.suite} case(s) were not executed under HARNESS_REQUIRE=1:\n  ${missing.join("\n  ")}`,
      );
    }
  }

  flush(): void {
    mkdirSync(RESULTS_DIR, { recursive: true });
    const sorted = [...this.cases.values()].sort((a, b) => a.key.localeCompare(b.key));
    writeFileSync(
      join(RESULTS_DIR, `${this.suite}.${this.language}.json`),
      `${JSON.stringify({ suite: this.suite, language: this.language, discovery: discoveryMode(), cases: sorted }, null, 2)}\n`,
    );
  }
}
