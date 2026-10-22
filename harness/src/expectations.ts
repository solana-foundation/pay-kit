// Per-SDK conformance expectations with exact-set reconciliation.
//
// Each SDK declares, in harness/expectations/<language>.toml, which suites
// it claims, which cases it cannot express (unsupported) and which cases it
// is known to fail. The drivers ask `decide()` what to do with every
// (language, case) pair and report each outcome through `Recorder`. The
// reconciliation is exact in both directions:
//
//   - a claimed case that fails and is not listed fails the run,
//   - a known_failing case that passes fails the run ("remove it"),
//   - an unsupported case is still executed and must report unsupported, so
//     a stale entry fails the run,
//   - every list entry must match at least one real case.
//
// Nothing here calls `skip`. A case is either executed and asserted, or
// recorded as `unclaimed` (the SDK does not claim that suite/intent), which
// the generated coverage table shows explicitly.

import { readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { parse as parseToml } from "smol-toml";

const here = dirname(fileURLToPath(import.meta.url));
export const EXPECTATIONS_DIR = join(here, "..", "expectations");
export const FINDINGS_FILE = "harness/expectations/FINDINGS.md";

// `cross`: offline cross-verification cells (`cross/<case>/<client>/<server>`),
// claimed and reconciled by the verifying SDK; run by `pkc run --cross --require`.
// `interop`: `pkc run --tier interop` cases (`interop/<scenario>/<client>/<server>`).
export type Suite = "vector" | "protocol" | "flow" | "cross" | "interop";
export const SUITES: readonly Suite[] = ["vector", "protocol", "flow", "cross", "interop"];

// Vector intents an SDK may claim (ConformanceVector["intent"]). A claim
// outside this list is a typo that would otherwise silently leave every
// real vector of the intended intent unclaimed.
export const VECTOR_INTENTS: readonly string[] = [
  "charge",
  "x402-exact",
  "session",
  "x402-upto",
  "x402-batch-settlement",
  "subscription",
];

// Interop roles an SDK may claim, `<protocol>:<scheme>:<role>`, the twin of
// `crate::interop::claims::Claim::all()` in rust/crates/conformance. The
// interop suite itself is run and reconciled by `pkc run --tier interop`;
// this parser only validates the files.
export const INTEROP_CLAIMS: readonly string[] = [
  "mpp:charge",
  "x402:exact",
  "x402:upto",
  "mpp:session",
].flatMap((intent) => [`${intent}:client`, `${intent}:server`]);

// A case as seen by the reconciler: its suite, id and (for vectors) intent.
export type CaseRef = {
  suite: Suite;
  id: string;
  // Capability bucket inside the suite. Vectors use the intent
  // ("charge", "x402-exact", "session"); protocol and flow use the suite
  // name itself.
  capability: string;
};

export function caseKey(ref: Pick<CaseRef, "suite" | "id">): string {
  return `${ref.suite}/${ref.id}`;
}

export type Decision =
  | { kind: "unclaimed" }
  | { kind: "unsupported"; reason: string }
  | { kind: "known_failing"; reason: string; tracking: string }
  | { kind: "pass" };

export type Expectations = {
  language: string;
  // suite -> claimed capability buckets
  capabilities: Record<Suite, Set<string>>;
  // Required when vectors are claimed; `pkc run` cross-checks it.
  honoursClock?: boolean;
  // Each entry lists exact case keys (`ids`) or one glob (`pattern`).
  unsupported: { label: string; suite: Suite; reason: string; matches: (key: string) => boolean }[];
  knownFailing: Map<string, { reason: string; tracking: string }>;
  source: string;
};

// Glob over case keys: `*` matches any run of characters. Everything else
// is literal, so ids containing `.`, `::` or spaces need no escaping.
function globToRegExp(pattern: string): RegExp {
  const escaped = pattern
    .split("*")
    .map((part) => part.replace(/[.+?^${}()|[\]\\]/g, "\\$&"))
    .join(".*");
  return new RegExp(`^${escaped}$`);
}

const TRACKING = /^(https:\/\/github\.com\/[^\s]+\/issues\/\d+|FINDINGS\.md#[a-z0-9-]+)$/;

function fail(source: string, message: string): never {
  throw new Error(`${source}: ${message}`);
}

// Every id and pattern must name its suite, so each entry is checked by
// exactly one driver and none can escape the dangling-entry check.
function suiteOf(key: string, source: string): Suite {
  const suite = key.split("/", 1)[0] as Suite;
  if (!SUITES.includes(suite) || !key.startsWith(`${suite}/`)) {
    fail(source, `"${key}" must start with one of ${SUITES.map((s) => `${s}/`).join(", ")}`);
  }
  return suite;
}

function asStringArray(value: unknown, source: string, field: string): string[] {
  if (!Array.isArray(value) || !value.every((v) => typeof v === "string")) {
    fail(source, `${field} must be an array of strings`);
  }
  return value as string[];
}

export function parseExpectations(text: string, source: string): Expectations {
  const raw = parseToml(text) as Record<string, unknown>;
  const allowedTop = new Set(["language", "capabilities", "unsupported", "known_failing"]);
  for (const key of Object.keys(raw)) {
    if (!allowedTop.has(key)) fail(source, `unknown top-level key "${key}"`);
  }
  if (typeof raw.language !== "string" || raw.language === "") {
    fail(source, "language must be a non-empty string");
  }

  const capabilities = Object.fromEntries(
    SUITES.map((s) => [s, new Set<string>()]),
  ) as Record<Suite, Set<string>>;
  const caps = (raw.capabilities ?? {}) as Record<string, unknown>;
  let honoursClock: boolean | undefined;
  for (const [suite, value] of Object.entries(caps)) {
    // Whether the testee drives the SDK at the clock a vector pins; checked
    // by `pkc run` against the testee's `capabilities` op.
    if (suite === "honours_clock") {
      if (typeof value !== "boolean") fail(source, "capabilities.honours_clock must be a boolean");
      honoursClock = value;
      continue;
    }
    if (!SUITES.includes(suite as Suite)) fail(source, `unknown capability suite "${suite}"`);
    if (suite === "interop") {
      for (const claim of asStringArray(value, source, "capabilities.interop")) {
        if (!INTEROP_CLAIMS.includes(claim)) {
          fail(source, `unknown interop claim "${claim}" (expected <protocol>:<scheme>:<role>, one of ${INTEROP_CLAIMS.join(", ")})`);
        }
        if (capabilities.interop.has(claim)) fail(source, `duplicate interop claim ${claim}`);
        capabilities.interop.add(claim);
      }
    } else if (suite === "vector") {
      for (const intent of asStringArray(value, source, "capabilities.vector")) {
        if (!VECTOR_INTENTS.includes(intent)) {
          fail(source, `unknown vector intent "${intent}" (expected one of ${VECTOR_INTENTS.join(", ")})`);
        }
        capabilities.vector.add(intent);
      }
    } else if (value === true) {
      capabilities[suite as Suite].add(suite);
    } else if (value !== false) {
      fail(source, `capabilities.${suite} must be a boolean`);
    }
  }
  // No default: an SDK claiming vectors states whether it honours pinned clocks.
  if (capabilities.vector.size > 0 && honoursClock === undefined) {
    fail(source, "claims vector intents, so capabilities.honours_clock must say whether the testee honours the clock a vector pins");
  }

  const unsupported: Expectations["unsupported"] = [];
  const seenIds = new Set<string>();
  for (const entry of (raw.unsupported ?? []) as Record<string, unknown>[]) {
    if (typeof entry.reason !== "string" || entry.reason === "") {
      fail(source, "every [[unsupported]] needs a non-empty reason");
    }
    const hasPattern = typeof entry.pattern === "string";
    const hasIds = entry.ids !== undefined;
    if (hasPattern === hasIds) {
      fail(source, "every [[unsupported]] needs exactly one of `pattern` or `ids`");
    }
    for (const key of Object.keys(entry)) {
      if (!["reason", "pattern", "ids"].includes(key)) fail(source, `unknown [[unsupported]] key "${key}"`);
    }
    if (hasPattern) {
      const regex = globToRegExp(entry.pattern as string);
      unsupported.push({
        label: `pattern "${entry.pattern}"`,
        suite: suiteOf(entry.pattern as string, source),
        reason: entry.reason,
        matches: (key) => regex.test(key),
      });
    } else {
      const ids = asStringArray(entry.ids, source, "unsupported.ids");
      for (const id of ids) {
        if (seenIds.has(id)) fail(source, `duplicate unsupported id ${id}`);
        seenIds.add(id);
      }
      // One entry per id, so a stale id is reported individually.
      for (const id of ids) {
        unsupported.push({
          label: `id "${id}"`,
          suite: suiteOf(id, source),
          reason: entry.reason,
          matches: (key) => key === id,
        });
      }
    }
  }

  const knownFailing = new Map<string, { reason: string; tracking: string }>();
  const shape =
    "every [[known_failing]] needs exactly one of a string `id` or a non-empty `ids` array, and a non-empty reason";
  for (const entry of (raw.known_failing ?? []) as Record<string, unknown>[]) {
    for (const key of Object.keys(entry)) {
      if (!["id", "ids", "reason", "tracking"].includes(key)) fail(source, `unknown [[known_failing]] key "${key}"`);
    }
    // `ids` lists several cases sharing one cause; each is still reconciled
    // (and reported stale) on its own.
    let ids: string[];
    if (typeof entry.id === "string" && entry.ids === undefined) {
      ids = [entry.id];
    } else if (entry.id === undefined && entry.ids !== undefined) {
      ids = asStringArray(entry.ids, source, "known_failing.ids");
      if (ids.length === 0) fail(source, shape);
    } else {
      fail(source, shape);
    }
    if (typeof entry.reason !== "string" || entry.reason === "") fail(source, shape);
    if (typeof entry.tracking !== "string" || !TRACKING.test(entry.tracking)) {
      fail(
        source,
        `known_failing ${ids[0]} needs tracking = a GitHub issue URL or "FINDINGS.md#<anchor>"`,
      );
    }
    for (const id of ids) {
      if (knownFailing.has(id)) fail(source, `duplicate known_failing ${id}`);
      suiteOf(id, source);
      knownFailing.set(id, { reason: entry.reason, tracking: entry.tracking });
    }
  }

  // An entry for a suite the SDK does not claim would never be executed by
  // any driver, so it could never be found stale.
  const entrySuites = [
    ...unsupported.map((u) => u.suite),
    ...[...knownFailing.keys()].map((k) => suiteOf(k, source)),
  ];
  for (const suite of new Set(entrySuites)) {
    if (capabilities[suite].size === 0) {
      fail(source, `has ${suite}/ entries but does not claim the ${suite} suite`);
    }
  }

  return {
    language: raw.language as string,
    capabilities,
    honoursClock,
    unsupported,
    knownFailing,
    source,
  };
}

export function loadAllExpectations(dir = EXPECTATIONS_DIR): Map<string, Expectations> {
  const out = new Map<string, Expectations>();
  for (const file of readdirSync(dir).filter((f) => f.endsWith(".toml")).sort()) {
    const exp = parseExpectations(readFileSync(join(dir, file), "utf8"), file);
    if (`${exp.language}.toml` !== file) {
      fail(file, `language "${exp.language}" does not match the file name`);
    }
    out.set(exp.language, exp);
  }
  return out;
}

export function decide(exp: Expectations, ref: CaseRef): Decision {
  if (!exp.capabilities[ref.suite].has(ref.capability)) return { kind: "unclaimed" };
  const key = caseKey(ref);
  const unsupported = exp.unsupported.find((u) => u.matches(key));
  const known = exp.knownFailing.get(key);
  if (unsupported && known) {
    fail(exp.source, `${key} is both unsupported and known_failing`);
  }
  if (unsupported) return { kind: "unsupported", reason: unsupported.reason };
  if (known) return { kind: "known_failing", ...known };
  return { kind: "pass" };
}

// Every list entry for `suite` must match a real case of a claimed
// capability, so a renamed or deleted case cannot leave a silent hole.
export function danglingEntries(
  exp: Expectations,
  suite: Suite,
  cases: readonly CaseRef[],
): string[] {
  const claimedKeys = cases
    .filter((c) => exp.capabilities[c.suite].has(c.capability))
    .map(caseKey);
  const problems: string[] = [];
  for (const u of exp.unsupported) {
    if (u.suite !== suite) continue;
    if (!claimedKeys.some((k) => u.matches(k))) {
      problems.push(`unsupported ${u.label} matches no claimed case`);
    }
  }
  for (const id of exp.knownFailing.keys()) {
    if (!id.startsWith(`${suite}/`)) continue;
    if (!claimedKeys.includes(id)) problems.push(`known_failing "${id}" matches no claimed case`);
  }
  return problems;
}

// What actually happened when a case was executed.
export type Observed =
  | { kind: "pass" }
  | { kind: "fail"; detail: string }
  | { kind: "unsupported"; detail: string };

// Turn (decision, observation) into a verdict. `ok: false` means the run
// must fail, with a message that says exactly which file to edit.
export function reconcile(
  exp: Expectations,
  ref: CaseRef,
  decision: Decision,
  observed: Observed,
): { ok: boolean; message: string } {
  const key = caseKey(ref);
  const where = `harness/expectations/${exp.source}`;
  switch (decision.kind) {
    case "unclaimed":
      return { ok: false, message: `${key}: unclaimed cases must not be executed` };
    case "unsupported":
      if (observed.kind === "unsupported") return { ok: true, message: "" };
      return {
        ok: false,
        message: `${key} is listed unsupported in ${where} but the runner ${observed.kind === "pass" ? "passed it" : "handled and failed it"}; remove or narrow the unsupported pattern${observed.kind === "fail" ? ` (${observed.detail})` : ""}`,
      };
    case "known_failing":
      if (observed.kind === "fail") return { ok: true, message: "" };
      if (observed.kind === "pass") {
        return { ok: false, message: `${key} now passes; remove it from known_failing in ${where}` };
      }
      return { ok: false, message: `${key} is known_failing but the runner reports unsupported: ${observed.detail}` };
    case "pass":
      if (observed.kind === "pass") return { ok: true, message: "" };
      if (observed.kind === "unsupported") {
        return {
          ok: false,
          message: `${key}: runner reports unsupported (${observed.detail}) but ${where} does not list it; add an [[unsupported]] entry with a reason or implement it`,
        };
      }
      return {
        ok: false,
        message: `${key} failed: ${observed.detail}\n(if this is a known gap, add it to known_failing in ${where} with tracking)`,
      };
  }
}
