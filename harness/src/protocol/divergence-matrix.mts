// Divergence-matrix driver for pay-kit-vs-canonical mpp-tools protocol conformance.
//
// Unlike the semantic-tolerant harness test, this driver captures RAW bytes for
// every operation and classifies each (op x scenario x SDK) cell as:
//   PASS        - matches the canonical oracle (byte-exact for exact ops;
//                 byte-exact OR semantically-equal-after-reparse for format ops;
//                 deep-equal for parse ops; error_type match for error cases)
//   DIVERGE     - ran but produced a different result than canonical; records
//                 our-bytes vs canonical-bytes
//   UNSUPPORTED - runner returned unsupported_operation / runner_error, or threw
//
// For *.format ops it ALSO records whether a byte-divergence is semantically
// equal (benign serialization difference) vs a real semantic divergence.

import { spawn } from "node:child_process";
import { readFileSync, readdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { Buffer } from "node:buffer";

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(here, "..", "..", "..");
const manifestsDir = join(repoRoot, "harness", "protocol-runners");
const vectorsDir = join(repoRoot, "harness", "vectors", "mpp-protocol");

// ---------- vector expansion (mirrors vectors.ts collectProtocolCases) ----------

type Op =
  | "challenge.parse" | "challenge.format"
  | "credential.parse" | "credential.format"
  | "receipt.parse" | "receipt.format"
  | "base64url.encode" | "base64url.decode"
  | "challenge.id";

type Case =
  | { op: Op; scenario: string; group: string; input: unknown; expectSuccess: true; golden: unknown; reparseWith?: Op; exact: boolean }
  | { op: Op; scenario: string; group: string; input: unknown; expectSuccess: false; errorType: string };

function load(file: string): any {
  return JSON.parse(readFileSync(join(vectorsDir, file), "utf8"));
}
function expectsError(flag: any): string | null {
  return flag && typeof flag === "object" && flag.success === false ? flag.error_type : null;
}
function expectsSuccess(flag: any): boolean { return flag === true; }

function collectCases(): Case[] {
  const cases: Case[] = [];
  const pushHeader = (group: string, parseOp: Op, formatOp: Op, file: any) => {
    for (const s of file.scenarios) {
      const pErr = expectsError(s.tests.parse);
      if (pErr) cases.push({ op: parseOp, scenario: s.name, group, input: { header: s.wire }, expectSuccess: false, errorType: pErr });
      else if (expectsSuccess(s.tests.parse) && s.object) cases.push({ op: parseOp, scenario: s.name, group, input: { header: s.wire }, expectSuccess: true, golden: s.object, exact: false });
      const fErr = expectsError(s.tests.format);
      if (fErr && s.object) cases.push({ op: formatOp, scenario: s.name, group, input: s.object, expectSuccess: false, errorType: fErr });
      else if (expectsSuccess(s.tests.format) && s.object) cases.push({ op: formatOp, scenario: s.name, group, input: s.object, expectSuccess: true, golden: { header: s.wire }, reparseWith: parseOp, exact: false });
    }
  };
  pushHeader("www-authenticate", "challenge.parse", "challenge.format", load("www-authenticate.json"));
  pushHeader("authorization", "credential.parse", "credential.format", load("authorization.json"));
  pushHeader("receipt", "receipt.parse", "receipt.format", load("receipt.json"));

  for (const s of load("base64url.json").scenarios) {
    const eErr = expectsError(s.tests.format);
    if (eErr) cases.push({ op: "base64url.encode", scenario: s.name, group: "base64url", input: { text: s.decoded }, expectSuccess: false, errorType: eErr });
    else if (expectsSuccess(s.tests.format)) cases.push({ op: "base64url.encode", scenario: s.name, group: "base64url", input: { text: s.decoded }, expectSuccess: true, golden: { text: s.encoded }, exact: true });
    const dErr = expectsError(s.tests.parse);
    if (dErr) cases.push({ op: "base64url.decode", scenario: s.name, group: "base64url", input: { text: s.encoded }, expectSuccess: false, errorType: dErr });
    else if (expectsSuccess(s.tests.parse)) cases.push({ op: "base64url.decode", scenario: s.name, group: "base64url", input: { text: s.encoded }, expectSuccess: true, golden: { text: s.decoded }, exact: true });
  }
  for (const s of load("challenge-id.json").scenarios) {
    cases.push({ op: "challenge.id", scenario: s.name, group: "challenge-id", input: s.input, expectSuccess: true, golden: { id: s.expected }, exact: true });
  }
  return cases;
}

// ---------- runner discovery + spawn ----------

type Runner = { language: string; command: string[]; cwd: string };
function discover(): Runner[] {
  return readdirSync(manifestsDir).filter((f) => f.endsWith(".json")).sort().map((f) => {
    const m = JSON.parse(readFileSync(join(manifestsDir, f), "utf8"));
    return { language: m.language, command: m.command, cwd: m.cwd ? join(repoRoot, m.cwd) : repoRoot };
  });
}

type AdapterResponse =
  | { success: true; result: any }
  | { success: false; error: string; error_type: string };

function runOne(runner: Runner, req: { op: Op; input: unknown }): Promise<AdapterResponse> {
  return new Promise((resolve) => {
    const [bin, ...args] = runner.command;
    const child = spawn(bin, args, { cwd: runner.cwd });
    let stdout = ""; let stderr = "";
    child.stdout.on("data", (c) => (stdout += c.toString()));
    child.stderr.on("data", (c) => (stderr += c.toString()));
    child.on("error", (e) => resolve({ success: false, error: `spawn failed: ${e.message}`, error_type: "runner_error" }));
    child.on("close", () => {
      const line = stdout.trim().split("\n").filter(Boolean).pop();
      if (!line) { resolve({ success: false, error: `no output; stderr: ${stderr.slice(0, 300)}`, error_type: "runner_error" }); return; }
      try { resolve(JSON.parse(line)); } catch (e) { resolve({ success: false, error: `non-JSON: ${line.slice(0, 200)}`, error_type: "runner_error" }); }
    });
    child.stdin.write(JSON.stringify(req)); child.stdin.end();
  });
}

// ---------- comparison ----------

function deepEqual(a: any, b: any): boolean {
  if (a === b) return true;
  if (typeof a !== typeof b) return false;
  if (a === null || b === null) return a === b;
  if (Array.isArray(a) || Array.isArray(b)) {
    if (!Array.isArray(a) || !Array.isArray(b) || a.length !== b.length) return false;
    return a.every((x, i) => deepEqual(x, b[i]));
  }
  if (typeof a === "object") {
    const ak = Object.keys(a), bk = Object.keys(b);
    if (ak.length !== bk.length) return false;
    return ak.every((k) => k in b && deepEqual(a[k], b[k]));
  }
  return false;
}
function normalizeCredential(result: any): any {
  if (!result || typeof result !== "object") return result;
  const r = { ...result };
  const ch = r.challenge;
  if (ch && typeof ch === "object") {
    const c = { ...ch };
    if (typeof c.request === "string") {
      try { c.request = JSON.parse(Buffer.from(c.request, "base64url").toString("utf8")); } catch {}
    }
    r.challenge = c;
  }
  return r;
}
function normalizeParsed(op: Op, result: any): any {
  return op === "credential.parse" ? normalizeCredential(result) : result;
}

type Verdict = "PASS" | "DIVERGE" | "UNSUPPORTED";
type Cell = { verdict: Verdict; note?: string; ours?: string; canonical?: string; benign?: boolean };

function isUnsupported(resp: AdapterResponse): boolean {
  return !resp.success && (resp.error_type === "unsupported_operation" || resp.error_type === "runner_error");
}

async function evalCase(runner: Runner, c: Case): Promise<Cell> {
  const resp = await runOne(runner, { op: c.op, input: c.input });

  if (!c.expectSuccess) {
    // Error scenario: canonical expects a specific error_type.
    if (resp.success) return { verdict: "DIVERGE", note: "expected error, got success", ours: "success", canonical: `error:${c.errorType}` };
    if (isUnsupported(resp)) return { verdict: "UNSUPPORTED", note: resp.error_type };
    if (resp.error_type === c.errorType) return { verdict: "PASS" };
    return { verdict: "DIVERGE", note: "error_type mismatch", ours: resp.error_type, canonical: c.errorType };
  }

  // Success scenario.
  if (!resp.success) {
    if (isUnsupported(resp)) return { verdict: "UNSUPPORTED", note: resp.error_type };
    return { verdict: "DIVERGE", note: `expected success, got error`, ours: `error:${resp.error_type}:${resp.error}`, canonical: JSON.stringify(c.golden) };
  }

  if (c.reparseWith) {
    // format op: capture raw bytes, then semantic re-parse comparison.
    const goldenHeader = (c.golden as any).header;
    const gotHeader = (resp.result as any).header;
    const byteEqual = goldenHeader === gotHeader;

    const goldenParsed = await runOne(runner, { op: c.reparseWith, input: { header: goldenHeader } });
    const gotParsed = await runOne(runner, { op: c.reparseWith, input: { header: gotHeader } });
    if (!goldenParsed.success) return { verdict: "DIVERGE", note: "cannot re-parse canonical golden", ours: gotHeader, canonical: goldenHeader };
    if (!gotParsed.success) return { verdict: "DIVERGE", note: "produced wire fails own parse", ours: gotHeader, canonical: goldenHeader };
    const a = normalizeParsed(c.reparseWith, goldenParsed.result);
    const b = normalizeParsed(c.reparseWith, gotParsed.result);
    const semEqual = deepEqual(a, b);
    if (byteEqual) return { verdict: "PASS" };
    if (semEqual) return { verdict: "PASS", note: "byte-diff but semantically equal", ours: gotHeader, canonical: goldenHeader, benign: true };
    return { verdict: "DIVERGE", note: "semantic divergence", ours: gotHeader, canonical: goldenHeader };
  }

  // parse op or exact op: deep-equal to golden.
  const golden = normalizeParsed(c.op, c.golden);
  const got = normalizeParsed(c.op, resp.result);
  if (deepEqual(golden, got)) return { verdict: "PASS" };
  return { verdict: "DIVERGE", note: c.exact ? "byte mismatch (exact op)" : "object mismatch", ours: JSON.stringify(got), canonical: JSON.stringify(golden) };
}

// ---------- main ----------

async function main() {
  const cases = collectCases();
  const runners = discover();
  const langs = runners.map((r) => r.language);
  // matrix[caseKey][lang] = Cell
  const matrix: Record<string, Record<string, Cell>> = {};
  const caseMeta: { key: string; op: Op; scenario: string; group: string; kind: string }[] = [];

  for (const c of cases) {
    const key = `${c.op}::${c.scenario}`;
    caseMeta.push({ key, op: c.op, scenario: c.scenario, group: c.group, kind: c.expectSuccess ? (("reparseWith" in c && c.reparseWith) ? "format" : ((c as any).exact ? "exact" : "parse")) : "error" });
    matrix[key] = {};
    for (const r of runners) {
      process.stderr.write(`. ${r.language} ${key}\n`);
      matrix[key][r.language] = await evalCase(r, c);
    }
  }

  writeFileSync(join(repoRoot, "harness", "divergence-raw.json"), JSON.stringify({ langs, caseMeta, matrix }, null, 2));
  console.log(JSON.stringify({ langs, total: cases.length }));
}

main().catch((e) => { console.error(e); process.exit(1); });
