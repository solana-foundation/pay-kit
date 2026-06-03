// Focused TypeScript-only protocol conformance check.
//
// Drives every canonical mpp-tools vector through the typescript protocol
// adapter in-process and classifies each (op x scenario) cell as PASS / DIV
// / UNSUP against the canonical oracle. Lets us confirm the typescript SDK
// conforms without spawning every other-language runner.

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { typescriptProtocolAdapter } from "./runners/typescript.js";
import type { AdapterResponse } from "./driver";

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(here, "..", "..", "..");
const vectorsDir = join(repoRoot, "harness", "vectors", "mpp-protocol");

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

function run(op: Op, input: unknown): AdapterResponse {
  // The TypeScript reference adapter answers synchronously.
  return typescriptProtocolAdapter.runProtocolRequest({ op, input }) as AdapterResponse;
}

function deepEqual(a: unknown, b: unknown): boolean {
  return JSON.stringify(canon(a)) === JSON.stringify(canon(b));
}
function canon(v: unknown): unknown {
  if (Array.isArray(v)) return v.map(canon);
  if (v && typeof v === "object") {
    const o: Record<string, unknown> = {};
    for (const k of Object.keys(v as Record<string, unknown>).sort()) o[k] = canon((v as Record<string, unknown>)[k]);
    return o;
  }
  return v;
}

function classify(c: Case): { status: string; detail?: string } {
  const resp = run(c.op, c.input);
  if (!c.expectSuccess) {
    if (resp.success) return { status: "DIV", detail: `expected error ${c.errorType}, got success ${JSON.stringify(resp.result)}` };
    if (resp.error_type !== c.errorType) return { status: "DIV", detail: `expected error_type ${c.errorType}, got ${resp.error_type}` };
    return { status: "PASS" };
  }
  if (!resp.success) return { status: "DIV", detail: `expected success, got error ${resp.error}` };
  if (c.reparseWith) {
    const gotHeader = (resp.result as { header: string }).header;
    const goldenHeader = (c.golden as { header: string }).header;
    if (gotHeader === goldenHeader) return { status: "PASS" };
    const gp = run(c.reparseWith, { header: gotHeader });
    const gg = run(c.reparseWith, { header: goldenHeader });
    if (gp.success && gg.success && deepEqual(gp.result, gg.result)) return { status: "PASS~", detail: `byte-diff but semantically equal` };
    return { status: "DIV", detail: `got "${gotHeader}" want "${goldenHeader}"` };
  }
  if (c.exact) {
    if (deepEqual(resp.result, c.golden)) return { status: "PASS" };
    return { status: "DIV", detail: `got ${JSON.stringify(resp.result)} want ${JSON.stringify(c.golden)}` };
  }
  if (deepEqual(resp.result, c.golden)) return { status: "PASS" };
  return { status: "DIV", detail: `got ${JSON.stringify(resp.result)} want ${JSON.stringify(c.golden)}` };
}

const cases = collectCases();
let div = 0, pass = 0, passt = 0;
const divs: string[] = [];
for (const c of cases) {
  const r = classify(c);
  if (r.status === "DIV") { div++; divs.push(`DIV  ${c.op} :: ${c.scenario}  -- ${r.detail}`); }
  else if (r.status === "PASS~") passt++;
  else pass++;
}
console.log(`typescript protocol cells: ${cases.length} total | PASS ${pass} | PASS~ ${passt} | DIV ${div}`);
for (const d of divs) console.log(d);
process.exit(div > 0 ? 1 : 0);
