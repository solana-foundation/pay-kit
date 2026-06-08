// Driver for the mpp-protocol conformance layer.
//
// Each pay-kit SDK exposes a protocol adapter that speaks the canonical
// mpp-tools adapter ABI: given an `{ op, input }` envelope it returns
//   { success: true,  result: <value> }
//   { success: false, error: <msg>, error_type: <type> }
// over stdin -> stdout. This driver is transport-agnostic: a runner can be
// in-process (the TypeScript reference runner) or a spawned subprocess
// (per-language runners, wired the same way the live interop harness wires
// its client/server adapters in `src/process.ts`).

import { Buffer } from "node:buffer";
import {
  type ProtocolCase,
  type ProtocolOperation,
} from "./vectors";

export type AdapterRequest = {
  op: ProtocolOperation;
  input: unknown;
};

export type AdapterResponse =
  | { success: true; result: unknown }
  | { success: false; error: string; error_type: string };

// A protocol adapter is anything that can answer a single ABI request.
// `runProtocolRequest` may be sync (in-process runner) or async (spawned
// subprocess), so the driver always awaits it.
export type ProtocolAdapter = {
  name: string;
  runProtocolRequest(request: AdapterRequest): AdapterResponse | Promise<AdapterResponse>;
};

export type CaseResult = {
  op: ProtocolOperation;
  scenario: string;
  ok: boolean;
  detail?: string;
};

// Deep structural equality used for `semantic` comparison. Objects compare
// key-by-key (order-insensitive); arrays compare element-by-element.
function deepEqual(a: unknown, b: unknown): boolean {
  if (a === b) return true;
  if (typeof a !== typeof b) return false;
  if (a === null || b === null) return a === b;
  if (Array.isArray(a) || Array.isArray(b)) {
    if (!Array.isArray(a) || !Array.isArray(b) || a.length !== b.length) return false;
    return a.every((item, index) => deepEqual(item, b[index]));
  }
  if (typeof a === "object") {
    const ao = a as Record<string, unknown>;
    const bo = b as Record<string, unknown>;
    const ak = Object.keys(ao);
    const bk = Object.keys(bo);
    if (ak.length !== bk.length) return false;
    return ak.every((k) => k in bo && deepEqual(ao[k], bo[k]));
  }
  return false;
}

// Normalize a parsed credential so a request kept as a base64url string and
// a request decoded to an object compare equal. Mirrors the canonical
// runner's `normalize_credential_result`.
function normalizeCredential(result: unknown): unknown {
  if (!result || typeof result !== "object") return result;
  const r = { ...(result as Record<string, unknown>) };
  const challenge = r["challenge"];
  if (challenge && typeof challenge === "object") {
    const c = { ...(challenge as Record<string, unknown>) };
    if (typeof c["request"] === "string") {
      try {
        const decoded = Buffer.from(c["request"] as string, "base64url").toString("utf8");
        c["request"] = JSON.parse(decoded);
      } catch {
        // leave as-is
      }
    }
    r["challenge"] = c;
  }
  return r;
}

function normalizeParsed(op: ProtocolOperation, result: unknown): unknown {
  return op === "credential.parse" ? normalizeCredential(result) : result;
}

function compareExact(
  golden: unknown,
  got: unknown,
): { ok: boolean; detail?: string } {
  const ok = deepEqual(golden, got);
  return ok
    ? { ok }
    : { ok, detail: `exact mismatch: want=${JSON.stringify(golden)} got=${JSON.stringify(got)}` };
}

export async function runCase(
  adapter: ProtocolAdapter,
  testCase: ProtocolCase,
): Promise<CaseResult> {
  let response: AdapterResponse;
  try {
    response = await adapter.runProtocolRequest({ op: testCase.op, input: testCase.input });
  } catch (err) {
    return {
      op: testCase.op,
      scenario: testCase.scenario,
      ok: false,
      detail: `adapter threw: ${err instanceof Error ? err.message : String(err)}`,
    };
  }

  if (testCase.expectSuccess) {
    if (!response.success) {
      return {
        op: testCase.op,
        scenario: testCase.scenario,
        ok: false,
        detail: `expected success, got error_type=${response.error_type} (${response.error})`,
      };
    }

    // Semantic `*.format` comparison: re-parse both the canonical golden
    // wire and the adapter's produced wire through the paired parse op, then
    // compare the parsed objects. This neutralizes JCS key order, header
    // param order, and request-encoding differences exactly like the
    // canonical mpp-tools runner does.
    if (testCase.reparseWith) {
      const goldenHeader = (testCase.golden as { header: string }).header;
      const gotHeader = (response.result as { header: string }).header;
      const goldenParsed = await adapter.runProtocolRequest({
        op: testCase.reparseWith,
        input: { header: goldenHeader },
      });
      const gotParsed = await adapter.runProtocolRequest({
        op: testCase.reparseWith,
        input: { header: gotHeader },
      });
      if (!goldenParsed.success) {
        return {
          op: testCase.op,
          scenario: testCase.scenario,
          ok: false,
          detail: `semantic: re-parsing canonical golden wire failed: ${goldenParsed.error}`,
        };
      }
      if (!gotParsed.success) {
        return {
          op: testCase.op,
          scenario: testCase.scenario,
          ok: false,
          detail: `semantic: re-parsing produced wire failed: ${gotParsed.error}`,
        };
      }
      const a = normalizeParsed(testCase.reparseWith, goldenParsed.result);
      const b = normalizeParsed(testCase.reparseWith, gotParsed.result);
      const cmp = compareExact(a, b);
      return { op: testCase.op, scenario: testCase.scenario, ok: cmp.ok, detail: cmp.detail };
    }

    // Parse / exact ops: compare directly, with credential normalization.
    const golden = normalizeParsed(testCase.op, testCase.golden);
    const got = normalizeParsed(testCase.op, response.result);
    const cmp = compareExact(golden, got);
    return { op: testCase.op, scenario: testCase.scenario, ok: cmp.ok, detail: cmp.detail };
  }

  // Error case.
  if (response.success) {
    return {
      op: testCase.op,
      scenario: testCase.scenario,
      ok: false,
      detail: `expected error_type=${testCase.errorType}, got success`,
    };
  }
  const ok = response.error_type === testCase.errorType;
  return {
    op: testCase.op,
    scenario: testCase.scenario,
    ok,
    detail: ok ? undefined : `want error_type=${testCase.errorType} got=${response.error_type}`,
  };
}

export async function runAllCases(
  adapter: ProtocolAdapter,
  cases: ProtocolCase[],
): Promise<CaseResult[]> {
  const results: CaseResult[] = [];
  for (const testCase of cases) {
    results.push(await runCase(adapter, testCase));
  }
  return results;
}
