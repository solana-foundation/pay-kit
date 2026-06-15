// Flow conformance driver for the canonical mpp-tools HTTP 402 flow suite.
//
// This is a TypeScript port of the NORMATIVE orchestration in
// `tempoxyz/mpp-tools conformance/scripts/flow_runner.py` (run_flow_case and
// friends), driving any `ProtocolAdapter` (the same interface the vector
// conformance layer uses) through the vendored flow cases against the
// vendored compliance server:
//
//   initial HTTP request -> expect 402 -> challenge.parse(WWW-Authenticate)
//   -> build credential from the case payload + parsed challenge (applying
//   the case's mutation knobs) -> credential.format -> retry with
//   Authorization -> receipt.parse(Payment-Receipt) -> record
//   { name, outcome, challenge, credential, receipt, ... }.
//
// Recorded results compare against `golden-results.json` after the canonical
// normalization (error_type truncated at the first ":", outcome.content_type
// dropped, challenge.expires dropped, problem_details dropped) with a deep,
// order-insensitive comparison — mirroring flow_runner.py's normalize_result
// + DeepDiff(ignore_order=True). See harness/vectors/mpp-protocol-flows/.

import { Buffer } from "node:buffer";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import type { ProtocolAdapter } from "./driver";

const here = dirname(fileURLToPath(import.meta.url));
export const FLOWS_DIR = join(here, "..", "..", "vectors", "mpp-protocol-flows");
export const FLOW_CASES_PATH = join(FLOWS_DIR, "flows.json");
export const COMPLIANCE_SERVER_PATH = join(FLOWS_DIR, "compliance-server.ts");

// ── Vendored file shapes ──

// Behavior knobs match `flows.json` / flow_runner.py verbatim.
export type FlowCase = {
  name: string;
  path: string;
  request?: Record<string, unknown>;
  payload?: Record<string, unknown>;
  expected_signature?: string;
  receipt?: Record<string, unknown>;
  body?: string;
  retry_body?: string;
  initial_query?: string;
  retry_query?: string;
  challenge_path?: string;
  http_method?: string;
  accept_payment?: string;
  idempotency_key?: string;
  bind_request_resource?: boolean;
  check_cache_headers?: boolean;
  check_expires?: boolean;
  concurrent_replay?: boolean;
  digest_binding?: boolean;
  discovery?: boolean;
  json_rpc?: boolean;
  expect_retry_after?: string;
  expect_problem_details?: Record<string, unknown>;
  fail_verification?: boolean;
  force_status?: number;
  invalid_challenge_id?: boolean;
  invalid_www_authenticate?: boolean;
  omit_challenge_expires?: boolean;
  omit_receipt?: boolean;
  mismatch_request?: boolean;
  no_payment?: boolean;
  skip_authorization?: boolean;
  verify_body_preserved?: boolean;
};

// Recorded per-case result. Shape mirrors what flow_runner.py records (and
// therefore what golden-results.json holds); fields beyond the fixed ones
// (concurrent_statuses, body_preserved, accept_payment_observed, ...) ride
// along as loose keys.
export type FlowResult = {
  name: string;
  outcome: Record<string, unknown>;
  [key: string]: unknown;
};

export function loadFlowCases(): FlowCase[] {
  const parsed = JSON.parse(readFileSync(FLOW_CASES_PATH, "utf8")) as { cases?: unknown };
  if (!Array.isArray(parsed.cases)) throw new Error("Invalid flow cases payload");
  return parsed.cases as FlowCase[];
}

export function loadGoldenFlowResults(): FlowResult[] {
  const raw = readFileSync(join(FLOWS_DIR, "golden-results.json"), "utf8");
  const parsed = JSON.parse(raw) as { results?: unknown };
  if (!Array.isArray(parsed.results)) throw new Error("Invalid results payload");
  return parsed.results as FlowResult[];
}

// ── Canonical normalization + comparison (flow_runner.py normalize_result) ──

// error_type compares only up to the first ":" — adapter error messages are
// not normative.
function normalizeErrorType(value: unknown): string | null {
  if (value === null || value === undefined) return null;
  return String(value).split(":")[0].trim();
}

// Mirrors normalize_result: deep-copy, then
//   outcome.error_type -> truncated (key always present, null when absent)
//   outcome.content_type -> dropped
//   challenge.expires -> dropped
//   problem_details -> dropped entirely
export function normalizeFlowResult(entry: FlowResult): FlowResult {
  const normalized = JSON.parse(JSON.stringify(entry)) as FlowResult;
  const outcome = normalized.outcome;
  if (outcome && typeof outcome === "object") {
    outcome["error_type"] = normalizeErrorType(outcome["error_type"]);
    delete outcome["content_type"];
  }
  const challenge = normalized["challenge"];
  if (challenge && typeof challenge === "object" && !Array.isArray(challenge)) {
    delete (challenge as Record<string, unknown>)["expires"];
  }
  delete normalized["problem_details"];
  return normalized;
}

// Deep equality, order-insensitive for both object keys and array elements
// (arrays compare as multisets), mirroring DeepDiff(ignore_order=True).
export function flowDeepEqual(a: unknown, b: unknown): boolean {
  if (a === b) return true;
  if (typeof a !== typeof b) return false;
  if (a === null || b === null) return a === b;
  if (Array.isArray(a) || Array.isArray(b)) {
    if (!Array.isArray(a) || !Array.isArray(b) || a.length !== b.length) return false;
    const remaining = [...b];
    return a.every((item) => {
      const index = remaining.findIndex((candidate) => flowDeepEqual(item, candidate));
      if (index === -1) return false;
      remaining.splice(index, 1);
      return true;
    });
  }
  if (typeof a === "object") {
    const ao = a as Record<string, unknown>;
    const bo = b as Record<string, unknown>;
    const ak = Object.keys(ao);
    const bk = Object.keys(bo);
    if (ak.length !== bk.length) return false;
    return ak.every((k) => k in bo && flowDeepEqual(ao[k], bo[k]));
  }
  return false;
}

// ── HTTP plumbing (flow_runner.py perform_request / perform_json_request) ──

type HttpResponse = {
  status: number;
  headers: Headers;
  body: Buffer;
};

// Builds `base + path + query` exactly like flow_case_url: the retry query
// falls back to the initial query, then to "".
export function flowCaseUrl(baseUrl: string, flowCase: FlowCase, retry = false): string {
  let query = retry ? flowCase.retry_query : flowCase.initial_query;
  if (retry && query === undefined) query = flowCase.initial_query;
  if (query === undefined || query === null) query = "";
  return `${baseUrl}${flowCase.path ?? "/"}${query}`;
}

// The canonical runner's default client name is "python"; call sites that
// drive an adapter pass the adapter name instead (only the discovery case
// uses the default, exactly like flow_runner.py).
async function performRequest(
  url: string,
  flowCase: FlowCase,
  authHeader: string | null = null,
  retry = false,
  clientName = "python",
): Promise<HttpResponse> {
  const method = flowCase.http_method ?? "GET";
  const body = retry ? (flowCase.retry_body ?? flowCase.body) : flowCase.body;
  const headers: Record<string, string> = { "X-Flow-Client": clientName };
  let data: string | undefined;
  if (body && method === "POST") {
    data = body;
    headers["Content-Type"] = "application/json";
  }
  if (flowCase.accept_payment) headers["Accept-Payment"] = String(flowCase.accept_payment);
  if (flowCase.idempotency_key) headers["Idempotency-Key"] = String(flowCase.idempotency_key);
  if (authHeader !== null) headers["Authorization"] = authHeader;

  const response = await fetch(url, {
    method,
    headers,
    body: data,
    signal: AbortSignal.timeout(10_000),
  });
  return {
    status: response.status,
    headers: response.headers,
    body: Buffer.from(await response.arrayBuffer()),
  };
}

async function performJsonRequest(url: string, payload: unknown): Promise<HttpResponse> {
  const response = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
    signal: AbortSignal.timeout(10_000),
  });
  return {
    status: response.status,
    headers: response.headers,
    body: Buffer.from(await response.arrayBuffer()),
  };
}

function parseJsonBody(body: Buffer): unknown {
  try {
    return JSON.parse(body.toString("utf8")) as unknown;
  } catch {
    return null;
  }
}

// problem+json extraction (flow_runner.py parse_problem_details): only when
// the Content-Type says application/problem+json; `detail` rides along only
// when present.
function parseProblemDetails(
  headers: Headers,
  body: Buffer,
): { problem: Record<string, unknown> | null; contentType: string | null } {
  const contentType = headers.get("Content-Type");
  if (!contentType || !contentType.includes("application/problem+json")) {
    return { problem: null, contentType: null };
  }
  const parsed = parseJsonBody(body);
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    return { problem: null, contentType };
  }
  const bodyObj = parsed as Record<string, unknown>;
  const problem: Record<string, unknown> = {
    type: bodyObj["type"] ?? null,
    title: bodyObj["title"] ?? null,
    status: bodyObj["status"] ?? null,
  };
  if (bodyObj["detail"] !== undefined && bodyObj["detail"] !== null) {
    problem["detail"] = bodyObj["detail"];
  }
  return { problem, contentType };
}

// ── Adapter ABI bridging ──

// flow_runner.py talks to adapters through the schema-backed `{ ok, value,
// error: { message, type } }` envelope; pay-kit adapters speak the legacy
// `{ success, result, error, error_type }` envelope (the same mapping
// mpp-tools' harness.py applies in `legacy_response_for_operation`). These
// helpers express the runner's `parsed.get("ok") / .get("value") /
// adapter_error_message` in pay-kit terms.
type AdapterOutcome = { ok: boolean; value: unknown; message: string };

async function callAdapter(
  adapter: ProtocolAdapter,
  op: "challenge.parse" | "credential.format" | "receipt.parse",
  input: unknown,
  fallbackMessage: string,
): Promise<AdapterOutcome> {
  try {
    const response = await adapter.runProtocolRequest({ op, input });
    if (response.success) return { ok: true, value: response.result, message: "" };
    return { ok: false, value: null, message: response.error || fallbackMessage };
  } catch (err) {
    return {
      ok: false,
      value: null,
      message: err instanceof Error ? err.message : fallbackMessage,
    };
  }
}

// ── Recorded-result helpers (challenge_result / credential_result / ...) ──

function flowError(name: string, status: number, errorType: string): FlowResult {
  return {
    name,
    outcome: { ok: false, status, error_type: errorType },
  };
}

// Only the canonical quintet of challenge fields is recorded; absent fields
// record as null (python .get semantics).
function challengeResult(challenge: Record<string, unknown>): Record<string, unknown> {
  return {
    id: challenge["id"] ?? null,
    method: challenge["method"] ?? null,
    intent: challenge["intent"] ?? null,
    realm: challenge["realm"] ?? null,
    request: challenge["request"] ?? null,
  };
}

function credentialResult(payload: unknown): Record<string, unknown> {
  return { payload: payload ?? null };
}

// Receipt is re-keyed with the canonical fields first, mirroring
// flow_runner.py's parse_receipt (cosmetic for golden regeneration; the
// comparison itself is order-insensitive).
async function parseReceipt(adapter: ProtocolAdapter, header: string | null): Promise<unknown> {
  if (!header) return null;
  const response = await callAdapter(adapter, "receipt.parse", { header }, "receipt parse failed");
  if (!response.ok) return null;
  const receipt = response.value;
  if (!receipt || typeof receipt !== "object" || Array.isArray(receipt)) return receipt;
  const source = receipt as Record<string, unknown>;
  const ordered: Record<string, unknown> = {};
  for (const key of ["status", "reference", "method", "timestamp"]) {
    if (key in source) ordered[key] = source[key];
  }
  for (const [key, value] of Object.entries(source)) {
    if (!(key in ordered)) ordered[key] = value;
  }
  return ordered;
}

// ── Adapter-free special cases (discovery / JSON-RPC) ──

async function runDiscoveryFlowCase(baseUrl: string, flowCase: FlowCase): Promise<FlowResult> {
  const name = String(flowCase.name);
  // Note: the canonical runner performs this request with its default
  // client name ("python"), not the adapter name.
  const { status, body } = await performRequest(`${baseUrl}${flowCase.path ?? "/"}`, flowCase);
  const parsed = (parseJsonBody(body) ?? {}) as Record<string, unknown>;
  const paths = (parsed["paths"] ?? {}) as Record<string, unknown>;
  const chargeSuccess = (paths["/charge/success"] ?? {}) as Record<string, unknown>;
  const operation = (chargeSuccess["get"] ?? {}) as Record<string, unknown>;
  const paymentInfo = (operation["x-payment-info"] ?? {}) as Record<string, unknown>;
  const offers = paymentInfo["offers"];
  return {
    name,
    outcome: { ok: status >= 200 && status < 300, status },
    discovery_valid:
      parsed["openapi"] === "3.1.0" &&
      Boolean(parsed["x-service-info"]) &&
      Array.isArray(offers) &&
      offers.length > 0 &&
      offers.some(
        (offer) =>
          offer !== null &&
          typeof offer === "object" &&
          !Array.isArray(offer) &&
          ((offer as Record<string, unknown>)["amount"] ?? null) === null,
      ),
  };
}

async function runJsonRpcFlowCase(baseUrl: string, flowCase: FlowCase): Promise<FlowResult> {
  const name = String(flowCase.name);
  const url = `${baseUrl}${flowCase.path ?? "/"}`;
  const initialPayload = {
    jsonrpc: "2.0",
    id: 1,
    method: "tools/call",
    params: { name: "paid" },
  };
  const initial = await performJsonRequest(url, initialPayload);
  const body = (parseJsonBody(initial.body) ?? {}) as Record<string, unknown>;
  const error = (body["error"] ?? {}) as Record<string, unknown>;
  const data = (error["data"] ?? {}) as Record<string, unknown>;
  const challenges = Array.isArray(data["challenges"]) ? (data["challenges"] as unknown[]) : [];
  const challenge = challenges.length > 0 ? challenges[0] : {};
  const retryPayload = {
    ...initialPayload,
    _meta: {
      "org.paymentauth/credential": {
        challenge,
        payload: flowCase.payload ?? {},
      },
    },
  };
  const retry = await performJsonRequest(url, retryPayload);
  const retryJson = (parseJsonBody(retry.body) ?? {}) as Record<string, unknown>;
  const result = (retryJson["result"] ?? {}) as Record<string, unknown>;
  const meta = (result["_meta"] ?? {}) as Record<string, unknown>;
  return {
    name,
    outcome: { ok: retry.status >= 200 && retry.status < 300, status: retry.status },
    json_rpc_receipt: Boolean(meta["org.paymentauth/receipt"]),
  };
}

// ── The normative per-case orchestration (flow_runner.py run_flow_case) ──

export async function runFlowCase(
  adapter: ProtocolAdapter,
  baseUrl: string,
  flowCase: FlowCase,
  casesByPath: Map<string, FlowCase>,
): Promise<FlowResult> {
  const name = String(flowCase.name);
  let url = flowCaseUrl(baseUrl, flowCase);

  // Cross-route cases obtain their challenge from another case's endpoint:
  // the initial request goes to challenge_path, the retry to the case path.
  let challengeCase = flowCase;
  if (flowCase.challenge_path) {
    const referenced = casesByPath.get(String(flowCase.challenge_path));
    if (!referenced) return flowError(name, 0, `missing_challenge_case:${flowCase.challenge_path}`);
    challengeCase = referenced;
    url = flowCaseUrl(baseUrl, challengeCase);
  }
  if (flowCase.discovery) return runDiscoveryFlowCase(baseUrl, flowCase);
  if (flowCase.json_rpc) return runJsonRpcFlowCase(baseUrl, flowCase);

  const initial = await performRequest(url, challengeCase, null, false, adapter.name);
  const initialCacheControl = initial.headers.get("Cache-Control");

  if (flowCase.no_payment) {
    return { name, outcome: { ok: initial.status < 400, status: initial.status } };
  }

  if (initial.status !== 402) return flowError(name, initial.status, "unexpected_status");

  const { problem: initialProblem, contentType: initialContentType } = parseProblemDetails(
    initial.headers,
    initial.body,
  );
  const wwwAuth = initial.headers.get("WWW-Authenticate");
  if (!wwwAuth) return flowError(name, initial.status, "missing_challenge");

  const parsed = await callAdapter(
    adapter,
    "challenge.parse",
    { header: wwwAuth },
    "challenge parse failed",
  );
  if (!parsed.ok) {
    // The canonical runner pins the recorded message for the deliberately
    // broken header so adapters with differing error text still compare.
    const message = flowCase.invalid_www_authenticate
      ? "Missing request parameter."
      : parsed.message;
    const outcome: Record<string, unknown> = {
      ok: false,
      status: initial.status,
      error_type: `challenge_parse_error: ${message}`,
    };
    if (initialContentType) outcome["content_type"] = initialContentType;
    return { name, outcome, problem_details: initialProblem };
  }

  const challenge: Record<string, unknown> = {
    ...((parsed.value ?? {}) as Record<string, unknown>),
  };
  const request = challenge["request"];
  if (flowCase.mismatch_request && request && typeof request === "object" && !Array.isArray(request)) {
    challenge["request"] = { ...(request as Record<string, unknown>), amount: "1" };
  }
  if (flowCase.invalid_challenge_id) challenge["id"] = "invalid-challenge-id";
  if (flowCase.omit_challenge_expires) delete challenge["expires"];

  const payload = flowCase.payload;
  const credential = { challenge, payload: payload ?? {} };
  const formatted = await callAdapter(
    adapter,
    "credential.format",
    credential,
    "credential format failed",
  );
  if (!formatted.ok) {
    return flowError(name, initial.status, `credential_format: ${formatted.message}`);
  }

  const retryAuth = flowCase.skip_authorization
    ? null
    : (((formatted.value ?? {}) as Record<string, unknown>)["header"] as string | undefined) ?? null;
  const challengePayload = challengeResult(challenge);
  const credentialPayload = credentialResult(payload);

  if (flowCase.concurrent_replay) {
    const retryUrl = flowCaseUrl(baseUrl, flowCase, true);
    const first = await performRequest(retryUrl, flowCase, retryAuth, true, adapter.name);
    const second = await performRequest(retryUrl, flowCase, retryAuth, true, adapter.name);
    return {
      name,
      outcome: { ok: true, status: 200 },
      challenge: challengePayload,
      credential: credentialPayload,
      concurrent_statuses: [first.status, second.status].sort((a, b) => a - b),
    };
  }

  const retryUrl = flowCaseUrl(baseUrl, flowCase, true);
  const retry = await performRequest(retryUrl, flowCase, retryAuth, true, adapter.name);

  if (retry.status === 402) {
    const { problem: retryProblem, contentType: retryContentType } = parseProblemDetails(
      retry.headers,
      retry.body,
    );
    const outcome: Record<string, unknown> = {
      ok: false,
      status: retry.status,
      error_type: "payment_required",
    };
    if (retryContentType) outcome["content_type"] = retryContentType;
    const result: FlowResult = {
      name,
      outcome,
      challenge: challengePayload,
      credential: credentialPayload,
      problem_details: retryProblem,
    };
    if (flowCase.check_cache_headers) {
      result["initial_cache_control"] = initialCacheControl;
      result["retry_cache_control"] = retry.headers.get("Cache-Control");
      result["retry_after"] = retry.headers.get("Retry-After");
      result["receipt_on_error"] = Boolean(retry.headers.get("Payment-Receipt"));
    }
    return result;
  }

  const responseJson = parseJsonBody(retry.body);
  const result: FlowResult = {
    name,
    outcome: { ok: retry.status < 400, status: retry.status },
    challenge: challengePayload,
    credential: credentialPayload,
    receipt: await parseReceipt(adapter, retry.headers.get("Payment-Receipt")),
  };
  if (flowCase.verify_body_preserved && flowCase.body) {
    result["body_preserved"] =
      responseJson !== null &&
      typeof responseJson === "object" &&
      !Array.isArray(responseJson) &&
      (responseJson as Record<string, unknown>)["received_body"] === flowCase.body;
  }
  if (flowCase.check_cache_headers) {
    result["initial_cache_control"] = initialCacheControl;
    result["retry_cache_control"] = retry.headers.get("Cache-Control");
  }
  if (responseJson !== null && typeof responseJson === "object" && !Array.isArray(responseJson)) {
    const responseObj = responseJson as Record<string, unknown>;
    for (const key of ["accept_payment_observed", "side_effect_count", "idempotency_key_observed"]) {
      if (key in responseObj) result[key] = responseObj[key];
    }
  }
  return result;
}

// Run every flow case in declaration order, like run_adapter_flows. Order
// matters: the compliance server is stateful (idempotency counters, seen
// credentials, accept-payment observations).
export async function runAllFlowCases(
  adapter: ProtocolAdapter,
  baseUrl: string,
): Promise<FlowResult[]> {
  const flowCases = loadFlowCases();
  const casesByPath = new Map(flowCases.map((flowCase) => [String(flowCase.path ?? "/"), flowCase]));
  const results: FlowResult[] = [];
  for (const flowCase of flowCases) {
    results.push(await runFlowCase(adapter, baseUrl, flowCase, casesByPath));
  }
  return results;
}
