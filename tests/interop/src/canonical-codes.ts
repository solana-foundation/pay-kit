// Canonical L6 / P1 structured error codes shared by every server adapter.
// Source of truth: python/src/solana_mpp/_errors.py CANONICAL_CODES,
// ruby/lib/mpp/error_codes.rb CANONICAL_CODES.
//
// The G39 fault matrix asserts that every server SDK emits the same code
// for the same failure class. Adapter fixtures that wrap a SDK that has
// not yet shipped L6 emission use `classifyMessageToCanonicalCode` below
// to map the SDK's free-text error message to a canonical code at the
// 402 response boundary.

export type CanonicalErrorCode =
  | "charge_request_mismatch"
  | "challenge_route_mismatch"
  | "challenge_verification_failed"
  | "challenge_expired"
  | "payment_invalid"
  | "wrong_network"
  | "signature_consumed";

export const CANONICAL_CODES: readonly CanonicalErrorCode[] = [
  "charge_request_mismatch",
  "challenge_route_mismatch",
  "challenge_verification_failed",
  "challenge_expired",
  "payment_invalid",
  "wrong_network",
  "signature_consumed",
];

// Map well-known legacy or per-language codes to canonical codes. Mirrors
// _LEGACY_TO_CANONICAL in the Python and Ruby SDKs.
const LEGACY_TO_CANONICAL: Record<string, CanonicalErrorCode> = {
  "challenge-expired": "challenge_expired",
  "challenge-mismatch": "challenge_verification_failed",
  "signature-consumed": "signature_consumed",
  "wrong-network": "wrong_network",
  "amount-mismatch": "charge_request_mismatch",
  "recipient-mismatch": "charge_request_mismatch",
  "splits-exceed-amount": "charge_request_mismatch",
  "invalid-payload": "payment_invalid",
  "malformed-credential": "payment_invalid",
  "verification-failed": "payment_invalid",
  "payment-expired": "challenge_expired",
  "no-transfer": "payment_invalid",
};

// Ordered message-substring patterns. First match wins. Catches the
// human-readable error messages that the TypeScript and Rust SDKs surface
// when the SDK has not yet shipped a structured code.
const MESSAGE_PATTERNS: readonly { pattern: RegExp; code: CanonicalErrorCode }[] = [
  { pattern: /already consumed/i, code: "signature_consumed" },
  { pattern: /signature.*consumed/i, code: "signature_consumed" },
  { pattern: /challenge.*verification.*failed/i, code: "challenge_verification_failed" },
  { pattern: /challenge id mismatch/i, code: "challenge_verification_failed" },
  { pattern: /not issued by this server/i, code: "challenge_verification_failed" },
  { pattern: /challenge expired/i, code: "challenge_expired" },
  { pattern: /signed against localnet but the server expects/i, code: "wrong_network" },
  { pattern: /network mismatch/i, code: "wrong_network" },
  { pattern: /wrong.*network/i, code: "wrong_network" },
  { pattern: /amount mismatch/i, code: "charge_request_mismatch" },
  { pattern: /currency mismatch/i, code: "charge_request_mismatch" },
  { pattern: /recipient mismatch/i, code: "charge_request_mismatch" },
  { pattern: /method details mismatch/i, code: "charge_request_mismatch" },
  { pattern: /split.*exceed.*amount/i, code: "charge_request_mismatch" },
  { pattern: /splits cannot exceed/i, code: "charge_request_mismatch" },
  { pattern: /splits consume the entire amount/i, code: "charge_request_mismatch" },
  { pattern: /too many splits/i, code: "charge_request_mismatch" },
  { pattern: /push-mode credentials are not allowed/i, code: "charge_request_mismatch" },
  // Compute-budget allowlist violations are a server policy rejection, not a
  // tx-shape mismatch; classify as `payment_invalid` to match Rust/Go/Python
  // server parity (see rust/src/bin/interop_server.rs::classify_canonical_code).
  { pattern: /unexpected program instruction/i, code: "charge_request_mismatch" },
  { pattern: /credential method does not match/i, code: "challenge_route_mismatch" },
  { pattern: /credential intent is not a charge/i, code: "challenge_route_mismatch" },
  { pattern: /credential realm does not match/i, code: "challenge_route_mismatch" },
];

export function classifyMessageToCanonicalCode(
  input: string | undefined | null,
): CanonicalErrorCode {
  if (!input) {
    return "payment_invalid";
  }
  if (CANONICAL_CODES.includes(input as CanonicalErrorCode)) {
    return input as CanonicalErrorCode;
  }
  const mapped = LEGACY_TO_CANONICAL[input];
  if (mapped) {
    return mapped;
  }
  for (const { pattern, code } of MESSAGE_PATTERNS) {
    if (pattern.test(input)) {
      return code;
    }
  }
  return "payment_invalid";
}

// Read an arbitrary 402 body (string or object) and return the same
// shape with a canonical `code` field added. The legacy `error` and
// `message` fields are preserved. Idempotent: if `code` is already
// set to a canonical value, it is left alone.
export function injectCanonicalCode(body: string): string {
  let parsed: Record<string, unknown>;
  try {
    parsed = JSON.parse(body) as Record<string, unknown>;
  } catch {
    return body;
  }
  if (
    typeof parsed.code === "string" &&
    CANONICAL_CODES.includes(parsed.code as CanonicalErrorCode)
  ) {
    return JSON.stringify(parsed);
  }
  const source =
    (typeof parsed.message === "string" && parsed.message) ||
    (typeof parsed.error === "string" && parsed.error) ||
    (typeof parsed.detail === "string" && parsed.detail) ||
    "";
  parsed.code = classifyMessageToCanonicalCode(source);
  return JSON.stringify(parsed);
}
