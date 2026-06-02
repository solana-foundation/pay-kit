// Maps the canonical @solana/mpp (TS reference) reject messages onto the
// shared RejectCode vocabulary. The reference is the spine, so this table
// defines what each normalized category MEANS; every other SDK runner
// mirrors the same vocabulary by classifying its own native errors.
//
// Note on decimals: the reference enforces transferChecked decimals through
// the transfer match key, so a decimals mismatch surfaces as a generic
// "no matching transfer" rather than a decimals-specific error. The honest
// category is therefore `no-matching-transfer`; isolating the decimals field
// itself is the job of a positive-control accept/reject vector pair, not of
// the reject-reason classifier.
import type { RejectCode } from "./schema";

const PATTERNS: Array<[RegExp, RejectCode]> = [
  [/compute unit price .* exceeds maximum/i, "compute-price-over-cap"],
  [/compute unit limit .* exceeds maximum/i, "compute-limit-over-cap"],
  [/fee payer cannot authorize/i, "fee-payer-not-authority"],
  [/fee payer .* (funding source|funds source)/i, "fee-payer-is-funds-source"],
  [/splits consume the entire amount/i, "splits-exceed-amount"],
  [/too many splits/i, "too-many-splits"],
  [/no matching (spl )?(transfer|transferchecked|sol transfer)/i, "no-matching-transfer"],
  [/unexpected .* (instruction|transfer)/i, "unexpected-instruction"],
  [/amount .* (mismatch|does not match)/i, "amount-mismatch"],
  // x402-exact reject categories. `unsupported version` must be checked
  // before the generic invalid/payload fallback (the message contains
  // "invalid payload: Unsupported x402 version"). `network mismatch`
  // likewise precedes the fallback.
  [/unsupported x402 version/i, "unsupported-version"],
  [/network mismatch/i, "wrong-network"],
];

// Classify a runner's native reject message onto the shared vocabulary.
// Returns undefined when no pattern matches so the harness can surface an
// unclassified rejection instead of silently passing it.
export function classifyReject(message: string | undefined): RejectCode | undefined {
  if (!message) return undefined;
  for (const [pattern, code] of PATTERNS) {
    if (pattern.test(message)) return code;
  }
  if (/invalid|malformed|decode|payload/i.test(message)) return "invalid-payload";
  return undefined;
}
