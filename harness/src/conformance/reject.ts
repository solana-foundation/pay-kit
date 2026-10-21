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
  // Charge verification policy (split arithmetic, split-recipient ATA
  // creation, fee payer placement, compute budget allowlist) and the client's
  // challenge checks. Checked first: several messages contain generic words.
  // Mirrored in every runner's classifier.
  [/fee payer (token account )?cannot fund/i, "fee-payer-is-funds-source"],
  [/primary amount is zero after splits|split amounts exceed/i, "splits-exceed-amount"],
  [/splits exceed maximum/i, "too-many-splits"],
  [/ata creation owner is not authorized|unsupported compute budget|unexpected_signer/i, "unexpected-instruction"],
  [/atacreationrequired requires|unsupported challenge network|invalid amount|requires feepayerkey/i, "invalid-challenge"],
  [/ata creation|ata payer|transaction fee payer (must be|mismatch)|memo cannot exceed/i, "invalid-payload"],
  // x402 v2: the credential's `accepted` matches none of the route's
  // requirements (targeted field checks or a structural offer match;
  // `accepted_mismatch` is @solana/pay-kit's x402 adapter reason).
  [
    /recipient mismatch|currency mismatch|accepted payment requirement does not match|accepted_mismatch|amount mismatch: expected \d+, got \d+/i,
    "accepted-mismatch",
  ],
  // A split memo or the route's extra.memo missing or different.
  [/no memo instruction found|invalid_exact_svm_payload_memo_(mismatch|count)/i, "invalid-payload"],
  // @x402/svm exact verifier: fee payer isolation (§2.1.1) and the static
  // layout's instruction set (§3.1).
  [
    /invalid_exact_svm_payload_transaction_fee_payer_(transferring_funds|in_instruction_accounts|included_in_instruction_accounts)/i,
    "fee-payer-not-authority",
  ],
  [
    /invalid_exact_svm_payload_(unknown_(fourth|fifth|sixth|optional)_instruction|transaction_instructions_length)/i,
    "unexpected-instruction",
  ],
  // Client refusing a challenge that violates the method spec (RULINGS C2,
  // C3). Checked first: these messages also contain generic words.
  [/decimals is required|failed to determine token program/i, "invalid-challenge"],
  [/compute unit price .* exceeds maximum/i, "compute-price-over-cap"],
  [/compute unit limit .* exceeds maximum/i, "compute-limit-over-cap"],
  [/fee payer cannot authorize/i, "fee-payer-not-authority"],
  [/fee payer .* (funding source|funds source)/i, "fee-payer-is-funds-source"],
  [/splits consume the entire amount/i, "splits-exceed-amount"],
  [/too many splits/i, "too-many-splits"],
  [/no matching (spl )?(transfer|transferchecked|sol transfer)/i, "no-matching-transfer"],
  [/unexpected .* (instruction|transfer)/i, "unexpected-instruction"],
  [/amount\b.* (mismatch|does not match)/i, "amount-mismatch"],
  // x402-exact reject categories. `unsupported version` must be checked
  // before the generic invalid/payload fallback (the message contains
  // "invalid payload: Unsupported x402 version"). `network mismatch`
  // likewise precedes the fallback.
  [/unsupported x402 version/i, "unsupported-version"],
  // @x402/core facilitator: no scheme registered for the envelope's version.
  [/no facilitator registered for x402 version/i, "unsupported-version"],
  [/network mismatch/i, "wrong-network"],
  // @x402/svm exact verifier reason codes.
  [/invalid_exact_svm_network_mismatch/i, "wrong-network"],
  [/invalid_exact_svm_payload_amount_mismatch/i, "amount-mismatch"],
  [
    /invalid_exact_svm_payload_(mint_mismatch|recipient_mismatch|no_transfer_instruction)/i,
    "no-matching-transfer",
  ],
  // x402-exact extensions: server required a payment-identifier id but the
  // credential echoed none / an invalid one. Checked before the generic
  // invalid/payload fallback.
  [/payment.identifier .*(required|missing|invalid)/i, "payment-identifier-required"],
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
