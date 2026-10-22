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
  // x402 batch-settlement SVM (scheme_batch_settlement_svm.md §7): the
  // scheme's machine-readable reasons map one to one. Checked first: their
  // messages contain generic words.
  [/invalid_batch_settlement_svm_payload_type/, "payload-type"],
  [/invalid_batch_settlement_svm_payment_flow/, "payment-flow"],
  [/invalid_batch_settlement_svm_token_program/, "token-program"],
  [/invalid_batch_settlement_svm_voucher_signature/, "voucher-signature"],
  [/invalid_batch_settlement_svm_channel_id_mismatch/, "channel-id-mismatch"],
  [/invalid_batch_settlement_svm_fee_payer_mismatch/, "fee-payer-mismatch"],
  [/invalid_batch_settlement_svm_receiver_authorizer_mismatch/, "receiver-authorizer-mismatch"],
  [/invalid_batch_settlement_svm_receiver_binding_unavailable/, "receiver-binding-unavailable"],
  [/invalid_batch_settlement_svm_close_authorization/, "close-authorization"],
  [/invalid_batch_settlement_svm_close_amount_unsupported/, "close-amount-unsupported"],
  [/invalid_batch_settlement_svm_close_state/, "close-state"],
  [/invalid_batch_settlement_svm_channel_closing/, "channel-closing"],
  [/invalid_batch_settlement_svm_withdraw_delay_mismatch/, "withdraw-delay-mismatch"],
  [/invalid_batch_settlement_svm_withdraw_delay_out_of_range/, "withdraw-delay-out-of-range"],
  [/invalid_batch_settlement_svm_cumulative_amount_mismatch/, "cumulative-amount-mismatch"],
  [/invalid_batch_settlement_svm_cumulative_exceeds_deposit/, "cumulative-exceeds-deposit"],
  [/invalid_batch_settlement_svm_voucher_expiry/, "voucher-expiry"],
  [/invalid_batch_settlement_svm_setup_transaction/, "setup-transaction"],
  [/invalid_batch_settlement_svm_settlement_simulation/, "settlement-simulation"],
  [/invalid_batch_settlement_svm_channel_state/, "channel-state"],
  [/invalid_batch_settlement_svm_refund_transaction/, "refund-transaction"],
  [/\bduplicate_settlement\b/, "duplicate-settlement"],
  [/\bunsupported_scheme\b/, "unsupported-scheme"],
  // @x402/svm batch-settlement client: refusals of a challenge's terms
  // (plain Errors, no reason code).
  [/extra\.tokenProgram (does not own|is not a supported)/, "token-program"],
  [/extra\.paymentFlow must be "authorization"/, "payment-flow"],
  [/extra\.withdrawDelay is outside the allowed range/, "withdraw-delay-out-of-range"],
  [/requires a server-signed channel whose operator|extra\.operator is only valid/, "invalid-challenge"],
  // Transaction versions (SIMD-0385): a message version the server does
  // not accept, or a client whose signer builds no advertised version
  // (x402 §1.5 `unsupported_transaction_version`). Then the version-1
  // envelope rules: a ComputeBudget instruction in a version-1 charge, an
  // incomplete header config, a size over the version's limit, a lookup
  // table. Checked first: the messages also contain generic words.
  [/transaction version .*not accepted|unsupported_transaction_version|signs up to version|advertises no transaction version/i, "unsupported-version"],
  // RULINGS SIG1: a client signature that does not verify over the message,
  // or a signature list short of the required signers.
  [/signature verification failed|signature slots do not match|invalid client transaction signature/i, "invalid-payload"],
  [/^(?!.*invalid_exact_svm).*must not contain computebudget instructions/i, "unexpected-instruction"],
  [/must set computeunitlimit|loaded accounts data size limit|-byte limit|address lookup tables/i, "invalid-payload"],
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
  // @solana/pay-kit's client refusing an offer's terms (an unknown network).
  [/invalid_challenge_terms|unsupported solana network/i, "invalid-challenge"],
  // Sponsors bound the priority fee as limit x price (RULINGS S6).
  [/priority fee .* exceeds the sponsored maximum/i, "compute-price-over-cap"],
  [/compute unit price .* exceeds maximum/i, "compute-price-over-cap"],
  [/compute unit limit .* exceeds maximum/i, "compute-limit-over-cap"],
  [/fee payer cannot authorize/i, "fee-payer-not-authority"],
  // Fee-sponsored charges: one funding authority, no other signers.
  [/share one funding authority/i, "mixed-funding-authority"],
  [/unexpected signer/i, "unexpected-signer"],
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
