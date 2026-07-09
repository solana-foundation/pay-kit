// Path x Outcome coverage matrix gate (bedrock gauge #2).
//
// ci-coverage-gate.test.ts proves every harness *test file* runs. This gate
// proves the protocol *surface* is accounted for: every enumerated protocol
// PATH crossed with every enumerated OUTCOME (accept + each reject code) is
// classified as one of exactly three things —
//
//   COVERED       -> bound to a real test/vector + Testing-Trophy tier,
//   KNOWN_GAP     -> deliberately untested for now, with a reason + the tier
//                    and vector a covering test should use,
//   NOT_APPLICABLE -> this outcome cannot arise on this path (with a reason),
//
// and the union of the axes is enforced against the LIVE code so the matrix
// cannot silently fall behind the SDKs:
//
//   * every PATH id must have at least one classified cell (a new protocol
//     path with no cells -> RED),
//   * every OUTCOME id in the enumerated taxonomy must be accounted (a new
//     reject code nobody mapped -> RED),
//   * every normalized RejectCode declared in src/conformance/schema.ts must
//     be accounted (a new harness reject category -> RED),
//   * every reject string actually emitted by a vector on disk
//     (x402ExactRejectCode / rejectCode) must be accounted (a vector inventing
//     an unmapped code -> RED).
//
// So: add a protocol path, a reject code, or a reject vector without deciding
// how it is tested, and CI turns red. The gaps this gate ranks live in
// KNOWN_GAP today; each carries the concrete vector/tier to graduate it to
// COVERED. Style mirrors ci-coverage-gate.test.ts: inline data + per-cell it().
import { readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const here = dirname(fileURLToPath(import.meta.url)); // harness/test
const harnessDir = join(here, "..");
const vectorsDir = join(harnessDir, "vectors");

// ---------------------------------------------------------------------------
// AXIS 1 — enumerated protocol PATHS (the audit's protocol-surface census).
// Keep in sync with the surface: a new operation on the wire needs a row here
// and at least one classified cell below, or this gate is RED.
// ---------------------------------------------------------------------------
const PATHS: string[] = [
  "x402-exact-challenge-issue",
  "x402-exact-build-client",
  "x402-exact-v1-build-client",
  "x402-exact-versioned-challenge-parse",
  "x402-exact-verify-server",
  "x402-exact-settle-server",
  "x402-payment-identifier-extension",
  "x402-upto-requirements-issue",
  "x402-upto-build-open-client",
  "x402-upto-verify-open-server",
  "x402-upto-confirm-open-server",
  "x402-upto-settle-actual-server",
  "x402-upto-over-ceiling-reject",
  "x402-upto-zero-actual-refund",
  "x402-batch-client-voucher",
  "x402-batch-verify-payment-server",
  "x402-batch-settle-batch-server",
  "mpp-charge-challenge-issue",
  "mpp-charge-pull-build-client",
  "mpp-charge-pull-verify-settle-server",
  "mpp-charge-push-build-client",
  "mpp-charge-push-verify-server",
  "mpp-charge-splits-spl-token",
  "mpp-charge-splits-token2022",
  "mpp-charge-splits-native-sol",
  "mpp-charge-splits-reject",
  "mpp-charge-symbol-currency",
  "mpp-charge-pubkey-currency",
  "mpp-charge-decimals",
  "mpp-charge-compute-budget-cap",
  "mpp-charge-network-mismatch",
  "mpp-charge-cross-server-portability",
  "mpp-charge-cross-route-replay",
  "mpp-charge-idempotent-resubmit",
  "mpp-charge-canonical-json",
  "mpp-session-challenge-issue",
  "mpp-session-open-push-client-submit",
  "mpp-session-open-push-server-submit",
  "mpp-session-open-pull-clientVoucher",
  "mpp-session-open-pull-operatedVoucher",
  "mpp-session-voucher",
  "mpp-session-voucher-canonical-bytes",
  "mpp-session-topup",
  "mpp-session-commit-deliver",
  "mpp-session-close-settle",
  "mpp-session-idle-close",
  "mpp-subscription-activation-validate",
  "mpp-subscription-activation-transaction",
  "mpp-subscription-activation-push",
  "mpp-subscription-renewal",
];

// ---------------------------------------------------------------------------
// AXIS 2 — enumerated OUTCOME taxonomy (accept + every reject code across the
// canonical / structural-verifier / settle-adapter / harness-normalized /
// legacy vocabularies). Each id must resolve below via a matrix cell,
// NOT_APPLICABLE, or DEAD_OR_ALIAS.
// ---------------------------------------------------------------------------
const OUTCOMES: string[] = [
  // accept family
  "accept",
  "accepted",
  "replayed",
  // x402-exact structural verifier reject codes (verify.go)
  "invalid_exact_svm_payload_transaction_instructions_length",
  "invalid_exact_svm_payload_transaction_instructions_compute_limit_instruction",
  "invalid_exact_svm_payload_transaction_instructions_compute_price_instruction",
  "invalid_exact_svm_payload_transaction_instructions_compute_price_instruction_too_high",
  "invalid_exact_svm_payload_no_transfer_instruction",
  "invalid_exact_svm_payload_transaction_fee_payer_transferring_funds",
  "invalid_exact_svm_payload_mint_mismatch",
  "invalid_exact_svm_payload_recipient_mismatch",
  "invalid_exact_svm_payload_amount_mismatch",
  "invalid_exact_svm_payload_unknown_fourth_instruction",
  "invalid_exact_svm_payload_unknown_fifth_instruction",
  "invalid_exact_svm_payload_unknown_sixth_instruction",
  "invalid_exact_svm_payload_unknown_optional_instruction",
  "invalid_exact_svm_payload_memo_count",
  "invalid_exact_svm_payload_memo_mismatch",
  // x402-exact reference-only (@x402/svm) codes Go does not emit
  "invalid_exact_svm_payload_transaction",
  "invalid_exact_svm_payload_transaction_could_not_be_decoded",
  "invalid_exact_svm_payload_missing_fee_payer",
  "invalid_exact_svm_payload_unknown_seventh_instruction",
  // x402-exact settle adapter (exact.go) verdict codes
  "payment_required",
  "invalid_payload",
  "charge_request_mismatch",
  "version_mismatch",
  "payment_identifier_required",
  "invalid_gate",
  "signature_consumed",
  "send_failed",
  "settlement_failed",
  // x402-upto reference codes (Go free-form except settlement_exceeds_amount)
  "invalid_upto_svm_payload_amount",
  "invalid_upto_svm_payload_amount_mismatch",
  "invalid_upto_svm_payload_authorized_signer",
  "invalid_upto_svm_payload_channel_id",
  "invalid_upto_svm_payload_deposit_not_ceiling",
  "invalid_upto_svm_payload_expired",
  "invalid_upto_svm_payload_not_yet_active",
  "invalid_upto_svm_payload_open_transaction",
  "invalid_upto_svm_payload_payer_mismatch",
  "invalid_upto_svm_payload_settlement_exceeds_amount",
  // mpp-charge canonical L6 codes
  "challenge_route_mismatch",
  "challenge_verification_failed",
  "challenge_expired",
  "payment_invalid",
  "wrong_network",
  // mpp-session voucher reject codes
  "below-min-delta",
  "channel-close-pending",
  "channel-finalized",
  "cumulative-not-monotonic",
  "exceeds-deposit",
  "expired",
  "expiry-too-soon",
  "invalid-cumulative",
  "invalid-signature",
  // mpp-session on-chain open/top-up value-binding reject codes
  "open-recipient-mismatch",
  "open-mint-mismatch",
  "open-authorized-signer-mismatch",
  "open-rent-payer-mismatch",
  "open-deposit-must-be-positive",
  "deposit-over-cap",
  "open-channel-pda-mismatch",
  "open-channel-id-mismatch",
  "distribution-hash-mismatch",
  "no-open-instruction",
  "open-too-few-accounts",
  "lookup-tables-unsupported",
  "signature-binding-mismatch",
  "topup-amount-delta-mismatch",
  "tx-not-found",
  "tx-failed-onchain",
  // harness normalized RejectCode vocabulary (schema.ts) — also asserted live
  "compute-price-over-cap",
  "compute-limit-over-cap",
  "fee-payer-not-authority",
  "fee-payer-is-funds-source",
  "decimals-mismatch",
  "splits-exceed-amount",
  "too-many-splits",
  "unexpected-instruction",
  "no-matching-transfer",
  "amount-mismatch",
  "invalid-payload",
  "unsupported-version",
  "wrong-network",
  "payment-identifier-required",
  // mpp-charge legacy ErrorCode vocabulary (core/error.go, paycore) —
  // alias/dead, resolved via DEAD_OR_ALIAS.
  "recipient-mismatch",
  "mint-mismatch",
  "no-transfer-instruction",
  "signature-consumed",
  "simulation-failed",
  "transaction-failed",
  "transaction-not-found",
  "missing-transaction",
  "missing-signature",
  "invalid-payload-type",
  "compute-budget-exceeded",
  "invalid-config",
  "challenge-expired",
  "challenge-mismatch",
  "challenge-route-mismatch",
  "invalid-method",
  "rpc-error",
  "other",
];

type Tier = "T0" | "T1" | "T2";
type Sev = "critical" | "high" | "medium" | "low";

// ---------------------------------------------------------------------------
// COVERED cells: (path::outcome) -> the test/vector proving it + tier.
// ---------------------------------------------------------------------------
const COVERED: Record<string, { test: string; tier: Tier }> = {
  // ---- x402-exact issue / build / versioned ----
  "x402-exact-challenge-issue::accept": {
    test: "vector x402-payment-required-envelope-canonical-wire (wire-bytes.json)",
    tier: "T0",
  },
  "x402-exact-build-client::accept": {
    test: "vector x402-exact-v2-build (x402-build.json)",
    tier: "T0",
  },
  "x402-exact-v1-build-client::accept": {
    test: "vector x402-exact-v1-build-devnet (x402-v1-build.json) + x402-v1-exact.test.ts",
    tier: "T0",
  },
  "x402-exact-versioned-challenge-parse::accept": {
    test: "vector x402-exact-v2-verify-accept (x402-verify.json)",
    tier: "T0",
  },
  "x402-exact-versioned-challenge-parse::version_mismatch": {
    test: "vector x402-exact-unknown-version-reject (x402-verify.json)",
    tier: "T0",
  },
  "x402-exact-versioned-challenge-parse::unsupported-version": {
    test: "vector x402-exact-unknown-version-reject (x402-verify.json) + x402-v1-verify.json",
    tier: "T0",
  },
  "x402-exact-versioned-challenge-parse::wrong-network": {
    test: "vector x402-exact-v1-verify-reject-wrong-network (x402-v1-verify.json)",
    tier: "T0",
  },
  // ---- x402-exact structural verifier ----
  "x402-exact-verify-server::accept": {
    test: "vector x402-exact-accept-with-memo (x402-exact-reject.json)",
    tier: "T0",
  },
  "x402-exact-verify-server::invalid_exact_svm_payload_mint_mismatch": {
    test: "vector x402-exact-mint-mismatch (x402-exact-reject.json)",
    tier: "T0",
  },
  "x402-exact-verify-server::invalid_exact_svm_payload_amount_mismatch": {
    test: "vector x402-exact-amount-mismatch (x402-exact-reject.json)",
    tier: "T0",
  },
  "x402-exact-verify-server::invalid_exact_svm_payload_recipient_mismatch": {
    test: "vector x402-exact-recipient-mismatch (x402-exact-reject.json)",
    tier: "T0",
  },
  "x402-exact-verify-server::invalid_exact_svm_payload_no_transfer_instruction": {
    test: "vector x402-exact-no-transfer (x402-exact-reject.json)",
    tier: "T0",
  },
  "x402-exact-verify-server::invalid_exact_svm_payload_transaction_fee_payer_transferring_funds": {
    test: "vector x402-exact-fee-payer-as-authority (x402-exact-reject.json)",
    tier: "T0",
  },
  // The NORMALIZED fee-payer-is-funds-source outcome is the SOURCE-side drain
  // (fee payer owns the transfer SOURCE ATA but is not the authority), distinct
  // from the fee-payer-as-authority case above. Covered by
  // x402-exact-fee-payer-as-source-ata, now executed against the REAL Go and
  // Rust structural verifiers via the go/rust cross-SDK conformance legs
  // (go.yml harness-go + ci.yml harness job set MPP_CONFORMANCE_LANGUAGES=go|rust
  // and run test/conformance.test.ts). Both reject with the exact canonical code
  // invalid_exact_svm_payload_transaction_fee_payer_transferring_funds
  // (verify.go:209-217 / verify.rs:429-434), so the guard can no longer silently
  // regress on Go or Rust.
  "x402-exact-verify-server::fee-payer-is-funds-source": {
    test: "vector x402-exact-fee-payer-as-source-ata (x402-exact-reject.json), run cross-SDK against the REAL Go + Rust verifiers via conformance.test.ts (MPP_CONFORMANCE_LANGUAGES=go|rust legs)",
    tier: "T0",
  },
  "x402-exact-verify-server::invalid_exact_svm_payload_transaction_instructions_compute_price_instruction_too_high":
    {
      test: "vector x402-exact-compute-price-too-high (x402-exact-reject.json)",
      tier: "T0",
    },
  "x402-exact-verify-server::invalid_exact_svm_payload_memo_count": {
    test: "vector x402-exact-memo-count (x402-exact-reject.json)",
    tier: "T0",
  },
  "x402-exact-verify-server::invalid_exact_svm_payload_memo_mismatch": {
    test: "vector x402-exact-memo-mismatch (x402-exact-reject.json)",
    tier: "T0",
  },
  "x402-exact-verify-server::invalid_exact_svm_payload_unknown_fourth_instruction": {
    test: "vector x402-exact-unknown-optional-instruction (x402-exact-reject.json)",
    tier: "T0",
  },
  "x402-exact-verify-server::invalid_exact_svm_payload_transaction_could_not_be_decoded": {
    test: "x402-exact-defect-verify.test.ts (malformed/undecodable proof)",
    tier: "T0",
  },
  // ---- x402-exact settle adapter ----
  "x402-exact-settle-server::accept": {
    test: "e2e.test.ts x402-exact-basic (Surfnet settle)",
    tier: "T1",
  },
  "x402-exact-settle-server::charge_request_mismatch": {
    test: "e2e.test.ts / x402-exact.e2e.test.ts cross-route-replay",
    tier: "T1",
  },
  "x402-exact-settle-server::version_mismatch": {
    test: "vector x402-exact-unknown-version-reject (x402-verify.json)",
    tier: "T0",
  },
  "x402-exact-settle-server::payment_identifier_required": {
    test: "vector x402-ext-server-rejects-required-missing-id (x402-extensions.json)",
    tier: "T0",
  },
  "x402-exact-settle-server::signature_consumed": {
    test: "e2e.test.ts x402-exact idempotent-resubmit",
    tier: "T1",
  },
  // ---- x402 payment-identifier extension ----
  "x402-payment-identifier-extension::accept": {
    test: "vectors x402-ext-echo-payment-identifier / x402-ext-server-accepts-valid-id (x402-extensions.json)",
    tier: "T0",
  },
  "x402-payment-identifier-extension::payment-identifier-required": {
    test: "vector x402-ext-server-rejects-required-missing-id (x402-extensions.json)",
    tier: "T0",
  },
  // ---- x402-upto (only the on-chain-settle green + challenge-issue) ----
  "x402-upto-requirements-issue::accept": {
    test: "unpaid-challenge-smoke.test.ts (x402 upto 402 challenge)",
    tier: "T1",
  },
  "x402-upto-confirm-open-server::accept": {
    test: "onchain.e2e.test.ts x402-upto settle (HARNESS_ONCHAIN=1)",
    tier: "T2",
  },
  "x402-upto-confirm-open-server::invalid_upto_svm_payload_payer_mismatch": {
    test: "go/protocols/x402/upto_confirm_open_payer_mismatch_test.go TestUptoVerifyOpenRejectsConfirmedChannelPayerMismatch (fake-RPC VerifyOpen, confirmed channel.Payer != payload.from -> upto.go:513)",
    tier: "T1",
  },
  "x402-upto-settle-actual-server::accept": {
    test: "onchain.e2e.test.ts x402-upto settle (payment-channels program)",
    tier: "T2",
  },
  "x402-upto-over-ceiling-reject::invalid_upto_svm_payload_settlement_exceeds_amount": {
    test: "x402-upto-over-ceiling.test.ts (real X402Upto.settle ceiling guard, actual > MaxAmount, RPC-free)",
    tier: "T1",
  },
  "x402-upto-verify-open-server::invalid_upto_svm_payload_authorized_signer": {
    test: "x402-upto-verify-open.test.ts (real @x402/svm facilitator rejects a non-operator authorizedSigner; mirrors Go VerifyUptoPayload:173)",
    tier: "T1",
  },
  "x402-upto-verify-open-server::invalid_upto_svm_payload_deposit_not_ceiling": {
    test: "x402-upto-verify-open.test.ts (real @x402/svm facilitator rejects deposit != signed maxAmount ceiling, under + over, with a deposit==ceiling control; mirrors Go VerifyUptoPayload:164)",
    tier: "T1",
  },
  // ---- mpp-charge ----
  "mpp-charge-challenge-issue::accept": {
    test: "flow-conformance.test.ts success_charge + protocol-conformance www-authenticate",
    tier: "T0",
  },
  "mpp-charge-pull-build-client::accept": {
    test: "e2e.test.ts charge-basic",
    tier: "T1",
  },
  "mpp-charge-pull-verify-settle-server::accept": {
    test: "e2e.test.ts charge-basic (balance delta = amount)",
    tier: "T1",
  },
  "mpp-charge-pull-verify-settle-server::charge_request_mismatch": {
    test: "e2e.test.ts charge cross-route-replay",
    tier: "T1",
  },
  "mpp-charge-pull-verify-settle-server::challenge_verification_failed": {
    test: "e2e.test.ts charge cross-server-portability",
    tier: "T1",
  },
  "mpp-charge-pull-verify-settle-server::challenge_expired": {
    test: "flow-conformance.test.ts expired_challenge",
    tier: "T0",
  },
  "mpp-charge-pull-verify-settle-server::payment_invalid": {
    test: "flow-conformance.test.ts invalid_payload",
    tier: "T0",
  },
  "mpp-charge-pull-verify-settle-server::wrong_network": {
    test: "e2e.test.ts charge network-mismatch",
    tier: "T1",
  },
  "mpp-charge-pull-verify-settle-server::signature_consumed": {
    test: "e2e.test.ts charge idempotent-resubmit",
    tier: "T1",
  },
  "mpp-charge-pull-verify-settle-server::compute-price-over-cap": {
    test: "vector charge-compute-price-over-cap-reject (charge-rejects.json)",
    tier: "T0",
  },
  "mpp-charge-pull-verify-settle-server::fee-payer-not-authority": {
    test: "vector charge-feepayer-as-authority-reject (charge-rejects.json)",
    tier: "T0",
  },
  "mpp-charge-pull-verify-settle-server::no-matching-transfer": {
    test: "vector charge-transferchecked-decimals-mismatch-reject (charge-rejects.json)",
    tier: "T0",
  },
  "mpp-charge-push-build-client::accept": {
    test: "e2e.test.ts charge-push",
    tier: "T1",
  },
  "mpp-charge-push-verify-server::accept": {
    test: "e2e.test.ts charge-push (server re-fetch by signature)",
    tier: "T1",
  },
  "mpp-charge-splits-spl-token::accept": {
    test: "vector charge-spl-field-omitted-defaults (charge-defaults.json) + e2e charge-split-ata",
    tier: "T0",
  },
  "mpp-charge-splits-token2022::accept": {
    test: "vector charge-token2022-default-program-by-currency (charge-defaults.json) + e2e charge-token2022-split-ata",
    tier: "T0",
  },
  "mpp-charge-splits-native-sol::accept": {
    test: "vector charge-sol-native-build (charge-defaults.json) + e2e charge-sol-native",
    tier: "T0",
  },
  "mpp-charge-splits-reject::splits-exceed-amount": {
    test: "vector charge-splits-consume-amount-reject (charge-rejects.json)",
    tier: "T0",
  },
  "mpp-charge-splits-reject::too-many-splits": {
    test: "e2e.test.ts charge splits-too-many",
    tier: "T1",
  },
  "mpp-charge-symbol-currency::accept": {
    test: "e2e.test.ts charge-symbol-usdc-localnet",
    tier: "T1",
  },
  "mpp-charge-pubkey-currency::accept": {
    test: "vector charge-asset-over-currency-precedence (charge-precedence.json) + e2e charge-basic",
    tier: "T0",
  },
  "mpp-charge-decimals::accept": {
    test: "vector charge-transferchecked-decimals-match-accept (charge-rejects.json) + e2e charge-decimals-9",
    tier: "T0",
  },
  "mpp-charge-decimals::no-matching-transfer": {
    test: "vector charge-transferchecked-decimals-mismatch-reject (charge-rejects.json)",
    tier: "T0",
  },
  "mpp-charge-compute-budget-cap::compute-price-over-cap": {
    test: "vector charge-compute-price-over-cap-reject (charge-rejects.json)",
    tier: "T0",
  },
  "mpp-charge-compute-budget-cap::compute-limit-over-cap": {
    test: "vector charge-compute-limit-over-cap-reject (charge-rejects.json)",
    tier: "T0",
  },
  "mpp-charge-network-mismatch::wrong_network": {
    test: "e2e.test.ts charge network-mismatch (canonical wrong_network)",
    tier: "T1",
  },
  "mpp-charge-network-mismatch::wrong-network": {
    test: "regression-bank-coverage.test.ts wrong-network binding",
    tier: "T0",
  },
  "mpp-charge-cross-server-portability::challenge_verification_failed": {
    test: "e2e.test.ts cross-server-portability",
    tier: "T1",
  },
  "mpp-charge-cross-route-replay::charge_request_mismatch": {
    test: "e2e.test.ts charge cross-route-replay",
    tier: "T1",
  },
  "mpp-charge-idempotent-resubmit::signature_consumed": {
    test: "e2e.test.ts charge idempotent-resubmit",
    tier: "T1",
  },
  "mpp-charge-canonical-json::accept": {
    test: "vectors canonical-json-* (canonical-bytes.json) + canonical-json.test.ts + challenge-id-hmac (wire-bytes.json)",
    tier: "T0",
  },
  // ---- mpp-session voucher (all direct-verified) ----
  "mpp-session-voucher::accepted": { test: "session-voucher-verify.test.ts (valid in-window)", tier: "T0" },
  "mpp-session-voucher::replayed": { test: "session-voucher-verify.test.ts (exact resubmission)", tier: "T0" },
  "mpp-session-voucher::below-min-delta": { test: "session-voucher-verify.test.ts", tier: "T0" },
  "mpp-session-voucher::channel-close-pending": { test: "session-voucher-verify.test.ts", tier: "T0" },
  "mpp-session-voucher::channel-finalized": { test: "session-voucher-verify.test.ts", tier: "T0" },
  "mpp-session-voucher::cumulative-not-monotonic": { test: "session-voucher-verify.test.ts", tier: "T0" },
  "mpp-session-voucher::exceeds-deposit": { test: "session-voucher-verify.test.ts", tier: "T0" },
  "mpp-session-voucher::expired": { test: "session-voucher-verify.test.ts", tier: "T0" },
  "mpp-session-voucher::expiry-too-soon": { test: "session-voucher-verify.test.ts (expires-within-settlement-window)", tier: "T0" },
  "mpp-session-voucher::invalid-cumulative": { test: "session-voucher-verify.test.ts", tier: "T0" },
  "mpp-session-voucher::invalid-signature": { test: "session-voucher-verify.test.ts", tier: "T0" },
  "mpp-session-voucher-canonical-bytes::accept": {
    test: "session-voucher-verify.test.ts byte-layout + vector session-voucher-preimage-frozen (session-voucher.json)",
    tier: "T0",
  },
  "mpp-session-close-settle::accept": {
    test: "session-close-settle-verify.test.ts (drives submitSettleAndDistribute: broadcasts ed25519+settle_and_finalize+distribute, precompile binds the highest voucher, distribute recipients+bps == splits, one writable recipient-ATA delta target per split)",
    tier: "T1",
  },
  // ---- mpp-session on-chain open/top-up value-binding (partial radar) ----
  "mpp-session-open-push-client-submit::signature-binding-mismatch": {
    test: "value-binding-verify.test.ts (a) / vector open-a (value-binding/open.json)",
    tier: "T1",
  },
  "mpp-session-open-push-client-submit::distribution-hash-mismatch": {
    test: "value-binding-verify.test.ts (d) / vector open-d-distribution-diverges-from-splits",
    tier: "T1",
  },
  "mpp-session-open-push-client-submit::tx-not-found": {
    test: "value-binding-verify.test.ts (b) / vector open-b-placeholder-signature-with-rpc-c1",
    tier: "T1",
  },
  "mpp-session-open-push-client-submit::open-recipient-mismatch": {
    test: "value-binding-verify.test.ts (e) / vector open-e-payee-diverges-from-recipient (value-binding/open.json)",
    tier: "T1",
  },
  "mpp-session-topup::topup-amount-delta-mismatch": {
    test: "value-binding-verify.test.ts (c) / vector topup-c-onchain-delta-mismatch",
    tier: "T1",
  },
  "mpp-session-topup::deposit-over-cap": {
    test: "value-binding-verify.test.ts (a) / vector topup-a-unrelated-confirmed-inflated-deposit",
    tier: "T1",
  },
  "mpp-session-topup::tx-not-found": {
    test: "value-binding-verify.test.ts (b) / vector topup-b-placeholder-signature-with-rpc",
    tier: "T1",
  },
};

// ---------------------------------------------------------------------------
// KNOWN_GAP cells: applicable but deliberately untested. Each carries the tier
// a covering test should use and how to cover it (which vector/test to add).
// severity x likelihood drives the ranked top-gap report.
// ---------------------------------------------------------------------------
const KNOWN_GAP: Record<
  string,
  { tier: Tier; severity: Sev; likelihood: Sev; reason: string; how: string }
> = {
  // ---- x402-exact structural verifier: the untested slots of a fund-safety verifier ----
  "x402-exact-verify-server::invalid_exact_svm_payload_transaction_instructions_length": {
    tier: "T0",
    severity: "high",
    likelihood: "medium",
    reason: "No vector exercises the [3,6] instruction-count bound (verify.go:75).",
    how: "Add x402-exact-ix-count-out-of-range vectors (2-ix and 7-ix txs) to x402-exact-reject.json.",
  },
  "x402-exact-verify-server::invalid_exact_svm_payload_transaction_instructions_compute_limit_instruction":
    {
      tier: "T0",
      severity: "high",
      likelihood: "medium",
      reason: "ix[0]-not-SetComputeUnitLimit path (verify.go:147) is unvectored; a payer could omit/spoof the CU-limit guard.",
      how: "Add x402-exact-compute-limit-wrong-program vector (ix[0] = non-ComputeBudget) to x402-exact-reject.json.",
    },
  "x402-exact-verify-server::invalid_exact_svm_payload_transaction_instructions_compute_price_instruction":
    {
      tier: "T0",
      severity: "medium",
      likelihood: "medium",
      reason: "ix[1]-not-SetComputeUnitPrice path (verify.go:159) is unvectored (only the too-high price is tested).",
      how: "Add x402-exact-compute-price-wrong-program vector to x402-exact-reject.json.",
    },
  "x402-exact-verify-server::invalid_exact_svm_payload_unknown_fifth_instruction": {
    tier: "T0",
    severity: "low",
    likelihood: "low",
    reason: "Only the fourth optional slot is vectored; 5th-slot unknown-program (verify.go:97) is not.",
    how: "Extend x402-exact-unknown-optional-instruction with a 5th-slot variant.",
  },
  "x402-exact-verify-server::invalid_exact_svm_payload_unknown_sixth_instruction": {
    tier: "T0",
    severity: "low",
    likelihood: "low",
    reason: "6th-slot unknown-program (verify.go:98) not vectored.",
    how: "Extend x402-exact-unknown-optional-instruction with a 6th-slot variant.",
  },
  "x402-exact-verify-server::invalid_exact_svm_payload_unknown_optional_instruction": {
    tier: "T0",
    severity: "medium",
    likelihood: "low",
    reason: "Generic optional-slot unknown-program fallback (verify.go:113) not directly vectored.",
    how: "Add a vector whose optional slot is a program outside {Memo,Lighthouse} to hit the fallback branch.",
  },
  // ---- x402-exact settle adapter: error branches with no driver ----
  "x402-exact-settle-server::payment_required": {
    tier: "T1",
    severity: "medium",
    likelihood: "medium",
    reason: "No test drives settle() with a missing PAYMENT-SIGNATURE header (exact.go:134).",
    how: "Add a unit/integration case posting to the settle route with no credential header.",
  },
  "x402-exact-settle-server::invalid_payload": {
    tier: "T1",
    severity: "medium",
    likelihood: "medium",
    reason: "Base64/JSON/tx-decode failure branch of the settle adapter (exact.go:138-217) is unexercised end-to-end.",
    how: "Add a settle case with a corrupt base64 credential body.",
  },
  "x402-exact-settle-server::invalid_gate": {
    tier: "T1",
    severity: "low",
    likelihood: "low",
    reason: "transferRequirements(gate) build-error branch (exact.go:192) unexercised.",
    how: "Add a settle case with an offer that fails gate construction.",
  },
  "x402-exact-settle-server::send_failed": {
    tier: "T1",
    severity: "low",
    likelihood: "low",
    reason: "RPC SendEncodedTransaction failure (exact.go:227) has no fault-injection test.",
    how: "Add a settle integration with a stub RPC that fails send.",
  },
  "x402-exact-settle-server::settlement_failed": {
    tier: "T1",
    severity: "medium",
    likelihood: "low",
    reason: "awaitConfirmation failure (exact.go:230) has no fault-injection test.",
    how: "Add a settle integration with a stub RPC that never confirms.",
  },
  // ---- x402-upto: nearly the whole verifier surface is unvectored ----
  "x402-upto-build-open-client::accept": {
    tier: "T0",
    severity: "medium",
    likelihood: "medium",
    reason: "No golden for the upto channel-open deposit header build (client/upto.go BuildUptoHeader).",
    how: "Add x402-upto-build.json with a deposit-at-ceiling open header golden.",
  },
  "x402-upto-verify-open-server::accept": {
    tier: "T1",
    severity: "high",
    likelihood: "medium",
    reason: "No structural open-verify accept case (validateUptoOpenInstruction / VerifyUptoPayload).",
    how: "Add an x402-upto verify-open accept vector (payee/mint/deposit<=cap all valid).",
  },
  "x402-upto-verify-open-server::invalid_upto_svm_payload_amount_mismatch": {
    tier: "T1",
    severity: "medium",
    likelihood: "medium",
    reason: "signed maxAmount!=advertised max (VerifyUptoPayload:157) unvectored.",
    how: "Add an x402-upto verify-open reject vector with a divergent signed maxAmount.",
  },
  "x402-upto-verify-open-server::invalid_upto_svm_payload_channel_id": {
    tier: "T1",
    severity: "medium",
    likelihood: "medium",
    reason: "channelId invalid/mismatch reject (upto.go:439) unvectored.",
    how: "Add an x402-upto verify-open reject vector with a mismatched channelId.",
  },
  "x402-upto-verify-open-server::invalid_upto_svm_payload_expired": {
    tier: "T1",
    severity: "medium",
    likelihood: "low",
    reason: "now>expiresAt reject (VerifyUptoPayload:170) unvectored.",
    how: "Add an x402-upto verify-open reject vector with an expired payload.",
  },
  "x402-upto-verify-open-server::invalid_upto_svm_payload_not_yet_active": {
    tier: "T1",
    severity: "low",
    likelihood: "low",
    reason: "now<validAfter reject (VerifyUptoPayload:167) unvectored.",
    how: "Add an x402-upto verify-open reject vector with validAfter in the future.",
  },
  "x402-upto-verify-open-server::invalid_upto_svm_payload_open_transaction": {
    tier: "T1",
    severity: "medium",
    likelihood: "medium",
    reason: "missing/invalid openTransaction reject (upto.go:461,468) unvectored.",
    how: "Add an x402-upto verify-open reject vector with a malformed open instruction.",
  },
  "x402-upto-verify-open-server::invalid_upto_svm_payload_amount": {
    tier: "T1",
    severity: "low",
    likelihood: "low",
    reason: "maxAmount-does-not-parse reject unvectored.",
    how: "Add an x402-upto verify-open reject vector with an unparseable maxAmount.",
  },
  "x402-upto-zero-actual-refund::accept": {
    tier: "T2",
    severity: "medium",
    likelihood: "medium",
    reason: "actualAmount=0 -> empty distribution / full refund + close (upto.go:526,878) is program-only and untested.",
    how: "Add an onchain.e2e x402-upto vector with actualAmount=0 asserting empty-distribution close.",
  },
  // ---- x402 batch-settlement (Rust-only scheme, no harness runner) ----
  "x402-batch-client-voucher::accept": {
    tier: "T1",
    severity: "medium",
    likelihood: "low",
    reason: "Rust-only batch cumulative-voucher build (payment.rs) has no harness coverage.",
    how: "Add a Rust batch-settlement conformance vector + wire the Rust runner into the harness.",
  },
  "x402-batch-verify-payment-server::accept": {
    tier: "T1",
    severity: "high",
    likelihood: "low",
    reason: "Rust batch voucher-header verify + channel-state record (batch_settlement.rs:305) untested in harness.",
    how: "Add a Rust batch verify_payment vector (accept + a stale-voucher reject).",
  },
  "x402-batch-settle-batch-server::accept": {
    tier: "T2",
    severity: "high",
    likelihood: "low",
    reason: "Rust batch settle_batch broadcast (batch_settlement.rs:687) is program-only and untested.",
    how: "Add an onchain.e2e Rust batch-settle leg packing multiple channels' highest vouchers.",
  },
  // ---- mpp-charge residual gaps ----
  "mpp-charge-pull-verify-settle-server::challenge_route_mismatch": {
    tier: "T1",
    severity: "medium",
    likelihood: "medium",
    reason: "Route (currency/method/intent/realm) mismatch is distinct from amount mismatch; e2e cross-route maps to charge_request_mismatch, not challenge_route_mismatch.",
    how: "Add a charge vector whose credential pins a different currency/method than the served route.",
  },
  "mpp-charge-pull-verify-settle-server::unexpected-instruction": {
    tier: "T1",
    severity: "medium",
    likelihood: "low",
    reason: "No charge vector carries an unexpected extra instruction to trip the structural verifier's unexpected-instruction reject.",
    how: "Add a charge reject vector with an unexpected program instruction alongside the transfer.",
  },
  "mpp-charge-pull-verify-settle-server::fee-payer-is-funds-source": {
    tier: "T0",
    severity: "medium",
    likelihood: "medium",
    reason: "Charge verifier's fee-payer-source-ATA drain guard is untested (only the fee-payer==authority case is vectored).",
    how: "Add a charge reject vector where the fee payer owns the source ATA but is not the authority.",
  },
  // ---- mpp-session: on-chain lifecycle largely unexercised in CI ----
  "mpp-session-challenge-issue::accept": {
    tier: "T1",
    severity: "low",
    likelihood: "low",
    reason: "unpaid-challenge-smoke covers charge/x402-exact/x402-upto but not the session challenge (cap/modes/pullVoucherStrategy).",
    how: "Extend unpaid-challenge-smoke.test.ts to boot a session adapter and assert its 402 challenge shape.",
  },
  "mpp-session-open-push-client-submit::accept": {
    tier: "T2",
    severity: "high",
    likelihood: "medium",
    reason: "No green open-by-signature accept; the value-binding radar only asserts rejects (program-only path).",
    how: "Add an onchain.e2e session vector opening a channel client-submit and asserting verifyOpenBySignature accepts.",
  },
  "mpp-session-open-push-client-submit::open-mint-mismatch": {
    tier: "T1",
    severity: "high",
    likelihood: "medium",
    reason: "open mint!=expected reject (session_onchain.go:234) unvectored.",
    how: "Add a value-binding/open.json vector with a diverging mint.",
  },
  "mpp-session-open-push-client-submit::open-authorized-signer-mismatch": {
    tier: "T1",
    severity: "high",
    likelihood: "medium",
    reason: "authorizedSigner!=expected-operator reject (session_onchain.go:237) unvectored.",
    how: "Add a value-binding/open.json vector with a wrong authorized signer.",
  },
  "mpp-session-open-push-client-submit::open-rent-payer-mismatch": {
    tier: "T1",
    severity: "medium",
    likelihood: "low",
    reason: "rentPayer!=expected-operator reject (session_onchain.go:243) unvectored.",
    how: "Add a value-binding/open.json vector with a wrong rent payer.",
  },
  "mpp-session-open-push-client-submit::open-deposit-must-be-positive": {
    tier: "T1",
    severity: "medium",
    likelihood: "low",
    reason: "deposit==0 reject (session_onchain.go:255) unvectored.",
    how: "Add a value-binding/open.json vector with a zero deposit.",
  },
  "mpp-session-open-push-client-submit::open-channel-pda-mismatch": {
    tier: "T1",
    severity: "medium",
    likelihood: "low",
    reason: "channel PDA!=derived reject (session_onchain.go:280) unvectored.",
    how: "Add a value-binding/open.json vector with a non-derived channel PDA.",
  },
  "mpp-session-open-push-client-submit::open-channel-id-mismatch": {
    tier: "T1",
    severity: "medium",
    likelihood: "low",
    reason: "openPayload.channelId!=tx channel reject (session_onchain.go:283) unvectored.",
    how: "Add a value-binding/open.json vector with a mismatched channelId.",
  },
  "mpp-session-open-push-client-submit::no-open-instruction": {
    tier: "T1",
    severity: "medium",
    likelihood: "low",
    reason: "no-open-instruction reject (session_onchain.go:195) unvectored.",
    how: "Add a value-binding/open.json vector whose tx carries no payment-channels open instruction.",
  },
  "mpp-session-open-push-client-submit::open-too-few-accounts": {
    tier: "T1",
    severity: "low",
    likelihood: "low",
    reason: "too-few-accounts reject (session_onchain.go:203) unvectored.",
    how: "Add a value-binding/open.json vector with a truncated open instruction.",
  },
  "mpp-session-open-push-client-submit::lookup-tables-unsupported": {
    tier: "T1",
    severity: "medium",
    likelihood: "low",
    reason: "v0 tx with address lookup tables reject (session_onchain.go:148) unvectored.",
    how: "Add a value-binding/open.json vector with a v0 tx referencing an ALT.",
  },
  "mpp-session-open-push-server-submit::accept": {
    tier: "T2",
    severity: "high",
    likelihood: "medium",
    reason: "server-submit open (co-sign fee payer + broadcast, session_method.go:38) is program-only and unexercised.",
    how: "Add an onchain.e2e session vector for the server-opened channel path.",
  },
  "mpp-session-open-pull-clientVoucher::accept": {
    tier: "T1",
    severity: "medium",
    likelihood: "medium",
    reason: "clientVoucher pull-strategy open (no multi-delegate) has no dedicated accept coverage beyond the voucher unit.",
    how: "Add a session vector opening in pull/clientVoucher mode and issuing a first voucher.",
  },
  "mpp-session-open-pull-operatedVoucher::accept": {
    tier: "T2",
    severity: "high",
    likelihood: "low",
    reason: "operatedVoucher multi-delegator program delegation (MultiDelegate.ts, MULTI_DELEGATOR_PROGRAM) is entirely untested.",
    how: "Add an onchain.e2e vector exercising initMultiDelegate/updateDelegation delegation.",
  },
  "mpp-session-topup::accept": {
    tier: "T2",
    severity: "high",
    likelihood: "medium",
    reason: "No green top-up accept; the session never settles/tops-up on-chain in CI (harness rpc=None, program absent).",
    how: "Add an onchain.e2e session top-up vector raising the cap and asserting verifyTopUpBySignature accepts.",
  },
  "mpp-session-topup::tx-failed-onchain": {
    tier: "T1",
    severity: "low",
    likelihood: "low",
    reason: "referenced-top-up-tx-failed reject (session_onchain.go:744) unvectored.",
    how: "Add a value-binding/topup.json vector referencing a failed on-chain tx.",
  },
  "mpp-session-commit-deliver::accept": {
    tier: "T1",
    severity: "medium",
    likelihood: "medium",
    reason: "The metering side channel (BeginDelivery/ProcessCommit idempotency, session.go:496,594) has no harness coverage.",
    how: "Add a harness integration hitting /__402/session/deliveries then /commit twice, asserting idempotent commit.",
  },
  "mpp-session-idle-close::accept": {
    tier: "T1",
    severity: "medium",
    likelihood: "low",
    reason: "The per-channel idle watchdog auto-close+settle (session_lifecycle.go) is untested.",
    how: "Add a harness test with a short idle delay asserting the watchdog fires close+settle.",
  },
  // ---- mpp-subscription (activation + renewal) ----
  "mpp-subscription-activation-validate::accept": {
    tier: "T0",
    severity: "medium",
    likelihood: "medium",
    reason: "Pure structural validateActivationInstructions is covered only by the SDK unit test (subscription-server.test.ts:350), not mirrored as a harness vector.",
    how: "Add a subscription-activation.json structural vector (subscribe + transfer_subscription, no dup) to the conformance corpus.",
  },
  "mpp-subscription-activation-transaction::accept": {
    tier: "T2",
    severity: "high",
    likelihood: "medium",
    reason: "transaction-mode activation (co-sign fee payer, simulate, broadcast) is program-only and untested in the harness.",
    how: "Add an onchain.e2e subscription activation (transaction mode) vector.",
  },
  "mpp-subscription-activation-push::accept": {
    tier: "T2",
    severity: "high",
    likelihood: "medium",
    reason: "push/signature-mode activation with the atomic claimConsumed replay guard (recent fix) has no end-to-end test.",
    how: "Add an onchain.e2e subscription push activation + a replay-resubmit asserting claimConsumed blocks the second.",
  },
  "mpp-subscription-renewal::accept": {
    tier: "T2",
    severity: "high",
    likelihood: "low",
    reason: "Server-driven recurring/fixed-delegation renewal (Rust transfer_recurring/transfer_fixed) is Rust-only with no runner.",
    how: "Add a Rust onchain renewal leg exercising transfer_recurring + transfer_fixed.",
  },
};

// ---------------------------------------------------------------------------
// NOT_APPLICABLE: (path::outcome) pairs a reader might expect to apply but that
// cannot arise on this path, each with a reason.
// ---------------------------------------------------------------------------
const NOT_APPLICABLE: Record<string, string> = {
  "x402-exact-verify-server::invalid_exact_svm_payload_transaction":
    "Reference-only (@x402/svm) generic transaction failure; Go verify.go never emits it (documented divergence).",
  "x402-exact-verify-server::invalid_exact_svm_payload_missing_fee_payer":
    "Reference-only (@x402/svm); the Go structural verifier does not emit a missing-fee-payer code (divergence).",
  "x402-exact-verify-server::invalid_exact_svm_payload_unknown_seventh_instruction":
    "Unreachable in Go: the instruction count is capped at 6 (verify.go:74) before any 7th-slot check.",
};

// ---------------------------------------------------------------------------
// DEAD_OR_ALIAS: outcome ids accounted at the taxonomy level with no per-path
// cell — legacy vocabulary that aliases a canonical/normalized code already
// covered, or codes declared-but-never-raised (dead), or non-payer-facing.
// ---------------------------------------------------------------------------
const DEAD_OR_ALIAS: Record<string, string> = {
  // legacy ErrorCode -> canonical (covered elsewhere)
  "recipient-mismatch": "legacy alias -> charge_request_mismatch (covered via cross-route-replay).",
  "no-transfer-instruction": "legacy alias -> payment_invalid / no-matching-transfer (covered).",
  "signature-consumed": "legacy alias -> canonical signature_consumed (covered).",
  "simulation-failed": "legacy alias -> payment_invalid (covered via flows invalid_payload).",
  "transaction-failed": "legacy alias -> payment_invalid.",
  "transaction-not-found": "legacy alias -> payment_invalid.",
  "missing-transaction": "legacy alias -> payment_invalid.",
  "missing-signature": "legacy alias -> payment_invalid.",
  "invalid-payload-type": "legacy alias -> payment_invalid (43 raise sites, all fold to the canonical bucket).",
  "challenge-expired": "legacy alias -> canonical challenge_expired (covered via flows expired_challenge).",
  "challenge-mismatch": "legacy alias -> challenge_verification_failed (covered via cross-server-portability).",
  "challenge-route-mismatch": "legacy alias -> canonical challenge_route_mismatch (tracked as a KNOWN_GAP cell).",
  "invalid-method": "legacy alias -> challenge_route_mismatch.",
  "rpc-error": "legacy alias -> payment_invalid.",
  "other": "legacy catch-all -> payment_invalid.",
  "amount-mismatch": "normalized/legacy alias; x402 amount enforced via invalid_exact_svm_payload_amount_mismatch (covered), charge via charge_request_mismatch.",
  "decimals-mismatch": "normalized code that surfaces as no-matching-transfer in the reference (reject.ts note); covered via charge-transferchecked-decimals-mismatch.",
  "invalid-payload": "normalized generic fallback; exercised via x402-exact-defect-verify (undecodable) + flows invalid_payload.",
  // declared-but-never-raised (dead) / non-payer-facing
  "mint-mismatch": "DEAD: declared in core/error.go but never raised in Go.",
  "compute-budget-exceeded": "DEAD: declared in core/error.go but never raised in Go.",
  "invalid-config": "Server-config error, not a payer-facing settlement verdict (23 raise sites).",
};

// ===========================================================================
// Enforcement
// ===========================================================================
const SEP = "::";
const cellKeys = [...Object.keys(COVERED), ...Object.keys(KNOWN_GAP)];

// Explicit applicable-cell universe. This is intentionally NOT derived from
// COVERED/KNOWN_GAP: deleting a single covered cell must leave an expected
// (path,outcome) behind so the gate turns red even if that path and outcome are
// still represented elsewhere.
const APPLICABLE_CELLS: string[] = [
  "mpp-charge-canonical-json::accept",
  "mpp-charge-challenge-issue::accept",
  "mpp-charge-compute-budget-cap::compute-limit-over-cap",
  "mpp-charge-compute-budget-cap::compute-price-over-cap",
  "mpp-charge-cross-route-replay::charge_request_mismatch",
  "mpp-charge-cross-server-portability::challenge_verification_failed",
  "mpp-charge-decimals::accept",
  "mpp-charge-decimals::no-matching-transfer",
  "mpp-charge-idempotent-resubmit::signature_consumed",
  "mpp-charge-network-mismatch::wrong-network",
  "mpp-charge-network-mismatch::wrong_network",
  "mpp-charge-pubkey-currency::accept",
  "mpp-charge-pull-build-client::accept",
  "mpp-charge-pull-verify-settle-server::accept",
  "mpp-charge-pull-verify-settle-server::challenge_expired",
  "mpp-charge-pull-verify-settle-server::challenge_route_mismatch",
  "mpp-charge-pull-verify-settle-server::challenge_verification_failed",
  "mpp-charge-pull-verify-settle-server::charge_request_mismatch",
  "mpp-charge-pull-verify-settle-server::compute-price-over-cap",
  "mpp-charge-pull-verify-settle-server::fee-payer-is-funds-source",
  "mpp-charge-pull-verify-settle-server::fee-payer-not-authority",
  "mpp-charge-pull-verify-settle-server::no-matching-transfer",
  "mpp-charge-pull-verify-settle-server::payment_invalid",
  "mpp-charge-pull-verify-settle-server::signature_consumed",
  "mpp-charge-pull-verify-settle-server::unexpected-instruction",
  "mpp-charge-pull-verify-settle-server::wrong_network",
  "mpp-charge-push-build-client::accept",
  "mpp-charge-push-verify-server::accept",
  "mpp-charge-splits-native-sol::accept",
  "mpp-charge-splits-reject::splits-exceed-amount",
  "mpp-charge-splits-reject::too-many-splits",
  "mpp-charge-splits-spl-token::accept",
  "mpp-charge-splits-token2022::accept",
  "mpp-charge-symbol-currency::accept",
  "mpp-session-challenge-issue::accept",
  "mpp-session-close-settle::accept",
  "mpp-session-commit-deliver::accept",
  "mpp-session-idle-close::accept",
  "mpp-session-open-pull-clientVoucher::accept",
  "mpp-session-open-pull-operatedVoucher::accept",
  "mpp-session-open-push-client-submit::accept",
  "mpp-session-open-push-client-submit::distribution-hash-mismatch",
  "mpp-session-open-push-client-submit::lookup-tables-unsupported",
  "mpp-session-open-push-client-submit::no-open-instruction",
  "mpp-session-open-push-client-submit::open-authorized-signer-mismatch",
  "mpp-session-open-push-client-submit::open-channel-id-mismatch",
  "mpp-session-open-push-client-submit::open-channel-pda-mismatch",
  "mpp-session-open-push-client-submit::open-deposit-must-be-positive",
  "mpp-session-open-push-client-submit::open-mint-mismatch",
  "mpp-session-open-push-client-submit::open-recipient-mismatch",
  "mpp-session-open-push-client-submit::open-rent-payer-mismatch",
  "mpp-session-open-push-client-submit::open-too-few-accounts",
  "mpp-session-open-push-client-submit::signature-binding-mismatch",
  "mpp-session-open-push-client-submit::tx-not-found",
  "mpp-session-open-push-server-submit::accept",
  "mpp-session-topup::accept",
  "mpp-session-topup::deposit-over-cap",
  "mpp-session-topup::topup-amount-delta-mismatch",
  "mpp-session-topup::tx-failed-onchain",
  "mpp-session-topup::tx-not-found",
  "mpp-session-voucher-canonical-bytes::accept",
  "mpp-session-voucher::accepted",
  "mpp-session-voucher::below-min-delta",
  "mpp-session-voucher::channel-close-pending",
  "mpp-session-voucher::channel-finalized",
  "mpp-session-voucher::cumulative-not-monotonic",
  "mpp-session-voucher::exceeds-deposit",
  "mpp-session-voucher::expired",
  "mpp-session-voucher::expiry-too-soon",
  "mpp-session-voucher::invalid-cumulative",
  "mpp-session-voucher::invalid-signature",
  "mpp-session-voucher::replayed",
  "mpp-subscription-activation-push::accept",
  "mpp-subscription-activation-transaction::accept",
  "mpp-subscription-activation-validate::accept",
  "mpp-subscription-renewal::accept",
  "x402-batch-client-voucher::accept",
  "x402-batch-settle-batch-server::accept",
  "x402-batch-verify-payment-server::accept",
  "x402-exact-build-client::accept",
  "x402-exact-challenge-issue::accept",
  "x402-exact-settle-server::accept",
  "x402-exact-settle-server::charge_request_mismatch",
  "x402-exact-settle-server::invalid_gate",
  "x402-exact-settle-server::invalid_payload",
  "x402-exact-settle-server::payment_identifier_required",
  "x402-exact-settle-server::payment_required",
  "x402-exact-settle-server::send_failed",
  "x402-exact-settle-server::settlement_failed",
  "x402-exact-settle-server::signature_consumed",
  "x402-exact-settle-server::version_mismatch",
  "x402-exact-v1-build-client::accept",
  "x402-exact-verify-server::accept",
  "x402-exact-verify-server::fee-payer-is-funds-source",
  "x402-exact-verify-server::invalid_exact_svm_payload_amount_mismatch",
  "x402-exact-verify-server::invalid_exact_svm_payload_memo_count",
  "x402-exact-verify-server::invalid_exact_svm_payload_memo_mismatch",
  "x402-exact-verify-server::invalid_exact_svm_payload_mint_mismatch",
  "x402-exact-verify-server::invalid_exact_svm_payload_no_transfer_instruction",
  "x402-exact-verify-server::invalid_exact_svm_payload_recipient_mismatch",
  "x402-exact-verify-server::invalid_exact_svm_payload_transaction_could_not_be_decoded",
  "x402-exact-verify-server::invalid_exact_svm_payload_transaction_fee_payer_transferring_funds",
  "x402-exact-verify-server::invalid_exact_svm_payload_transaction_instructions_compute_limit_instruction",
  "x402-exact-verify-server::invalid_exact_svm_payload_transaction_instructions_compute_price_instruction",
  "x402-exact-verify-server::invalid_exact_svm_payload_transaction_instructions_compute_price_instruction_too_high",
  "x402-exact-verify-server::invalid_exact_svm_payload_transaction_instructions_length",
  "x402-exact-verify-server::invalid_exact_svm_payload_unknown_fifth_instruction",
  "x402-exact-verify-server::invalid_exact_svm_payload_unknown_fourth_instruction",
  "x402-exact-verify-server::invalid_exact_svm_payload_unknown_optional_instruction",
  "x402-exact-verify-server::invalid_exact_svm_payload_unknown_sixth_instruction",
  "x402-exact-versioned-challenge-parse::accept",
  "x402-exact-versioned-challenge-parse::unsupported-version",
  "x402-exact-versioned-challenge-parse::version_mismatch",
  "x402-exact-versioned-challenge-parse::wrong-network",
  "x402-payment-identifier-extension::accept",
  "x402-payment-identifier-extension::payment-identifier-required",
  "x402-upto-build-open-client::accept",
  "x402-upto-confirm-open-server::accept",
  "x402-upto-confirm-open-server::invalid_upto_svm_payload_payer_mismatch",
  "x402-upto-over-ceiling-reject::invalid_upto_svm_payload_settlement_exceeds_amount",
  "x402-upto-requirements-issue::accept",
  "x402-upto-settle-actual-server::accept",
  "x402-upto-verify-open-server::accept",
  "x402-upto-verify-open-server::invalid_upto_svm_payload_amount",
  "x402-upto-verify-open-server::invalid_upto_svm_payload_amount_mismatch",
  "x402-upto-verify-open-server::invalid_upto_svm_payload_authorized_signer",
  "x402-upto-verify-open-server::invalid_upto_svm_payload_channel_id",
  "x402-upto-verify-open-server::invalid_upto_svm_payload_deposit_not_ceiling",
  "x402-upto-verify-open-server::invalid_upto_svm_payload_expired",
  "x402-upto-verify-open-server::invalid_upto_svm_payload_not_yet_active",
  "x402-upto-verify-open-server::invalid_upto_svm_payload_open_transaction",
  "x402-upto-zero-actual-refund::accept",
];

function pathOf(key: string): string {
  return key.slice(0, key.indexOf(SEP));
}
function outcomeOf(key: string): string {
  return key.slice(key.indexOf(SEP) + SEP.length);
}

// Live reject vocabulary pulled from source so the matrix cannot drift.
function schemaRejectCodes(): string[] {
  const src = readFileSync(join(harnessDir, "src", "conformance", "schema.ts"), "utf8");
  const start = src.indexOf("export type RejectCode =");
  const end = src.indexOf(";", start);
  const body = src.slice(start, end);
  return [...body.matchAll(/"([^"]+)"/g)].map((m) => m[1]);
}

function vectorRejectStrings(): Set<string> {
  const codes = new Set<string>();
  const walk = (dir: string) => {
    for (const name of readdirSync(dir, { withFileTypes: true })) {
      const full = join(dir, name.name);
      if (name.isDirectory()) {
        walk(full);
        continue;
      }
      if (!name.name.endsWith(".json")) continue;
      let parsed: unknown;
      try {
        parsed = JSON.parse(readFileSync(full, "utf8"));
      } catch {
        continue;
      }
      const visit = (node: unknown) => {
        if (Array.isArray(node)) {
          node.forEach(visit);
        } else if (node && typeof node === "object") {
          const o = node as Record<string, unknown>;
          for (const k of ["rejectCode", "x402ExactRejectCode"]) {
            if (typeof o[k] === "string") codes.add(o[k] as string);
          }
          Object.values(o).forEach(visit);
        }
      };
      visit(parsed);
    }
  };
  walk(vectorsDir);
  return codes;
}

const accountedOutcomes = new Set<string>([
  ...cellKeys.map(outcomeOf),
  ...Object.keys(NOT_APPLICABLE).map(outcomeOf),
  ...Object.keys(DEAD_OR_ALIAS),
]);

describe("matrix coverage gate: every applicable (path,outcome) is covered or a declared gap", () => {
  it("has a non-trivial matrix (paths, outcomes, cells)", () => {
    expect(PATHS.length).toBeGreaterThan(40);
    expect(OUTCOMES.length).toBeGreaterThan(80);
    expect(cellKeys.length).toBeGreaterThan(80);
  });

  it("declares no cell twice (a cell is COVERED xor KNOWN_GAP)", () => {
    const both = Object.keys(COVERED).filter((k) => k in KNOWN_GAP);
    expect(both, `cells in BOTH COVERED and KNOWN_GAP: ${both.join(", ")}`).toEqual([]);
  });

  it("enumerates each applicable cell exactly once", () => {
    const duplicates = APPLICABLE_CELLS.filter(
      (key, index) => APPLICABLE_CELLS.indexOf(key) !== index,
    );
    expect(duplicates, `duplicate APPLICABLE_CELLS entries: ${duplicates.join(", ")}`).toEqual([]);
    const applicable = new Set(APPLICABLE_CELLS);
    const unlisted = cellKeys.filter((key) => !applicable.has(key));
    expect(
      unlisted,
      `classified cell(s) missing from APPLICABLE_CELLS: ${unlisted.join(", ")}`,
    ).toEqual([]);
  });

  it("references only enumerated paths and outcomes (no typo'd axis)", () => {
    const paths = new Set(PATHS);
    const outcomes = new Set(OUTCOMES);
    const badPath = cellKeys.filter((k) => !paths.has(pathOf(k)));
    const badOutcome = cellKeys.filter((k) => !outcomes.has(outcomeOf(k)));
    expect(badPath, `cells on unknown path: ${badPath.join(", ")}`).toEqual([]);
    expect(badOutcome, `cells with unknown outcome: ${badOutcome.join(", ")}`).toEqual([]);
    const naBad = Object.keys(NOT_APPLICABLE).filter(
      (k) => !paths.has(pathOf(k)) || !outcomes.has(outcomeOf(k)),
    );
    expect(naBad, `NOT_APPLICABLE on unknown path/outcome: ${naBad.join(", ")}`).toEqual([]);
  });

  // TRIPWIRE 1: a new protocol path with no classified cell turns this red.
  it("classifies at least one cell for every enumerated PATH", () => {
    const withCells = new Set(cellKeys.map(pathOf));
    const orphanPaths = PATHS.filter((p) => !withCells.has(p));
    expect(
      orphanPaths,
      `protocol path(s) with no COVERED/KNOWN_GAP cell: ${orphanPaths.join(", ")}. ` +
        "Classify at least one (path,outcome) cell (accept or a reject) or the path is untested-in-the-dark.",
    ).toEqual([]);
  });

  // TRIPWIRE 2: a new reject code nobody mapped turns this red.
  it("accounts for every enumerated OUTCOME id", () => {
    const unaccounted = OUTCOMES.filter((o) => !accountedOutcomes.has(o));
    expect(
      unaccounted,
      `outcome id(s) not accounted: ${unaccounted.join(", ")}. ` +
        "Bind to a matrix cell (COVERED/KNOWN_GAP), or add to NOT_APPLICABLE / DEAD_OR_ALIAS with a reason.",
    ).toEqual([]);
  });

  // TRIPWIRE 3: a new normalized RejectCode in schema.ts turns this red.
  it("accounts for every normalized RejectCode declared in schema.ts (live)", () => {
    const live = schemaRejectCodes();
    expect(live.length).toBeGreaterThan(10);
    const missing = live.filter((c) => !accountedOutcomes.has(c) && !OUTCOMES.includes(c));
    expect(
      missing,
      `schema.ts RejectCode(s) missing from the matrix taxonomy: ${missing.join(", ")}. ` +
        "Add to OUTCOMES and classify.",
    ).toEqual([]);
  });

  // TRIPWIRE 4: a vector inventing an unmapped reject string turns this red.
  it("accounts for every reject string actually emitted by a vector on disk (live)", () => {
    const emitted = [...vectorRejectStrings()];
    const unmapped = emitted.filter((c) => !accountedOutcomes.has(c) && !OUTCOMES.includes(c));
    expect(
      unmapped,
      `vector reject code(s) with no matrix classification: ${unmapped.join(", ")}. ` +
        "Add to OUTCOMES and classify (a vector cannot emit a code the matrix does not know).",
    ).toEqual([]);
  });

  // Per-cell: every enumerated applicable cell must be COVERED, KNOWN_GAP, or
  // explicitly NOT_APPLICABLE. This is the anti-vacuous guard: deleting one
  // covered accept cell for a path that still has reject cells leaves the
  // applicable key here and turns the gate red.
  for (const key of [...APPLICABLE_CELLS].sort()) {
    it(`${key} is covered or a declared gap`, () => {
      const covered = COVERED[key];
      const gap = KNOWN_GAP[key];
      const notApplicable = NOT_APPLICABLE[key];
      if (covered) {
        expect(covered.test.length, `${key}: COVERED must name a test/vector`).toBeGreaterThan(0);
        expect(["T0", "T1", "T2"]).toContain(covered.tier);
      } else if (gap) {
        expect(gap.reason.length, `${key}: KNOWN_GAP must give a reason`).toBeGreaterThan(0);
        expect(gap.how.length, `${key}: KNOWN_GAP must say how to cover it`).toBeGreaterThan(0);
        expect(["T0", "T1", "T2"]).toContain(gap.tier);
      } else if (notApplicable) {
        expect(notApplicable.length, `${key}: NOT_APPLICABLE must give a reason`).toBeGreaterThan(0);
      } else {
        throw new Error(
          `${key} is neither COVERED, KNOWN_GAP, nor NOT_APPLICABLE. An applicable cell ` +
            "must be classified — cover it, declare the gap, or document why it cannot apply.",
        );
      }
    });
  }
});
