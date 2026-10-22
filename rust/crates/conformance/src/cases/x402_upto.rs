//! x402 `upto` (SVM) cases: the 50-byte voucher, distribution and channel
//! PDA goldens; client builds of the channel `open` against the fixture
//! RPC; and the server's read-only verify of a client authorization (the
//! payload bindings and the complete `openTransaction` acceptance policy of
//! scheme_upto_svm.md Phase 3), honest or tampered with one [`Tamper`].
//! Transaction-version (SIMD-0385) cases cite the x402-txv1 draft.
//!
//! Multi-step behaviour is not here: settle (deposit broadcast, claim with a
//! voucher, the `actual <= maxAmount` ceiling, zero-amount refunds), the
//! duplicate-settlement cache, pending settlements, delegated receiver
//! authorization, rent cleanup and channel discovery all need state a
//! single-shot vector cannot carry.

use serde_json::{json, Value};

use super::client_secret;
use crate::case::{
    spec, BugType, Case, CaseBuilder, Expect, Input, Intent, Mode, Pin, RejectCode, Role, SpecRef,
    Suite,
};
use crate::keys::{self, MINT, MINT_2022, OTHER_MINT, TOKEN_2022_PROGRAM, X402_PAY_TO};
use crate::realize::upto::{
    client, compute_budget, fixtures_json, key, lighthouse_ix, memo_ix, route_memo, stranger,
    unit_limit_ix, unit_price_ix, Form, PayerSignature, Route, Tamper, VerifySpec, NONCE_MEMO, NOW,
    RECEIVER_AUTHORIZER_SEED, SLOT,
};

const SVM: &str = "x402/specs/schemes/upto/scheme_upto_svm.md";
const UPTO: &str = "x402/specs/schemes/upto/scheme_upto.md";
const TXV1: &str = "x402-txv1/specs/schemes/upto/scheme_upto_svm.md";

const VERIFY_FILE: &str = "x402-upto-verify.json";
const POLICY_FILE: &str = "x402-upto-open-policy.json";
const BUILD_FILE: &str = "x402-upto-build.json";
const WIRE_FILE: &str = "x402-upto-wire.json";
const TXV1_FILE: &str = "x402-upto-txv1.json";

// Requirement ids (`pkc req-lint --list x402`, `--list x402-txv1`).
const TIME_BOUND: &str = "X402-d851126afb";
const RECIPIENT_BIND: &str = "X402-4504985ded";
const ZERO_EXPIRY: &str = "X402-77ee69c328";
const CEILING_VERIFY: &str = "X402-6a72109261";
const CANONICAL_PROGRAM: &str = "X402-edc9de017f";
const WITHDRAW_EXACT: &str = "X402-d90b7dc5de";
const WITHDRAW_POSITIVE: &str = "X402-ffe188aee8";
const MEMO_DECLARED: &str = "X402-d5f1ded529";
const EXPLICIT_DISTRIBUTION: &str = "X402-8969786085";
const NOT_AWAY_FROM_PAY_TO: &str = "X402-2cb22aa0de";
const MAX_EQ_AMOUNT: &str = "X402-99f2a389e8";
const DEPOSIT_EQ_MAX: &str = "X402-521ba9b673";
const AUTHORIZED_SIGNER: &str = "X402-1c7e99f632";
const CLIENT_DERIVES: &str = "X402-eace5aece9";
const REDERIVE_PDA: &str = "X402-cf373442ff";
const OPEN_ENCODES: &str = "X402-d75fb10a6f";
const DEPOSIT_NO_VOUCHER: &str = "X402-f747c74e76";
const STATIC_INSPECT: &str = "X402-52c9f1e405";
const NO_LOOKUP_TABLES: &str = "X402-c1174b72d8";
const FEE_PAYER_EQ: &str = "X402-9d68660de5";
const SIGNER_SET: &str = "X402-9af8f33cd6";
const FROM_SIGNATURE: &str = "X402-bcbf7025e5";
const FEE_PAYER_OUTSIDE_OPEN: &str = "X402-005b043052";
const LAYOUT: &str = "X402-ce3692afe0";
const LIMIT_BEFORE_PRICE: &str = "X402-11bbb0287f";
const LIGHTHOUSE_MAX: &str = "X402-d46a6b2b3b";
const CLIENT_MEMO: &str = "X402-6b3e9350c8";
const NO_OTHER_PROGRAM: &str = "X402-c8544c0fdd";
const CB_DISCRIMINATOR: &str = "X402-683361bbae";
const CB_LIMIT: &str = "X402-b4167aad45";
const CB_PRICE: &str = "X402-233dcf8a3e";
const CB_ABSOLUTE: &str = "X402-443a167ea1";
const WRAPPER_FEE_PAYER: &str = "X402-d0ce5e5325";
const MEMO_ENFORCED: &str = "X402-b2b604a864";
const ALLOWLIST: &str = "X402-7cd3ca69a6";
const OPEN_14_ACCOUNTS: &str = "X402-e829ad118e";
const PRIVILEGE_UNION: &str = "X402-14b8b2b598";
const FULL_DECODE: &str = "X402-aec23b2308";
const IN_ORDER: &str = "X402-e4509fb732";
const UNEXPECTED_VOUCHER: &str = "X402-aaee5a4f5b";
const UNEXPECTED_TYPE: &str = "X402-4c364688fc";
const ALREADY_OPEN: &str = "X402-865b05c15d";
const NO_REPLAY_OF_OPENED: &str = "X402-076bb2bdc3";
const VERIFIER_POLICY: &str = "X402-3b5914a7c5";

const TV_CLIENT: &str = "X402TX-61c735c7a9";
const TV_CLIENT_EMPTY: &str = "X402TX-2909c4b4ec";
const TV_REJECT_FIRST: &str = "X402TX-5267172b18";
const TV_SIZE: &str = "X402TX-dc7b0f3305";
const TV_V1_BUDGET: &str = "X402TX-644919eb3b";
const TV_MESSAGE: &str = "X402TX-4de59a1f27";
const TV_NO_PREFIX: &str = "X402TX-125d312b26";
const TV_V1_CAPS: &str = "X402TX-0f874a9c63";
const TV_V1_NO_CB: &str = "X402TX-936b492daa";
const TV_LEGACY: &str = "X402TX-77742f428c";
const TV_OPEN_VERSION: &str = "X402TX-d444d01b9e";

// ── spec references ────────────────────────────────────────────────────────

fn s_payload() -> SpecRef {
    spec(
        SVM,
        "4.2 UptoPayload (in PAYMENT-SIGNATURE.payload)",
        "The server/facilitator MUST rederive the PDA from the decoded openTransaction and reject the payload if it differs from either the decoded channel account or payload.channelId.",
    )
}

fn s_encode() -> SpecRef {
    spec(
        SVM,
        "4.2 UptoPayload (in PAYMENT-SIGNATURE.payload)",
        "The open instruction MUST encode:",
    )
}

fn s_in_order() -> SpecRef {
    spec(
        SVM,
        "Phase 3 - Deposit settle (before resource execution)",
        "The server/facilitator MUST, in order:",
    )
}

fn s_time() -> SpecRef {
    spec(
        SVM,
        "Phase 3 - Deposit settle (before resource execution)",
        "Validate validAfter <= now < expiresAt and reject expiresAt == 0.",
    )
}

fn s_lifetime() -> SpecRef {
    spec(
        SVM,
        "Phase 3 - Deposit settle (before resource execution)",
        "Reject when maxTimeoutSeconds or remaining expiresAt - now exceeds the facilitator's maxChannelLifetimeSecs, or when expiresAt is later than now + maxTimeoutSeconds (plus clock skew).",
    )
}

fn s_message() -> SpecRef {
    spec(
        SVM,
        "Message and signer rules",
        "The complete required-signer set MUST equal the distinct addresses in { payload.from, extra.feePayer }.",
    )
}

fn s_layout() -> SpecRef {
    spec(
        SVM,
        "Top-level instruction layout",
        "The top-level instructions MUST consist only of the following ordered regions:",
    )
}

fn s_compute() -> SpecRef {
    spec(
        SVM,
        "Top-level instruction layout",
        "MUST use only discriminator 2 (SetComputeUnitLimit, exactly 5 data bytes) or discriminator 3 (SetComputeUnitPrice, exactly 9 data bytes);",
    )
}

fn s_open() -> SpecRef {
    spec(
        SVM,
        "Canonical open instruction",
        "The open instruction MUST invoke the canonical payment-channels program for the selected network, use discriminator 1, contain exactly the following 14 account positions in order, and contain no remaining accounts:",
    )
}

fn s_decode() -> SpecRef {
    spec(
        SVM,
        "Canonical open instruction",
        "The facilitator MUST fully decode the canonical open instruction data, reject truncated data or trailing bytes, and enforce every field binding defined in section 4.2, including the exact deposit, salt, open slot, grace period, distribution, and rederived channel PDA.",
    )
}

fn s_txv1() -> SpecRef {
    spec(
        TXV1,
        "Transaction versions",
        "The client MUST intersect the advertised versions ([0] when the field is absent) with the versions it and its signer support, then build the highest version in that intersection.",
    )
}

fn s_txv1_reject() -> SpecRef {
    spec(
        TXV1,
        "Transaction versions",
        "The facilitator MUST reject a message whose version is outside the set it accepts, before inspecting any instruction, with unsupported_transaction_version.",
    )
}

fn s_txv1_budget() -> SpecRef {
    spec(
        TXV1,
        "Top-level instruction layout",
        "In a version-1 transaction the same caps apply to the message TransactionConfig instead: computeUnitLimit MUST be present and MUST NOT exceed 400000, loadedAccountsDataSizeLimit MUST be present, and priorityFee (total lamports) MUST satisfy priorityFee 1000000 <= 5000000 computeUnitLimit.",
    )
}

// ── builders ───────────────────────────────────────────────────────────────

fn base() -> VerifySpec {
    VerifySpec::honest(Route::default())
}

fn route_bound() -> Route {
    Route {
        bound: true,
        ..Route::default()
    }
}

fn v1_route() -> Route {
    Route {
        versions: Some(vec![0, 1]),
        ..Route::default()
    }
}

fn input_of(spec: &VerifySpec) -> Input {
    Input::Static(
        spec.input()
            .unwrap_or_else(|e| panic!("upto vector input: {e}")),
    )
}

const VERIFY_NOTE: &str = " Verify is the read-only preflight of the deposit settle (Phase 3): every static check before co-signing, at the vector's clock (nowSeconds).";

#[allow(clippy::too_many_arguments)]
fn verify_case(
    id: &str,
    file: &'static str,
    spec: SpecRef,
    reqs: &[&str],
    bug: BugType,
    description: &str,
    vspec: VerifySpec,
    expect: Expect,
    divergence: Option<&str>,
) -> Case {
    let authored = divergence.is_some() || matches!(expect, Expect::AcceptAuthored(_));
    let mut builder = CaseBuilder::new(
        id,
        file,
        Suite::X402Upto,
        Intent::X402Upto,
        Mode::VerifyTransaction,
        Role::Server,
        bug,
        spec,
        &format!("{description}{VERIFY_NOTE}"),
        input_of(&vspec),
        expect,
    )
    .requirements(reqs);
    if authored {
        builder = builder.authored(divergence);
    }
    builder.build()
}

/// An accept a stricter-than-spec verifier would refuse.
fn accept_lenient(
    id: &str,
    file: &'static str,
    spec: SpecRef,
    reqs: &[&str],
    description: &str,
    vspec: VerifySpec,
) -> Case {
    verify_case(
        id,
        file,
        spec,
        reqs,
        BugType::Defaults,
        description,
        vspec,
        Expect::Accept(Pin::Outcome),
        None,
    )
}

fn accept(
    id: &str,
    file: &'static str,
    spec: SpecRef,
    reqs: &[&str],
    description: &str,
    vspec: VerifySpec,
) -> Case {
    verify_case(
        id,
        file,
        spec,
        reqs,
        BugType::AuthBypass,
        description,
        vspec,
        Expect::Accept(Pin::Outcome),
        None,
    )
}

/// An honest base with one tamper applied. The tamper's paired code must be
/// the declared one.
#[allow(clippy::too_many_arguments)]
fn reject(
    id: &str,
    file: &'static str,
    spec: SpecRef,
    reqs: &[&str],
    bug: BugType,
    mut vspec: VerifySpec,
    tamper: Tamper,
    code: RejectCode,
    divergence: Option<&str>,
) -> Case {
    if let Some(paired) = tamper.expected() {
        assert_eq!(
            paired, code,
            "{id}: {tamper:?} is paired with {paired}, the case declares {code}"
        );
    }
    let description = format!("{}: rejected as {code}.", tamper.describe());
    tamper.apply(&mut vspec);
    verify_case(
        id,
        file,
        spec,
        reqs,
        bug,
        &description,
        vspec,
        Expect::Reject { code, reason: None },
        divergence,
    )
}

fn with(mut vspec: VerifySpec, tamper: Tamper) -> VerifySpec {
    tamper.apply(&mut vspec);
    vspec
}

/// The build input for an offer.
fn build_input(offer: Value) -> Value {
    json!({
        "x402Offer": offer,
        "signerSecretKey": client_secret(),
        "nowSeconds": NOW,
        "x402UptoExpiresAt": NOW + 300,
        "x402UptoRequestNonce": "request-7",
        "rpcFixtures": fixtures_json(MINT, keys::TOKEN_PROGRAM),
    })
}

const BUILD_NOTE: &str = " The client builds and signs the channel open from the challenge hints (no live RPC); the judge runs the Rust upto verifier on the SDK's header and compares the open with the kit's own build modulo the salt.";

#[allow(clippy::too_many_arguments)]
fn build_case(
    id: &str,
    file: &'static str,
    spec: SpecRef,
    reqs: &[&str],
    description: &str,
    input: Value,
    expect: Expect,
    divergence: Option<&str>,
) -> Case {
    let authored = divergence.is_some() || matches!(expect, Expect::AcceptAuthored(_));
    let mut builder = CaseBuilder::new(
        id,
        file,
        Suite::X402Upto,
        Intent::X402Upto,
        Mode::BuildTransaction,
        Role::Client,
        BugType::Wire,
        spec,
        &format!("{description}{BUILD_NOTE}"),
        Input::Static(input),
        expect,
    )
    .requirements(reqs);
    if authored {
        builder = builder.authored(divergence);
    }
    builder.build()
}

fn wire_case(
    id: &str,
    spec: SpecRef,
    reqs: &[&str],
    description: &str,
    input: Value,
    expect: Expect,
) -> Case {
    CaseBuilder::new(
        id,
        WIRE_FILE,
        Suite::X402Upto,
        Intent::X402Upto,
        Mode::CanonicalBytes,
        Role::Both,
        BugType::Wire,
        spec,
        description,
        Input::Static(input),
        expect,
    )
    .requirements(reqs)
    .build()
}

fn offer_with(edit: impl FnOnce(&mut Value)) -> Value {
    let mut offer = Route::default().offer();
    edit(&mut offer);
    offer
}

fn ra() -> String {
    key(RECEIVER_AUTHORIZER_SEED).to_string()
}

crate::registry! {
    // ── wire goldens ───────────────────────────────────────────────────────
    x402_upto_voucher_message_golden => wire_case(
        "x402-upto-voucher-message-golden",
        spec(SVM, "4.2 UptoPayload (in PAYMENT-SIGNATURE.payload)", "0x56 0x01 || channelId || u64(cumulativeAmount).le || i64(expiresAt).le"),
        &[TIME_BOUND],
        "The 50-byte receiver-authorizer voucher message magic(0x56,0x01) || channelId(32) || u64 LE cumulativeAmount || i64 LE expiresAt for the spec example (1858 units, expiresAt 1893456000). Frozen byte for byte: the facilitator rebuilds exactly these bytes to verify a claim voucher.",
        json!({"x402UptoVoucher": {"channelId": "cGfHiC6Kgg3FpFZvgwGcswsCRtp4aBP2fzuXRQPizuN", "cumulativeAmount": "1858", "expiresAt": 1_893_456_000_i64}}),
        Expect::Accept(Pin::ExactBytes(vec!["bytes", "base64Url"])),
    );
    x402_upto_voucher_message_zero_amount => wire_case(
        "x402-upto-voucher-message-zero-amount",
        spec(SVM, "4.2 UptoPayload (in PAYMENT-SIGNATURE.payload)", "where cumulativeAmount == actual for upto, which MAY be 0 for a zero-charge settlement or refund."),
        &[TIME_BOUND],
        "The zero-charge refund voucher (cumulativeAmount 0) with a u64-max-adjacent expiry: still exactly 50 bytes, zero encoded verbatim.",
        json!({"x402UptoVoucher": {"channelId": "cGfHiC6Kgg3FpFZvgwGcswsCRtp4aBP2fzuXRQPizuN", "cumulativeAmount": "0", "expiresAt": 4_102_444_800_i64}}),
        Expect::Accept(Pin::ExactBytes(vec!["bytes"])),
    );
    x402_upto_voucher_message_bad_channel_reject => wire_case(
        "x402-upto-voucher-message-bad-channel-reject",
        spec(SVM, "4.2 UptoPayload (in PAYMENT-SIGNATURE.payload)", "0x56 0x01 || channelId || u64(cumulativeAmount).le || i64(expiresAt).le"),
        &[TIME_BOUND],
        "A channelId that does not decode to 32 bytes cannot be packed into the voucher message and must be refused rather than truncated or padded.",
        json!({"x402UptoVoucher": {"channelId": "abc", "cumulativeAmount": "1", "expiresAt": 1_893_456_000_i64}}),
        Expect::Reject { code: RejectCode::InvalidPayload, reason: Some("channelId is not a 32-byte address".into()) },
    );
    x402_upto_distribution_hash_golden => wire_case(
        "x402-upto-distribution-hash-golden",
        spec(SVM, "4.1 PaymentRequirements (in PAYMENT-REQUIRED.accepts[])", "The explicit single-entry distribution is REQUIRED in all cases, including when payTo equals extra.receiverAuthorizer or extra.feePayer: the payee implicit remainder MUST be zero so that the facilitator in the payee seat has no claim on settled funds."),
        &[EXPLICIT_DISTRIBUTION],
        "sha256(count u32 LE || recipient(32) || bps u16 LE) of the single explicit [{ payTo, 10000 }] distribution an upto open commits (the program's distribution_hash).",
        json!({"x402UptoDistribution": {"recipients": [{"recipient": X402_PAY_TO, "bps": 10000}]}}),
        Expect::Accept(Pin::ExactBytes(vec!["bytes"])),
    );
    x402_upto_channel_pda_golden => wire_case(
        "x402-upto-channel-pda-golden",
        spec(SVM, "4.2 UptoPayload (in PAYMENT-SIGNATURE.payload)", "The client MUST derive channelId before signing openTransaction, include the same PDA as the writable channel account in the open instruction, and set payload.channelId to that address."),
        &[CLIENT_DERIVES, CANONICAL_PROGRAM],
        "The channel PDA find_program_address([\"channel\", from, feePayer, asset, receiverAuthorizer, u64 LE nonce, u64 LE openSlot], canonical program), as 32 bytes.",
        json!({"x402UptoChannelPda": {"payer": keys::CLIENT, "payee": keys::X402_OFFER_FEE_PAYER, "mint": MINT, "authorizedSigner": ra(), "salt": "4242", "openSlot": SLOT.to_string()}}),
        Expect::Accept(Pin::ExactBytes(vec!["bytes"])),
    );

    // ── verify: accepts ────────────────────────────────────────────────────
    x402_upto_verify_accept => accept(
        "x402-upto-verify-accept",
        VERIFY_FILE,
        s_in_order(),
        &[IN_ORDER, REDERIVE_PDA, OPEN_ENCODES, STATIC_INSPECT, MAX_EQ_AMOUNT, DEPOSIT_EQ_MAX],
        "The canonical client authorization: ComputeBudget limit then price, the 14-account open (payee and rent payer the fee payer, authorized signer the receiver authorizer, 100% to payTo), a hex nonce memo; payload bound to the open, deposit == maxAmount == amount, validAfter <= now < expiresAt <= now + maxTimeoutSeconds.",
        base(),
    );
    x402_upto_verify_bare_open_accept => accept(
        "x402-upto-verify-bare-open-accept",
        POLICY_FILE,
        s_layout(),
        &[LAYOUT],
        "Both wrapper regions are optional for the facilitator: a lone open (no ComputeBudget prefix, no suffix) is accepted.",
        VerifySpec::bare(Route::default()),
    );
    x402_upto_verify_lighthouse_accept => accept(
        "x402-upto-verify-lighthouse-accept",
        POLICY_FILE,
        spec(SVM, "Top-level instruction layout", "The suffix MUST contain at most three Lighthouse instructions."),
        &[LIGHTHOUSE_MAX, LAYOUT],
        "ComputeBudget prefix, open, three wallet-injected Lighthouse assertions and the memo: the largest allowed suffix (four instructions, three Lighthouse).",
        {
            let mut s = base();
            let lh = lighthouse_ix(&s.open);
            s.tx.suffix = vec![lh.clone(), lh.clone(), lh, memo_ix(NONCE_MEMO)];
            s
        },
    );
    x402_upto_verify_self_facilitated_accept => accept(
        "x402-upto-verify-self-facilitated-accept",
        VERIFY_FILE,
        spec(SVM, "Message and signer rules", "If two requirements-bound roles intentionally have the same address (for example feePayer == receiverAuthorizer), each occurrence in its prescribed open position is permitted."),
        &[FEE_PAYER_OUTSIDE_OPEN, PRIVILEGE_UNION],
        "The server self-facilitates: feePayer == receiverAuthorizer, so the fee payer appears at open positions 1, 2 and 4 with the unioned privileges.",
        VerifySpec::honest(Route { receiver_authorizer_seed: keys::X402_OFFER_FEE_PAYER_SEED, ..Route::default() }),
    );
    x402_upto_verify_pay_to_fee_payer_accept => accept(
        "x402-upto-verify-pay-to-fee-payer-accept",
        VERIFY_FILE,
        spec(SVM, "4.1 PaymentRequirements (in PAYMENT-REQUIRED.accepts[])", "The explicit single-entry distribution is REQUIRED in all cases, including when payTo equals extra.receiverAuthorizer or extra.feePayer: the payee implicit remainder MUST be zero so that the facilitator in the payee seat has no claim on settled funds."),
        &[EXPLICIT_DISTRIBUTION],
        "payTo equals extra.feePayer and the open still carries the explicit single-entry [{ payTo, 10000 }] distribution.",
        VerifySpec::honest(Route { pay_to: key(keys::X402_OFFER_FEE_PAYER_SEED), ..Route::default() }),
    );
    x402_upto_verify_route_memo_accept => accept(
        "x402-upto-verify-route-memo-accept",
        POLICY_FILE,
        spec(SVM, "Top-level instruction layout", "If extra.memo is present, the facilitator MUST verify that exactly one Memo instruction exists in the suffix and that its data matches extra.memo encoded as UTF-8."),
        &[MEMO_ENFORCED],
        "The route declares extra.memo and the open carries exactly that memo once.",
        VerifySpec::honest(route_bound()),
    );
    x402_upto_verify_legacy_message_accept => accept(
        "x402-upto-verify-legacy-message-accept",
        POLICY_FILE,
        spec(SVM, "Message and signer rules", "The message MAY be legacy or version 0, but it MUST NOT contain Address Lookup Table lookups."),
        &[NO_LOOKUP_TABLES],
        "The same open compiled as a legacy (unversioned) message is accepted and policed like version 0.",
        with(base(), Tamper::Form(Form::Legacy)),
    );
    x402_upto_verify_compute_at_caps_accept => accept(
        "x402-upto-verify-compute-at-caps-accept",
        POLICY_FILE,
        spec(SVM, "Top-level instruction layout", "A sponsor MAY apply a stricter local policy for compute-unit limit, compute-unit price, and required-signature count (operator-configurable caps), but MUST NOT admit a compute-unit limit above 400000 or a compute-unit price above 5000000 microlamports."),
        &[CB_LIMIT, CB_PRICE, CB_ABSOLUTE],
        "SetComputeUnitLimit 400000 and SetComputeUnitPrice 5000000 sit exactly at the absolute ceilings and are accepted.",
        with(base(), Tamper::Prefix(vec![unit_limit_ix(400_000), unit_price_ix(5_000_000)])),
    );
    x402_upto_verify_two_memos_unbound_accept => accept_lenient(
        "x402-upto-verify-two-memos-unbound-accept",
        POLICY_FILE,
        spec(SVM, "Top-level instruction layout", "An optional suffix of at most four instructions, each invoking either Lighthouse (L2TExMFKdjpN9kozasaurPirfHy9P8sbXoAN1qA3S95) or SPL Memo (MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr)."),
        &[LAYOUT],
        "The route declares no extra.memo, so the suffix is only bounded at four Lighthouse/Memo instructions; two memos are allowed.",
        with(base(), Tamper::Suffix(vec![memo_ix(NONCE_MEMO), memo_ix("second-memo-0123456789abcdef")])),
    );
    x402_upto_verify_open_slot_number_accept => accept_lenient(
        "x402-upto-verify-open-slot-number-accept",
        VERIFY_FILE,
        spec(SVM, "4.2 UptoPayload (in PAYMENT-SIGNATURE.payload)", "| openSlot | number | u64 slot encoded in the open instruction and used as a channel PDA seed. |"),
        &[OPEN_ENCODES],
        "payload.openSlot as the JSON number the pinned table types it as (every fixture elsewhere uses the decimal string all SDKs emit; RULINGS.md U1).",
        with(base(), Tamper::PayloadValue("openSlot", json!(SLOT))),
    );

    // ── verify: payload and requirement bindings ───────────────────────────
    x402_upto_verify_client_voucher_reject => reject(
        "x402-upto-verify-client-voucher-reject",
        VERIFY_FILE,
        spec(SVM, "Phase 3 - Deposit settle (before resource execution)", "voucherSignature is claim-only and server-owned; presence on the client payload (including an empty string or undefined value) MUST fail with invalid_upto_svm_payload_unexpected_voucher."),
        &[UNEXPECTED_VOUCHER, DEPOSIT_NO_VOUCHER],
        BugType::AuthBypass,
        base(),
        Tamper::PayloadKey("voucherSignature", json!("5VERv8NMvzbJMEkV8xnrLkEaWRtSz9CosKDYjCJjBRnbJLgp8uirBgmQpjKhoR4tjF3ZpRzrFmBV6UjKdiSZkQUW")),
        RejectCode::UnexpectedVoucher,
        None,
    );
    x402_upto_verify_client_voucher_empty_reject => reject(
        "x402-upto-verify-client-voucher-empty-reject",
        VERIFY_FILE,
        spec(SVM, "Phase 3 - Deposit settle (before resource execution)", "voucherSignature is claim-only and server-owned; presence on the client payload (including an empty string or undefined value) MUST fail with invalid_upto_svm_payload_unexpected_voucher."),
        &[UNEXPECTED_VOUCHER],
        BugType::AuthBypass,
        base(),
        Tamper::PayloadKey("voucherSignature", json!("")),
        RejectCode::UnexpectedVoucher,
        None,
    );
    x402_upto_verify_client_type_reject => reject(
        "x402-upto-verify-client-type-reject",
        VERIFY_FILE,
        spec(SVM, "Phase 3 - Deposit settle (before resource execution)", "type is per-settle and not part of the client authorization; presence on the client payload MUST fail with invalid_upto_svm_payload_type."),
        &[UNEXPECTED_TYPE],
        BugType::AuthBypass,
        base(),
        Tamper::PayloadKey("type", json!("deposit")),
        RejectCode::UnexpectedType,
        None,
    );
    x402_upto_verify_max_amount_mismatch_reject => reject(
        "x402-upto-verify-max-amount-mismatch-reject",
        VERIFY_FILE,
        spec(SVM, "4.2 UptoPayload (in PAYMENT-SIGNATURE.payload)", "| maxAmount | string | Signed ceiling in base units. MUST equal verification-phase amount. |"),
        &[MAX_EQ_AMOUNT, CEILING_VERIFY],
        BugType::Settlement,
        base(),
        Tamper::PayloadValue("maxAmount", json!("999999")),
        RejectCode::AmountMismatch,
        None,
    );
    x402_upto_verify_max_amount_not_integer_reject => reject(
        "x402-upto-verify-max-amount-not-integer-reject",
        VERIFY_FILE,
        spec(SVM, "4.2 UptoPayload (in PAYMENT-SIGNATURE.payload)", "| maxAmount | string | Signed ceiling in base units. MUST equal verification-phase amount. |"),
        &[MAX_EQ_AMOUNT],
        BugType::Wire,
        base(),
        Tamper::PayloadValue("maxAmount", json!("1e6")),
        RejectCode::InvalidPayload,
        None,
    );
    x402_upto_verify_deposit_below_ceiling_reject => reject(
        "x402-upto-verify-deposit-below-ceiling-reject",
        VERIFY_FILE,
        spec(SVM, "4.2 UptoPayload (in PAYMENT-SIGNATURE.payload)", "| deposit | string | Onchain escrow amount. MUST equal maxAmount. |"),
        &[DEPOSIT_EQ_MAX],
        BugType::Settlement,
        base(),
        Tamper::PayloadValue("deposit", json!("999999")),
        RejectCode::DepositNotCeiling,
        None,
    );
    x402_upto_verify_deposit_above_ceiling_reject => reject(
        "x402-upto-verify-deposit-above-ceiling-reject",
        VERIFY_FILE,
        spec(SVM, "4.2 UptoPayload (in PAYMENT-SIGNATURE.payload)", "| deposit | string | Onchain escrow amount. MUST equal maxAmount. |"),
        &[DEPOSIT_EQ_MAX],
        BugType::Settlement,
        base(),
        Tamper::PayloadValue("deposit", json!("1000001")),
        RejectCode::DepositNotCeiling,
        None,
    );
    x402_upto_verify_authorized_signer_reject => reject(
        "x402-upto-verify-authorized-signer-reject",
        VERIFY_FILE,
        spec(SVM, "4.2 UptoPayload (in PAYMENT-SIGNATURE.payload)", "| authorizedSigner | string | MUST equal extra.receiverAuthorizer; included for explicit payload validation."),
        &[AUTHORIZED_SIGNER],
        BugType::AuthBypass,
        base(),
        Tamper::PayloadValue("authorizedSigner", json!(keys::CLIENT)),
        RejectCode::ReceiverAuthorizerMismatch,
        None,
    );
    x402_upto_verify_channel_id_reject => reject(
        "x402-upto-verify-channel-id-reject",
        VERIFY_FILE,
        s_payload(),
        &[REDERIVE_PDA],
        BugType::AuthBypass,
        base(),
        Tamper::PayloadValue("channelId", json!(stranger().to_string())),
        RejectCode::ChannelIdMismatch,
        None,
    );
    x402_upto_verify_nonce_mismatch_reject => reject(
        "x402-upto-verify-nonce-mismatch-reject",
        VERIFY_FILE,
        s_encode(),
        &[OPEN_ENCODES, FULL_DECODE],
        BugType::AuthBypass,
        base(),
        Tamper::OpenSaltRederived(4243),
        RejectCode::OpenBindingMismatch,
        None,
    );
    x402_upto_verify_nonce_missing_reject => reject(
        "x402-upto-verify-nonce-missing-reject",
        VERIFY_FILE,
        spec(SVM, "4.2 UptoPayload (in PAYMENT-SIGNATURE.payload)", "| nonce | string | Unique decimal u64 salt encoded in the open instruction. |"),
        &[OPEN_ENCODES],
        BugType::Wire,
        base(),
        Tamper::PayloadRemove("nonce"),
        RejectCode::InvalidPayload,
        None,
    );
    x402_upto_verify_nonce_not_decimal_reject => verify_case(
        "x402-upto-verify-nonce-not-decimal-reject",
        VERIFY_FILE,
        spec(SVM, "4.2 UptoPayload (in PAYMENT-SIGNATURE.payload)", "| nonce | string | Unique decimal u64 salt encoded in the open instruction. |"),
        &[OPEN_ENCODES],
        BugType::Wire,
        "payload.nonce is not a decimal u64 (\"abc\"): the payload is malformed, rejected as invalid-payload.",
        with(base(), Tamper::PayloadValue("nonce", json!("abc"))),
        Expect::Reject { code: RejectCode::InvalidPayload, reason: Some("nonce is not a decimal u64".into()) },
        None,
    );
    x402_upto_verify_open_slot_not_decimal_reject => verify_case(
        "x402-upto-verify-open-slot-not-decimal-reject",
        VERIFY_FILE,
        spec(SVM, "4.2 UptoPayload (in PAYMENT-SIGNATURE.payload)", "| openSlot | number | u64 slot encoded in the open instruction and used as a channel PDA seed. |"),
        &[OPEN_ENCODES],
        BugType::Wire,
        "payload.openSlot is not an integer (\"abc\"): the payload is malformed, rejected as invalid-payload.",
        with(base(), Tamper::PayloadValue("openSlot", json!("abc"))),
        Expect::Reject { code: RejectCode::InvalidPayload, reason: Some("openSlot is not a u64".into()) },
        None,
    );
    x402_upto_verify_missing_open_transaction_reject => verify_case(
        "x402-upto-verify-missing-open-transaction-reject",
        VERIFY_FILE,
        spec(SVM, "4.2 UptoPayload (in PAYMENT-SIGNATURE.payload)", "| openTransaction | string | Base64 partially signed open transaction."),
        &[STATIC_INSPECT],
        BugType::Wire,
        "The payload carries no openTransaction: there is no authorization to inspect, rejected as invalid-payload.",
        {
            let mut s = base();
            s.input.insert("x402PaymentHeader".into(), json!(header_without_open(&s)));
            s
        },
        Expect::Reject { code: RejectCode::InvalidPayload, reason: None },
        None,
    );
    x402_upto_verify_fractional_expires_at_reject => reject(
        "x402-upto-verify-fractional-expires-at-reject",
        VERIFY_FILE,
        spec(SVM, "4.2 UptoPayload (in PAYMENT-SIGNATURE.payload)", "| expiresAt | number | Nonzero deadline (Unix seconds); signed into the server voucher. |"),
        &[TIME_BOUND],
        BugType::Wire,
        base(),
        Tamper::PayloadValue("expiresAt", json!(1_800_000_100.5)),
        RejectCode::InvalidPayload,
        None,
    );
    x402_upto_verify_fractional_valid_after_reject => reject(
        "x402-upto-verify-fractional-valid-after-reject",
        VERIFY_FILE,
        spec(SVM, "4.2 UptoPayload (in PAYMENT-SIGNATURE.payload)", "| validAfter | number | Activation time (Unix seconds). |"),
        &[TIME_BOUND],
        BugType::Wire,
        base(),
        Tamper::PayloadValue("validAfter", json!(1_799_999_999.5)),
        RejectCode::InvalidPayload,
        None,
    );
    x402_upto_verify_scheme_mismatch_reject => reject(
        "x402-upto-verify-scheme-mismatch-reject",
        VERIFY_FILE,
        spec(SVM, "4.1 PaymentRequirements (in PAYMENT-REQUIRED.accepts[])", "| scheme | string | yes | \"upto\" |"),
        &[IN_ORDER],
        BugType::Wire,
        base(),
        Tamper::Accepted("scheme", json!("exact")),
        RejectCode::AcceptedMismatch,
        None,
    );
    x402_upto_verify_network_mismatch_reject => reject(
        "x402-upto-verify-network-mismatch-reject",
        VERIFY_FILE,
        spec(SVM, "Phase 3 - Deposit settle (before resource execution)", "Confirm network, asset (mint), tokenProgram, and payTo match the selected requirements."),
        &[IN_ORDER],
        BugType::Wire,
        base(),
        Tamper::Accepted("network", json!(keys::MAINNET_CAIP2)),
        RejectCode::AcceptedMismatch,
        None,
    );

    // ── verify: time bounds ────────────────────────────────────────────────
    x402_upto_verify_expires_next_second_accept => accept(
        "x402-upto-verify-expires-next-second-accept",
        VERIFY_FILE,
        s_time(),
        &[IN_ORDER, TIME_BOUND],
        "expiresAt = now + 1 is the earliest accepted deadline (now < expiresAt).",
        with(base(), Tamper::ExpiresAt(1)),
    );
    x402_upto_verify_expired_at_now_reject => reject(
        "x402-upto-verify-expired-at-now-reject",
        VERIFY_FILE,
        s_time(),
        &[IN_ORDER, TIME_BOUND],
        BugType::Replay,
        base(),
        Tamper::ExpiresAt(0),
        RejectCode::VoucherExpired,
        None,
    );
    x402_upto_verify_expired_reject => reject(
        "x402-upto-verify-expired-reject",
        VERIFY_FILE,
        spec(UPTO, "2. Time-Bound Authorization", "Each authorization MUST have explicit validity time constraints:"),
        &[IN_ORDER, TIME_BOUND],
        BugType::Replay,
        base(),
        Tamper::ExpiresAt(-60),
        RejectCode::VoucherExpired,
        None,
    );
    x402_upto_verify_zero_expiry_reject => reject(
        "x402-upto-verify-zero-expiry-reject",
        VERIFY_FILE,
        spec(SVM, "2. Mapping the five core requirements to SVM", "Although the program supports expires_at == 0 as no expiry, SVM upto MUST reject expiresAt == 0."),
        &[ZERO_EXPIRY],
        BugType::Replay,
        base(),
        Tamper::ExpiresAt(-NOW),
        RejectCode::VoucherExpired,
        None,
    );
    x402_upto_verify_valid_after_now_accept => accept(
        "x402-upto-verify-valid-after-now-accept",
        VERIFY_FILE,
        s_time(),
        &[IN_ORDER, TIME_BOUND],
        "validAfter == now is active (validAfter <= now).",
        with(base(), Tamper::ValidAfter(0)),
    );
    x402_upto_verify_not_yet_active_reject => reject(
        "x402-upto-verify-not-yet-active-reject",
        VERIFY_FILE,
        s_time(),
        &[IN_ORDER, TIME_BOUND],
        BugType::Replay,
        base(),
        Tamper::ValidAfter(1),
        RejectCode::NotYetActive,
        None,
    );
    x402_upto_verify_expires_beyond_timeout_reject => verify_case(
        "x402-upto-verify-expires-beyond-timeout-reject",
        VERIFY_FILE,
        s_lifetime(),
        &[IN_ORDER],
        BugType::Replay,
        "expiresAt = now + maxTimeoutSeconds + 3600, far past any clock skew, while maxChannelLifetimeSecs (86400) allows it: rejected as expires-at-mismatch.",
        {
            let mut s = VerifySpec::honest(Route { max_channel_lifetime_seconds: 86_400, ..Route::default() });
            Tamper::ExpiresAt(300 + 3_600).apply(&mut s);
            s
        },
        Expect::Reject { code: RejectCode::ExpiresAtMismatch, reason: None },
        None,
    );
    x402_upto_verify_timeout_over_lifetime_reject => verify_case(
        "x402-upto-verify-timeout-over-lifetime-reject",
        VERIFY_FILE,
        s_lifetime(),
        &[IN_ORDER],
        BugType::Replay,
        "The route's maxTimeoutSeconds (7200) exceeds the facilitator's maxChannelLifetimeSecs (3600): rejected as channel-lifetime-exceeded even though expiresAt is near.",
        with(VerifySpec::honest(Route { max_timeout_seconds: 7_200, ..Route::default() }), Tamper::ExpiresAt(300)),
        Expect::Reject { code: RejectCode::ChannelLifetimeExceeded, reason: None },
        None,
    );
    x402_upto_verify_expires_over_lifetime_reject => verify_case(
        "x402-upto-verify-expires-over-lifetime-reject",
        VERIFY_FILE,
        s_lifetime(),
        &[IN_ORDER],
        BugType::Replay,
        "expiresAt - now (86400) exceeds maxChannelLifetimeSecs (3600) by far more than any clock skew: rejected as channel-lifetime-exceeded.",
        with(base(), Tamper::ExpiresAt(86_400)),
        Expect::Reject { code: RejectCode::ChannelLifetimeExceeded, reason: None },
        None,
    );

    // ── verify: replay ─────────────────────────────────────────────────────
    x402_upto_verify_channel_already_open_reject => reject(
        "x402-upto-verify-channel-already-open-reject",
        VERIFY_FILE,
        spec(SVM, "Phase 3 - Deposit settle (before resource execution)", "Confirm the channel account does not already exist. If it does, reject with invalid_upto_svm_channel_already_open."),
        &[ALREADY_OPEN, NO_REPLAY_OF_OPENED, IN_ORDER],
        BugType::Replay,
        base(),
        Tamper::ChannelExists,
        RejectCode::ChannelAlreadyOpen,
        None,
    );

    // ── open policy: message and signers ───────────────────────────────────
    x402_upto_verify_lookup_table_reject => reject(
        "x402-upto-verify-lookup-table-reject",
        POLICY_FILE,
        spec(SVM, "Message and signer rules", "The message MAY be legacy or version 0, but it MUST NOT contain Address Lookup Table lookups."),
        &[NO_LOOKUP_TABLES],
        BugType::AuthBypass,
        base(),
        Tamper::Form(Form::V0WithLookupTable),
        RejectCode::InvalidPayload,
        None,
    );
    x402_upto_verify_client_fee_payer_reject => reject(
        "x402-upto-verify-client-fee-payer-reject",
        POLICY_FILE,
        spec(SVM, "Message and signer rules", "The transaction fee payer MUST equal extra.feePayer."),
        &[FEE_PAYER_EQ, SIGNER_SET],
        BugType::AuthBypass,
        base(),
        Tamper::ClientPaysFees,
        RejectCode::InvalidPayload,
        None,
    );
    x402_upto_verify_extra_signer_reject => reject(
        "x402-upto-verify-extra-signer-reject",
        POLICY_FILE,
        s_message(),
        &[SIGNER_SET],
        BugType::AuthBypass,
        base(),
        Tamper::ExtraSigner,
        RejectCode::UnexpectedInstruction,
        None,
    );
    x402_upto_verify_missing_payer_signature_reject => reject(
        "x402-upto-verify-missing-payer-signature-reject",
        POLICY_FILE,
        spec(SVM, "Message and signer rules", "The payload.from signature MUST be present and valid before the facilitator signs."),
        &[FROM_SIGNATURE],
        BugType::AuthBypass,
        base(),
        Tamper::Signature(PayerSignature::Missing),
        RejectCode::InvalidPayload,
        None,
    );
    x402_upto_verify_invalid_payer_signature_reject => reject(
        "x402-upto-verify-invalid-payer-signature-reject",
        POLICY_FILE,
        spec(SVM, "Message and signer rules", "The payload.from signature MUST be present and valid before the facilitator signs."),
        &[FROM_SIGNATURE],
        BugType::AuthBypass,
        base(),
        Tamper::Signature(PayerSignature::Invalid),
        RejectCode::InvalidPayload,
        None,
    );

    // ── open policy: layout ────────────────────────────────────────────────
    x402_upto_verify_foreign_program_after_open_reject => reject(
        "x402-upto-verify-foreign-program-after-open-reject",
        POLICY_FILE,
        spec(SVM, "Top-level instruction layout", "In particular, another payment-channels instruction, an arbitrary wallet program, or a duplicate open MUST cause rejection."),
        &[NO_OTHER_PROGRAM, ALLOWLIST, VERIFIER_POLICY],
        BugType::AuthBypass,
        base(),
        Tamper::Suffix(vec![memo_ix(NONCE_MEMO), solana_instruction::Instruction { program_id: keys::pubkey(keys::SPLIT_RECIPIENT_2), accounts: vec![], data: vec![1] }]),
        RejectCode::UnexpectedInstruction,
        None,
    );
    x402_upto_verify_duplicate_open_reject => reject(
        "x402-upto-verify-duplicate-open-reject",
        POLICY_FILE,
        spec(SVM, "Top-level instruction layout", "In particular, another payment-channels instruction, an arbitrary wallet program, or a duplicate open MUST cause rejection."),
        &[NO_OTHER_PROGRAM],
        BugType::AuthBypass,
        base(),
        Tamper::DuplicateOpen,
        RejectCode::UnexpectedInstruction,
        None,
    );
    x402_upto_verify_no_open_reject => reject(
        "x402-upto-verify-no-open-reject",
        POLICY_FILE,
        spec(SVM, "Top-level instruction layout", "Exactly one payment-channels open instruction."),
        &[LAYOUT],
        BugType::AuthBypass,
        base(),
        Tamper::DropOpen,
        RejectCode::UnexpectedInstruction,
        None,
    );
    x402_upto_verify_memo_before_open_reject => reject(
        "x402-upto-verify-memo-before-open-reject",
        POLICY_FILE,
        s_layout(),
        &[LAYOUT],
        BugType::AuthBypass,
        base(),
        Tamper::BeforeOpen(memo_ix(NONCE_MEMO)),
        RejectCode::UnexpectedInstruction,
        None,
    );
    x402_upto_verify_not_open_instruction_reject => reject(
        "x402-upto-verify-not-open-instruction-reject",
        POLICY_FILE,
        s_open(),
        &[OPEN_14_ACCOUNTS, NO_OTHER_PROGRAM],
        BugType::AuthBypass,
        base(),
        Tamper::OpenDiscriminator(2),
        RejectCode::UnexpectedInstruction,
        None,
    );
    x402_upto_verify_foreign_channel_program_reject => reject(
        "x402-upto-verify-foreign-channel-program-reject",
        POLICY_FILE,
        spec(SVM, "3. Payment-channel Method", "Implementations MUST target the canonical payment-channels program id for the selected network and MUST NOT trust or negotiate a channelProgram value from extra."),
        &[CANONICAL_PROGRAM, OPEN_14_ACCOUNTS],
        BugType::AuthBypass,
        base(),
        Tamper::OpenProgram(keys::pubkey(keys::SPLIT_RECIPIENT_2)),
        RejectCode::UnexpectedInstruction,
        None,
    );
    x402_upto_verify_suffix_over_four_reject => reject(
        "x402-upto-verify-suffix-over-four-reject",
        POLICY_FILE,
        spec(SVM, "Top-level instruction layout", "An optional suffix of at most four instructions, each invoking either Lighthouse (L2TExMFKdjpN9kozasaurPirfHy9P8sbXoAN1qA3S95) or SPL Memo (MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr)."),
        &[LAYOUT],
        BugType::AuthBypass,
        base(),
        Tamper::Suffix({
            let s = base();
            let lh = lighthouse_ix(&s.open);
            vec![lh.clone(), lh.clone(), lh, memo_ix(NONCE_MEMO), memo_ix("ffffffffffffffffffffffffffffffff")]
        }),
        RejectCode::UnexpectedInstruction,
        None,
    );
    x402_upto_verify_four_lighthouse_reject => reject(
        "x402-upto-verify-four-lighthouse-reject",
        POLICY_FILE,
        spec(SVM, "Top-level instruction layout", "The suffix MUST contain at most three Lighthouse instructions."),
        &[LIGHTHOUSE_MAX],
        BugType::AuthBypass,
        base(),
        Tamper::Suffix({
            let s = base();
            let lh = lighthouse_ix(&s.open);
            vec![lh.clone(), lh.clone(), lh.clone(), lh]
        }),
        RejectCode::UnexpectedInstruction,
        None,
    );
    x402_upto_verify_fee_payer_in_lighthouse_reject => reject(
        "x402-upto-verify-fee-payer-in-lighthouse-reject",
        POLICY_FILE,
        spec(SVM, "Top-level instruction layout", "Lighthouse and Memo instructions are allowed only in the optional suffix and MUST NOT reference extra.feePayer as an account or as the invoked program."),
        &[WRAPPER_FEE_PAYER, FEE_PAYER_OUTSIDE_OPEN],
        BugType::AuthBypass,
        with(base(), Tamper::Suffix({ let s = base(); vec![lighthouse_ix(&s.open), memo_ix(NONCE_MEMO)] })),
        Tamper::FeePayerInSuffix(0),
        RejectCode::FeePayerNotAuthority,
        None,
    );
    x402_upto_verify_fee_payer_in_memo_reject => reject(
        "x402-upto-verify-fee-payer-in-memo-reject",
        POLICY_FILE,
        spec(SVM, "Top-level instruction layout", "Lighthouse and Memo instructions are allowed only in the optional suffix and MUST NOT reference extra.feePayer as an account or as the invoked program."),
        &[WRAPPER_FEE_PAYER, FEE_PAYER_OUTSIDE_OPEN],
        BugType::AuthBypass,
        base(),
        Tamper::FeePayerInSuffix(0),
        RejectCode::FeePayerNotAuthority,
        None,
    );
    x402_upto_verify_fee_payer_as_program_reject => reject(
        "x402-upto-verify-fee-payer-as-program-reject",
        POLICY_FILE,
        spec(SVM, "Message and signer rules", "Outside the canonical open account positions defined below, extra.feePayer MUST NOT appear in any instruction's account list or as an invoked program."),
        &[FEE_PAYER_OUTSIDE_OPEN, WRAPPER_FEE_PAYER],
        BugType::AuthBypass,
        base(),
        Tamper::FeePayerAsProgram,
        RejectCode::UnexpectedInstruction,
        None,
    );
    x402_upto_verify_route_memo_missing_reject => reject(
        "x402-upto-verify-route-memo-missing-reject",
        POLICY_FILE,
        spec(SVM, "Top-level instruction layout", "If extra.memo is present, the facilitator MUST verify that exactly one Memo instruction exists in the suffix and that its data matches extra.memo encoded as UTF-8."),
        &[MEMO_ENFORCED],
        BugType::AuthBypass,
        VerifySpec::honest(route_bound()),
        Tamper::Suffix(vec![]),
        RejectCode::InvalidPayload,
        None,
    );
    x402_upto_verify_route_memo_mismatch_reject => reject(
        "x402-upto-verify-route-memo-mismatch-reject",
        POLICY_FILE,
        spec(SVM, "Top-level instruction layout", "If extra.memo is present, the facilitator MUST verify that exactly one Memo instruction exists in the suffix and that its data matches extra.memo encoded as UTF-8."),
        &[MEMO_ENFORCED],
        BugType::AuthBypass,
        VerifySpec::honest(route_bound()),
        Tamper::Suffix(vec![memo_ix(NONCE_MEMO)]),
        RejectCode::InvalidPayload,
        None,
    );
    x402_upto_verify_route_memo_twice_reject => reject(
        "x402-upto-verify-route-memo-twice-reject",
        POLICY_FILE,
        spec(SVM, "Top-level instruction layout", "If extra.memo is present, the facilitator MUST verify that exactly one Memo instruction exists in the suffix and that its data matches extra.memo encoded as UTF-8."),
        &[MEMO_ENFORCED],
        BugType::AuthBypass,
        VerifySpec::honest(route_bound()),
        Tamper::Suffix(vec![memo_ix(&route_memo()), memo_ix(&route_memo())]),
        RejectCode::InvalidPayload,
        None,
    );

    // ── open policy: ComputeBudget prefix ──────────────────────────────────
    x402_upto_verify_compute_price_over_cap_reject => reject(
        "x402-upto-verify-compute-price-over-cap-reject",
        POLICY_FILE,
        spec(SVM, "Top-level instruction layout", "MUST set a compute-unit price no greater than 5000000 microlamports per compute unit (5 lamports per compute unit)."),
        &[CB_PRICE, CB_ABSOLUTE],
        BugType::AuthBypass,
        base(),
        Tamper::Prefix(vec![unit_limit_ix(200_000), unit_price_ix(5_000_001)]),
        RejectCode::ComputePriceOverCap,
        None,
    );
    x402_upto_verify_compute_limit_over_cap_reject => reject(
        "x402-upto-verify-compute-limit-over-cap-reject",
        POLICY_FILE,
        spec(SVM, "Top-level instruction layout", "MUST set a compute-unit limit no greater than 400000; and"),
        &[CB_LIMIT, CB_ABSOLUTE],
        BugType::AuthBypass,
        base(),
        Tamper::Prefix(vec![unit_limit_ix(400_001), unit_price_ix(1)]),
        RejectCode::ComputeLimitOverCap,
        None,
    );
    x402_upto_verify_compute_price_before_limit_reject => reject(
        "x402-upto-verify-compute-price-before-limit-reject",
        POLICY_FILE,
        spec(SVM, "Top-level instruction layout", "If both are present, SetComputeUnitLimit MUST precede SetComputeUnitPrice."),
        &[LIMIT_BEFORE_PRICE],
        BugType::Wire,
        base(),
        Tamper::Prefix(vec![unit_price_ix(1), unit_limit_ix(200_000)]),
        RejectCode::UnexpectedInstruction,
        None,
    );
    x402_upto_verify_compute_duplicate_limit_reject => reject(
        "x402-upto-verify-compute-duplicate-limit-reject",
        POLICY_FILE,
        spec(SVM, "Top-level instruction layout", "An optional Compute Budget prefix containing at most one SetComputeUnitLimit instruction and at most one SetComputeUnitPrice instruction."),
        &[LAYOUT],
        BugType::Wire,
        base(),
        Tamper::Prefix(vec![unit_limit_ix(200_000), unit_limit_ix(200_000), unit_price_ix(1)]),
        RejectCode::UnexpectedInstruction,
        None,
    );
    x402_upto_verify_compute_duplicate_price_reject => reject(
        "x402-upto-verify-compute-duplicate-price-reject",
        POLICY_FILE,
        spec(SVM, "Top-level instruction layout", "An optional Compute Budget prefix containing at most one SetComputeUnitLimit instruction and at most one SetComputeUnitPrice instruction."),
        &[LAYOUT],
        BugType::Wire,
        base(),
        Tamper::Prefix(vec![unit_limit_ix(200_000), unit_price_ix(1), unit_price_ix(1)]),
        RejectCode::UnexpectedInstruction,
        None,
    );
    x402_upto_verify_compute_unknown_opcode_reject => reject(
        "x402-upto-verify-compute-unknown-opcode-reject",
        POLICY_FILE,
        s_compute(),
        &[CB_DISCRIMINATOR],
        BugType::Wire,
        base(),
        Tamper::Prefix(vec![unit_limit_ix(200_000), compute_budget({ let mut d = vec![4u8]; d.extend_from_slice(&65_536u32.to_le_bytes()); d })]),
        RejectCode::UnexpectedInstruction,
        None,
    );
    x402_upto_verify_compute_malformed_limit_reject => reject(
        "x402-upto-verify-compute-malformed-limit-reject",
        POLICY_FILE,
        s_compute(),
        &[CB_DISCRIMINATOR],
        BugType::Wire,
        base(),
        Tamper::Prefix(vec![compute_budget(vec![2, 0x40, 0x0d, 0x03, 0x00, 0x00]), unit_price_ix(1)]),
        RejectCode::UnexpectedInstruction,
        None,
    );
    x402_upto_verify_compute_after_open_reject => reject(
        "x402-upto-verify-compute-after-open-reject",
        POLICY_FILE,
        s_layout(),
        &[LAYOUT, ALLOWLIST],
        BugType::Wire,
        base(),
        Tamper::Suffix(vec![memo_ix(NONCE_MEMO), unit_price_ix(1)]),
        RejectCode::UnexpectedInstruction,
        None,
    );

    // ── open policy: the canonical open instruction ────────────────────────
    x402_upto_verify_open_extra_account_reject => reject(
        "x402-upto-verify-open-extra-account-reject",
        POLICY_FILE,
        s_open(),
        &[OPEN_14_ACCOUNTS],
        BugType::AuthBypass,
        base(),
        Tamper::OpenExtraAccount,
        RejectCode::OpenBindingMismatch,
        None,
    );
    x402_upto_verify_open_missing_account_reject => reject(
        "x402-upto-verify-open-missing-account-reject",
        POLICY_FILE,
        s_open(),
        &[OPEN_14_ACCOUNTS],
        BugType::AuthBypass,
        base(),
        Tamper::OpenMissingAccount,
        RejectCode::OpenBindingMismatch,
        None,
    );
    x402_upto_verify_rent_payer_reject => reject(
        "x402-upto-verify-rent-payer-reject",
        POLICY_FILE,
        s_encode(),
        &[OPEN_ENCODES, OPEN_14_ACCOUNTS],
        BugType::AuthBypass,
        base(),
        Tamper::OpenAccount(1, client()),
        RejectCode::OpenBindingMismatch,
        None,
    );
    x402_upto_verify_payee_reject => reject(
        "x402-upto-verify-payee-reject",
        POLICY_FILE,
        s_encode(),
        &[OPEN_ENCODES, OPEN_14_ACCOUNTS],
        BugType::Settlement,
        base(),
        Tamper::OpenAccount(2, keys::pubkey(X402_PAY_TO)),
        RejectCode::OpenBindingMismatch,
        None,
    );
    x402_upto_verify_mint_reject => reject(
        "x402-upto-verify-mint-reject",
        POLICY_FILE,
        s_open(),
        &[OPEN_14_ACCOUNTS, IN_ORDER],
        BugType::Settlement,
        base(),
        Tamper::OpenAccount(3, keys::pubkey(OTHER_MINT)),
        RejectCode::OpenBindingMismatch,
        None,
    );
    x402_upto_verify_open_authorized_signer_reject => reject(
        "x402-upto-verify-open-authorized-signer-reject",
        POLICY_FILE,
        s_encode(),
        &[OPEN_ENCODES, OPEN_14_ACCOUNTS],
        BugType::AuthBypass,
        base(),
        Tamper::OpenAccount(4, keys::pubkey(keys::CLIENT)),
        RejectCode::OpenBindingMismatch,
        None,
    );
    x402_upto_verify_channel_not_derived_reject => reject(
        "x402-upto-verify-channel-not-derived-reject",
        POLICY_FILE,
        s_payload(),
        &[REDERIVE_PDA, FULL_DECODE],
        BugType::AuthBypass,
        base(),
        Tamper::ChannelNotDerived,
        RejectCode::ChannelIdMismatch,
        None,
    );
    x402_upto_verify_payer_token_account_reject => reject(
        "x402-upto-verify-payer-token-account-reject",
        POLICY_FILE,
        s_open(),
        &[OPEN_14_ACCOUNTS],
        BugType::AuthBypass,
        base(),
        Tamper::OpenAccount(6, keys::ata(keys::CLIENT, OTHER_MINT, keys::TOKEN_PROGRAM)),
        RejectCode::OpenBindingMismatch,
        None,
    );
    x402_upto_verify_token_program_reject => reject(
        "x402-upto-verify-token-program-reject",
        POLICY_FILE,
        s_open(),
        &[OPEN_14_ACCOUNTS, IN_ORDER],
        BugType::AuthBypass,
        base(),
        Tamper::OpenAccount(8, keys::pubkey(TOKEN_2022_PROGRAM)),
        RejectCode::OpenBindingMismatch,
        None,
    );
    x402_upto_verify_system_program_reject => reject(
        "x402-upto-verify-system-program-reject",
        POLICY_FILE,
        s_open(),
        &[OPEN_14_ACCOUNTS],
        BugType::AuthBypass,
        base(),
        Tamper::OpenAccount(9, stranger()),
        RejectCode::OpenBindingMismatch,
        None,
    );
    x402_upto_verify_event_authority_reject => reject(
        "x402-upto-verify-event-authority-reject",
        POLICY_FILE,
        s_open(),
        &[OPEN_14_ACCOUNTS],
        BugType::AuthBypass,
        base(),
        Tamper::OpenAccount(12, stranger()),
        RejectCode::OpenBindingMismatch,
        None,
    );
    x402_upto_verify_self_program_reject => reject(
        "x402-upto-verify-self-program-reject",
        POLICY_FILE,
        s_open(),
        &[OPEN_14_ACCOUNTS, CANONICAL_PROGRAM],
        BugType::AuthBypass,
        base(),
        Tamper::OpenAccount(13, stranger()),
        RejectCode::OpenBindingMismatch,
        None,
    );
    x402_upto_verify_writable_mint_reject => reject(
        "x402-upto-verify-writable-mint-reject",
        POLICY_FILE,
        spec(SVM, "Canonical open instruction", "No account outside the writable roles in the table (including an intentional equal-key union) may be writable."),
        &[OPEN_14_ACCOUNTS, PRIVILEGE_UNION],
        BugType::AuthBypass,
        base(),
        Tamper::OpenWritableMint,
        RejectCode::OpenBindingMismatch,
        None,
    );
    x402_upto_verify_deposit_arg_above_reject => reject(
        "x402-upto-verify-deposit-arg-above-reject",
        POLICY_FILE,
        s_encode(),
        &[OPEN_ENCODES, FULL_DECODE, DEPOSIT_EQ_MAX],
        BugType::Settlement,
        base(),
        Tamper::OpenDeposit(1_000_001),
        RejectCode::OpenBindingMismatch,
        None,
    );
    x402_upto_verify_deposit_arg_below_reject => reject(
        "x402-upto-verify-deposit-arg-below-reject",
        POLICY_FILE,
        s_encode(),
        &[OPEN_ENCODES, FULL_DECODE, DEPOSIT_EQ_MAX],
        BugType::Settlement,
        base(),
        Tamper::OpenDeposit(999_999),
        RejectCode::OpenBindingMismatch,
        None,
    );
    x402_upto_verify_grace_period_reject => reject(
        "x402-upto-verify-grace-period-reject",
        POLICY_FILE,
        spec(SVM, "4.1 PaymentRequirements (in PAYMENT-REQUIRED.accepts[])", "The client MUST encode this exact value in open; the facilitator MUST reject any other value."),
        &[WITHDRAW_EXACT, FULL_DECODE],
        BugType::Settlement,
        base(),
        Tamper::OpenGracePeriod(60),
        RejectCode::OpenBindingMismatch,
        None,
    );
    x402_upto_verify_open_slot_arg_reject => reject(
        "x402-upto-verify-open-slot-arg-reject",
        POLICY_FILE,
        s_encode(),
        &[OPEN_ENCODES, FULL_DECODE],
        BugType::AuthBypass,
        base(),
        Tamper::OpenSlotArg(SLOT - 1),
        RejectCode::OpenBindingMismatch,
        None,
    );
    x402_upto_verify_recipient_reject => reject(
        "x402-upto-verify-recipient-reject",
        POLICY_FILE,
        spec(SVM, "4.1 PaymentRequirements (in PAYMENT-REQUIRED.accepts[])", "The channel distribution for upto MUST NOT assign any portion of the settled amount away from payTo."),
        &[NOT_AWAY_FROM_PAY_TO, RECIPIENT_BIND, FULL_DECODE],
        BugType::Settlement,
        base(),
        Tamper::OpenRecipients(vec![(keys::pubkey(keys::X402_OTHER_PAY_TO), 10_000)]),
        RejectCode::OpenBindingMismatch,
        None,
    );
    x402_upto_verify_recipient_bps_reject => reject(
        "x402-upto-verify-recipient-bps-reject",
        POLICY_FILE,
        spec(SVM, "4.1 PaymentRequirements (in PAYMENT-REQUIRED.accepts[])", "The explicit single-entry distribution is REQUIRED in all cases, including when payTo equals extra.receiverAuthorizer or extra.feePayer: the payee implicit remainder MUST be zero so that the facilitator in the payee seat has no claim on settled funds."),
        &[EXPLICIT_DISTRIBUTION, FULL_DECODE],
        BugType::Settlement,
        base(),
        Tamper::OpenRecipients(vec![(keys::pubkey(X402_PAY_TO), 9_999)]),
        RejectCode::OpenBindingMismatch,
        None,
    );
    x402_upto_verify_recipient_split_reject => reject(
        "x402-upto-verify-recipient-split-reject",
        POLICY_FILE,
        spec(SVM, "4.1 PaymentRequirements (in PAYMENT-REQUIRED.accepts[])", "The channel distribution for upto MUST NOT assign any portion of the settled amount away from payTo."),
        &[NOT_AWAY_FROM_PAY_TO, FULL_DECODE],
        BugType::Settlement,
        base(),
        Tamper::OpenRecipients(vec![(keys::pubkey(X402_PAY_TO), 9_000), (keys::pubkey(keys::X402_OTHER_PAY_TO), 1_000)]),
        RejectCode::OpenBindingMismatch,
        None,
    );
    x402_upto_verify_recipient_implicit_reject => reject(
        "x402-upto-verify-recipient-implicit-reject",
        POLICY_FILE,
        spec(SVM, "4.1 PaymentRequirements (in PAYMENT-REQUIRED.accepts[])", "The explicit single-entry distribution is REQUIRED in all cases, including when payTo equals extra.receiverAuthorizer or extra.feePayer: the payee implicit remainder MUST be zero so that the facilitator in the payee seat has no claim on settled funds."),
        &[EXPLICIT_DISTRIBUTION],
        BugType::Settlement,
        base(),
        Tamper::OpenRecipients(vec![]),
        RejectCode::OpenBindingMismatch,
        None,
    );
    x402_upto_verify_open_trailing_byte_reject => reject(
        "x402-upto-verify-open-trailing-byte-reject",
        POLICY_FILE,
        s_decode(),
        &[FULL_DECODE],
        BugType::Malleability,
        base(),
        Tamper::OpenTrailingByte,
        RejectCode::OpenBindingMismatch,
        None,
    );
    x402_upto_verify_open_truncated_reject => reject(
        "x402-upto-verify-open-truncated-reject",
        POLICY_FILE,
        s_decode(),
        &[FULL_DECODE],
        BugType::Malleability,
        base(),
        Tamper::OpenTruncated,
        RejectCode::OpenBindingMismatch,
        None,
    );

    // ── client builds ──────────────────────────────────────────────────────
    x402_upto_build_accept => build_case(
        "x402-upto-build-accept",
        BUILD_FILE,
        spec(SVM, "Phase 1 - Setup", "The client builds an open transaction against the canonical payment-channels program, deposits maxAmount, sets payee and rent_payer to extra.feePayer, sets authorized_signer to extra.receiverAuthorizer, encodes grace_period = extra.withdrawDelay, and signs as channel payer."),
        &[CLIENT_DERIVES, OPEN_ENCODES, EXPLICIT_DISTRIBUTION, WITHDRAW_EXACT],
        "An external-facilitator offer (feePayer != receiverAuthorizer, cold payTo) with the blockhash and recentSlot hints: a version-0 open the Rust verifier accepts, openSlot = recentSlot, deposit = maxAmount = amount, channelId the PDA of the open's own seeds.",
        build_input(Route::default().offer()),
        Expect::Accept(Pin::ExactBytes(vec!["openMessageVersion"])),
        None,
    );
    x402_upto_build_declared_memo => build_case(
        "x402-upto-build-declared-memo",
        BUILD_FILE,
        spec(SVM, "4.1 PaymentRequirements (in PAYMENT-REQUIRED.accepts[])", "When present, the client MUST use this value as the Memo instruction data instead of a random nonce."),
        &[MEMO_DECLARED, CLIENT_MEMO],
        "The offer declares extra.memo: the open carries exactly that memo, once.",
        build_input(route_bound().offer()),
        Expect::Accept(Pin::ExactBytes(vec!["openMessageVersion", "openMemo"])),
        None,
    );
    x402_upto_build_memo_nonce => build_case(
        "x402-upto-build-memo-nonce",
        BUILD_FILE,
        spec(SVM, "Top-level instruction layout", "Clients MUST include a Memo instruction containing either the value of extra.memo (when present) or a random nonce (at least 16 bytes, hex-encoded for UTF-8 compliance)."),
        &[CLIENT_MEMO],
        "The offer declares no memo: the client still emits one Memo carrying a random nonce of at least 16 bytes, hex encoded.",
        build_input(Route::default().offer()),
        Expect::AcceptAuthored(json!({"exactBytes": {"openMemo": "nonce"}})),
        None,
    );
    x402_upto_build_memo_max_length => build_case(
        "x402-upto-build-memo-max-length",
        BUILD_FILE,
        spec(SVM, "4.1 PaymentRequirements (in PAYMENT-REQUIRED.accepts[])", "When present, the client MUST use this value as the Memo instruction data instead of a random nonce."),
        &[MEMO_DECLARED],
        "A 256-byte extra.memo (the stated maximum) is emitted verbatim.",
        build_input(offer_with(|o| o["extra"]["memo"] = json!("m".repeat(256)))),
        Expect::AcceptAuthored(json!({"exactBytes": {"openMemo": "declared"}})),
        None,
    );
    x402_upto_build_memo_too_long_reject => build_case(
        "x402-upto-build-memo-too-long-reject",
        BUILD_FILE,
        spec(SVM, "4.1 PaymentRequirements (in PAYMENT-REQUIRED.accepts[])", "When present, the client MUST use this value as the Memo instruction data instead of a random nonce."),
        &[MEMO_DECLARED],
        "A 257-byte extra.memo exceeds the 256-byte maximum: the client cannot honour the challenge and refuses it.",
        build_input(offer_with(|o| o["extra"]["memo"] = json!("m".repeat(257)))),
        Expect::Reject { code: RejectCode::InvalidChallenge, reason: Some("extra.memo over 256 bytes".into()) },
        None,
    );
    x402_upto_build_pay_to_receiver_authorizer => build_case(
        "x402-upto-build-pay-to-receiver-authorizer",
        BUILD_FILE,
        spec(SVM, "4.1 PaymentRequirements (in PAYMENT-REQUIRED.accepts[])", "The explicit single-entry distribution is REQUIRED in all cases, including when payTo equals extra.receiverAuthorizer or extra.feePayer: the payee implicit remainder MUST be zero so that the facilitator in the payee seat has no claim on settled funds."),
        &[EXPLICIT_DISTRIBUTION],
        "payTo equals extra.receiverAuthorizer: the open still commits the explicit [{ payTo, 10000 }] distribution (the judge compares the open arguments with the kit's).",
        build_input(Route { pay_to: key(RECEIVER_AUTHORIZER_SEED), ..Route::default() }.offer()),
        Expect::Accept(Pin::ExactBytes(vec!["openMessageVersion"])),
        None,
    );
    x402_upto_build_self_facilitated => build_case(
        "x402-upto-build-self-facilitated",
        BUILD_FILE,
        spec(SVM, "4.1 PaymentRequirements (in PAYMENT-REQUIRED.accepts[])", "| feePayer | string | yes | Base58 sponsor key from facilitator /supported. Set as channel payee (zero share) and rent_payer."),
        &[OPEN_ENCODES],
        "The server self-facilitates (feePayer == receiverAuthorizer): one key at open positions 1, 2 and 4.",
        build_input(Route { receiver_authorizer_seed: keys::X402_OFFER_FEE_PAYER_SEED, ..Route::default() }.offer()),
        Expect::Accept(Pin::ExactBytes(vec!["openMessageVersion"])),
        None,
    );
    x402_upto_build_token_2022 => build_case(
        "x402-upto-build-token-2022",
        BUILD_FILE,
        spec(SVM, "Canonical open instruction", "The open instruction MUST invoke the canonical payment-channels program for the selected network, use discriminator 1, contain exactly the following 14 account positions in order, and contain no remaining accounts:"),
        &[OPEN_14_ACCOUNTS],
        "A Token-2022 mint with extra.tokenProgram = Token-2022: both token accounts are derived under Token-2022 and the open names it at position 8.",
        {
            let mut input = build_input(Route { mint: MINT_2022, token_program: TOKEN_2022_PROGRAM, ..Route::default() }.offer());
            input["rpcFixtures"] = fixtures_json(MINT_2022, TOKEN_2022_PROGRAM);
            input
        },
        Expect::Accept(Pin::ExactBytes(vec!["openMessageVersion"])),
        None,
    );
    x402_upto_build_without_slot_hint => build_case(
        "x402-upto-build-without-slot-hint",
        BUILD_FILE,
        spec(SVM, "4.1 PaymentRequirements (in PAYMENT-REQUIRED.accepts[])", "| recentSlot | number | no | Recent slot the client MAY use as openSlot when it does not fetch its own slot."),
        &[CLIENT_DERIVES, OPEN_ENCODES],
        "The offer omits extra.recentSlot: the client reads the slot from its RPC (the fixture's slot) and binds openSlot, the open argument and the PDA to it.",
        build_input(offer_with(|o| { o["extra"].as_object_mut().unwrap().remove("recentSlot"); })),
        Expect::Accept(Pin::ExactBytes(vec!["openMessageVersion"])),
        None,
    );
    x402_upto_build_recent_slot_number => build_case(
        "x402-upto-build-recent-slot-number",
        BUILD_FILE,
        spec(SVM, "4.1 PaymentRequirements (in PAYMENT-REQUIRED.accepts[])", "| recentSlot | number | no | Recent slot the client MAY use as openSlot when it does not fetch its own slot."),
        &[CLIENT_DERIVES],
        "extra.recentSlot as the JSON number the pinned table and its examples use (\"recentSlot\": 341000000): the client builds the open (RULINGS.md U1).",
        build_input(offer_with(|o| o["extra"]["recentSlot"] = json!(SLOT))),
        Expect::AcceptAuthored(json!({"exactBytes": {"openMessageVersion": 0}})),
        None,
    );
    x402_upto_build_zero_withdraw_delay_reject => build_case(
        "x402-upto-build-zero-withdraw-delay-reject",
        BUILD_FILE,
        spec(SVM, "4.1 PaymentRequirements (in PAYMENT-REQUIRED.accepts[])", "MUST be an integer greater than zero."),
        &[WITHDRAW_POSITIVE],
        "extra.withdrawDelay 0 is outside the scheme: the client refuses the challenge instead of opening a channel with no escape-hatch delay.",
        build_input(offer_with(|o| o["extra"]["withdrawDelay"] = json!(0))),
        Expect::Reject { code: RejectCode::InvalidChallenge, reason: None },
        None,
    );
    x402_upto_build_fractional_withdraw_delay_reject => build_case(
        "x402-upto-build-fractional-withdraw-delay-reject",
        BUILD_FILE,
        spec(SVM, "4.1 PaymentRequirements (in PAYMENT-REQUIRED.accepts[])", "MUST be an integer greater than zero."),
        &[WITHDRAW_POSITIVE],
        "extra.withdrawDelay 900.5 is not an integer: the client refuses the challenge.",
        build_input(offer_with(|o| o["extra"]["withdrawDelay"] = json!(900.5))),
        Expect::Reject { code: RejectCode::InvalidChallenge, reason: None },
        None,
    );
    x402_upto_build_missing_fee_payer_reject => build_case(
        "x402-upto-build-missing-fee-payer-reject",
        BUILD_FILE,
        spec(SVM, "4.1 PaymentRequirements (in PAYMENT-REQUIRED.accepts[])", "| feePayer | string | yes | Base58 sponsor key from facilitator /supported. Set as channel payee (zero share) and rent_payer."),
        &[OPEN_ENCODES],
        "extra.feePayer is absent: no payee, rent payer or transaction fee payer can be derived; the client refuses the challenge.",
        build_input(offer_with(|o| { o["extra"].as_object_mut().unwrap().remove("feePayer"); })),
        Expect::Reject { code: RejectCode::InvalidChallenge, reason: None },
        None,
    );
    x402_upto_build_missing_receiver_authorizer_reject => build_case(
        "x402-upto-build-missing-receiver-authorizer-reject",
        BUILD_FILE,
        spec(SVM, "4.1 PaymentRequirements (in PAYMENT-REQUIRED.accepts[])", "| receiverAuthorizer | string | yes | Server-defined Base58 key, or the facilitator's /supported receiverAuthorizer when the server delegates. Set as channel authorized_signer; signs settlement vouchers. |"),
        &[OPEN_ENCODES, AUTHORIZED_SIGNER],
        "extra.receiverAuthorizer is absent: the channel's authorized signer cannot be set; the client refuses the challenge.",
        build_input(offer_with(|o| { o["extra"].as_object_mut().unwrap().remove("receiverAuthorizer"); })),
        Expect::Reject { code: RejectCode::InvalidChallenge, reason: None },
        None,
    );

    // ── transaction versions (SIMD-0385) ───────────────────────────────────
    x402_upto_build_v0_when_unadvertised => build_case(
        "x402-upto-build-v0-when-unadvertised",
        TXV1_FILE,
        s_txv1(),
        &[TV_CLIENT, TV_LEGACY],
        "No extra.transactionVersions: the accepted set is [0], so the client builds a version-0 open (never legacy).",
        build_input(Route::default().offer()),
        Expect::Accept(Pin::ExactBytes(vec!["openMessageVersion"])),
        None,
    );
    x402_upto_build_v1_when_advertised => build_case(
        "x402-upto-build-v1-when-advertised",
        TXV1_FILE,
        s_txv1(),
        &[TV_CLIENT, TV_V1_BUDGET, TV_OPEN_VERSION],
        "extra.transactionVersions [0, 1] and a signer that signs version 1: the client builds the highest version, a version-1 open whose compute budget rides in the message config (no ComputeBudget instructions).",
        build_input(v1_route().offer()),
        Expect::Accept(Pin::ExactBytes(vec!["openMessageVersion", "openComputeBudget"])),
        None,
    );
    x402_upto_build_v0_for_v0_signer => build_case(
        "x402-upto-build-v0-for-v0-signer",
        TXV1_FILE,
        s_txv1(),
        &[TV_CLIENT],
        "extra.transactionVersions [0, 1] but the signer signs up to version 0: the intersection is [0], a version-0 open.",
        { let mut i = build_input(v1_route().offer()); i["x402ClientMaxTransactionVersion"] = json!(0); i },
        Expect::Accept(Pin::ExactBytes(vec!["openMessageVersion"])),
        None,
    );
    x402_upto_build_no_common_version_reject => build_case(
        "x402-upto-build-no-common-version-reject",
        TXV1_FILE,
        spec(TXV1, "Transaction versions", "It MUST fail with unsupported_transaction_version when the intersection is empty."),
        &[TV_CLIENT_EMPTY],
        "extra.transactionVersions [1] and a signer that signs up to version 0: no version is buildable, the client fails with unsupported_transaction_version.",
        { let mut i = build_input(Route { versions: Some(vec![1]), ..Route::default() }.offer()); i["x402ClientMaxTransactionVersion"] = json!(0); i },
        Expect::Reject { code: RejectCode::UnsupportedVersion, reason: None },
        None,
    );
    x402_upto_verify_v1_accept => accept(
        "x402-upto-verify-v1-accept",
        TXV1_FILE,
        spec(TXV1, "Message and signer rules", "The message version MUST be one advertised in extra.transactionVersions (0 when the field is absent; see [Transaction versions](#transaction-versions)), and the message MUST NOT contain Address Lookup Table lookups."),
        &[TV_MESSAGE, TV_OPEN_VERSION, TV_NO_PREFIX],
        "The server accepts [0, 1]: a version-1 open (header compute budget 200000 units, 1 lamport priority fee, the maximum loaded-data limit; no ComputeBudget prefix) passes the same policy.",
        with(VerifySpec::honest(v1_route()), Tamper::Form(Form::v1())),
    );
    x402_upto_verify_v1_unadvertised_reject => reject(
        "x402-upto-verify-v1-unadvertised-reject",
        TXV1_FILE,
        s_txv1_reject(),
        &[TV_REJECT_FIRST, TV_MESSAGE],
        BugType::Wire,
        base(),
        Tamper::Form(Form::v1()),
        RejectCode::UnsupportedVersion,
        None,
    );
    x402_upto_verify_v1_unadvertised_before_layout_reject => reject(
        "x402-upto-verify-v1-unadvertised-before-layout-reject",
        TXV1_FILE,
        s_txv1_reject(),
        &[TV_REJECT_FIRST],
        BugType::Wire,
        with(base(), Tamper::Suffix(vec![memo_ix(NONCE_MEMO), solana_instruction::Instruction { program_id: keys::pubkey(keys::SPLIT_RECIPIENT_2), accounts: vec![], data: vec![1] }])),
        Tamper::Form(Form::v1()),
        RejectCode::UnsupportedVersion,
        None,
    );
    x402_upto_verify_v1_compute_budget_instruction_reject => reject(
        "x402-upto-verify-v1-compute-budget-instruction-reject",
        TXV1_FILE,
        spec(TXV1, "Top-level instruction layout", "A version-1 transaction that contains a Compute Budget instruction MUST be rejected."),
        &[TV_V1_NO_CB, TV_NO_PREFIX],
        BugType::Wire,
        with(VerifySpec::honest(v1_route()), Tamper::Form(Form::v1())),
        Tamper::Prefix(vec![unit_limit_ix(200_000)]),
        RejectCode::UnexpectedInstruction,
        None,
    );
    x402_upto_verify_v1_limit_over_cap_reject => verify_case(
        "x402-upto-verify-v1-limit-over-cap-reject",
        TXV1_FILE,
        s_txv1_budget(),
        &[TV_V1_CAPS],
        BugType::AuthBypass,
        "A version-1 open whose header computeUnitLimit is 400001: rejected as compute-limit-over-cap.",
        with(VerifySpec::honest(v1_route()), Tamper::Form(Form::V1 { unit_limit: Some(400_001), priority_fee_lamports: Some(1), loaded_accounts_data_size_limit: Some(64 * 1024 * 1024) })),
        Expect::Reject { code: RejectCode::ComputeLimitOverCap, reason: None },
        None,
    );
    x402_upto_verify_v1_priority_fee_over_cap_reject => verify_case(
        "x402-upto-verify-v1-priority-fee-over-cap-reject",
        TXV1_FILE,
        s_txv1_budget(),
        &[TV_V1_CAPS],
        BugType::AuthBypass,
        "A version-1 open at 200000 units with priorityFee 1000001 lamports (priorityFee * 1000000 > 5000000 * computeUnitLimit): rejected as compute-price-over-cap.",
        with(VerifySpec::honest(v1_route()), Tamper::Form(Form::V1 { unit_limit: Some(200_000), priority_fee_lamports: Some(1_000_001), loaded_accounts_data_size_limit: Some(64 * 1024 * 1024) })),
        Expect::Reject { code: RejectCode::ComputePriceOverCap, reason: None },
        None,
    );
    x402_upto_verify_v1_priority_fee_at_cap_accept => accept(
        "x402-upto-verify-v1-priority-fee-at-cap-accept",
        TXV1_FILE,
        s_txv1_budget(),
        &[TV_V1_CAPS],
        "A version-1 open at 200000 units with priorityFee 1000000 lamports: exactly 5000000 micro-lamports per unit, accepted.",
        with(VerifySpec::honest(v1_route()), Tamper::Form(Form::V1 { unit_limit: Some(200_000), priority_fee_lamports: Some(1_000_000), loaded_accounts_data_size_limit: Some(64 * 1024 * 1024) })),
    );
    x402_upto_verify_v1_missing_limit_reject => verify_case(
        "x402-upto-verify-v1-missing-limit-reject",
        TXV1_FILE,
        s_txv1_budget(),
        &[TV_V1_CAPS, TV_V1_BUDGET],
        BugType::Defaults,
        "A version-1 open whose header omits computeUnitLimit (budgeted zero, it cannot execute after the fee is charged): rejected as invalid-payload.",
        with(VerifySpec::honest(v1_route()), Tamper::Form(Form::V1 { unit_limit: None, priority_fee_lamports: Some(1), loaded_accounts_data_size_limit: Some(64 * 1024 * 1024) })),
        Expect::Reject { code: RejectCode::InvalidPayload, reason: None },
        None,
    );
    x402_upto_verify_v1_missing_loaded_limit_reject => verify_case(
        "x402-upto-verify-v1-missing-loaded-limit-reject",
        TXV1_FILE,
        s_txv1_budget(),
        &[TV_V1_CAPS, TV_V1_BUDGET],
        BugType::Defaults,
        "A version-1 open whose header omits loadedAccountsDataSizeLimit: rejected as invalid-payload.",
        with(VerifySpec::honest(v1_route()), Tamper::Form(Form::V1 { unit_limit: Some(200_000), priority_fee_lamports: Some(1), loaded_accounts_data_size_limit: None })),
        Expect::Reject { code: RejectCode::InvalidPayload, reason: None },
        None,
    );
    x402_upto_verify_v1_small_loaded_limit_accept => accept_lenient(
        "x402-upto-verify-v1-small-loaded-limit-accept",
        TXV1_FILE,
        s_txv1_budget(),
        &[TV_V1_CAPS],
        "A version-1 open whose loadedAccountsDataSizeLimit is present but below the runtime maximum (1 MiB): the spec requires presence only, so it is accepted.",
        with(VerifySpec::honest(v1_route()), Tamper::Form(Form::V1 { unit_limit: Some(200_000), priority_fee_lamports: Some(1), loaded_accounts_data_size_limit: Some(1024 * 1024) })),
    );
    x402_upto_verify_v0_oversize_reject => verify_case(
        "x402-upto-verify-v0-oversize-reject",
        TXV1_FILE,
        spec(TXV1, "Transaction versions", "A legacy or version-0 transaction MUST NOT exceed 1232 serialized bytes; a version-1 transaction MUST NOT exceed 4096 serialized bytes."),
        &[TV_SIZE],
        BugType::Wire,
        "A version-0 open padded with a 1000-byte memo (no memo declared) serializes above 1232 bytes: rejected as invalid-payload.",
        with(base(), Tamper::Suffix(vec![memo_ix(&"a".repeat(1000))])),
        Expect::Reject { code: RejectCode::InvalidPayload, reason: Some("serialized above 1232 bytes".into()) },
        None,
    );
    x402_upto_verify_v1_large_accept => accept(
        "x402-upto-verify-v1-large-accept",
        TXV1_FILE,
        spec(TXV1, "Transaction versions", "A legacy or version-0 transaction MUST NOT exceed 1232 serialized bytes; a version-1 transaction MUST NOT exceed 4096 serialized bytes."),
        &[TV_SIZE],
        "The same 1000-byte memo in a version-1 open stays under 4096 bytes and is accepted where the server accepts version 1.",
        with(with(VerifySpec::honest(v1_route()), Tamper::Form(Form::v1())), Tamper::Suffix(vec![memo_ix(&"a".repeat(1000))])),
    );
    x402_upto_verify_v1_oversize_reject => verify_case(
        "x402-upto-verify-v1-oversize-reject",
        TXV1_FILE,
        spec(TXV1, "Transaction versions", "A legacy or version-0 transaction MUST NOT exceed 1232 serialized bytes; a version-1 transaction MUST NOT exceed 4096 serialized bytes."),
        &[TV_SIZE],
        BugType::Wire,
        "A version-1 open padded with a 3900-byte memo serializes above 4096 bytes: rejected as invalid-payload.",
        with(with(VerifySpec::honest(v1_route()), Tamper::Form(Form::v1())), Tamper::Suffix(vec![memo_ix(&"a".repeat(3900))])),
        Expect::Reject { code: RejectCode::InvalidPayload, reason: Some("serialized above 4096 bytes".into()) },
        None,
    );
}

/// The honest header with `payload.openTransaction` removed.
fn header_without_open(spec: &VerifySpec) -> String {
    use base64::Engine;
    let input = spec.input().unwrap();
    let header = input["x402PaymentHeader"].as_str().unwrap();
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(header)
        .unwrap();
    let mut envelope: Value = serde_json::from_slice(&bytes).unwrap();
    envelope["payload"]
        .as_object_mut()
        .unwrap()
        .remove("openTransaction");
    base64::engine::general_purpose::STANDARD.encode(envelope.to_string())
}
