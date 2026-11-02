//! Subscription cases (MPP `subscription` intent, Solana method draft
//! `draft-solana-subscription-00`): bearer-proof bytes, period mapping, PDA
//! and instruction layouts, wire shapes, the client's activation build, the
//! server's activation verification up to the broadcast, the on-chain
//! usability check at a pinned clock, and bearer-proof verification.

use serde_json::{json, Value};

use super::client_secret;
use crate::case::{
    spec, BugType, CaseBuilder, Expect, Input, Intent, Mode, Pin, RejectCode, Role, SpecRef, Suite,
};
use crate::keys::{self, TOKEN_2022_PROGRAM, TOKEN_PROGRAM};
use crate::realize::subscription::fx::{self, DelegationSpec, PlanSpec};
use crate::realize::subscription::{proof, Activation, AuthEdit, PayloadEdit, TxEdit};

const SOL: &str = "mpp-specs-solana/specs/methods/solana/draft-solana-subscription-00.md";
const INTENT: &str = "mpp-specs/specs/intents/draft-payment-intent-subscription-00.md";

const CANONICAL: &str = "subscription-canonical.json";
const WIRE: &str = "subscription-wire.json";
const BUILD: &str = "subscription-build.json";
const VERIFY: &str = "subscription-verify.json";
const ACTIVE: &str = "subscription-active.json";
const PROOF: &str = "subscription-proof.json";

// Requirement ids (`pkc req-lint --list mpp-solana|mpp`).
const R_JCS: &str = "MPP-42cf63c8b8";
const R_RECIPIENT_REQUIRED: &str = "MPP-2bbba2b551";
const R_DAY_OR_WEEK: &str = "MPP-cdbcb3a843";
const R_AMOUNT_FORMAT: &str = "MPP-6739698bb1";
const R_LEADING_ZEROS: &str = "MPP-95dab3a64d";
const R_PERIOD_COUNT_FORMAT: &str = "MPP-aadffadc90";
const R_REJECT_MONTH: &str = "MPP-d063521350";
const R_INTERVAL_RANGE: &str = "MPP-58828c88cd";
const R_CURRENCY_IS_MINT: &str = "MPP-5d14dd20cb";
const R_PLAN_MINT: &str = "MPP-4a98642d3c";
const R_DECIMALS_REQUIRED: &str = "MPP-60413f3bf6";
const R_TOKEN_PROGRAM: &str = "MPP-634239a4f5";
const R_PULLER_REQUIRED: &str = "MPP-463ea35304";
const R_PULLER_AUTHORIZED: &str = "MPP-327d9b66ba";
const R_PLAN_ADDRESS: &str = "MPP-7ebd75eefc";
const R_FEE_PAYER_KEY: &str = "MPP-f90bd07116";
const R_PROGRAM_PINNED: &str = "MPP-12c23b8418";
const R_ONE_DESTINATION: &str = "MPP-1d44630921";
const R_REJECT_DESTINATIONS: &str = "MPP-fc9334823a";
const R_TYPE_TRANSACTION: &str = "MPP-45b8ba4317";
const R_TRANSACTION_REQUIRED: &str = "MPP-98987d4454";
const R_AUTHENTICATION_REQUIRED: &str = "MPP-52f835b76c";
const R_TYPE_PROOF: &str = "MPP-9edde7b556";
const R_ACTIVATION_PROOF: &str = "MPP-ef1bb057fc";
const R_VERIFY_PROOF: &str = "MPP-dcaa3d63c8";
const R_ACTIVATION_MUST: &str = "MPP-11cddfe4f2";
const R_ACTIVATION_MUST_NOT: &str = "MPP-8a193ab322";
const R_ON_RECEIVE: &str = "MPP-9255227955";
const R_EXPIRES_SETTLES: &str = "MPP-e0965cb0fe";
const R_SOURCE: &str = "MPP-0e0da9c6a6";
const R_PAYER_FROM_TX: &str = "MPP-afd07e174b";
const R_SCOPE: &str = "MPP-89be025a89";
const R_BROADER_SCOPE: &str = "MPP-449b853cb2";
const R_LATER_ACCESS: &str = "MPP-0a7c7d7791";
const R_RECHECK: &str = "MPP-1ec64dcbc6";
const R_OWNER_FIRST: &str = "MPP-b87a0cd7d3";
const R_CLIENT_VERIFY: &str = "MPP-4a9406cfcb";
const R_PLAN_MATCHES: &str = "MPP-62866c1462";
const R_DESTINATION_SCOPING: &str = "MPP-83bfc235ab";
const R_CANCELLED: &str = "MPP-9dab72f223";
const R_SHARED_FIELDS: &str = "MPP-c1bffbb1a3";
const R_REPRESENT_EXACTLY: &str = "MPP-3688fa68c7";
const R_BINDING: &str = "MPP-5a84bf0d0b";

fn proof_spec() -> SpecRef {
    spec(
        SOL,
        "Subscription Bearer Proof",
        "The client signs the UTF-8 bytes of the JCS serialization with the Ed25519 private key corresponding to payer.",
    )
}

fn period_spec() -> SpecRef {
    spec(
        SOL,
        "Optional Fields",
        "Servers MUST reject request objects where the mapped per-billing- period interval is zero or exceeds 8760 hours.",
    )
}

fn count_spec() -> SpecRef {
    spec(
        SOL,
        "Optional Fields",
        "The periodCount value MUST be a string representation of a positive integer in base 10 with no sign, decimal point, exponent, or surrounding whitespace.",
    )
}

fn delegation_pda_spec() -> SpecRef {
    spec(
        SOL,
        "Terminology",
        "Derived from [\"subscription\", plan_pda, subscriber].",
    )
}

fn authority_pda_spec() -> SpecRef {
    spec(
        SOL,
        "Terminology",
        "Derived from [\"SubscriptionAuthority\", subscriber, mint].",
    )
}

fn activation_spec() -> SpecRef {
    spec(
        SOL,
        "Subscription Bearer Proof",
        "The subscriber-signed activation transaction MUST:",
    )
}

fn scope_spec(quote: &str) -> SpecRef {
    spec(SOL, "Authorization Scope Verification", quote)
}

fn client_verify_spec(quote: &str) -> SpecRef {
    spec(SOL, "Amount and Period Verification", quote)
}

fn canonical_case(
    id: &str,
    file: &'static str,
    bug: BugType,
    spec: SpecRef,
    description: &str,
    input: Value,
    expect: Expect,
) -> CaseBuilder {
    CaseBuilder::new(
        id,
        file,
        Suite::Subscription,
        Intent::Subscription,
        Mode::CanonicalBytes,
        Role::Both,
        bug,
        spec,
        description,
        Input::Static(input),
        expect,
    )
}

fn reject(code: RejectCode, reason: &str) -> Expect {
    Expect::Reject {
        code,
        reason: Some(reason.into()),
    }
}

fn json_bytes() -> Expect {
    Expect::Accept(Pin::ExactBytes(vec!["canonicalJson", "base64Url"]))
}

fn period(unit: &str, count: &str) -> Value {
    json!({ "subscriptionPeriod": { "periodUnit": unit, "periodCount": count } })
}

// ── build inputs ───────────────────────────────────────────────────────────

fn build_input(request: Value, chain: Value) -> Value {
    json!({
        "signerSecretKey": client_secret(),
        "subscriptionChallenge": {
            "id": fx::CHALLENGE_ID,
            "realm": fx::REALM,
            "method": "solana",
            "intent": "subscription",
            "expires": fx::rfc3339(fx::NOW + 300),
            "request": request,
        },
        "rpcFixtures": chain,
    })
}

fn default_chain() -> Value {
    fx::chain(&PlanSpec::default(), fx::PROGRAM, TOKEN_PROGRAM)
}

/// The kit-shaped request (spec fields plus the kit's methodDetails
/// extensions) with `edit` applied to the decoded JSON.
fn kit_request(edit: impl FnOnce(&mut Value)) -> Value {
    let mut request = fx::with_kit_extensions(fx::request());
    edit(&mut request);
    request
}

fn build_case(
    id: &str,
    description: &str,
    spec: SpecRef,
    input: Value,
    expect: Expect,
) -> CaseBuilder {
    CaseBuilder::new(
        id,
        BUILD,
        Suite::Subscription,
        Intent::Subscription,
        Mode::BuildTransaction,
        Role::Client,
        BugType::AuthBypass,
        spec,
        description,
        Input::Static(input),
        expect,
    )
}

fn build_reject(id: &str, description: &str, spec: SpecRef, input: Value) -> CaseBuilder {
    build_case(
        id,
        description,
        spec,
        input,
        reject(
            RejectCode::InvalidChallenge,
            "the client must refuse to sign this challenge",
        ),
    )
}

/// The chain an attacker-controlled program presents: the Plan and the
/// subscriber's authority exist and are owned by that program, so only the
/// client's program pin can refuse the challenge.
fn untrusted_program_chain() -> Value {
    let mut chain = fx::chain(&PlanSpec::default(), fx::FOREIGN_PROGRAM, TOKEN_PROGRAM);
    let authority = solana_pay_kit::mpp::program::subscriptions::find_subscription_authority_pda(
        &keys::pubkey(fx::SUBSCRIBER),
        &keys::pubkey(fx::MINT),
        &keys::pubkey(fx::FOREIGN_PROGRAM),
    )
    .0
    .to_string();
    let mut account = fx::authority_account(fx::SUBSCRIBER, fx::MINT, fx::INIT_ID);
    account["owner"] = json!(fx::FOREIGN_PROGRAM);
    chain["accounts"][authority] = account;
    chain
}

fn plan_chain(plan: PlanSpec) -> Value {
    fx::chain(&plan, fx::PROGRAM, TOKEN_PROGRAM)
}

// ── verify inputs ──────────────────────────────────────────────────────────

fn verify_case(
    id: &str,
    description: &str,
    bug: BugType,
    spec: SpecRef,
    activation: Activation,
    expect: Expect,
) -> CaseBuilder {
    CaseBuilder::new(
        id,
        VERIFY,
        Suite::Subscription,
        Intent::Subscription,
        Mode::VerifyTransaction,
        Role::Server,
        bug,
        spec,
        description,
        activation.recipe(),
        expect,
    )
}

fn tx_reject(id: &str, description: &str, spec: SpecRef, edit: TxEdit) -> CaseBuilder {
    let code = edit.expected();
    let reason = edit.describe();
    verify_case(
        id,
        description,
        BugType::AuthBypass,
        spec,
        Activation::new().tx(edit),
        reject(code, &reason),
    )
}

fn active_input(
    delegation: Option<(DelegationSpec, &str)>,
    authority: Option<(i64, &str)>,
) -> Value {
    let mut accounts = serde_json::Map::new();
    if let Some((spec, owner)) = delegation {
        accounts.insert(fx::delegation(), fx::delegation_account(&spec, owner));
    }
    if let Some((init_id, owner)) = authority {
        let mut account = fx::authority_account(fx::SUBSCRIBER, fx::MINT, init_id);
        account["owner"] = json!(owner);
        accounts.insert(fx::authority_of(fx::SUBSCRIBER, fx::MINT), account);
    }
    json!({
        "nowSeconds": fx::NOW,
        "subscriptionServer": fx::server(),
        "subscriptionActive": { "subscriber": fx::SUBSCRIBER, "amount": fx::AMOUNT },
        "rpcFixtures": { "recentBlockhash": fx::BLOCKHASH, "accounts": accounts },
    })
}

fn live() -> Option<(DelegationSpec, &'static str)> {
    Some((DelegationSpec::default(), fx::PROGRAM))
}

fn current_authority() -> Option<(i64, &'static str)> {
    Some((fx::INIT_ID, fx::PROGRAM))
}

fn active_case(
    id: &str,
    description: &str,
    spec: SpecRef,
    input: Value,
    expect: Expect,
) -> CaseBuilder {
    CaseBuilder::new(
        id,
        ACTIVE,
        Suite::Subscription,
        Intent::Subscription,
        Mode::VerifyTransaction,
        Role::Server,
        BugType::Settlement,
        spec,
        description,
        Input::Static(input),
        expect,
    )
}

fn usable_spec() -> SpecRef {
    spec(
        SOL,
        "Server Accounting and Idempotency",
        "Verify the subscription is still usable by reading delegation.expires_at_ts on-chain; a non-zero timestamp only blocks renewal once the current time is at or after that timestamp.",
    )
}

fn inactive() -> Expect {
    reject(
        RejectCode::SubscriptionInactive,
        "the on-chain subscription is not usable at the pinned clock",
    )
}

fn proof_case(
    id: &str,
    description: &str,
    authentication: Value,
    delegation: String,
    expect: Expect,
) -> CaseBuilder {
    CaseBuilder::new(
        id,
        PROOF,
        Suite::Subscription,
        Intent::Subscription,
        Mode::VerifyTransaction,
        Role::Server,
        BugType::AuthBypass,
        spec(
            SOL,
            "Subscription Bearer Proof",
            "the Ed25519 signature verifies over the exact JCS object above.",
        ),
        description,
        Input::Static(json!({
            "subscriptionProof": {
                "authentication": authentication,
                "subscriptionDelegation": delegation,
            }
        })),
        expect,
    )
}

fn proof_rejected() -> Expect {
    reject(
        RejectCode::AuthenticationInvalid,
        "the proof does not verify for this delegation",
    )
}

fn spec_example_request() -> Value {
    json!({
        "amount": "10000000",
        "currency": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
        "periodUnit": "day",
        "periodCount": "30",
        "subscriptionExpires": "2026-07-14T12:00:00Z",
        "recipient": "9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin",
        "description": "Monthly Pro plan",
        "externalId": "merchant-subscription-270",
        "methodDetails": {
            "subscriptionProgram": "De1egAFMkMWZSN5rYXRj9CAdheBamobVNubTsi9avR44",
            "planAddress": "8tWbqLkUJoYy7zXc5h2EvCRoaQEv2xnQjUuYhc3rzCgT",
            "mint": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
            "tokenProgram": "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
            "decimals": 6,
            "puller": "5fKb5cF22cFybZB1H4hLDydFhwoQy9JzKzRWaSbMkB6h",
            "network": "mainnet",
            "feePayer": true,
            "feePayerKey": "5fKb5cF22cFybZB1H4hLDydFhwoQy9JzKzRWaSbMkB6h"
        }
    })
}

fn sample_authentication() -> Value {
    proof(keys::CLIENT_SEED, fx::CHALLENGE_ID, &fx::delegation())
}

crate::registry! {
    // ── canonical bytes: bearer-proof message ──────────────────────────────
    subscription_auth_message_frozen => canonical_case(
        "subscription-auth-message-frozen",
        CANONICAL,
        BugType::Wire,
        proof_spec(),
        "Bearer-proof preimage: the JCS object {domain: \"mpp-subscription-auth-v1\", payer, subscriptionChallengeId, subscriptionDelegation}, UTF-8, keys sorted, no whitespace. Frozen byte for byte: a renamed key, a different domain string or a non-canonical serialization signs different bytes, and a proof from one SDK stops verifying in another.",
        json!({ "subscriptionAuthenticationMessage": {
            "challengeId": fx::CHALLENGE_ID,
            "payer": fx::SUBSCRIBER,
            "subscriptionDelegation": fx::delegation(),
        }}),
        json_bytes(),
    )
    .requirements(&[R_ACTIVATION_PROOF])
    .build();
    subscription_auth_message_other_challenge => canonical_case(
        "subscription-auth-message-other-challenge",
        CANONICAL,
        BugType::Wire,
        proof_spec(),
        "Bearer-proof preimage for another activation challenge id and delegation: the challenge id is signed as subscriptionChallengeId (not challengeId), so a proof for one activation never verifies for another.",
        json!({ "subscriptionAuthenticationMessage": {
            "challengeId": "c3ViX3NvbGFuYV8wMQ",
            "payer": fx::stranger(),
            "subscriptionDelegation": fx::delegation_of(&fx::plan(), &fx::stranger()),
        }}),
        json_bytes(),
    )
    .requirements(&[R_ACTIVATION_PROOF])
    .build();

    // ── canonical bytes: period mapping ────────────────────────────────────
    subscription_period_day_1 => canonical_case(
        "subscription-period-day-1",
        CANONICAL,
        BugType::Wire,
        period_spec(),
        "periodUnit=day, periodCount=1 maps to 24 period_hours (periodCount * 24).",
        period("day", "1"),
        json_bytes(),
    )
    .requirements(&[R_INTERVAL_RANGE])
    .build();
    subscription_period_day_30 => canonical_case(
        "subscription-period-day-30",
        CANONICAL,
        BugType::Wire,
        period_spec(),
        "periodUnit=day, periodCount=30 maps to 720 period_hours.",
        period("day", "30"),
        json_bytes(),
    )
    .requirements(&[R_INTERVAL_RANGE])
    .build();
    subscription_period_day_365_upper_bound => canonical_case(
        "subscription-period-day-365-upper-bound",
        CANONICAL,
        BugType::Wire,
        period_spec(),
        "periodUnit=day, periodCount=365 maps to 8760 period_hours, the largest interval the profile accepts.",
        period("day", "365"),
        json_bytes(),
    )
    .requirements(&[R_INTERVAL_RANGE])
    .build();
    subscription_period_week_1 => canonical_case(
        "subscription-period-week-1",
        CANONICAL,
        BugType::Wire,
        period_spec(),
        "periodUnit=week, periodCount=1 maps to 168 period_hours (periodCount * 168).",
        period("week", "1"),
        json_bytes(),
    )
    .requirements(&[R_INTERVAL_RANGE])
    .build();
    subscription_period_week_52 => canonical_case(
        "subscription-period-week-52",
        CANONICAL,
        BugType::Wire,
        period_spec(),
        "periodUnit=week, periodCount=52 maps to 8736 period_hours, the largest week count within 8760 hours.",
        period("week", "52"),
        json_bytes(),
    )
    .requirements(&[R_INTERVAL_RANGE])
    .build();
    subscription_period_day_366_reject => canonical_case(
        "subscription-period-day-366-reject",
        CANONICAL,
        BugType::Wire,
        period_spec(),
        "periodUnit=day, periodCount=366 maps to 8784 hours, over the 8760-hour limit: the request must be rejected, not clamped.",
        period("day", "366"),
        reject(RejectCode::InvalidChallenge, "mapped interval exceeds 8760 hours"),
    )
    .requirements(&[R_INTERVAL_RANGE])
    .build();
    subscription_period_week_53_reject => canonical_case(
        "subscription-period-week-53-reject",
        CANONICAL,
        BugType::Wire,
        period_spec(),
        "periodUnit=week, periodCount=53 maps to 8904 hours, over the 8760-hour limit.",
        period("week", "53"),
        reject(RejectCode::InvalidChallenge, "mapped interval exceeds 8760 hours"),
    )
    .requirements(&[R_INTERVAL_RANGE])
    .build();
    subscription_period_count_zero_reject => canonical_case(
        "subscription-period-count-zero-reject",
        CANONICAL,
        BugType::Wire,
        count_spec(),
        "periodCount=0 is not a positive integer (and maps to a zero interval).",
        period("day", "0"),
        reject(RejectCode::InvalidChallenge, "periodCount must be positive"),
    )
    .requirements(&[R_PERIOD_COUNT_FORMAT, R_INTERVAL_RANGE])
    .build();
    subscription_period_month_reject => canonical_case(
        "subscription-period-month-reject",
        CANONICAL,
        BugType::Wire,
        spec(SOL, "Optional Fields", "Servers MUST reject periodUnit=\"month\"."),
        "periodUnit=month cannot be represented by fixed elapsed-time delegations; the Solana profile rejects it rather than approximating 30 or 31 days.",
        period("month", "1"),
        reject(RejectCode::InvalidChallenge, "month is not representable"),
    )
    .requirements(&[R_REJECT_MONTH, R_DAY_OR_WEEK])
    .build();
    subscription_period_count_leading_zero_reject => canonical_case(
        "subscription-period-count-leading-zero-reject",
        CANONICAL,
        BugType::Malleability,
        count_spec(),
        "periodCount=\"030\" uses a leading zero, which the profile forbids. Accepting it makes two encodings of one cadence, so a challenge's canonical bytes (and HMAC) are no longer unique for its terms.",
        period("day", "030"),
        reject(RejectCode::InvalidChallenge, "leading zero in periodCount"),
    )
    .requirements(&[R_PERIOD_COUNT_FORMAT, R_LEADING_ZEROS])
    .authored(None)
    .build();
    subscription_period_count_sign_reject => canonical_case(
        "subscription-period-count-sign-reject",
        CANONICAL,
        BugType::Malleability,
        count_spec(),
        "periodCount=\"+30\" carries a sign, which the profile forbids.",
        period("day", "+30"),
        reject(RejectCode::InvalidChallenge, "sign in periodCount"),
    )
    .requirements(&[R_PERIOD_COUNT_FORMAT])
    .authored(None)
    .build();
    subscription_period_count_decimal_point_reject => canonical_case(
        "subscription-period-count-decimal-point-reject",
        CANONICAL,
        BugType::Malleability,
        count_spec(),
        "periodCount=\"30.0\" carries a decimal point, which the profile forbids.",
        period("day", "30.0"),
        reject(RejectCode::InvalidChallenge, "decimal point in periodCount"),
    )
    .requirements(&[R_PERIOD_COUNT_FORMAT])
    .build();
    subscription_period_count_exponent_reject => canonical_case(
        "subscription-period-count-exponent-reject",
        CANONICAL,
        BugType::Malleability,
        count_spec(),
        "periodCount=\"3e1\" uses an exponent, which the profile forbids (a lenient numeric parse reads it as 30).",
        period("day", "3e1"),
        reject(RejectCode::InvalidChallenge, "exponent in periodCount"),
    )
    .requirements(&[R_PERIOD_COUNT_FORMAT])
    .build();
    subscription_period_count_whitespace_reject => canonical_case(
        "subscription-period-count-whitespace-reject",
        CANONICAL,
        BugType::Malleability,
        count_spec(),
        "periodCount=\" 30\" has surrounding whitespace, which the profile forbids.",
        period("day", " 30"),
        reject(RejectCode::InvalidChallenge, "whitespace in periodCount"),
    )
    .requirements(&[R_PERIOD_COUNT_FORMAT])
    .build();

    // ── canonical bytes: PDAs ──────────────────────────────────────────────
    subscription_pda_delegation => canonical_case(
        "subscription-pda-delegation",
        CANONICAL,
        BugType::Wire,
        delegation_pda_spec(),
        "SubscriptionDelegation PDA [\"subscription\", plan, subscriber] under the canonical subscriptions program. The bearer proof signs this address and the server re-derives it, so every SDK must derive the same one.",
        json!({ "subscriptionPda": {
            "kind": "delegation",
            "planAddress": fx::plan(),
            "subscriber": fx::SUBSCRIBER,
            "subscriptionProgram": fx::PROGRAM,
        }}),
        json_bytes(),
    )
    .requirements(&[R_ACTIVATION_PROOF])
    .build();
    subscription_pda_delegation_spec_example => canonical_case(
        "subscription-pda-delegation-spec-example",
        CANONICAL,
        BugType::Wire,
        delegation_pda_spec(),
        "SubscriptionDelegation PDA for the plan and recipient addresses of the spec's request example (seed order is plan, then subscriber).",
        json!({ "subscriptionPda": {
            "kind": "delegation",
            "planAddress": "8tWbqLkUJoYy7zXc5h2EvCRoaQEv2xnQjUuYhc3rzCgT",
            "subscriber": "9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin",
            "subscriptionProgram": fx::PROGRAM,
        }}),
        json_bytes(),
    )
    .requirements(&[R_ACTIVATION_PROOF])
    .build();
    subscription_pda_authority => canonical_case(
        "subscription-pda-authority",
        CANONICAL,
        BugType::Wire,
        authority_pda_spec(),
        "SubscriptionAuthority PDA [\"SubscriptionAuthority\", subscriber, mint]: the account whose init_id a server compares with the delegation's before granting access.",
        json!({ "subscriptionPda": {
            "kind": "authority",
            "subscriber": fx::SUBSCRIBER,
            "mint": fx::MINT,
            "subscriptionProgram": fx::PROGRAM,
        }}),
        json_bytes(),
    )
    .requirements(&[R_LATER_ACCESS])
    .build();
    subscription_pda_authority_token_2022 => canonical_case(
        "subscription-pda-authority-token-2022",
        CANONICAL,
        BugType::Wire,
        authority_pda_spec(),
        "SubscriptionAuthority PDA for a Token-2022 mint: one authority per (subscriber, mint), whatever the token program.",
        json!({ "subscriptionPda": {
            "kind": "authority",
            "subscriber": fx::SUBSCRIBER,
            "mint": fx::MINT_2022,
            "subscriptionProgram": fx::PROGRAM,
        }}),
        json_bytes(),
    )
    .requirements(&[R_LATER_ACCESS])
    .build();

    // ── canonical bytes: instruction data ──────────────────────────────────
    subscription_instruction_subscribe_data => canonical_case(
        "subscription-instruction-subscribe-data",
        CANONICAL,
        BugType::Wire,
        activation_spec(),
        "subscribe instruction data: discriminator 11, then plan_id u64 LE, plan_bump u8, expected mint (32), expected amount u64 LE, expected period_hours u64 LE, expected created_at i64 LE, expected authority init_id i64 LE (74 bytes). The program refuses a subscribe whose expected terms differ from the live plan.",
        json!({ "subscriptionInstruction": {
            "kind": "subscribe",
            "planId": fx::PLAN_ID,
            "planBump": fx::plan_pda().1,
            "mint": fx::MINT,
            "amount": fx::AMOUNT,
            "periodHours": 720,
            "createdAt": fx::CREATED_AT,
            "authorityInitId": fx::INIT_ID,
        }}),
        Expect::Accept(Pin::ExactBytes(vec!["bytes", "base64Url"])),
    )
    .requirements(&[R_ACTIVATION_MUST])
    .build();
    subscription_instruction_transfer_data => canonical_case(
        "subscription-instruction-transfer-data",
        CANONICAL,
        BugType::Wire,
        activation_spec(),
        "transfer_subscription instruction data: discriminator 10, amount u64 LE, delegator (32), mint (32), 73 bytes. Servers read the amount, delegator and mint from these bytes.",
        json!({ "subscriptionInstruction": {
            "kind": "transfer",
            "amount": fx::AMOUNT,
            "delegator": fx::SUBSCRIBER,
            "mint": fx::MINT,
        }}),
        Expect::Accept(Pin::ExactBytes(vec!["bytes", "base64Url"])),
    )
    .requirements(&[R_ACTIVATION_MUST])
    .build();

    // ── canonical bytes: wire shapes ───────────────────────────────────────
    subscription_wire_request_spec_example => canonical_case(
        "subscription-wire-request-spec-example",
        WIRE,
        BugType::Wire,
        spec(SOL, "Request Schema", "The request JSON MUST be serialized using JSON Canonicalization Scheme (JCS) {{RFC8785}} and base64url-encoded without padding per {{I-D.httpauth-payment}}."),
        "The spec's request example round-tripped through the SDK's subscription request type and re-encoded as JCS: every shared and methodDetails field survives with its name and type.",
        json!({ "subscriptionWire": { "shape": "request", "value": spec_example_request() } }),
        json_bytes(),
    )
    .requirements(&[R_JCS])
    .build();
    subscription_wire_request_required_only => canonical_case(
        "subscription-wire-request-required-only",
        WIRE,
        BugType::Wire,
        spec(SOL, "Shared Fields", "The Solana profile elevates recipient from OPTIONAL to REQUIRED and constrains the values that periodUnit may take."),
        "A request with only the REQUIRED shared fields and REQUIRED methodDetails: no optional field is invented on re-encode.",
        json!({ "subscriptionWire": { "shape": "request", "value": {
            "amount": fx::AMOUNT,
            "currency": fx::MINT,
            "periodUnit": "week",
            "periodCount": "2",
            "recipient": fx::RECIPIENT,
            "methodDetails": {
                "subscriptionProgram": fx::PROGRAM,
                "planAddress": fx::plan(),
                "mint": fx::MINT,
                "tokenProgram": TOKEN_PROGRAM,
                "decimals": 6,
                "puller": fx::merchant(),
            }
        }}}),
        json_bytes(),
    )
    .requirements(&[R_RECIPIENT_REQUIRED, R_JCS])
    .build();
    subscription_wire_request_month_reject => canonical_case(
        "subscription-wire-request-month-reject",
        WIRE,
        BugType::Wire,
        spec(SOL, "Required Fields", "Billing period unit. The value MUST be day or week"),
        "periodUnit=month is not a Solana subscription period unit; the request type refuses it.",
        json!({ "subscriptionWire": { "shape": "request", "value": {
            "amount": fx::AMOUNT,
            "currency": fx::MINT,
            "periodUnit": "month",
            "periodCount": "1",
            "recipient": fx::RECIPIENT,
            "methodDetails": fx::request()["methodDetails"].clone(),
        }}}),
        reject(RejectCode::InvalidChallenge, "periodUnit month"),
    )
    .requirements(&[R_DAY_OR_WEEK, R_REJECT_MONTH])
    .build();
    subscription_wire_request_no_recipient_reject => canonical_case(
        "subscription-wire-request-no-recipient-reject",
        WIRE,
        BugType::Wire,
        spec(SOL, "Shared Fields", "The Solana profile elevates recipient from OPTIONAL to REQUIRED and constrains the values that periodUnit may take."),
        "A request without recipient: optional in the shared intent, REQUIRED in the Solana profile.",
        json!({ "subscriptionWire": { "shape": "request", "value": {
            "amount": fx::AMOUNT,
            "currency": fx::MINT,
            "periodUnit": "day",
            "periodCount": "30",
            "methodDetails": fx::request()["methodDetails"].clone(),
        }}}),
        reject(RejectCode::InvalidChallenge, "recipient missing"),
    )
    .requirements(&[R_RECIPIENT_REQUIRED])
    .build();
    subscription_wire_request_no_period_count_reject => canonical_case(
        "subscription-wire-request-no-period-count-reject",
        WIRE,
        BugType::Wire,
        count_spec(),
        "A request without periodCount, a REQUIRED shared field.",
        json!({ "subscriptionWire": { "shape": "request", "value": {
            "amount": fx::AMOUNT,
            "currency": fx::MINT,
            "periodUnit": "day",
            "recipient": fx::RECIPIENT,
            "methodDetails": fx::request()["methodDetails"].clone(),
        }}}),
        reject(RejectCode::InvalidChallenge, "periodCount missing"),
    )
    .requirements(&[R_PERIOD_COUNT_FORMAT])
    .build();
    subscription_wire_activation_payload => canonical_case(
        "subscription-wire-activation-payload",
        WIRE,
        BugType::Wire,
        spec(SOL, "Payload", "| authentication | object | REQUIRED | Reusable payer proof defined in {{subscription-bearer-proof}} |"),
        "Activation payload {type: \"transaction\", transaction, authentication: {type: \"proof\", challengeId, payer, signature}} round-tripped through the SDK's activation payload type.",
        json!({ "subscriptionWire": { "shape": "activation", "value": {
            "type": "transaction",
            "transaction": "AQAB",
            "authentication": sample_authentication(),
        }}}),
        json_bytes(),
    )
    .requirements(&[R_TYPE_TRANSACTION, R_AUTHENTICATION_REQUIRED])
    .build();
    subscription_wire_activation_no_authentication_reject => canonical_case(
        "subscription-wire-activation-no-authentication-reject",
        WIRE,
        BugType::Wire,
        spec(SOL, "Payload", "| authentication | object | REQUIRED | Reusable payer proof defined in {{subscription-bearer-proof}} |"),
        "An activation payload without the REQUIRED authentication proof.",
        json!({ "subscriptionWire": { "shape": "activation", "value": {
            "type": "transaction",
            "transaction": "AQAB",
        }}}),
        reject(RejectCode::InvalidPayload, "authentication missing"),
    )
    .requirements(&[R_AUTHENTICATION_REQUIRED])
    .authored(None)
    .build();
    subscription_wire_access_payload => canonical_case(
        "subscription-wire-access-payload",
        WIRE,
        BugType::Wire,
        spec(SOL, "Subscription Bearer Proof", "| type | string | REQUIRED | The string \"proof\" |"),
        "Later-access payload {type: \"proof\", subscriptionDelegation, authentication} round-tripped through the SDK's access payload type.",
        json!({ "subscriptionWire": { "shape": "access", "value": {
            "type": "proof",
            "subscriptionDelegation": fx::delegation(),
            "authentication": sample_authentication(),
        }}}),
        json_bytes(),
    )
    .requirements(&[R_TYPE_PROOF])
    .build();
    subscription_wire_access_wrong_proof_type_reject => canonical_case(
        "subscription-wire-access-wrong-proof-type-reject",
        WIRE,
        BugType::Wire,
        spec(SOL, "Subscription Bearer Proof", "| type | string | REQUIRED | The string \"proof\" |"),
        "An access payload whose authentication.type is \"signature\" instead of \"proof\".",
        json!({ "subscriptionWire": { "shape": "access", "value": {
            "type": "proof",
            "subscriptionDelegation": fx::delegation(),
            "authentication": {
                "type": "signature",
                "challengeId": fx::CHALLENGE_ID,
                "payer": fx::SUBSCRIBER,
                "signature": sample_authentication()["signature"].clone(),
            },
        }}}),
        reject(RejectCode::InvalidPayload, "authentication.type is not proof"),
    )
    .requirements(&[R_TYPE_PROOF])
    .build();

    // ── build (client) ─────────────────────────────────────────────────────
    subscription_build_activation => build_case(
        "subscription-build-activation",
        "Activation for a 30-day plan, subscriber as fee payer: subscribe then transfer_subscription on the pinned program, first charge to the recipient's ATA, the merchant as puller. The SDK's build must pass the Rust server's activation verification and carry the same instruction multiset as the kit's build.",
        activation_spec(),
        build_input(kit_request(|_| {}), default_chain()),
        Expect::Accept(Pin::Outcome),
    )
    .requirements(&[R_ACTIVATION_MUST, R_ACTIVATION_MUST_NOT])
    .build();
    subscription_build_sponsored => build_case(
        "subscription-build-sponsored",
        "feePayer=true: the activation's fee payer is methodDetails.feePayerKey, whose signature slot the client leaves for the server.",
        spec(SOL, "Subscription Bearer Proof", "set the fee payer to methodDetails.feePayerKey when methodDetails.feePayer is true, and to the subscriber otherwise;"),
        build_input(
            kit_request(|r| {
                r["methodDetails"]["feePayer"] = json!(true);
                r["methodDetails"]["feePayerKey"] = json!(fx::SPONSOR);
            }),
            default_chain(),
        ),
        Expect::Accept(Pin::Outcome),
    )
    .requirements(&[R_ACTIVATION_MUST])
    .build();
    subscription_build_external_id_memo => build_case(
        "subscription-build-external-id-memo",
        "externalId set: the activation may carry it as a memo instruction (memo is the one optional instruction besides compute budget).",
        activation_spec(),
        build_input(
            kit_request(|r| r["externalId"] = json!("merchant-subscription-270")),
            default_chain(),
        ),
        Expect::Accept(Pin::Outcome),
    )
    .requirements(&[R_ACTIVATION_MUST])
    .build();
    subscription_build_week_period => build_case(
        "subscription-build-week-period",
        "A 2-week plan (336 period_hours): the subscribe instruction's expected period_hours is the mapped interval.",
        period_spec(),
        build_input(
            kit_request(|r| {
                r["periodUnit"] = json!("week");
                r["periodCount"] = json!("2");
                r["methodDetails"]["expectedPeriodHours"] = json!(336);
            }),
            plan_chain(PlanSpec { period_hours: 336, ..PlanSpec::default() }),
        ),
        Expect::Accept(Pin::Outcome),
    )
    .requirements(&[R_INTERVAL_RANGE, R_ACTIVATION_MUST])
    .build();
    subscription_build_token_2022 => build_case(
        "subscription-build-token-2022",
        "A Token-2022 mint: every token-touching instruction uses methodDetails.tokenProgram and the ATAs are derived under Token-2022.",
        spec(SOL, "Subscription Bearer Proof", "use the SPL Token or Token-2022 program identified by methodDetails.tokenProgram for all token-touching instructions;"),
        build_input(
            kit_request(|r| {
                r["currency"] = json!(fx::MINT_2022);
                r["methodDetails"]["mint"] = json!(fx::MINT_2022);
                r["methodDetails"]["tokenProgram"] = json!(TOKEN_2022_PROGRAM);
            }),
            fx::chain(&PlanSpec { mint: fx::MINT_2022.into(), ..PlanSpec::default() }, fx::PROGRAM, TOKEN_2022_PROGRAM),
        ),
        Expect::Accept(Pin::Outcome),
    )
    .requirements(&[R_TOKEN_PROGRAM, R_ACTIVATION_MUST])
    .build();
    subscription_build_plan_puller_listed => build_case(
        "subscription-build-plan-puller-listed",
        "The challenge's puller is not the plan owner but is listed in plan.pullers, so it may collect: the client signs.",
        spec(SOL, "Method Details", "MUST be plan.owner or appear in plan.pullers |"),
        build_input(
            kit_request(|r| r["methodDetails"]["puller"] = json!(fx::stranger())),
            plan_chain(PlanSpec { pullers: vec![fx::stranger()], ..PlanSpec::default() }),
        ),
        Expect::Accept(Pin::Outcome),
    )
    .requirements(&[R_PULLER_AUTHORIZED])
    .build();
    subscription_build_spec_request => build_case(
        "subscription-build-spec-request",
        "A challenge carrying exactly the spec's fields (REQUIRED methodDetails plus network and recentBlockhash), with the plan on-chain: everything the activation needs is in the challenge or the plan, so the client builds it.",
        spec(INTENT, "Shared Fields", "All payment methods implementing the \"subscription\" intent MUST support the required shared fields below."),
        build_input(fx::request(), default_chain()),
        Expect::AcceptAuthored(json!({})),
    )
    .requirements(&[R_SHARED_FIELDS])
    .authored(None)
    .build();
    subscription_build_fee_payer_without_key_reject => build_reject(
        "subscription-build-fee-payer-without-key-reject",
        "feePayer=true without feePayerKey: the client cannot name the fee payer and must refuse the challenge.",
        spec(SOL, "Method Details", "REQUIRED when feePayer is true |"),
        build_input(kit_request(|r| r["methodDetails"]["feePayer"] = json!(true)), default_chain()),
    )
    .requirements(&[R_FEE_PAYER_KEY])
    .build();
    subscription_build_untrusted_program_reject => build_reject(
        "subscription-build-untrusted-program-reject",
        "methodDetails.subscriptionProgram names a program other than the subscriptions deployment the client trusts. The program would receive the subscriber's signature and token account; the client must refuse before signing.",
        spec(SOL, "Definition", "Servers MUST pin its deployment address in methodDetails.subscriptionProgram, and clients MUST validate that address before signing."),
        build_input(
            kit_request(|r| r["methodDetails"]["subscriptionProgram"] = json!(fx::FOREIGN_PROGRAM)),
            untrusted_program_chain(),
        ),
    )
    .requirements(&[R_PROGRAM_PINNED])
    .build();
    subscription_build_currency_not_mint_reject => build_reject(
        "subscription-build-currency-not-mint-reject",
        "currency names one mint and methodDetails.mint another: the wallet would display one token and sign a delegation over another.",
        spec(SOL, "Currency Formats", "Implementations MUST treat currency and methodDetails.mint as the same value; servers MUST reject request objects where they differ."),
        build_input(kit_request(|r| r["currency"] = json!(keys::OTHER_MINT)), default_chain()),
    )
    .requirements(&[R_CURRENCY_IS_MINT])
    .build();
    subscription_build_month_reject => build_reject(
        "subscription-build-month-reject",
        "periodUnit=month: a client must not approximate a calendar month with a fixed interval.",
        spec(INTENT, "Required Fields", "Payment methods MUST reject request objects whose periodUnit or periodCount values they cannot represent exactly."),
        build_input(kit_request(|r| r["periodUnit"] = json!("month")), default_chain()),
    )
    .requirements(&[R_REPRESENT_EXACTLY, R_DAY_OR_WEEK])
    .build();
    subscription_build_interval_over_limit_reject => build_reject(
        "subscription-build-interval-over-limit-reject",
        "periodCount=366 days maps to 8784 hours, over the profile's 8760-hour limit.",
        period_spec(),
        build_input(
            kit_request(|r| {
                r["periodCount"] = json!("366");
                r["methodDetails"]["expectedPeriodHours"] = json!(8784);
            }),
            plan_chain(PlanSpec { period_hours: 8784, ..PlanSpec::default() }),
        ),
    )
    .requirements(&[R_INTERVAL_RANGE])
    .build();
    subscription_build_amount_leading_zero_reject => build_reject(
        "subscription-build-amount-leading-zero-reject",
        "amount=\"010000000\" uses a leading zero; the client must refuse the request rather than read it as 10000000.",
        spec(SOL, "Optional Fields", "The amount value MUST be a string representation of a positive integer in base 10 with no sign, decimal point, exponent, or surrounding whitespace."),
        build_input(
            kit_request(|r| {
                r["amount"] = json!("010000000");
                r["methodDetails"]["amount"] = json!("010000000");
            }),
            default_chain(),
        ),
    )
    .requirements(&[R_AMOUNT_FORMAT, R_LEADING_ZEROS])
    .authored(None)
    .build();
    subscription_build_zero_amount_reject => build_reject(
        "subscription-build-zero-amount-reject",
        "amount=\"0\" is not a positive integer, even against a plan whose amount is 0.",
        spec(SOL, "Optional Fields", "The amount value MUST be a string representation of a positive integer in base 10 with no sign, decimal point, exponent, or surrounding whitespace."),
        build_input(
            kit_request(|r| {
                r["amount"] = json!("0");
                r["methodDetails"]["amount"] = json!("0");
            }),
            plan_chain(PlanSpec { amount: 0, ..PlanSpec::default() }),
        ),
    )
    .requirements(&[R_AMOUNT_FORMAT])
    .authored(None)
    .build();
    subscription_build_period_count_leading_zero_reject => build_reject(
        "subscription-build-period-count-leading-zero-reject",
        "periodCount=\"030\" uses a leading zero.",
        count_spec(),
        build_input(kit_request(|r| r["periodCount"] = json!("030")), default_chain()),
    )
    .requirements(&[R_PERIOD_COUNT_FORMAT, R_LEADING_ZEROS])
    .authored(None)
    .build();
    subscription_build_token_program_not_spl_reject => build_reject(
        "subscription-build-token-program-not-spl-reject",
        "methodDetails.tokenProgram is the System program, neither SPL Token nor Token-2022.",
        spec(SOL, "Method Details", "The value MUST be the SPL Token program or the SPL Token-2022 program |"),
        build_input(
            kit_request(|r| r["methodDetails"]["tokenProgram"] = json!(keys::SYSTEM_PROGRAM)),
            default_chain(),
        ),
    )
    .requirements(&[R_TOKEN_PROGRAM])
    .authored(None)
    .build();
    subscription_build_no_plan_address_reject => build_reject(
        "subscription-build-no-plan-address-reject",
        "methodDetails without planAddress, a REQUIRED field.",
        spec(SOL, "Method Details", "| methodDetails.planAddress | string | REQUIRED | Base58 address of the on-chain Plan account |"),
        build_input(
            kit_request(|r| {
                r["methodDetails"].as_object_mut().unwrap().remove("planAddress");
            }),
            default_chain(),
        ),
    )
    .requirements(&[R_PLAN_ADDRESS])
    .build();
    subscription_build_no_puller_reject => build_reject(
        "subscription-build-no-puller-reject",
        "methodDetails without puller, a REQUIRED field: the client cannot name the transfer_subscription signer.",
        spec(SOL, "Method Details", "| methodDetails.puller | string | REQUIRED | Base58 of the server's puller pubkey."),
        build_input(
            kit_request(|r| {
                r["methodDetails"].as_object_mut().unwrap().remove("puller");
            }),
            default_chain(),
        ),
    )
    .requirements(&[R_PULLER_REQUIRED])
    .build();
    subscription_build_no_decimals_reject => build_reject(
        "subscription-build-no-decimals-reject",
        "methodDetails without decimals, a REQUIRED field (wallets render the per-period amount with it).",
        spec(SOL, "Method Details", "| methodDetails.decimals | number | REQUIRED | Decimal precision of the mint |"),
        build_input(
            kit_request(|r| {
                r["methodDetails"].as_object_mut().unwrap().remove("decimals");
            }),
            default_chain(),
        ),
    )
    .requirements(&[R_DECIMALS_REQUIRED])
    .authored(None)
    .build();
    subscription_build_invalid_plan_address_reject => build_reject(
        "subscription-build-invalid-plan-address-reject",
        "methodDetails.planAddress is not a base58 address.",
        spec(SOL, "Method Details", "| methodDetails.planAddress | string | REQUIRED | Base58 address of the on-chain Plan account |"),
        build_input(kit_request(|r| r["methodDetails"]["planAddress"] = json!("not-a-plan")), default_chain()),
    )
    .requirements(&[R_PLAN_ADDRESS])
    .build();
    subscription_build_plan_missing_reject => build_reject(
        "subscription-build-plan-missing-reject",
        "No account exists at methodDetails.planAddress: there is no on-chain Plan for the challenge to agree with.",
        client_verify_spec("Clients MUST NOT sign an activation transaction whose on-chain Plan does not match the challenge."),
        build_input(kit_request(|_| {}), {
            let mut chain = default_chain();
            chain["accounts"].as_object_mut().unwrap().remove(&fx::plan());
            chain
        }),
    )
    .requirements(&[R_PLAN_MATCHES, R_CLIENT_VERIFY])
    .authored(None)
    .build();
    subscription_build_plan_amount_mismatch_reject => build_reject(
        "subscription-build-plan-amount-mismatch-reject",
        "The on-chain Plan charges 5000000 per period; the challenge says 10000000.",
        client_verify_spec("Clients MUST NOT sign an activation transaction whose on-chain Plan does not match the challenge."),
        build_input(kit_request(|_| {}), plan_chain(PlanSpec { amount: 5_000_000, ..PlanSpec::default() })),
    )
    .requirements(&[R_PLAN_MATCHES, R_CLIENT_VERIFY])
    .authored(None)
    .build();
    subscription_build_plan_period_mismatch_reject => build_reject(
        "subscription-build-plan-period-mismatch-reject",
        "The on-chain Plan bills every 168 hours; the challenge says 30 days (720 hours).",
        client_verify_spec("Clients MUST NOT sign an activation transaction whose on-chain Plan does not match the challenge."),
        build_input(kit_request(|_| {}), plan_chain(PlanSpec { period_hours: 168, ..PlanSpec::default() })),
    )
    .requirements(&[R_PLAN_MATCHES, R_CLIENT_VERIFY])
    .authored(None)
    .build();
    subscription_build_plan_mint_mismatch_reject => build_reject(
        "subscription-build-plan-mint-mismatch-reject",
        "The on-chain Plan is denominated in another mint than methodDetails.mint.",
        spec(SOL, "Method Details", "MUST equal the on-chain plan.mint |"),
        build_input(kit_request(|_| {}), {
            let mut chain = plan_chain(PlanSpec { mint: keys::OTHER_MINT.into(), ..PlanSpec::default() });
            chain["accounts"][fx::authority_of(fx::SUBSCRIBER, fx::MINT)] =
                fx::authority_account(fx::SUBSCRIBER, fx::MINT, fx::INIT_ID);
            chain
        }),
    )
    .requirements(&[R_PLAN_MINT, R_PLAN_MATCHES])
    .authored(None)
    .build();
    subscription_build_plan_puller_unauthorized_reject => build_reject(
        "subscription-build-plan-puller-unauthorized-reject",
        "The challenge's puller is neither plan.owner nor in plan.pullers: the program would refuse every pull, so the activation could never charge.",
        spec(SOL, "Method Details", "MUST be plan.owner or appear in plan.pullers |"),
        build_input(
            kit_request(|r| r["methodDetails"]["puller"] = json!(fx::stranger())),
            default_chain(),
        ),
    )
    .requirements(&[R_PULLER_AUTHORIZED, R_CLIENT_VERIFY])
    .authored(None)
    .build();
    subscription_build_plan_no_destination_reject => build_reject(
        "subscription-build-plan-no-destination-reject",
        "The plan's destination whitelist is empty, so the program would let renewals pay any receiver.",
        spec(SOL, "Method Details", "Servers and clients MUST reject request objects referencing a plan with an empty destination whitelist, more than one non-zero destination, or a destination different from recipient."),
        build_input(kit_request(|_| {}), plan_chain(PlanSpec { destinations: vec![], ..PlanSpec::default() })),
    )
    .requirements(&[R_REJECT_DESTINATIONS])
    .authored(None)
    .build();
    subscription_build_plan_two_destinations_reject => build_reject(
        "subscription-build-plan-two-destinations-reject",
        "The plan whitelists the recipient and a second address: renewals could be routed to the other one.",
        spec(SOL, "Method Details", "Servers and clients MUST reject request objects referencing a plan with an empty destination whitelist, more than one non-zero destination, or a destination different from recipient."),
        build_input(
            kit_request(|_| {}),
            plan_chain(PlanSpec { destinations: vec![fx::RECIPIENT.into(), fx::ATTACKER.into()], ..PlanSpec::default() }),
        ),
    )
    .requirements(&[R_REJECT_DESTINATIONS])
    .authored(None)
    .build();
    subscription_build_plan_other_destination_reject => build_reject(
        "subscription-build-plan-other-destination-reject",
        "The plan's only destination is not the challenge's recipient.",
        spec(SOL, "Method Details", "The non-zero entries in plan.destinations MUST consist of exactly one address, and that address MUST equal recipient."),
        build_input(
            kit_request(|_| {}),
            plan_chain(PlanSpec { destinations: vec![fx::ATTACKER.into()], ..PlanSpec::default() }),
        ),
    )
    .requirements(&[R_ONE_DESTINATION, R_REJECT_DESTINATIONS])
    .authored(None)
    .build();

    // ── verify (server): accepts ───────────────────────────────────────────
    subscription_verify_activation => verify_case(
        "subscription-verify-activation",
        "A kit-built activation for the route's challenge, the bearer proof over the derived delegation, source = did:pkh of the subscriber: passes every check before the server co-signs and broadcasts.",
        BugType::Settlement,
        spec(SOL, "Activation", "When the server receives a Solana \"subscription\" credential, it MUST:"),
        Activation::new(),
        Expect::Accept(Pin::Outcome),
    )
    .requirements(&[R_ON_RECEIVE, R_SCOPE])
    .build();
    subscription_verify_sponsored => verify_case(
        "subscription-verify-sponsored",
        "A sponsored activation (feePayer=true): the server's key is the fee payer, the subscriber the next signer; the server co-signs before broadcasting.",
        BugType::Settlement,
        spec(SOL, "Activation", "When methodDetails.feePayer is true, also sign as methodDetails.feePayerKey, then broadcast."),
        Activation::sponsored(),
        Expect::Accept(Pin::Outcome),
    )
    .requirements(&[R_ON_RECEIVE])
    .build();
    subscription_verify_external_id_memo => verify_case(
        "subscription-verify-external-id-memo",
        "The challenge carries externalId and the activation the matching memo.",
        BugType::Settlement,
        scope_spec("contains no other subscriptions-program, system-program, or token-program instructions; compute-budget and memo instructions are permitted."),
        Activation::new().request_field("externalId", json!("merchant-subscription-270")),
        Expect::Accept(Pin::Outcome),
    )
    .requirements(&[R_SCOPE])
    .build();
    subscription_verify_no_source => verify_case(
        "subscription-verify-no-source",
        "source is OPTIONAL: an activation without it is verified from the transaction alone.",
        BugType::Settlement,
        spec(SOL, "Source Verification", "Servers MUST determine the payer identity from the activation transaction itself"),
        Activation { source: None, ..Activation::new() },
        Expect::Accept(Pin::Outcome),
    )
    .requirements(&[R_PAYER_FROM_TX])
    .build();
    subscription_verify_challenge_expires_after_now => verify_case(
        "subscription-verify-challenge-expires-after-now",
        "The activation challenge expires one second after the pinned clock: still valid.",
        BugType::Replay,
        spec(SOL, "Subscription Bearer Proof", "The activation challenge's expires auth-param limits creation of the binding"),
        Activation { expires: Some(fx::rfc3339(fx::NOW + 1)), ..Activation::new() },
        Expect::Accept(Pin::Outcome),
    )
    .requirements(&[R_BINDING])
    .build();
    subscription_verify_subscription_expires_later => verify_case(
        "subscription-verify-subscription-expires-later",
        "subscriptionExpires is a day after the pinned clock: activation may proceed.",
        BugType::Settlement,
        spec(SOL, "Activation", "Servers MUST NOT treat activation as successful if subscriptionExpires is present and the activation transaction settles at or after that timestamp."),
        Activation::new().request_field("subscriptionExpires", json!(fx::rfc3339(fx::NOW + 86_400))),
        Expect::Accept(Pin::Outcome),
    )
    .requirements(&[R_EXPIRES_SETTLES])
    .build();

    // ── verify (server): challenge binding and expiry ──────────────────────
    subscription_verify_challenge_expired_reject => verify_case(
        "subscription-verify-challenge-expired-reject",
        "The activation challenge expires exactly at the pinned clock: the binding can no longer be created.",
        BugType::Replay,
        spec(SOL, "Subscription Bearer Proof", "The activation challenge's expires auth-param limits creation of the binding"),
        Activation { expires: Some(fx::rfc3339(fx::NOW)), ..Activation::new() },
        reject(RejectCode::ChallengeExpired, "challenge expires == now"),
    )
    .requirements(&[R_BINDING])
    .build();
    subscription_verify_subscription_expired_reject => verify_case(
        "subscription-verify-subscription-expired-reject",
        "subscriptionExpires equals the pinned clock: any settlement happens at or after it, so the activation cannot succeed.",
        BugType::Settlement,
        spec(SOL, "Activation", "Servers MUST NOT treat activation as successful if subscriptionExpires is present and the activation transaction settles at or after that timestamp."),
        Activation::new().request_field("subscriptionExpires", json!(fx::rfc3339(fx::NOW))),
        reject(RejectCode::SubscriptionExpired, "subscriptionExpires == now"),
    )
    .requirements(&[R_EXPIRES_SETTLES])
    .build();
    subscription_verify_forged_challenge_id_reject => verify_case(
        "subscription-verify-forged-challenge-id-reject",
        "The echoed challenge id is not the HMAC this server computes over the echoed parameters: the server did not issue it.",
        BugType::AuthBypass,
        spec("mpp-specs/specs/core/draft-httpauth-payment-01.md", "Challenge Binding", "Servers MUST verify the binding when processing a credential and MUST reject a credential whose echoed challenge parameters do not match the expected binding."),
        Activation { forged_id: true, ..Activation::new() },
        reject(RejectCode::ChallengeMismatch, "HMAC mismatch"),
    )
    .requirements(&[R_BINDING])
    .build();
    subscription_verify_other_method_reject => verify_case(
        "subscription-verify-other-method-reject",
        "A challenge bound under this server's secret for method \"other\": not a Solana subscription credential for this route.",
        BugType::AuthBypass,
        spec("mpp-specs/specs/core/draft-httpauth-payment-01.md", "Challenge Binding", "Servers MUST verify the binding when processing a credential and MUST reject a credential whose echoed challenge parameters do not match the expected binding."),
        Activation { method: "other".into(), ..Activation::new() },
        reject(RejectCode::ChallengeMismatch, "method differs from the route"),
    )
    .requirements(&[R_BINDING])
    .build();
    subscription_verify_charge_intent_reject => verify_case(
        "subscription-verify-charge-intent-reject",
        "A charge challenge (same secret, realm and request) presented to the subscription route.",
        BugType::AuthBypass,
        spec("mpp-specs/specs/core/draft-httpauth-payment-01.md", "Challenge Binding", "Servers MUST verify the binding when processing a credential and MUST reject a credential whose echoed challenge parameters do not match the expected binding."),
        Activation { intent: "charge".into(), ..Activation::new() },
        reject(RejectCode::ChallengeMismatch, "intent differs from the route"),
    )
    .requirements(&[R_BINDING])
    .build();
    subscription_verify_other_realm_reject => verify_case(
        "subscription-verify-other-realm-reject",
        "A challenge for another realm sharing the secret.",
        BugType::AuthBypass,
        spec("mpp-specs/specs/core/draft-httpauth-payment-01.md", "Challenge Binding", "Servers MUST verify the binding when processing a credential and MUST reject a credential whose echoed challenge parameters do not match the expected binding."),
        Activation { realm: "other.example.com".into(), ..Activation::new() },
        reject(RejectCode::ChallengeMismatch, "realm differs from the route"),
    )
    .requirements(&[R_BINDING])
    .build();
    subscription_verify_cheaper_route_reject => verify_case(
        "subscription-verify-cheaper-route-reject",
        "Two routes share realm, secret, mint, recipient and Plan; the credential was issued for the 10000000-per-period route and presented to the 100000000 one. A proof for the cheaper route must not unlock the pricier one.",
        BugType::AuthBypass,
        spec("mpp-specs/specs/core/draft-httpauth-payment-01.md", "Challenge Binding", "Servers MUST verify the binding when processing a credential and MUST reject a credential whose echoed challenge parameters do not match the expected binding."),
        Activation::new().server_field("amount", json!("100000000")),
        reject(RejectCode::ChallengeMismatch, "route amount differs"),
    )
    .requirements(&[R_BINDING])
    .build();
    subscription_verify_shorter_period_route_reject => verify_case(
        "subscription-verify-shorter-period-route-reject",
        "The credential was issued for a 30-day route sharing the Plan; the route it is presented to bills every 7 days.",
        BugType::AuthBypass,
        spec("mpp-specs/specs/core/draft-httpauth-payment-01.md", "Challenge Binding", "Servers MUST verify the binding when processing a credential and MUST reject a credential whose echoed challenge parameters do not match the expected binding."),
        Activation::new().server_field("periodCount", json!(7)),
        reject(RejectCode::ChallengeMismatch, "route period differs"),
    )
    .requirements(&[R_BINDING])
    .build();
    subscription_verify_other_plan_reject => verify_case(
        "subscription-verify-other-plan-reject",
        "The challenge names another Plan than the route's.",
        BugType::AuthBypass,
        spec(SOL, "Activation", "Verify the activation transaction matches the challenge: program ID, plan address, token program, mint, puller, recipient, and per-period amount as described in {{authorization-scope-verification}}."),
        Activation::new().server_field("planAddress", json!(fx::delegation())),
        reject(RejectCode::ChallengeMismatch, "plan differs from the route"),
    )
    .requirements(&[R_ON_RECEIVE, R_BINDING])
    .build();
    subscription_verify_other_recipient_reject => verify_case(
        "subscription-verify-other-recipient-reject",
        "The route pays another recipient than the challenge.",
        BugType::AuthBypass,
        spec(SOL, "Destination Scoping", "Solana subscription delegations MUST be bound to a receiver identified by recipient."),
        Activation::new().server_field("recipient", json!(fx::ATTACKER)),
        reject(RejectCode::ChallengeMismatch, "recipient differs from the route"),
    )
    .requirements(&[R_BINDING])
    .build();
    subscription_verify_other_currency_reject => verify_case(
        "subscription-verify-other-currency-reject",
        "The route charges another mint than the challenge.",
        BugType::AuthBypass,
        spec("mpp-specs/specs/core/draft-httpauth-payment-01.md", "Challenge Binding", "Servers MUST verify the binding when processing a credential and MUST reject a credential whose echoed challenge parameters do not match the expected binding."),
        Activation::new().server_field("mint", json!(keys::OTHER_MINT)),
        reject(RejectCode::ChallengeMismatch, "mint differs from the route"),
    )
    .requirements(&[R_BINDING])
    .build();
    subscription_verify_other_network_reject => verify_case(
        "subscription-verify-other-network-reject",
        "The challenge is for mainnet; the route serves devnet.",
        BugType::AuthBypass,
        spec("mpp-specs/specs/core/draft-httpauth-payment-01.md", "Challenge Binding", "Servers MUST verify the binding when processing a credential and MUST reject a credential whose echoed challenge parameters do not match the expected binding."),
        Activation::new().issued_field("methodDetails.network", json!("mainnet")),
        reject(RejectCode::WrongNetwork, "network differs from the route"),
    )
    .requirements(&[R_BINDING])
    .build();
    subscription_verify_no_network_on_devnet_reject => verify_case(
        "subscription-verify-no-network-on-devnet-reject",
        "The challenge omits network, which then means mainnet; the route serves devnet.",
        BugType::Defaults,
        spec(SOL, "Method Details", "If omitted, the default value is \"mainnet\""),
        Activation::new().issued_field("methodDetails.network", Value::Null),
        reject(RejectCode::WrongNetwork, "omitted network defaults to mainnet"),
    )
    .requirements(&[R_BINDING])
    .build();

    // ── verify (server): payload and bearer proof ──────────────────────────
    subscription_verify_push_mode_reject => verify_case(
        "subscription-verify-push-mode-reject",
        "A push-mode credential (type=\"signature\", the client broadcast the activation itself): Solana subscription activation is type=\"transaction\" only.",
        BugType::AuthBypass,
        spec(SOL, "Payload", "| type | string | REQUIRED | The string \"transaction\" |"),
        Activation::new().payload(PayloadEdit::PushSignature),
        reject(RejectCode::InvalidPayload, "push mode is not part of the profile"),
    )
    .requirements(&[R_TYPE_TRANSACTION])
    .build();
    subscription_verify_unknown_type_reject => verify_case(
        "subscription-verify-unknown-type-reject",
        "An activation payload whose type is neither \"transaction\" nor \"proof\".",
        BugType::Wire,
        spec(SOL, "Payload", "| type | string | REQUIRED | The string \"transaction\" |"),
        Activation::new().payload(PayloadEdit::Type("hash")),
        reject(RejectCode::InvalidPayload, "unknown payload type"),
    )
    .requirements(&[R_TYPE_TRANSACTION])
    .build();
    subscription_verify_no_transaction_reject => verify_case(
        "subscription-verify-no-transaction-reject",
        "type=\"transaction\" without the transaction.",
        BugType::Wire,
        spec(SOL, "Payload", "| transaction | string | REQUIRED | Standard-base64 of the activation transaction signed by the subscriber."),
        Activation::new().payload(PayloadEdit::NoTransaction),
        reject(RejectCode::InvalidPayload, "transaction missing"),
    )
    .requirements(&[R_TRANSACTION_REQUIRED])
    .build();
    subscription_verify_no_authentication_reject => verify_case(
        "subscription-verify-no-authentication-reject",
        "An activation without the REQUIRED bearer proof: the server has nothing to bind for later access.",
        BugType::AuthBypass,
        spec(SOL, "Payload", "| authentication | object | REQUIRED | Reusable payer proof defined in {{subscription-bearer-proof}} |"),
        Activation::new().auth(AuthEdit::Missing),
        reject(RejectCode::AuthenticationInvalid, "authentication missing"),
    )
    .requirements(&[R_AUTHENTICATION_REQUIRED, R_ACTIVATION_PROOF])
    .build();
    subscription_verify_proof_other_challenge_reject => verify_case(
        "subscription-verify-proof-other-challenge-reject",
        "The proof's challengeId (and signed subscriptionChallengeId) is another challenge than the activation's.",
        BugType::Replay,
        spec(SOL, "Subscription Bearer Proof", "authentication.challengeId equals the activation challenge ID;"),
        Activation::new().auth(AuthEdit::ChallengeId("c3ViX3NvbGFuYV8wMQ")),
        reject(RejectCode::AuthenticationInvalid, "proof bound to another challenge"),
    )
    .requirements(&[R_ACTIVATION_PROOF])
    .build();
    subscription_verify_proof_other_delegation_reject => verify_case(
        "subscription-verify-proof-other-delegation-reject",
        "The proof signs another subscriptionDelegation than the PDA of (planAddress, subscriber, subscriptionProgram).",
        BugType::AuthBypass,
        spec(SOL, "Subscription Bearer Proof", "the signed subscriptionDelegation equals the canonical PDA derived from methodDetails.planAddress, the subscriber, and methodDetails.subscriptionProgram;"),
        Activation::new().auth(AuthEdit::Delegation(fx::ATTACKER)),
        reject(RejectCode::AuthenticationInvalid, "proof bound to another delegation"),
    )
    .requirements(&[R_ACTIVATION_PROOF])
    .build();
    subscription_verify_proof_other_payer_reject => verify_case(
        "subscription-verify-proof-other-payer-reject",
        "The proof is valid but made by another key than the subscriber who signed the activation.",
        BugType::AuthBypass,
        spec(SOL, "Subscription Bearer Proof", "authentication.payer equals the subscriber signer extracted from the activation transaction; and"),
        Activation::new().auth(AuthEdit::Signer(fx::STRANGER_SEED)),
        reject(RejectCode::AuthenticationInvalid, "proof payer is not the subscriber"),
    )
    .requirements(&[R_ACTIVATION_PROOF])
    .build();
    subscription_verify_proof_tampered_reject => verify_case(
        "subscription-verify-proof-tampered-reject",
        "One byte of the proof's Ed25519 signature flipped.",
        BugType::AuthBypass,
        spec(SOL, "Subscription Bearer Proof", "the Ed25519 signature verifies over the exact JCS object above."),
        Activation::new().auth(AuthEdit::TamperSignature),
        reject(RejectCode::AuthenticationInvalid, "proof signature does not verify"),
    )
    .requirements(&[R_ACTIVATION_PROOF])
    .build();
    subscription_verify_source_other_address_reject => verify_case(
        "subscription-verify-source-other-address-reject",
        "source names another address than the activation's subscriber.",
        BugType::AuthBypass,
        spec(SOL, "Source Verification", "If source is present, servers MUST verify that it uses the did:pkh:solana: method and that its address matches the subscriber signer extracted from the activation transaction."),
        Activation { source: Some(format!("did:pkh:solana:{}:{}", fx::NETWORK, fx::ATTACKER)), ..Activation::new() },
        reject(RejectCode::SourceMismatch, "source is not the subscriber"),
    )
    .requirements(&[R_SOURCE])
    .authored(None)
    .build();
    subscription_verify_source_other_method_reject => verify_case(
        "subscription-verify-source-other-method-reject",
        "source uses a DID method other than did:pkh:solana.",
        BugType::AuthBypass,
        spec(SOL, "Source Verification", "If source is present, servers MUST verify that it uses the did:pkh:solana: method and that its address matches the subscriber signer extracted from the activation transaction."),
        Activation { source: Some(format!("did:web:{}", fx::REALM)), ..Activation::new() },
        reject(RejectCode::SourceMismatch, "source is not did:pkh:solana"),
    )
    .requirements(&[R_SOURCE])
    .authored(None)
    .build();

    // ── verify (server): activation scope ──────────────────────────────────
    subscription_verify_extra_program_reject => tx_reject(
        "subscription-verify-extra-program-reject",
        "An instruction of an unrelated program appended to the activation. Any program the subscriber's signature reaches could move funds outside the per-period limit.",
        spec(SOL, "Subscription Bearer Proof", "The subscriber-signed activation transaction MUST NOT contain SPL Token Approve or any other non-subscriptions-program instruction that could move the subscriber's tokens outside the per-period limit"),
        TxEdit::ExtraInstruction { program: fx::FOREIGN_PROGRAM, data: &[1, 2, 3] },
    )
    .requirements(&[R_ACTIVATION_MUST_NOT, R_BROADER_SCOPE])
    .build();
    subscription_verify_system_transfer_reject => tx_reject(
        "subscription-verify-system-transfer-reject",
        "A System transfer from the subscriber appended to the activation.",
        scope_spec("contains no other subscriptions-program, system-program, or token-program instructions; compute-budget and memo instructions are permitted."),
        TxEdit::SystemTransfer,
    )
    .requirements(&[R_SCOPE])
    .build();
    subscription_verify_token_approve_reject => tx_reject(
        "subscription-verify-token-approve-reject",
        "An SPL Token Approve of the subscriber's token account to another delegate appended to the activation: a standing allowance outside the per-period limit.",
        spec(SOL, "Subscription Bearer Proof", "The subscriber-signed activation transaction MUST NOT contain SPL Token Approve or any other non-subscriptions-program instruction that could move the subscriber's tokens outside the per-period limit"),
        TxEdit::TokenApprove,
    )
    .requirements(&[R_ACTIVATION_MUST_NOT, R_SCOPE])
    .build();
    subscription_verify_receiver_ata_other_owner_reject => tx_reject(
        "subscription-verify-receiver-ata-other-owner-reject",
        "transfer_subscription's receiver ATA belongs to another owner than recipient.",
        spec(SOL, "Destination Scoping", "Clients and servers MUST reject credentials whose activation transaction uses a receiver ATA owned by any other address."),
        TxEdit::ReceiverAta { owner: fx::ATTACKER },
    )
    .requirements(&[R_DESTINATION_SCOPING, R_SCOPE])
    .build();
    subscription_verify_missing_subscribe_reject => tx_reject(
        "subscription-verify-missing-subscribe-reject",
        "subscribe removed: a transfer without the delegation it should create.",
        scope_spec("contains exactly one subscribe instruction and exactly one first-period transfer instruction on the subscriptions program, ordered with subscribe first;"),
        TxEdit::DropSubscribe,
    )
    .requirements(&[R_SCOPE])
    .build();
    subscription_verify_missing_transfer_reject => tx_reject(
        "subscription-verify-missing-transfer-reject",
        "transfer_subscription removed: a delegation without the first-period charge.",
        scope_spec("contains exactly one subscribe instruction and exactly one first-period transfer instruction on the subscriptions program, ordered with subscribe first;"),
        TxEdit::DropTransfer,
    )
    .requirements(&[R_SCOPE])
    .build();
    subscription_verify_duplicate_subscribe_reject => tx_reject(
        "subscription-verify-duplicate-subscribe-reject",
        "subscribe appears twice.",
        scope_spec("contains exactly one subscribe instruction and exactly one first-period transfer instruction on the subscriptions program, ordered with subscribe first;"),
        TxEdit::DuplicateSubscribe,
    )
    .requirements(&[R_SCOPE])
    .build();
    subscription_verify_duplicate_transfer_reject => tx_reject(
        "subscription-verify-duplicate-transfer-reject",
        "transfer_subscription appears twice: a second pull in the activation period.",
        scope_spec("contains exactly one subscribe instruction and exactly one first-period transfer instruction on the subscriptions program, ordered with subscribe first;"),
        TxEdit::DuplicateTransfer,
    )
    .requirements(&[R_SCOPE])
    .build();
    subscription_verify_transfer_before_subscribe_reject => tx_reject(
        "subscription-verify-transfer-before-subscribe-reject",
        "transfer_subscription ordered before subscribe.",
        scope_spec("contains exactly one subscribe instruction and exactly one first-period transfer instruction on the subscriptions program, ordered with subscribe first;"),
        TxEdit::TransferFirst,
    )
    .requirements(&[R_SCOPE])
    .build();
    subscription_verify_foreign_program_reject => tx_reject(
        "subscription-verify-foreign-program-reject",
        "subscribe and transfer_subscription sent to another program than methodDetails.subscriptionProgram.",
        scope_spec("invokes only the subscriptions program identified by methodDetails.subscriptionProgram for subscription instructions"),
        TxEdit::ForeignProgram,
    )
    .requirements(&[R_SCOPE])
    .build();
    subscription_verify_ata_for_other_owner_reject => tx_reject(
        "subscription-verify-ata-for-other-owner-reject",
        "An extra idempotent ATA creation for an unrelated owner, a writable account the activation has no use for.",
        spec(SOL, "Subscription Bearer Proof", "and MUST NOT reference writable accounts that could redirect funds away from recipient."),
        TxEdit::CreateAtaFor { owner: fx::ATTACKER },
    )
    .requirements(&[R_ACTIVATION_MUST_NOT])
    .build();
    subscription_verify_subscribe_other_plan_reject => tx_reject(
        "subscription-verify-subscribe-other-plan-reject",
        "subscribe names another Plan account than methodDetails.planAddress.",
        scope_spec("uses methodDetails.planAddress as the Plan account and uses methodDetails.puller as the authorized puller signer;"),
        TxEdit::SubscribePlan { plan: fx::ATTACKER },
    )
    .requirements(&[R_SCOPE])
    .build();
    subscription_verify_unrelated_authority_init_reject => tx_reject(
        "subscription-verify-unrelated-authority-init-reject",
        "initialize_subscription_authority for another mint than the activation's: not the (subscriber, mint) authority the activation needs.",
        scope_spec("conditionally contains one subscription-authority initialization instruction, only if the (subscriber, mint) authority does not yet exist on-chain;"),
        TxEdit::InitAuthority { mint: keys::OTHER_MINT },
    )
    .requirements(&[R_SCOPE])
    .build();
    subscription_verify_transfer_amount_reject => tx_reject(
        "subscription-verify-transfer-amount-reject",
        "transfer_subscription pulls one base unit more than the per-period amount.",
        spec(SOL, "Activation", "Verify the activation transaction matches the challenge: program ID, plan address, token program, mint, puller, recipient, and per-period amount as described in {{authorization-scope-verification}}."),
        TxEdit::TransferAmount { delta: 1 },
    )
    .requirements(&[R_ON_RECEIVE])
    .build();
    subscription_verify_sponsored_subscriber_not_signer_reject => verify_case(
        "subscription-verify-sponsored-subscriber-not-signer-reject",
        "Sponsored activation in which the subscriber signs nothing: the only signers are the server's fee payer and puller, so there is no subscriber to extract.",
        BugType::AuthBypass,
        spec(SOL, "Source Verification", "Servers MUST determine the payer identity from the activation transaction itself, by extracting the subscriber signer"),
        Activation::sponsored().tx(TxEdit::DemoteSubscriber),
        reject(RejectCode::InvalidPayload, "no subscriber signer"),
    )
    .requirements(&[R_PAYER_FROM_TX])
    .build();
    subscription_verify_sponsor_not_fee_payer_reject => verify_case(
        "subscription-verify-sponsor-not-fee-payer-reject",
        "The challenge sets feePayer=true but the activation's fee payer is the subscriber, not methodDetails.feePayerKey.",
        BugType::AuthBypass,
        spec(SOL, "Subscription Bearer Proof", "set the fee payer to methodDetails.feePayerKey when methodDetails.feePayer is true, and to the subscriber otherwise;"),
        {
            let mut a = Activation::sponsored();
            a.build_request = fx::with_kit_extensions(fx::request());
            a
        },
        reject(RejectCode::FeePayerMismatch, "fee payer is not feePayerKey"),
    )
    .requirements(&[R_ACTIVATION_MUST])
    .authored(None)
    .build();

    // ── verify (server): on-chain usability at a pinned clock ──────────────
    subscription_active_live => active_case(
        "subscription-active-live",
        "Delegation for the route's plan and payer, paid for the current period (started an hour ago), authority generation current: usable.",
        usable_spec(),
        active_input(live(), current_authority()),
        Expect::Accept(Pin::Outcome),
    )
    .requirements(&[R_LATER_ACCESS, R_RECHECK])
    .build();
    subscription_active_cancellation_scheduled => active_case(
        "subscription-active-cancellation-scheduled",
        "Cancellation scheduled a minute after the pinned clock: the paid period is still honoured.",
        usable_spec(),
        active_input(Some((DelegationSpec { expires_at: fx::NOW + 60, ..DelegationSpec::default() }, fx::PROGRAM)), current_authority()),
        Expect::Accept(Pin::Outcome),
    )
    .requirements(&[R_LATER_ACCESS])
    .build();
    subscription_active_cancelled_now_reject => active_case(
        "subscription-active-cancelled-now-reject",
        "delegation.expires_at_ts equals the pinned clock: cancellation has taken effect.",
        usable_spec(),
        active_input(Some((DelegationSpec { expires_at: fx::NOW, ..DelegationSpec::default() }, fx::PROGRAM)), current_authority()),
        inactive(),
    )
    .requirements(&[R_LATER_ACCESS, R_CANCELLED])
    .build();
    subscription_active_last_second_of_period => active_case(
        "subscription-active-last-second-of-period",
        "The pinned clock is the last second of the paid period [start, start + 720h): still usable.",
        spec(SOL, "Server Accounting and Idempotency", "Period 0: [anchor, anchor + mappedPeriodSeconds)"),
        active_input(Some((DelegationSpec { period_start: fx::NOW - 720 * 3600 + 1, ..DelegationSpec::default() }, fx::PROGRAM)), current_authority()),
        Expect::Accept(Pin::Outcome),
    )
    .requirements(&[R_LATER_ACCESS])
    .build();
    subscription_active_period_ended_reject => active_case(
        "subscription-active-period-ended-reject",
        "The paid period ended exactly at the pinned clock (end is exclusive) and the next one is not charged.",
        spec(SOL, "Server Accounting and Idempotency", "Period 0: [anchor, anchor + mappedPeriodSeconds)"),
        active_input(Some((DelegationSpec { period_start: fx::NOW - 720 * 3600, ..DelegationSpec::default() }, fx::PROGRAM)), current_authority()),
        inactive(),
    )
    .requirements(&[R_LATER_ACCESS, R_RECHECK])
    .build();
    subscription_active_unpaid_period_reject => active_case(
        "subscription-active-unpaid-period-reject",
        "amount_pulled_in_period is zero: the current period was never charged.",
        spec(SOL, "Subscription Bearer Proof", "It becomes invalid when cancellation takes effect, subscriptionExpires is reached, the delegation or its authority is invalidated, or the current billing period is not paid."),
        active_input(Some((DelegationSpec { amount_pulled: 0, ..DelegationSpec::default() }, fx::PROGRAM)), current_authority()),
        inactive(),
    )
    .requirements(&[R_RECHECK])
    .build();
    subscription_active_authority_reinitialized_reject => active_case(
        "subscription-active-authority-reinitialized-reject",
        "The subscriber closed and reopened their SubscriptionAuthority: its init_id (78) no longer equals the delegation's (77).",
        spec(SOL, "Server Accounting and Idempotency", "A missing authority or mismatched incarnation invalidates the subscription."),
        active_input(live(), Some((fx::INIT_ID + 1, fx::PROGRAM))),
        inactive(),
    )
    .requirements(&[R_LATER_ACCESS])
    .build();
    subscription_active_authority_missing_reject => active_case(
        "subscription-active-authority-missing-reject",
        "The SubscriptionAuthority account is closed.",
        spec(SOL, "Server Accounting and Idempotency", "A missing authority or mismatched incarnation invalidates the subscription."),
        active_input(live(), None),
        inactive(),
    )
    .requirements(&[R_LATER_ACCESS])
    .build();
    subscription_active_authority_foreign_owner_reject => active_case(
        "subscription-active-authority-foreign-owner-reject",
        "An account at the authority PDA, but owned by another program.",
        spec(SOL, "Account Ownership and Program-ID Validation", "Before deserializing or mutating any account, implementations MUST validate the expected program owner for:"),
        active_input(live(), Some((fx::INIT_ID, fx::FOREIGN_PROGRAM))),
        inactive(),
    )
    .requirements(&[R_OWNER_FIRST, R_LATER_ACCESS])
    .build();
    subscription_active_delegation_missing_reject => active_case(
        "subscription-active-delegation-missing-reject",
        "No SubscriptionDelegation at the derived PDA: a derivable address is not evidence of a subscription.",
        spec(SOL, "Subscription Bearer Proof", "A signature over a derivable PDA whose account does not exist is not evidence of an active subscription."),
        active_input(None, current_authority()),
        inactive(),
    )
    .requirements(&[R_LATER_ACCESS])
    .build();
    subscription_active_delegation_foreign_owner_reject => active_case(
        "subscription-active-delegation-foreign-owner-reject",
        "Delegation bytes at the derived PDA, owned by another program.",
        spec(SOL, "Account Ownership and Program-ID Validation", "Before deserializing or mutating any account, implementations MUST validate the expected program owner for:"),
        active_input(Some((DelegationSpec::default(), fx::FOREIGN_PROGRAM)), current_authority()),
        inactive(),
    )
    .requirements(&[R_OWNER_FIRST, R_LATER_ACCESS])
    .build();
    subscription_active_delegation_other_plan_reject => active_case(
        "subscription-active-delegation-other-plan-reject",
        "The delegation at the derived address names another plan as delegatee.",
        spec(SOL, "Server Accounting and Idempotency", "Verify the SubscriptionDelegation account exists, is owned by methodDetails.subscriptionProgram, has the expected discriminator and version, and still identifies the bound plan and payer."),
        active_input(Some((DelegationSpec { plan: fx::ATTACKER.into(), ..DelegationSpec::default() }, fx::PROGRAM)), current_authority()),
        inactive(),
    )
    .requirements(&[R_LATER_ACCESS])
    .build();
    subscription_active_delegation_wrong_version_reject => active_case(
        "subscription-active-delegation-wrong-version-reject",
        "The delegation header carries version 2.",
        spec(SOL, "Server Accounting and Idempotency", "Verify the SubscriptionDelegation account exists, is owned by methodDetails.subscriptionProgram, has the expected discriminator and version, and still identifies the bound plan and payer."),
        active_input(Some((DelegationSpec { version: 2, ..DelegationSpec::default() }, fx::PROGRAM)), current_authority()),
        inactive(),
    )
    .requirements(&[R_LATER_ACCESS])
    .build();

    // ── verify (server): bearer proof ──────────────────────────────────────
    subscription_proof_valid => proof_case(
        "subscription-proof-valid",
        "A proof by the subscriber over (challengeId, payer, delegation) verifies against that delegation.",
        sample_authentication(),
        fx::delegation(),
        Expect::Accept(Pin::Outcome),
    )
    .requirements(&[R_VERIFY_PROOF, R_ACTIVATION_PROOF])
    .build();
    subscription_proof_other_delegation_reject => proof_case(
        "subscription-proof-other-delegation-reject",
        "The same proof presented for another delegation.",
        sample_authentication(),
        fx::delegation_of(&fx::plan(), &fx::stranger()),
        proof_rejected(),
    )
    .requirements(&[R_VERIFY_PROOF])
    .build();
    subscription_proof_other_signer_reject => proof_case(
        "subscription-proof-other-signer-reject",
        "Signed by another key, but naming the subscriber as payer.",
        {
            let mut a = proof(fx::STRANGER_SEED, fx::CHALLENGE_ID, &fx::delegation());
            a["payer"] = json!(fx::SUBSCRIBER);
            a
        },
        fx::delegation(),
        proof_rejected(),
    )
    .requirements(&[R_VERIFY_PROOF])
    .build();
    subscription_proof_tampered_signature_reject => proof_case(
        "subscription-proof-tampered-signature-reject",
        "One byte of the signature flipped.",
        {
            let mut a = sample_authentication();
            let mut sig = bs58::decode(a["signature"].as_str().unwrap()).into_vec().unwrap();
            sig[10] ^= 0x80;
            a["signature"] = json!(bs58::encode(sig).into_string());
            a
        },
        fx::delegation(),
        proof_rejected(),
    )
    .requirements(&[R_VERIFY_PROOF])
    .build();
    subscription_proof_challenge_id_altered_reject => proof_case(
        "subscription-proof-challenge-id-altered-reject",
        "challengeId changed after signing: the signed subscriptionChallengeId no longer matches.",
        {
            let mut a = sample_authentication();
            a["challengeId"] = json!("c3ViX3NvbGFuYV8wMQ");
            a
        },
        fx::delegation(),
        proof_rejected(),
    )
    .requirements(&[R_VERIFY_PROOF])
    .build();
    subscription_proof_invalid_payer_reject => proof_case(
        "subscription-proof-invalid-payer-reject",
        "payer is not a base58 Ed25519 public key.",
        {
            let mut a = sample_authentication();
            a["payer"] = json!("not-a-public-key");
            a
        },
        fx::delegation(),
        proof_rejected(),
    )
    .requirements(&[R_VERIFY_PROOF])
    .build();
}
