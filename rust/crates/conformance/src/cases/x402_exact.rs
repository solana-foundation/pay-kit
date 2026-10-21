//! x402 `exact` (SVM) cases: client envelope builds against the fixture RPC,
//! and server verifies of payment headers whose transaction is in the
//! scheme_exact_svm §3.1 static layout, valid, mutated or lying about the
//! route in `accepted`.

use serde_json::{json, Value};

use super::{client_secret, mints};
use crate::case::{
    spec, BugType, Case, CaseBuilder, Expect, Input, Intent, Mode, Pin, RejectCode, Role, SpecRef,
    Suite, X402HeaderSpec, X402Payment, X402Route,
};
use crate::keys::{
    BLOCKHASH, DEVNET_CAIP2, MAINNET_CAIP2, MAINNET_USDC, MINT, OTHER_MINT, TOKEN_PROGRAM,
    X402_OFFER_FEE_PAYER, X402_OTHER_PAY_TO, X402_PAY_TO,
};
use crate::mutate::Mutation;

const V2: &str = "x402/specs/x402-specification-v2.md";
const V1: &str = "x402/specs/x402-specification-v1.md";
pub(super) const SVM: &str = "x402/specs/schemes/exact/scheme_exact_svm.md";
const EXACT: &str = "x402/specs/schemes/exact/scheme_exact.md";
const PID: &str = "x402/specs/extensions/payment_identifier.md";

const PROOF_IN_PAYLOAD: &str = "X402-f870a56d25";
pub(super) const CLIENT_MEMO: &str = "X402-6b3e9350c8";
pub(super) const EXACTLY_ONE: &str = "X402-ee90546220";
const ZERO_MATCHING: &str = "X402-bac6bc288a";
const MORE_THAN_ONE: &str = "X402-2f0d5ef017";
const NOT_LESS: &str = "X402-516a2d7b57";
const FEE_PAYER_NOT_AUTHORITY: &str = "X402-ed41478ffe";
pub(super) const FEE_PAYER_NOT_IN_ACCOUNTS: &str = "X402-6708749c55";
pub(super) const MEMO_ENFORCED: &str = "X402-c9a227ad88";
const DESTINATION: &str = "X402-f45fed3f51";
pub(super) const SPONSOR_BEFORE_SIGNING: &str = "X402-93650bf2e3";

pub(super) fn offer(network: &str, amount: &str, asset: &str, timeout: u64) -> Value {
    json!({
        "scheme": "exact",
        "network": network,
        "amount": amount,
        "asset": asset,
        "payTo": X402_PAY_TO,
        "maxTimeoutSeconds": timeout,
        "extra": { "feePayer": X402_OFFER_FEE_PAYER }
    })
}

pub(super) fn build_input(version: Option<u64>, offer: Value, mint: &str, extra: Value) -> Value {
    let mut input = json!({
        "x402Offer": offer,
        "signerSecretKey": client_secret(),
        "rpcFixtures": { "recentBlockhash": BLOCKHASH, "mints": mints(&[(mint, TOKEN_PROGRAM, 6)]) },
    });
    if let Some(version) = version {
        input["x402Version"] = json!(version);
    }
    if let Value::Object(extra) = extra {
        for (k, v) in extra {
            input[k] = v;
        }
    }
    input
}

const BUILD_NOTE: &str = " Offer per scheme_exact_svm.md: extra.feePayer is required, decimals come from the mint account (fixture RPC), and the client builds and signs a real transfer.";

pub(super) const V2_SHAPE: [&str; 8] = [
    "x402Version",
    "hasAccepted",
    "payloadHasTransaction",
    "acceptedScheme",
    "acceptedNetwork",
    "acceptedAsset",
    "acceptedPayTo",
    "acceptedAmount",
];
const V1_SHAPE: [&str; 5] = [
    "x402Version",
    "scheme",
    "network",
    "hasAccepted",
    "payloadHasTransaction",
];

#[allow(clippy::too_many_arguments)]
pub(super) fn build_case(
    id: &str,
    file: &'static str,
    spec: SpecRef,
    reqs: &[&str],
    description: &str,
    input: Value,
    pin: Vec<&'static str>,
) -> Case {
    CaseBuilder::new(
        id,
        file,
        Suite::X402Exact,
        Intent::X402Exact,
        Mode::BuildTransaction,
        Role::Client,
        BugType::Wire,
        spec,
        &format!("{description}{BUILD_NOTE}"),
        Input::Static(input),
        Expect::Accept(Pin::Envelope(pin)),
    )
    .requirements(reqs)
    .build()
}

pub(super) fn devnet_route() -> X402Route {
    X402Route {
        network: "devnet",
        recipient: X402_PAY_TO,
        currency: MINT,
        amount: "1000",
        memo: None,
    }
}

pub(super) fn header(route: X402Route) -> X402HeaderSpec {
    X402HeaderSpec {
        route,
        version: 2,
        v1_network: None,
        accepted_overrides: vec![],
        extensions: None,
        pays: None,
        memo: None,
        mutation: None,
        extra_input: vec![],
        tx_format: crate::tx::MessageFormat::V0,
        server_transaction_versions: None,
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn verify_case(
    id: &str,
    file: &'static str,
    bug: BugType,
    spec: SpecRef,
    reqs: &[&str],
    description: &str,
    header: X402HeaderSpec,
    expect: Expect,
) -> CaseBuilder {
    let description = match &header.mutation {
        Some(m) => format!("{description} Mutation: {}.", m.describe()),
        None => description.to_string(),
    };
    CaseBuilder::new(
        id,
        file,
        Suite::X402Exact,
        Intent::X402Exact,
        Mode::VerifyTransaction,
        Role::Server,
        bug,
        spec,
        &description,
        Input::X402Header(Box::new(header)),
        expect,
    )
    .requirements(reqs)
}

/// A mutated verify case; the code comes from the operator table.
pub(super) fn mutation_case(
    id: &str,
    spec: SpecRef,
    reqs: &[&str],
    description: &str,
    mutation: Mutation,
) -> CaseBuilder {
    let code = mutation
        .expected(Suite::X402Exact)
        .unwrap_or_else(|| panic!("{id}: {mutation:?} has no x402 reject code"));
    let mut spec_header = header(devnet_route());
    spec_header.mutation = Some(mutation);
    verify_case(
        id,
        "x402-verify-mutations.json",
        BugType::Settlement,
        spec,
        reqs,
        description,
        spec_header,
        Expect::Reject { code, reason: None },
    )
}

pub(super) fn reject(code: RejectCode, reason: &str) -> Expect {
    Expect::Reject {
        code,
        reason: Some(reason.to_string()),
    }
}

fn v2_accepted_spec() -> SpecRef {
    spec(
        V2,
        "5.2.2 Field Descriptions (PaymentPayload)",
        "| accepted | object | Required | PaymentRequirements object indicating the payment method chosen |",
    )
}

fn echo_spec() -> SpecRef {
    spec(
        V2,
        "5.1.2 Field Descriptions (PaymentRequired)",
        "The client must include at least the info received; it may append additional info but cannot delete or overwrite existing info.",
    )
}

fn v1_route(network: &'static str, currency: &'static str, amount: &'static str) -> X402Route {
    X402Route {
        network,
        recipient: X402_PAY_TO,
        currency,
        amount,
        memo: None,
    }
}

fn v1_header(route: X402Route, version: u64, slug: &'static str) -> X402HeaderSpec {
    let mut h = header(route);
    h.version = version;
    h.v1_network = Some(slug);
    h
}

fn payment_identifier_header(extension_info: Value) -> X402HeaderSpec {
    let mut h = header(devnet_route());
    h.extensions = Some(json!({ "payment-identifier": { "info": extension_info } }));
    h.extra_input = vec![("x402ServerRequiresPaymentIdentifier", json!(true))];
    h
}

fn lie(field: &'static str, value: &'static str, pays: X402Payment) -> X402HeaderSpec {
    let mut h = header(devnet_route());
    h.accepted_overrides = vec![(field, json!(value))];
    h.pays = Some(pays);
    h
}

crate::registry! {
    x402_exact_v2_build => build_case(
        "x402-exact-v2-build",
        "x402-build.json",
        v2_accepted_spec(),
        &[PROOF_IN_PAYLOAD, CLIENT_MEMO],
        "Client builds a v2 PAYMENT-SIGNATURE envelope from a devnet USDC offer. Asserts the canonical v2 shape: x402Version=2, hasAccepted=true, accepted echoes the offer (scheme/network/asset/payTo/amount), payloadHasTransaction=true, and NO top-level scheme/network (v2 must not leak the legacy fields).",
        build_input(Some(2), offer(DEVNET_CAIP2, "1000", MINT, 300), MINT, json!({})),
        V2_SHAPE.to_vec(),
    );
    x402_exact_v1_build_devnet => build_case(
        "x402-exact-v1-build-devnet",
        "x402-v1-build.json",
        spec(V1, "5.2.2 Field Descriptions (PaymentPayload)", "Protocol version identifier (must be 1)"),
        &[PROOF_IN_PAYLOAD, CLIENT_MEMO],
        "Client builds a legacy v1 X-PAYMENT envelope from a devnet USDC offer. Asserts the v1 shape: x402Version=1, top-level scheme=\"exact\" and plain network slug \"solana-devnet\" (NOT CAIP-2), payloadHasTransaction=true, and NO accepted object (v1 commits only to scheme+network, unlike v2).",
        build_input(Some(1), offer(DEVNET_CAIP2, "1000", MINT, 60), MINT, json!({})),
        V1_SHAPE.to_vec(),
    );
    x402_exact_v1_build_mainnet_network_name => build_case(
        "x402-exact-v1-build-mainnet-network-name",
        "x402-v1-build.json",
        spec(V1, "5.2.2 Field Descriptions (PaymentPayload)", "Protocol version identifier (must be 1)"),
        &[PROOF_IN_PAYLOAD, CLIENT_MEMO],
        "v1 SVM network-name mapping: a mainnet CAIP-2 offer produces the plain legacy slug \"solana\" (everything not devnet-family maps to \"solana\"). Confirms the producer emits a plain name, never the CAIP-2 string, on the top-level network field.",
        build_input(Some(1), offer(MAINNET_CAIP2, "10000", MAINNET_USDC, 300), MAINNET_USDC, json!({})),
        V1_SHAPE.to_vec(),
    );
    x402_exact_v2_build_default_producer => build_case(
        "x402-exact-v2-build-default-producer",
        "x402-v1-build.json",
        v2_accepted_spec(),
        &[PROOF_IN_PAYLOAD, CLIENT_MEMO],
        "Default producer stays v2: with no version pinned, the client emits a v2 PAYMENT-SIGNATURE envelope (x402Version=2, accepted echoes the offer, NO top-level scheme/network). Guards that adding v1 support does not flip the default emitter.",
        build_input(None, offer(DEVNET_CAIP2, "1000", MINT, 300), MINT, json!({})),
        V2_SHAPE.to_vec(),
    );
    x402_ext_echo_payment_identifier => build_case(
        "x402-ext-echo-payment-identifier",
        "x402-extensions.json",
        echo_spec(),
        &[PROOF_IN_PAYLOAD],
        "(a) Client echoes a server-advertised payment-identifier (info.required=true) and populates a fresh client-side id. The outbound v2 PAYMENT-SIGNATURE carries extensions['payment-identifier'].info with required=true preserved and a generated pay_-shaped id matching ^[A-Za-z0-9_-]{16,128}$. The schema field the server published is echoed verbatim.",
        build_input(Some(2), offer(DEVNET_CAIP2, "1000", MINT, 300), MINT, json!({
            "x402AdvertisedExtensions": { "payment-identifier": { "info": { "required": true }, "schema": { "type": "object", "required": ["id"] } } }
        })),
        [&V2_SHAPE[..], &["hasExtensions", "hasPaymentIdentifier", "paymentIdentifierRequired", "extensionKeys"]].concat(),
    );
    x402_ext_echo_payment_identifier_pinned_id => build_case(
        "x402-ext-echo-payment-identifier-pinned-id",
        "x402-extensions.json",
        echo_spec(),
        &[PROOF_IN_PAYLOAD],
        "Deterministic variant of (a): the vector pins the client id so the echoed payment-identifier.info.id is byte-asserted. Confirms the client appends its id WITHOUT overwriting the server's info.required.",
        build_input(Some(2), offer(DEVNET_CAIP2, "1000", MINT, 300), MINT, json!({
            "x402PaymentIdentifierId": "pay_abcdef1234567890abcdef1234567890",
            "x402AdvertisedExtensions": { "payment-identifier": { "info": { "required": true } } }
        })),
        vec!["x402Version", "hasAccepted", "payloadHasTransaction", "hasExtensions", "hasPaymentIdentifier", "paymentIdentifierRequired", "paymentIdentifierId", "extensionKeys"],
    );
    x402_ext_preserve_unknown_verbatim => build_case(
        "x402-ext-preserve-unknown-verbatim",
        "x402-extensions.json",
        echo_spec(),
        &[PROOF_IN_PAYLOAD],
        "(b) Forward-compat echo-and-append: the server advertises an extension this SDK does not type natively alongside payment-identifier. The client MUST re-emit the unknown extension verbatim. extensionKeys pins that BOTH keys survive, sorted.",
        build_input(Some(2), offer(DEVNET_CAIP2, "1000", MINT, 300), MINT, json!({
            "x402PaymentIdentifierId": "pay_abcdef1234567890abcdef1234567890",
            "x402AdvertisedExtensions": { "payment-identifier": { "info": { "required": true } }, "future-extension": { "info": { "foo": "bar" } } }
        })),
        vec!["x402Version", "hasAccepted", "payloadHasTransaction", "hasExtensions", "hasPaymentIdentifier", "paymentIdentifierRequired", "paymentIdentifierId", "extensionKeys"],
    );
    x402_ext_omit_when_none_advertised => build_case(
        "x402-ext-omit-when-none-advertised",
        "x402-extensions.json",
        echo_spec(),
        &[PROOF_IN_PAYLOAD],
        "(c) Echo-and-omit: the server advertised NO extensions, so the outbound v2 PAYMENT-SIGNATURE MUST NOT carry an `extensions` key at all (no empty {}).",
        build_input(Some(2), offer(DEVNET_CAIP2, "1000", MINT, 300), MINT, json!({})),
        vec!["x402Version", "hasAccepted", "payloadHasTransaction", "hasExtensions", "hasPaymentIdentifier", "extensionKeys"],
    );
    x402_exact_v2_verify_accept => verify_case(
        "x402-exact-v2-verify-accept",
        "x402-verify.json",
        BugType::Settlement,
        spec(SVM, "1.4 Exactly One Matching Transfer (MUST)", "Across all top-level instructions and the full CPI trace, exactly one transfer MUST match the requirements (correct mint, correct destination ATA, amount >= required)."),
        &[EXACTLY_ONE, PROOF_IN_PAYLOAD],
        "Server accepts a v2 PAYMENT-SIGNATURE whose accepted offer matches the configured devnet route (network/amount/recipient/asset all agree) and whose transaction is a valid §3.1 static-layout payment. Positive control for every x402 verify reject in x402-verify-mutations.json.",
        header(devnet_route()),
        Expect::Accept(Pin::Envelope(vec!["x402Version", "hasAccepted", "payloadHasTransaction", "acceptedNetwork", "acceptedAmount", "acceptedPayTo", "acceptedAsset"])),
    )
    .build();
    x402_exact_unknown_version_reject => verify_case(
        "x402-exact-unknown-version-reject",
        "x402-verify.json",
        BugType::Wire,
        spec(V2, "5.1.2 Field Descriptions (PaymentRequired)", "Protocol version identifier (must be 2)"),
        &[PROOF_IN_PAYLOAD],
        "Server rejects an envelope carrying x402Version=3 (neither legacy v1 nor canonical v2). The reject category is unsupported-version: a server that silently accepted an unknown version would settle a payment whose wire contract it does not understand.",
        X402HeaderSpec { version: 3, ..header(devnet_route()) },
        reject(RejectCode::UnsupportedVersion, "x402Version 3 is neither v1 nor v2"),
    )
    .build();
    x402_exact_v1_verify_accept_devnet => verify_case(
        "x402-exact-v1-verify-accept-devnet",
        "x402-v1-verify.json",
        BugType::Wire,
        spec(V1, "5.2.2 Field Descriptions (PaymentPayload)", "Protocol version identifier (must be 1)"),
        &[PROOF_IN_PAYLOAD],
        "Server accepts a legacy v1 X-PAYMENT envelope (x402Version=1, top-level scheme=\"exact\" + plain network \"solana-devnet\", payload.transaction) against a devnet route. v1 has no accepted object: the server binds only scheme + network, then verifies the transaction. The decoded shape carries scheme/network and hasAccepted=false.",
        v1_header(v1_route("devnet", MINT, "1000"), 1, "solana-devnet"),
        Expect::Accept(Pin::Envelope(V1_SHAPE.to_vec())),
    )
    .build();
    x402_exact_v1_verify_accept_mainnet => verify_case(
        "x402-exact-v1-verify-accept-mainnet",
        "x402-v1-verify.json",
        BugType::Wire,
        spec(V1, "5.2.2 Field Descriptions (PaymentPayload)", "Protocol version identifier (must be 1)"),
        &[PROOF_IN_PAYLOAD],
        "v1 SVM network-name mapping on the server side: a v1 credential with plain network \"solana\" verifies against a mainnet-beta route. The server normalizes \"solana\" -> mainnet CAIP-2 before the network gate, so the plain legacy slug is accepted.",
        v1_header(v1_route("mainnet-beta", MAINNET_USDC, "10000"), 1, "solana"),
        Expect::Accept(Pin::Envelope(V1_SHAPE.to_vec())),
    )
    .build();
    x402_exact_v1_verify_reject_unknown_version => verify_case(
        "x402-exact-v1-verify-reject-unknown-version",
        "x402-v1-verify.json",
        BugType::Wire,
        spec(V1, "5.2.2 Field Descriptions (PaymentPayload)", "Protocol version identifier (must be 1)"),
        &[PROOF_IN_PAYLOAD],
        "Server still REJECTS a genuinely-unknown version even on the v1 dual-accept path: an envelope shaped like v1 (top-level scheme/network) but carrying x402Version=9 is neither v1 nor v2. Adding v1 support must not widen the version gate.",
        v1_header(v1_route("devnet", MINT, "1000"), 9, "solana-devnet"),
        reject(RejectCode::UnsupportedVersion, "x402Version 9 is neither v1 nor v2"),
    )
    .build();
    x402_exact_v1_verify_reject_wrong_network => verify_case(
        "x402-exact-v1-verify-reject-wrong-network",
        "x402-v1-verify.json",
        BugType::Wire,
        spec(V1, "5.2.2 Field Descriptions (PaymentPayload)", "Protocol version identifier (must be 1)"),
        &[PROOF_IN_PAYLOAD],
        "Server rejects a v1 credential signed for the wrong network: a v1 envelope with plain network \"solana\" (mainnet) presented to a devnet route fails the v1 network gate.",
        v1_header(v1_route("devnet", MINT, "1000"), 1, "solana"),
        reject(RejectCode::WrongNetwork, "v1 network solana normalizes to mainnet, route is devnet"),
    )
    .build();
    x402_ext_server_accepts_valid_id => verify_case(
        "x402-ext-server-accepts-valid-id",
        "x402-extensions.json",
        BugType::Replay,
        spec(PID, "Idempotency Behavior", "required: true, no id provided | Return 400 Bad Request"),
        &[PROOF_IN_PAYLOAD],
        "(e) Server ACCEPTS a credential when payment-identifier.info.required=true on the route and the credential echoed a valid pay_-shaped id.",
        payment_identifier_header(json!({ "required": true, "id": "pay_abcdef1234567890abcdef1234567890" })),
        Expect::Accept(Pin::Envelope(vec![
            "x402Version",
            "hasAccepted",
            "payloadHasTransaction",
            "hasExtensions",
            "hasPaymentIdentifier",
            "paymentIdentifierRequired",
            "paymentIdentifierId",
            "extensionKeys",
        ])),
    )
    .build();
    x402_ext_server_rejects_required_missing_id => verify_case(
        "x402-ext-server-rejects-required-missing-id",
        "x402-extensions.json",
        BugType::Replay,
        spec(PID, "Idempotency Behavior", "required: true, no id provided | Return 400 Bad Request"),
        &[PROOF_IN_PAYLOAD],
        "(d) Server REJECTS a credential when payment-identifier.info.required=true on the route but the credential echoed no valid id (the echoed extension carries info.required but no info.id). All other route fields match, so this isolates the missing-id gate.",
        payment_identifier_header(json!({ "required": true })),
        reject(RejectCode::PaymentIdentifierRequired, "payment-identifier required but credential echoed no id"),
    )
    .build();
    x402_exact_v2_verify_wrong_network_reject => mutation_case(
        "x402-exact-v2-verify-wrong-network-reject",
        spec(V2, "5.1.2 Field Descriptions (PaymentRequired)", "| network | string | Required | Blockchain network identifier in CAIP-2 format (e.g., \"eip155:84532\") |"),
        &[PROOF_IN_PAYLOAD],
        "Server rejects a v2 credential whose accepted.network names mainnet when the route is devnet.",
        Mutation::WrongNetwork { network: MAINNET_CAIP2 },
    )
    .build();
    x402_exact_verify_zero_transfers_reject => mutation_case(
        "x402-exact-verify-zero-transfers-reject",
        spec(SVM, "1.4 Exactly One Matching Transfer (MUST)", "MUST reject if zero matching transfers are found."),
        &[ZERO_MATCHING, EXACTLY_ONE],
        "The transaction carries no TransferChecked at all.",
        Mutation::DropTransfer { transfer: 0 },
    )
    .build();
    x402_exact_verify_two_transfers_reject => mutation_case(
        "x402-exact-verify-two-transfers-reject",
        spec(SVM, "1.4 Exactly One Matching Transfer (MUST)", "MUST reject if more than one matching transfer is found (ambiguous / potential double-payment)."),
        &[MORE_THAN_ONE, EXACTLY_ONE],
        "The transaction carries two identical matching TransferChecked instructions.",
        Mutation::ExtraTransfer { transfer: 0 },
    )
    .build();
    x402_exact_verify_underpayment_reject => mutation_case(
        "x402-exact-verify-underpayment-reject",
        spec(SVM, "1.4 Exactly One Matching Transfer (MUST)", "A matching transfer MAY exceed PaymentRequirements.amount (overpayment is tolerated to accommodate smart wallets with internal fee rounding); it MUST NOT be less."),
        &[NOT_LESS],
        "The transfer pays one base unit less than the route amount.",
        Mutation::BumpAmount { transfer: 0, delta: -1 },
    )
    .build();
    x402_exact_verify_fee_payer_authority_reject => mutation_case(
        "x402-exact-verify-fee-payer-authority-reject",
        spec(SVM, "2.1.1 Fee Payer Isolation (MUST)", "The feePayer MUST NOT be used as an authority, source, or delegate for any transfer."),
        &[FEE_PAYER_NOT_AUTHORITY, SPONSOR_BEFORE_SIGNING],
        "The sponsor (fee payer) is the TransferChecked authority.",
        Mutation::FeePayerAsAuthority { transfer: 0 },
    )
    .build();
    x402_exact_verify_fee_payer_in_accounts_reject => mutation_case(
        "x402-exact-verify-fee-payer-in-accounts-reject",
        spec(SVM, "2.1.1 Fee Payer Isolation (MUST)", "The feePayer MUST NOT appear in the accounts list of any instruction (top-level or, where resolvable, otherwise referenced), and MUST NOT be invoked as a program."),
        &[FEE_PAYER_NOT_IN_ACCOUNTS, SPONSOR_BEFORE_SIGNING],
        "The sponsor (fee payer) is listed as a signer account of the Memo instruction, so the sponsor's signature would authorize an instruction other than fee payment.",
        Mutation::FeePayerAsAccount { memo: 0 },
    )
    .build();
    x402_exact_verify_memo_match_accept => verify_case(
        "x402-exact-verify-memo-match-accept",
        "x402-verify-mutations.json",
        BugType::Settlement,
        spec(SVM, "3.1 Path 1 — Static Layout Verification (standard wallets)", "If extra.memo is present, the facilitator MUST verify that exactly one Memo instruction exists and that its data matches extra.memo encoded as UTF-8."),
        &[MEMO_ENFORCED],
        "Positive control: the route sets extra.memo (input.x402ServerMemo) and the transaction's single Memo carries it.",
        header(X402Route { memo: Some("pi_conformance_0001"), ..devnet_route() }),
        Expect::Accept(Pin::Envelope(V2_SHAPE.to_vec())),
    )
    .build();
    x402_exact_verify_memo_mismatch_reject => verify_case(
        "x402-exact-verify-memo-mismatch-reject",
        "x402-verify-mutations.json",
        BugType::Settlement,
        spec(SVM, "3.1 Path 1 — Static Layout Verification (standard wallets)", "If extra.memo is present, the facilitator MUST verify that exactly one Memo instruction exists and that its data matches extra.memo encoded as UTF-8."),
        &[MEMO_ENFORCED],
        "The route sets extra.memo (input.x402ServerMemo) but the transaction's Memo carries other text. Mutation: memo #0 replaced with \"pi_conformance_0002\".",
        X402HeaderSpec {
            mutation: Some(Mutation::ReplaceMemo { memo: 0, text: "pi_conformance_0002" }),
            ..header(X402Route { memo: Some("pi_conformance_0001"), ..devnet_route() })
        },
        Expect::Reject { code: RejectCode::InvalidPayload, reason: Some("memo does not match extra.memo".into()) },
    )
    .build();
    x402_exact_verify_overpayment_accept => verify_case(
        "x402-exact-verify-overpayment-accept",
        "x402-verify-mutations.json",
        BugType::Settlement,
        spec(SVM, "1.4 Exactly One Matching Transfer (MUST)", "A matching transfer MAY exceed PaymentRequirements.amount (overpayment is tolerated to accommodate smart wallets with internal fee rounding); it MUST NOT be less."),
        &[NOT_LESS, EXACTLY_ONE],
        "The transfer pays one base unit more than the route amount; §1.4 tolerates overpayment. See RULINGS S5: default verifiers accept overpayment.",
        X402HeaderSpec { mutation: Some(Mutation::OverPay { transfer: 0, delta: 1 }), ..header(devnet_route()) },
        Expect::Accept(Pin::Envelope(vec!["x402Version", "hasAccepted", "payloadHasTransaction"])),
    )
    .build();
    x402_exact_verify_accepted_amount_lie_reject => verify_case(
        "x402-exact-verify-accepted-amount-lie-reject",
        "x402-verify-mutations.json",
        BugType::AuthBypass,
        spec(SVM, "1.4 Exactly One Matching Transfer (MUST)", "A matching transfer MAY exceed PaymentRequirements.amount (overpayment is tolerated to accommodate smart wallets with internal fee rounding); it MUST NOT be less."),
        &[NOT_LESS],
        "Cross-route lie: the credential's accepted.amount claims 1 (a cheaper route) and the transaction pays 1; the route requires 1000. A server that trusts accepted instead of its own route under-charges.",
        lie("amount", "1", X402Payment { recipient: X402_PAY_TO, mint: MINT, amount: "1" }),
        Expect::Reject { code: RejectCode::AcceptedMismatch, reason: Some("accepted.amount differs from the route".into()) },
    )
    .build();
    x402_exact_verify_accepted_payto_lie_reject => verify_case(
        "x402-exact-verify-accepted-payto-lie-reject",
        "x402-verify-mutations.json",
        BugType::AuthBypass,
        spec(EXACT, "SVM", "Destination correctness: the receiver MUST match the payTo derived destination for the specified asset."),
        &[DESTINATION, ZERO_MATCHING],
        "Cross-route lie: the credential's accepted.payTo names another merchant and the transaction pays that merchant; the route's payTo receives nothing.",
        lie("payTo", X402_OTHER_PAY_TO, X402Payment { recipient: X402_OTHER_PAY_TO, mint: MINT, amount: "1000" }),
        Expect::Reject { code: RejectCode::AcceptedMismatch, reason: Some("accepted.payTo differs from the route".into()) },
    )
    .build();
    x402_exact_verify_accepted_asset_lie_reject => verify_case(
        "x402-exact-verify-accepted-asset-lie-reject",
        "x402-verify-mutations.json",
        BugType::AuthBypass,
        spec(EXACT, "SVM", "Destination correctness: the receiver MUST match the payTo derived destination for the specified asset."),
        &[DESTINATION, ZERO_MATCHING],
        "Cross-route lie: the credential's accepted.asset names another mint and the transaction pays in that mint; the route's asset is never transferred.",
        lie("asset", OTHER_MINT, X402Payment { recipient: X402_PAY_TO, mint: OTHER_MINT, amount: "1000" }),
        Expect::Reject { code: RejectCode::AcceptedMismatch, reason: Some("accepted.asset differs from the route".into()) },
    )
    .build();
}
