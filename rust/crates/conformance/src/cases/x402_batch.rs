//! x402 `batch-settlement` (SVM) cases.
//!
//! - canonical bytes: the 50-byte voucher message, the server-mode payer
//!   proof message, the CloseAuthorization digest, the receiver-binding
//!   memo, the channel PDA, and wire round trips of every payload variant;
//! - client builds (deposit, voucher, top-up, refund) and the client's
//!   checks of a challenge's terms and of a corrective 402;
//! - resource-server verification of `voucher`, `deposit` (open and
//!   top-up) and `refund` payloads against a seeded channel store and the
//!   channel / token accounts the fixture RPC serves, including the
//!   sponsor's static transaction acceptance policy;
//! - transaction versions (SIMD-0385, x402-txv1 draft): advertisement,
//!   negotiation and the version-1 policy.
//!
//! Every input is built here from deterministic keys (`realize::batch::fx`):
//! vouchers and transactions are signed by the filler, chain state is the
//! kit's own `Channel` account encoding.

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use solana_instruction::Instruction;

use crate::case::{
    spec, BugType, Case, CaseBuilder, Expect, Input, Intent, Mode, Pin, RejectCode, Role, SpecRef,
    Suite,
};
use crate::keys::{self, MINT, OTHER_MINT, TOKEN_2022_PROGRAM, TOKEN_PROGRAM, X402_PAY_TO};
use crate::realize::batch::fx::{self, Atas, ChannelAccount, Route};

const SVM: &str = "x402/specs/schemes/batch-settlement/scheme_batch_settlement_svm.md";
const TXV1: &str = "x402-txv1/specs/schemes/batch-settlement/scheme_batch_settlement_svm.md";

// ── requirement ids (harness/requirements/x402.toml, x402-txv1.toml) ──

const EVERY_PAID_REQUEST: &str = "X402-a6efa8062a";
const NO_EXPIRY: &str = "X402-2073737c58";
const EXPIRES_ZERO: &str = "X402-d71a021041";
const AUTHORIZER_IS_SIGNER: &str = "X402-5b328b9a73";
const CORRECTIVE_VERIFY: &str = "X402-638126c26b";
const CORRECTIVE_REJECT: &str = "X402-171a57666e";
const AUTH_MESSAGE: &str = "X402-fb76d46cb8";
const AUTH_VERIFY: &str = "X402-2ae0fdc5c6";
const REFUND_AUTH_ZERO: &str = "X402-cee6662254";
const CLOSE_AUTH_VALIDATE: &str = "X402-f5205e3932";
const SELF_MANAGED_CLOSE: &str = "X402-c0dd3bd5b3";
const BINDING_KEY: &str = "X402-063b58b983";
const SERVER_REJECTS_FOREIGN_BINDING: &str = "X402-556df29ac2";
const RA_EQUAL: &str = "X402-91ecad3faa";
const RA_BOTH_PRESENT: &str = "X402-6ac6583e77";
const RECEIVER_IS_PAY_TO: &str = "X402-a2dd2eb911";
const TOKEN_IS_ASSET: &str = "X402-ae5ee4f564";
const WITHDRAW_EQUAL: &str = "X402-f0a4201d93";
const WITHDRAW_RANGE: &str = "X402-7556a4ec7c";
const WITHDRAW_ENFORCED: &str = "X402-180abaa115";
const PAYER_NOT_FEE_PAYER: &str = "X402-d171becfd9";
const AUTHORIZER_NOT_FEE_PAYER: &str = "X402-2f8ea170e2";
const CONFIG_NOT_FEE_PAYER: &str = "X402-13c8fefbbf";
const ACCEPTED_EQUAL: &str = "X402-d29d49ebde";
const VERSION_TWO: &str = "X402-c3d9b43d25";
const PAYLOAD_VARIANTS: &str = "X402-3485cafa46";
const DEPOSIT_VOUCHER: &str = "X402-24cd5fed02";
const REFUND_NO_AMOUNT: &str = "X402-e98b9b9bec";
const REFUND_VOUCHER: &str = "X402-fa34804f1b";
const REFUND_CUMULATIVE: &str = "X402-3679bfc55e";
const REFUND_STATUS: &str = "X402-fbdea947ae";
const BINDING_UNAVAILABLE: &str = "X402-a8645e7833";
const RC_ONE_INSTRUCTION: &str = "X402-a6092f0a02";
const RC_SUFFIX: &str = "X402-5276aee847";
const RC_ACCOUNTS: &str = "X402-d450762477";
const RC_SIGNERS: &str = "X402-c88cc9c766";
const CLOSING: &str = "X402-d167f9a958";
const CLOSE_PENDING: &str = "X402-dcd8fcf77b";
const PAYMENT_FLOW: &str = "X402-bde1322bb3";
const PAYMENT_FLOW_EMIT: &str = "X402-04b1c68ba2";
const OPERATOR_CLIENT_MODE: &str = "X402-df15443ca9";
const NO_GRANT: &str = "X402-f882f2074a";
const OPT_IN: &str = "X402-84916fe051";
const TOKEN_PROGRAM_OWNER: &str = "X402-23747f44c3";
const TOKEN_PROGRAM_VERIFY: &str = "X402-1230bb35a3";
const CLAIMS_ONE_TO_FOUR: &str = "X402-7f4ee54a73";
const SEAL_CLOSE_AUTH: &str = "X402-45c411d301";
const COMMITMENT_ID: &str = "X402-5ebca343d1";
const STATIC_VALIDATE: &str = "X402-4ea8d1b0d9";
const FEE_PAYER_IS_TX_FEE_PAYER: &str = "X402-9d68660de5";
const SIGNER_SET: &str = "X402-f729304bf1";
const PAYER_SIGNATURE: &str = "X402-55d34e173c";
const LAYOUT: &str = "X402-ce3692afe0";
const LIMIT_BEFORE_PRICE: &str = "X402-ae18578132";
const MEMO_DATA: &str = "X402-ebd20058fd";
const CB_DISCRIMINATOR: &str = "X402-683361bbae";
const CB_LIMIT: &str = "X402-b4167aad45";
const CB_PRICE: &str = "X402-a93234f1d7";
const SUFFIX_NO_FEE_PAYER: &str = "X402-3ed2ac9962";
const ALLOWLIST: &str = "X402-897add7b39";
const NO_SMUGGLING: &str = "X402-15a1a9834e";
const TOP_UP_LAYOUT: &str = "X402-be2f5b7ea4";
const TOP_UP_AMOUNT: &str = "X402-06bb8f3a9e";
const TOP_UP_FEE_PAYER: &str = "X402-129e295f0c";
const FULL_DECODE: &str = "X402-176a26e5b6";
const OPEN_ENCODE: &str = "X402-87c5fe8803";
const OPEN_SLOT_WINDOW: &str = "X402-f0d0755fc9";
const NO_DIVERSION: &str = "X402-f265c321e3";
const MEMO_EXACT: &str = "X402-536163eb05";
const SETTLEMENT_ACCOUNTS: &str = "X402-4cedb5114b";
const CLIENT_OPEN: &str = "X402-d16b3abbab";
// x402-txv1 (PR 3473).
const TX_ADVERTISED: &str = "X402TX-4de59a1f27";
const TX_DEPOSIT_VERSION: &str = "X402TX-d444d01b9e";
const TX_REFUND_VERSION: &str = "X402TX-4750df8921";
const TX_FACILITATOR_REJECTS: &str = "X402TX-5267172b18";
const TX_CLIENT_INTERSECT: &str = "X402TX-61c735c7a9";
const TX_CLIENT_EMPTY: &str = "X402TX-2909c4b4ec";
const TX_SIZE: &str = "X402TX-dc7b0f3305";
const TX_V1_BUDGET: &str = "X402TX-644919eb3b";
const TX_V1_CAPS: &str = "X402TX-0f874a9c63";
const TX_V1_NO_CB: &str = "X402TX-936b492daa";
const TX_SERVER_COPIES: &str = "X402TX-f39a33ff74";

// ── spec references ──

fn s(section: &str, quote: &str) -> SpecRef {
    spec(SVM, section, quote)
}

fn t(section: &str, quote: &str) -> SpecRef {
    spec(TXV1, section, quote)
}

fn voucher_layout() -> SpecRef {
    s("4.2 Shared Wire Objects and Program Mapping", "This is the payment-channels program voucher layout (`VOUCHER_MAGIC`, `channel_id`, `cumulative_amount`, `expires_at`), 50 bytes total.")
}
fn auth_layout() -> SpecRef {
    s("4.2 Shared Wire Objects and Program Mapping", "Each decoded address MUST be exactly 32 bytes, and `requestId` MUST encode to 1 through 256 UTF-8 bytes.")
}
fn close_digest_spec() -> SpecRef {
    s(
        "4.2 Shared Wire Objects and Program Mapping",
        "The receiver authorizer signs the SHA-256 digest of this exact byte sequence:",
    )
}
fn binding_spec() -> SpecRef {
    s(
        "3. Payment-Channel Method",
        "a binding Memo whose UTF-8 data is exactly:",
    )
}
fn pda_spec() -> SpecRef {
    s(
        "4.2 Shared Wire Objects and Program Mapping",
        "`channelId` is the program-derived address:",
    )
}
fn variants_spec() -> SpecRef {
    s("4.5 Facilitator Interface", "`paymentPayload.payload` MUST be one of the client-authored `deposit`, `voucher`, `authorization`, or `refund` variants in section 4.3.")
}
fn refund_voucher_spec() -> SpecRef {
    s("4.3 Client PaymentPayload Variants", "| `voucher` | `BatchVoucher` | REQUIRED in client mode. The server's accepted cumulative amount (`expiresAt` MUST be `0`).")
}
fn claims_spec() -> SpecRef {
    s("4.5 Facilitator Interface", "`claims[]` MUST contain between one and four entries so the instruction pairs fit in a legacy Solana transaction without address lookup tables.")
}
fn wire_spec() -> SpecRef {
    s(
        "4.3 Client PaymentPayload Variants",
        "The client payload is a tagged union on `payload.type`.",
    )
}
fn cumulative_spec() -> SpecRef {
    s("Phase 3 - Voucher Acceptance (before serving)", "In client mode, require `maxClaimableAmount == chargedCumulativeAmount + PaymentRequirements.amount` and `maxClaimableAmount <= channel.deposit`.")
}
fn expiry_spec() -> SpecRef {
    s("Phase 3 - Voucher Acceptance (before serving)", "The client MUST sign `expiresAt = 0`, and the server and facilitator MUST reject any voucher with nonzero `expiresAt`.")
}
fn signature_spec() -> SpecRef {
    s("Phase 3 - Voucher Acceptance (before serving)", "In client mode, verify the Ed25519 signature over the 50-byte voucher message using `channelConfig.payerAuthorizer`.")
}
fn channel_id_spec() -> SpecRef {
    s("Phase 3 - Voucher Acceptance (before serving)", "Confirm `channelId` matches the PDA derived from `channelConfig` and the canonical payment-channels program id.")
}
fn bindings_spec() -> SpecRef {
    s("Phase 3 - Voucher Acceptance (before serving)", "Confirm the channel exists, is `Open`, has `mint == channelConfig.token == asset`, `payee == extra.feePayer`")
}
fn closing_spec() -> SpecRef {
    s("4.5 Facilitator Interface", "a `claim` for that channel, and a `voucher` or `authorization` verification against it, MUST fail with `invalid_batch_settlement_svm_channel_closing`.")
}
fn fee_payer_spec() -> SpecRef {
    s(
        "Phase 3 - Voucher Acceptance (before serving)",
        "Reject if `payer` or `payerAuthorizer` equals `feePayer`.",
    )
}
fn ra_spec() -> SpecRef {
    s(
        "Phase 3 - Voucher Acceptance (before serving)",
        "`channelConfig.receiverAuthorizer` MUST equal `extra.receiverAuthorizer` (section 3).",
    )
}
fn accepted_spec() -> SpecRef {
    s(
        "4.5 Facilitator Interface",
        "For every request, `paymentPayload.accepted` MUST equal `paymentRequirements`.",
    )
}
fn policy_spec(quote: &str) -> SpecRef {
    s("Client-supplied transaction acceptance policy", quote)
}
fn top_up_spec() -> SpecRef {
    s("Canonical top_up", "The facilitator MUST confirm the decoded amount equals `payload.deposit.amount`; the channel is `Open`;")
}
fn refund_spec(quote: &str) -> SpecRef {
    s("Canonical refund request_close", quote)
}
fn withdraw_spec() -> SpecRef {
    s("4.1 PaymentRequirements (in PAYMENT-REQUIRED.accepts[])", "MUST be an integer from `900` through `2592000` (15 minutes through 30 days), MUST be `>= maxTimeoutSeconds`")
}
fn corrective_spec() -> SpecRef {
    s("4.6 Corrective PaymentRequired", "The client MUST reject the snapshot when the signature does not verify or when `channelState.chargedCumulativeAmount` exceeds `voucherState.signedMaxClaimable`.")
}
fn tx_versions_spec(quote: &str) -> SpecRef {
    t("Transaction versions", quote)
}

// ── builders ──

#[allow(clippy::too_many_arguments)]
fn case(
    id: &str,
    file: &'static str,
    mode: Mode,
    role: Role,
    bug: BugType,
    spec: SpecRef,
    description: &str,
    input: Value,
    expect: Expect,
) -> CaseBuilder {
    CaseBuilder::new(
        id,
        file,
        Suite::BatchSettlement,
        Intent::X402BatchSettlement,
        mode,
        role,
        bug,
        spec,
        description,
        Input::Static(input),
        expect,
    )
}

fn rej(code: RejectCode) -> Expect {
    Expect::Reject { code, reason: None }
}

fn bytes_pin() -> Expect {
    Expect::Accept(Pin::ExactBytes(vec!["bytes", "base64Url"]))
}

fn json_pin() -> Expect {
    Expect::Accept(Pin::ExactBytes(vec!["canonicalJson", "base64Url"]))
}

fn authored_bytes(bytes: &[u8]) -> Expect {
    use base64::Engine;
    Expect::AcceptAuthored(json!({ "exactBytes": {
        "bytes": bytes,
        "base64Url": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes),
    }}))
}

/// The spec's round trip of a wire value: its own JCS canonical form.
fn authored_json(value: &Value) -> Expect {
    use base64::Engine;
    let json = crate::realize::batch::jcs(value);
    Expect::AcceptAuthored(json!({ "exactBytes": {
        "canonicalJson": json,
        "base64Url": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json.as_bytes()),
    }}))
}

fn route() -> Route {
    Route::default()
}

fn cfg() -> Value {
    fx::config(&route())
}

fn channel(config: &Value) -> String {
    fx::channel_id(config).to_string()
}

fn requirements() -> Value {
    route().requirements()
}

/// A server-verify input.
fn verify_input(
    route: &Route,
    accepted: &Value,
    payload: &Value,
    record: Option<Value>,
    fixtures: Value,
) -> Value {
    let mut input = json!({
        "batchServer": route.server_json(),
        "batchRequirements": route.requirements(),
        "x402PaymentHeader": fx::header(accepted, payload),
        "rpcFixtures": fixtures,
    });
    if let Some(record) = record {
        input["batchServerChannel"] = record;
    }
    input
}

fn voucher_payload(config: &Value, voucher: Value) -> Value {
    json!({ "type": "voucher", "channelConfig": config, "voucher": voucher })
}

/// A `voucher` payload for `config` at `cumulative`, against a channel the
/// server has charged `charged` and whose deposit is `deposit` (store and
/// chain agree).
fn voucher_input(
    config: &Value,
    voucher: Value,
    charged: u64,
    deposit: u64,
    account: ChannelAccount,
) -> Value {
    let honest = cfg();
    let account = ChannelAccount { deposit, ..account };
    verify_input(
        &route(),
        &requirements(),
        &voucher_payload(config, voucher),
        Some(fx::store_record(&honest, charged, deposit)),
        fx::rpc_fixtures(Some((&honest, &account)), Atas::Healthy, TOKEN_PROGRAM),
    )
}

fn honest_voucher(cumulative: u64) -> Value {
    fx::voucher(&channel(&cfg()), cumulative, 0, fx::PAYER_SEED)
}

fn voucher_case(
    id: &str,
    spec: SpecRef,
    bug: BugType,
    description: &str,
    input: Value,
    expect: Expect,
) -> CaseBuilder {
    case(
        id,
        "batch-verify-voucher.json",
        Mode::VerifyTransaction,
        Role::Server,
        bug,
        spec,
        description,
        input,
        expect,
    )
}

fn with(mut value: Value, key: &str, new: Value) -> Value {
    value[key] = new;
    value
}

fn without(mut value: Value, key: &str) -> Value {
    value.as_object_mut().unwrap().remove(key);
    value
}

// Top-up: the server charged 3000 of a 4000 deposit; the client adds 6000
// and authorizes the next request (4000 <= 10000).
const TOP_UP_CHARGED: u64 = 3_000;
const TOP_UP_DEPOSIT: u64 = 4_000;
const TOP_UP_AMOUNT_ADDED: u64 = 6_000;

fn top_up_tx(prefix: Vec<Instruction>, amount: u64, suffix: Vec<Instruction>) -> String {
    let mut ixs = prefix;
    ixs.push(fx::top_up_ix(&cfg(), amount));
    ixs.extend(suffix);
    fx::sponsored(ixs)
}

fn memo() -> Vec<Instruction> {
    vec![fx::memo_ix(fx::MEMO)]
}

fn top_up_input_with(
    route: &Route,
    transaction: String,
    amount: &str,
    cumulative: u64,
    atas: Atas,
    mint_owner: &str,
) -> Value {
    let config = fx::config(route);
    let payload = json!({
        "type": "deposit",
        "channelConfig": config,
        "voucher": fx::voucher(&channel(&config), cumulative, 0, fx::PAYER_SEED),
        "deposit": { "amount": amount, "transaction": transaction },
    });
    let account = ChannelAccount {
        deposit: TOP_UP_DEPOSIT,
        ..Default::default()
    };
    verify_input(
        route,
        &route.requirements(),
        &payload,
        Some(fx::store_record(&config, TOP_UP_CHARGED, TOP_UP_DEPOSIT)),
        fx::rpc_fixtures(Some((&config, &account)), atas, mint_owner),
    )
}

fn top_up_input(transaction: String) -> Value {
    top_up_input_with(
        &route(),
        transaction,
        &TOP_UP_AMOUNT_ADDED.to_string(),
        TOP_UP_CHARGED + fx::AMOUNT,
        Atas::Healthy,
        TOKEN_PROGRAM,
    )
}

fn policy_case(
    id: &str,
    spec: SpecRef,
    reqs: &[&str],
    description: &str,
    transaction: String,
    expect: Expect,
) -> Case {
    case(
        id,
        "batch-verify-setup-policy.json",
        Mode::VerifyTransaction,
        Role::Server,
        BugType::AuthBypass,
        spec,
        description,
        top_up_input(transaction),
        expect,
    )
    .requirements(reqs)
    .build()
}

/// An `open` deposit: no stored record, no channel onchain yet.
fn open_input(transaction: String) -> Value {
    let config = cfg();
    let payload = json!({
        "type": "deposit",
        "channelConfig": config,
        "voucher": honest_voucher(fx::AMOUNT),
        "deposit": { "amount": "10000", "transaction": transaction },
    });
    verify_input(
        &route(),
        &requirements(),
        &payload,
        None,
        fx::rpc_fixtures(None, Atas::Healthy, TOKEN_PROGRAM),
    )
}

fn open_suffix() -> Vec<Instruction> {
    vec![
        fx::memo_ix(fx::MEMO),
        fx::memo_ix(&fx::binding_memo(&fx::receiver_authorizer())),
    ]
}

fn open_tx(open: Instruction, suffix: Vec<Instruction>) -> String {
    let mut ixs = vec![open];
    ixs.extend(suffix);
    fx::sponsored(ixs)
}

fn honest_open() -> Instruction {
    fx::open_ix(&cfg(), 10_000, X402_PAY_TO)
}

fn open_case(
    id: &str,
    spec: SpecRef,
    reqs: &[&str],
    description: &str,
    transaction: String,
    expect: Expect,
) -> CaseBuilder {
    case(
        id,
        "batch-verify-open.json",
        Mode::VerifyTransaction,
        Role::Server,
        BugType::AuthBypass,
        spec,
        description,
        open_input(transaction),
        expect,
    )
    .requirements(reqs)
}

/// A client-mode refund: the accepted voucher (charged 3000) and, as on a
/// retry after `receiver_binding_unavailable`, a request_close.
fn refund_input_with(payload: Value, account: ChannelAccount) -> Value {
    let config = cfg();
    verify_input(
        &route(),
        &requirements(),
        &payload,
        Some(fx::store_record(&config, 3_000, 10_000)),
        fx::rpc_fixtures(Some((&config, &account)), Atas::Healthy, TOKEN_PROGRAM),
    )
}

fn request_close(suffix: Vec<Instruction>) -> String {
    let mut ixs = vec![fx::request_close_ix(&cfg())];
    ixs.extend(suffix);
    fx::sponsored(ixs)
}

fn refund_payload(voucher: Option<Value>, transaction: Option<String>) -> Value {
    let mut payload = json!({ "type": "refund", "channelConfig": cfg() });
    if let Some(voucher) = voucher {
        payload["voucher"] = voucher;
    }
    if let Some(transaction) = transaction {
        payload["transaction"] = json!(transaction);
    }
    payload
}

fn refund_case(
    id: &str,
    spec: SpecRef,
    reqs: &[&str],
    description: &str,
    transaction: String,
    expect: Expect,
) -> Case {
    case(
        id,
        "batch-verify-refund.json",
        Mode::VerifyTransaction,
        Role::Server,
        BugType::AuthBypass,
        spec,
        description,
        refund_input_with(
            refund_payload(Some(honest_voucher(3_000)), Some(transaction)),
            ChannelAccount::default(),
        ),
        expect,
    )
    .requirements(reqs)
    .authored(None)
    .build()
}

/// A client build.
fn build_input(operation: &str, requirements: Value, extra: Value) -> Value {
    let mut client = json!({
        "secretKey": keys::secret_json(fx::PAYER_SEED),
        "requirements": requirements,
        "operation": operation,
        "blockhash": keys::BLOCKHASH,
    });
    if let Value::Object(extra) = extra {
        for (k, v) in extra {
            client[k] = v;
        }
    }
    json!({ "batchClient": client })
}

fn tracked_channel(charged: u64, deposit: u64) -> Value {
    json!({
        "channelConfig": cfg(),
        "chargedCumulativeAmount": charged.to_string(),
        "deposit": deposit.to_string(),
    })
}

/// A build the judge verifies against the server: the server config, its
/// stored record and the chain state ride along.
fn judged_build(
    operation: &str,
    route: &Route,
    client: Value,
    charged: u64,
    deposit: u64,
    account_deposit: u64,
) -> Value {
    let config = fx::config(route);
    let account = ChannelAccount {
        deposit: account_deposit,
        ..Default::default()
    };
    let mut input = build_input(operation, route.requirements(), client);
    input["batchServer"] = route.server_json();
    input["batchServerChannel"] = fx::store_record(&config, charged, deposit);
    input["rpcFixtures"] =
        fx::rpc_fixtures(Some((&config, &account)), Atas::Healthy, TOKEN_PROGRAM);
    input
}

fn terms_input(requirements: Value, mint_owner: &str) -> Value {
    let mut input = build_input(
        "deposit",
        requirements,
        json!({ "depositAmount": "10000", "openSlot": fx::OPEN_SLOT }),
    );
    input["rpcFixtures"] = fx::rpc_fixtures(None, Atas::Healthy, mint_owner);
    input
}

fn requirements_with(extra: &[(&str, Value)]) -> Value {
    let mut r = requirements();
    for (k, v) in extra {
        r["extra"][*k] = v.clone();
    }
    r
}

fn terms_case_authored(
    id: &str,
    spec: SpecRef,
    reqs: &[&str],
    description: &str,
    input: Value,
    expect: Expect,
) -> Case {
    case(
        id,
        "batch-build.json",
        Mode::BuildTransaction,
        Role::Client,
        BugType::Defaults,
        spec,
        description,
        input,
        expect,
    )
    .requirements(reqs)
    .authored(None)
    .build()
}

fn terms_case(
    id: &str,
    spec: SpecRef,
    reqs: &[&str],
    description: &str,
    input: Value,
    expect: Expect,
) -> Case {
    case(
        id,
        "batch-build.json",
        Mode::BuildTransaction,
        Role::Client,
        BugType::Defaults,
        spec,
        description,
        input,
        expect,
    )
    .requirements(reqs)
    .build()
}

fn corrective_input(
    charged: u64,
    signed: u64,
    expires_at: i64,
    seed: [u8; 32],
    channel_id: Option<String>,
    proof: bool,
) -> Value {
    let ch = channel(&cfg());
    let mut r = requirements();
    r["extra"]["channelState"] = json!({
        "channelId": channel_id.clone().unwrap_or_else(|| ch.clone()),
        "balance": "10000",
        "totalClaimed": "2000",
        "withdrawRequestedAt": 0,
        "chargedCumulativeAmount": charged.to_string(),
    });
    if proof {
        r["extra"]["voucherState"] = json!({
            "signedMaxClaimable": signed.to_string(),
            "expiresAt": expires_at,
            "signature": fx::sign_voucher(&ch, signed, expires_at, seed),
        });
    }
    json!({ "batchCorrective": { "requirements": r, "channel": tracked_channel(1_000, 10_000) } })
}

fn corrective_case(id: &str, description: &str, input: Value, expect: Expect) -> Case {
    case(
        id,
        "batch-corrective.json",
        Mode::VerifyTransaction,
        Role::Client,
        BugType::Settlement,
        corrective_spec(),
        description,
        input,
        expect,
    )
    .requirements(&[CORRECTIVE_VERIFY, CORRECTIVE_REJECT])
    .build()
}

fn close_digest(
    network: &str,
    program: &str,
    fee_payer: &str,
    channel: &str,
    max: u64,
    voucher_expires_at: i64,
    valid_before: i64,
) -> Vec<u8> {
    let mut message = b"x402:batch-settlement:svm:close:v1".to_vec();
    message.push(0);
    message.extend_from_slice(&(network.len() as u16).to_le_bytes());
    message.extend_from_slice(network.as_bytes());
    for key in [program, fee_payer, channel] {
        message.extend_from_slice(keys::pubkey(key).as_ref());
    }
    message.extend_from_slice(&max.to_le_bytes());
    message.extend_from_slice(&voucher_expires_at.to_le_bytes());
    message.extend_from_slice(&valid_before.to_le_bytes());
    Sha256::digest(&message).to_vec()
}

fn close_digest_input(network: &str, max: u64, valid_before: i64) -> Value {
    json!({ "batchCloseAuthorizationDigest": {
        "network": network,
        "programId": solana_pay_kit::core::payment_channels::PAYMENT_CHANNELS_PROGRAM_ID,
        "feePayer": fx::fee_payer(),
        "channelId": channel(&cfg()),
        "maxClaimableAmount": max.to_string(),
        "voucherExpiresAt": 0,
        "validBefore": valid_before,
    }})
}

fn close_digest_expect(network: &str, max: u64, valid_before: i64) -> Expect {
    authored_bytes(&close_digest(
        network,
        solana_pay_kit::core::payment_channels::PAYMENT_CHANNELS_PROGRAM_ID,
        &fx::fee_payer(),
        &channel(&cfg()),
        max,
        0,
        valid_before,
    ))
}

fn auth_input(request_id: &str, amount: &str) -> Value {
    json!({ "batchAuthorizationMessage": {
        "channelId": channel(&cfg()),
        "payer": fx::payer(),
        "operator": fx::addr(fx::OPERATOR_SEED),
        "requestId": request_id,
        "authorizedAmount": amount,
        "expiresAt": 1_758_215_100_i64,
    }})
}

fn claim_entry(config: &Value, cumulative: u64) -> Value {
    json!({
        "channelId": channel(config),
        "channelConfig": config,
        "voucher": fx::voucher(&channel(config), cumulative, 0, fx::PAYER_SEED),
    })
}

fn wire(shape: &str, value: Value) -> Value {
    json!({ "batchWire": { "shape": shape, "value": value } })
}

fn wire_case(
    id: &str,
    spec: SpecRef,
    reqs: &[&str],
    description: &str,
    input: Value,
    expect: Expect,
) -> CaseBuilder {
    case(
        id,
        "batch-wire.json",
        Mode::CanonicalBytes,
        Role::Both,
        BugType::Wire,
        spec,
        description,
        input,
        expect,
    )
    .requirements(reqs)
}

fn bytes_case(
    id: &str,
    spec: SpecRef,
    reqs: &[&str],
    description: &str,
    input: Value,
    expect: Expect,
) -> CaseBuilder {
    case(
        id,
        "batch-canonical.json",
        Mode::CanonicalBytes,
        Role::Both,
        BugType::Wire,
        spec,
        description,
        input,
        expect,
    )
    .requirements(reqs)
}

fn v1_route() -> Route {
    Route {
        tx_versions: Some(vec![0, 1]),
        ..Route::default()
    }
}

fn v1_top_up(config: solana_message::v1::TransactionConfig, prefix: Vec<Instruction>) -> String {
    let mut ixs = prefix;
    ixs.push(fx::top_up_ix(&cfg(), TOP_UP_AMOUNT_ADDED));
    ixs.extend(memo());
    fx::sponsored_v1(ixs, config)
}

fn v1_input(route: &Route, transaction: String) -> Value {
    top_up_input_with(
        route,
        transaction,
        &TOP_UP_AMOUNT_ADDED.to_string(),
        TOP_UP_CHARGED + fx::AMOUNT,
        Atas::Healthy,
        TOKEN_PROGRAM,
    )
}

fn txv1_case(
    id: &str,
    spec: SpecRef,
    reqs: &[&str],
    description: &str,
    input: Value,
    expect: Expect,
) -> CaseBuilder {
    case(
        id,
        "batch-txv1.json",
        Mode::VerifyTransaction,
        Role::Server,
        BugType::AuthBypass,
        spec,
        description,
        input,
        expect,
    )
    .requirements(reqs)
}

/// Three Lighthouse assertions of 330 bytes each: the top-up then exceeds
/// the 1232-byte version-0 limit while staying under version 1's 4096.
fn heavy_lighthouse() -> Vec<Instruction> {
    (0..3).map(|i| fx::lighthouse_ix(&[i as u8; 330])).collect()
}

crate::registry! {
    // ── canonical bytes ──
    batch_voucher_message_frozen => bytes_case(
        "batch-voucher-message-frozen", voucher_layout(), &[CORRECTIVE_VERIFY, EXPIRES_ZERO],
        "The 50-byte voucher message 0x56 0x01 || channelId || u64(maxClaimableAmount).le || i64(expiresAt).le for the fixture channel at 5000 with expiresAt 0: the bytes every payerAuthorizer signature covers.",
        json!({ "batchVoucherMessage": { "channelId": channel(&cfg()), "maxClaimableAmount": "5000", "expiresAt": 0 } }),
        bytes_pin(),
    ).build();
    batch_voucher_message_u64_max => bytes_case(
        "batch-voucher-message-u64-max", voucher_layout(), &[CORRECTIVE_VERIFY],
        "maxClaimableAmount = u64::MAX packs as eight 0xff bytes: a string amount above 2^53 must not lose precision on the way to the signed message.",
        json!({ "batchVoucherMessage": { "channelId": channel(&cfg()), "maxClaimableAmount": "18446744073709551615", "expiresAt": 0 } }),
        bytes_pin(),
    ).build();
    batch_voucher_message_nonzero_expiry_layout => bytes_case(
        "batch-voucher-message-nonzero-expiry-layout", voucher_layout(), &[CORRECTIVE_VERIFY],
        "The layout itself encodes any i64 expiresAt (it is the program's VoucherArgs); rejecting a nonzero expiry is a verification rule, not an encoding one. Pins the little-endian i64 field.",
        json!({ "batchVoucherMessage": { "channelId": channel(&cfg()), "maxClaimableAmount": "1000", "expiresAt": 1_758_215_100_i64 } }),
        bytes_pin(),
    ).build();
    batch_voucher_message_non_decimal_amount_reject => bytes_case(
        "batch-voucher-message-non-decimal-amount-reject", voucher_layout(), &[CORRECTIVE_VERIFY],
        "maxClaimableAmount \"1e3\" is not a decimal u64 in atomic units and has no voucher encoding.",
        json!({ "batchVoucherMessage": { "channelId": channel(&cfg()), "maxClaimableAmount": "1e3", "expiresAt": 0 } }),
        rej(RejectCode::InvalidPayload),
    ).build();
    batch_authorization_message_frozen => bytes_case(
        "batch-authorization-message-frozen", auth_layout(), &[AUTH_MESSAGE, AUTH_VERIFY],
        "Server-mode payer proof message: utf8(\"x402-batch-authorization-v2\") || channelId || payer || operator || u16(len(requestId)).le || requestId || u64(authorizedAmount).le || i64(expiresAt).le.",
        auth_input("req-1", "1000"),
        bytes_pin(),
    ).build();
    batch_authorization_message_request_id_256_bytes => bytes_case(
        "batch-authorization-message-request-id-256-bytes", auth_layout(), &[AUTH_MESSAGE],
        "A 256-byte requestId is the longest allowed; the u16 length prefix is 0x0100.",
        auth_input(&"r".repeat(256), "1000"),
        bytes_pin(),
    ).build();
    batch_authorization_message_multibyte_request_id => bytes_case(
        "batch-authorization-message-multibyte-request-id", auth_layout(), &[AUTH_MESSAGE],
        "The requestId length prefix counts UTF-8 bytes, not characters: \"réq-✓\" is 5 characters and 8 bytes.",
        auth_input("réq-✓", "1000"),
        bytes_pin(),
    ).build();
    batch_authorization_message_refund_zero_amount => bytes_case(
        "batch-authorization-message-refund-zero-amount", auth_layout(), &[AUTH_MESSAGE, REFUND_AUTH_ZERO],
        "A server-mode refund's close-intent proof carries authorizedAmount \"0\", which encodes as eight zero bytes.",
        auth_input("refund-1", "0"),
        bytes_pin(),
    ).build();
    batch_authorization_message_empty_request_id_reject => bytes_case(
        "batch-authorization-message-empty-request-id-reject", auth_layout(), &[AUTH_MESSAGE],
        "An empty requestId (0 bytes) is outside 1 through 256 UTF-8 bytes.",
        auth_input("", "1000"),
        rej(RejectCode::InvalidPayload),
    ).build();
    batch_authorization_message_request_id_257_bytes_reject => bytes_case(
        "batch-authorization-message-request-id-257-bytes-reject", auth_layout(), &[AUTH_MESSAGE],
        "A 257-byte requestId is one byte over the 256-byte bound.",
        auth_input(&"r".repeat(257), "1000"),
        rej(RejectCode::InvalidPayload),
    ).build();
    batch_authorization_message_amount_over_u64_reject => bytes_case(
        "batch-authorization-message-amount-over-u64-reject", auth_layout(), &[AUTH_MESSAGE],
        "authorizedAmount 2^64 does not fit the u64(authorizedAmount).le field.",
        auth_input("req-1", "18446744073709551616"),
        rej(RejectCode::InvalidPayload),
    ).build();
    batch_close_authorization_digest_frozen => bytes_case(
        "batch-close-authorization-digest-frozen", close_digest_spec(), &[CLOSE_AUTH_VALIDATE, SELF_MANAGED_CLOSE],
        "CloseAuthorization digest: SHA-256 of UTF8(\"x402:batch-settlement:svm:close:v1\") || 0x00 || u16(len(network)).le || network || programId || feePayer || channelId || u64(maxClaimableAmount).le || i64(voucherExpiresAt).le || i64(validBefore).le, for the devnet fixture channel at 5000, validBefore 1785341100. Expected bytes computed from the spec text.",
        close_digest_input(fx::NETWORK, 5_000, 1_785_341_100),
        close_digest_expect(fx::NETWORK, 5_000, 1_785_341_100),
    ).authored(None).build();
    batch_close_authorization_digest_binds_network => bytes_case(
        "batch-close-authorization-digest-binds-network", close_digest_spec(), &[CLOSE_AUTH_VALIDATE],
        "The same close on mainnet: the length-prefixed network changes the digest, so a devnet close authorization cannot authorize a mainnet close.",
        close_digest_input(keys::MAINNET_CAIP2, 5_000, 1_785_341_100),
        close_digest_expect(keys::MAINNET_CAIP2, 5_000, 1_785_341_100),
    ).authored(None).build();
    batch_close_authorization_digest_binds_watermark => bytes_case(
        "batch-close-authorization-digest-binds-watermark", close_digest_spec(), &[CLOSE_AUTH_VALIDATE],
        "maxClaimableAmount 4999 instead of 5000: the digest binds the exact final watermark, so an authorization cannot be replayed at an older voucher.",
        close_digest_input(fx::NETWORK, 4_999, 1_785_341_100),
        close_digest_expect(fx::NETWORK, 4_999, 1_785_341_100),
    ).authored(None).build();
    batch_receiver_binding_memo_frozen => bytes_case(
        "batch-receiver-binding-memo-frozen", binding_spec(), &[BINDING_KEY, SERVER_REJECTS_FOREIGN_BINDING],
        "The receiver-binding memo every open carries: UTF-8 x402:batch-settlement:svm:rcvauth:v1:<base58 receiverAuthorizer>.",
        json!({ "batchReceiverBindingMemo": { "receiverAuthorizer": fx::receiver_authorizer() } }),
        authored_bytes(fx::binding_memo(&fx::receiver_authorizer()).as_bytes()),
    ).authored(None).build();
    batch_channel_id_derivation_frozen => bytes_case(
        "batch-channel-id-derivation-frozen", pda_spec(), &[EVERY_PAID_REQUEST],
        "channelId = find_program_address([\"channel\", payer, extra.feePayer, token, payerAuthorizer, u64(salt).le, u64(openSlot).le], CHNL…): the 32 PDA bytes for the fixture channel.",
        json!({ "batchChannelId": { "channelConfig": cfg(), "feePayer": fx::fee_payer() } }),
        bytes_pin(),
    ).build();
    batch_channel_id_salt_u64_max => bytes_case(
        "batch-channel-id-salt-u64-max", pda_spec(), &[EVERY_PAID_REQUEST],
        "salt \"18446744073709551615\": the decimal-string salt seeds the PDA as eight 0xff bytes.",
        json!({ "batchChannelId": { "channelConfig": with(cfg(), "salt", json!("18446744073709551615")), "feePayer": fx::fee_payer() } }),
        bytes_pin(),
    ).build();
    batch_channel_id_receiver_is_not_a_seed => bytes_case(
        "batch-channel-id-receiver-is-not-a-seed", pda_spec(), &[EVERY_PAID_REQUEST],
        "receiver and receiverAuthorizer are not PDA seeds: a config naming another receiver derives the same channelId as the fixture, which is why the receiver is bound by the distribution hash and the channelConfig checks instead.",
        json!({ "batchChannelId": { "channelConfig": with(cfg(), "receiver", json!(keys::X402_OTHER_PAY_TO)), "feePayer": fx::fee_payer() } }),
        bytes_pin(),
    ).build();
    batch_channel_id_hex_salt_reject => bytes_case(
        "batch-channel-id-hex-salt-reject", pda_spec(), &[EVERY_PAID_REQUEST],
        "salt \"0x2a\" is not a decimal u64 and seeds no PDA.",
        json!({ "batchChannelId": { "channelConfig": with(cfg(), "salt", json!("0x2a")), "feePayer": fx::fee_payer() } }),
        rej(RejectCode::InvalidPayload),
    ).build();

    // ── wire round trips ──
    batch_wire_requirements_frozen => wire_case(
        "batch-wire-requirements-frozen", s("4.1 PaymentRequirements (in PAYMENT-REQUIRED.accepts[])", "Per-request amount in atomic units."), &[WITHDRAW_RANGE, PAYMENT_FLOW_EMIT],
        "The route's PaymentRequirements: scheme, CAIP-2 network, atomic amount, mint, payTo, maxTimeoutSeconds and extra (feePayer, receiverAuthorizer, withdrawDelay, tokenProgram, memo), round-tripped and JCS-canonicalized. No channelProgram and no paymentFlow on the wire.",
        wire("requirements", requirements()),
        json_pin(),
    ).build();
    batch_wire_payload_voucher_frozen => wire_case(
        "batch-wire-payload-voucher-frozen", wire_spec(), &[PAYLOAD_VARIANTS],
        "voucher payload: channelConfig (decimal-string salt, numeric openSlot and withdrawDelay) and a BatchVoucher with a string maxClaimableAmount and numeric expiresAt 0.",
        wire("payload", voucher_payload(&cfg(), honest_voucher(5_000))),
        json_pin(),
    ).build();
    batch_wire_payload_deposit_frozen => wire_case(
        "batch-wire-payload-deposit-frozen", wire_spec(), &[PAYLOAD_VARIANTS, DEPOSIT_VOUCHER],
        "deposit payload: channelConfig, the first voucher, and deposit {amount, transaction}.",
        wire("payload", json!({ "type": "deposit", "channelConfig": cfg(), "voucher": honest_voucher(1_000), "deposit": { "amount": "100000", "transaction": "AQID" } })),
        json_pin(),
    ).build();
    batch_wire_payment_payload_frozen => wire_case(
        "batch-wire-payment-payload-frozen", accepted_spec(), &[ACCEPTED_EQUAL, VERSION_TWO],
        "The PAYMENT-SIGNATURE envelope: x402Version 2, accepted (the requirements echoed verbatim) and the voucher payload.",
        wire("paymentPayload", json!({ "x402Version": 2, "accepted": requirements(), "payload": voucher_payload(&cfg(), honest_voucher(5_000)) })),
        json_pin(),
    ).build();
    batch_wire_payload_refund_cooperative => wire_case(
        "batch-wire-payload-refund-cooperative", refund_voucher_spec(), &[REFUND_VOUCHER],
        "The default (cooperative) client-mode refund carries channelConfig and the accepted voucher and no transaction: it must parse and round-trip unchanged.",
        wire("payload", refund_payload(Some(honest_voucher(5_000)), None)),
        authored_json(&refund_payload(Some(honest_voucher(5_000)), None)),
    ).authored(None).build();
    batch_wire_payload_refund_with_transaction => wire_case(
        "batch-wire-payload-refund-with-transaction", refund_voucher_spec(), &[REFUND_VOUCHER],
        "A refund retried after receiver_binding_unavailable carries the voucher and a request_close transaction.",
        wire("payload", refund_payload(Some(honest_voucher(5_000)), Some("AQID".into()))),
        json_pin(),
    ).build();
    batch_wire_payload_refund_transaction_without_voucher_reject => wire_case(
        "batch-wire-payload-refund-transaction-without-voucher-reject", refund_voucher_spec(), &[REFUND_VOUCHER],
        "A client-mode refund with a transaction but no voucher is not a valid refund variant: the voucher is REQUIRED in client mode.",
        wire("payload", refund_payload(None, Some("AQID".into()))),
        rej(RejectCode::InvalidPayload),
    ).authored(None).build();
    batch_wire_payload_authorization_frozen => wire_case(
        "batch-wire-payload-authorization-frozen", s("4.3 Client PaymentPayload Variants", "**`authorization`** is the server-mode steady-state request."), &[PAYLOAD_VARIANTS],
        "Server-mode authorization payload: channelConfig with voucherSigner \"server\" and payerAuthorizer = operator, plus a BatchAuthorization proof (type \"proof\").",
        wire("payload", json!({
            "type": "authorization",
            "channelConfig": with(with(cfg(), "payerAuthorizer", json!(fx::addr(fx::OPERATOR_SEED))), "voucherSigner", json!("server")),
            "authorization": { "type": "proof", "channelId": channel(&cfg()), "payer": fx::payer(), "requestId": "req-1", "authorizedAmount": "1000", "expiresAt": 1_758_215_100_i64, "signature": "1111111111111111111111111111111111111111111111111111111111111111" },
        })),
        json_pin(),
    ).build();
    batch_wire_payload_legacy_channel_id_reject => wire_case(
        "batch-wire-payload-legacy-channel-id-reject", wire_spec(), &[PAYLOAD_VARIANTS],
        "The superseded voucher shape with a top-level channelId and no channelConfig is not a current variant.",
        wire("payload", json!({ "type": "voucher", "channelId": channel(&cfg()), "voucher": honest_voucher(1_000) })),
        rej(RejectCode::InvalidPayload),
    ).build();
    batch_wire_payload_numeric_max_claimable_reject => wire_case(
        "batch-wire-payload-numeric-max-claimable-reject", s("4.2 Shared Wire Objects and Program Mapping", "| `maxClaimableAmount` | string | Cumulative authorized total in atomic units"), &[PAYLOAD_VARIANTS],
        "maxClaimableAmount as a JSON number (1000) instead of a decimal string.",
        wire("payload", voucher_payload(&cfg(), with(honest_voucher(1_000), "maxClaimableAmount", json!(1000)))),
        rej(RejectCode::InvalidPayload),
    ).build();
    batch_wire_payload_unknown_type_reject => wire_case(
        "batch-wire-payload-unknown-type-reject", variants_spec(), &[PAYLOAD_VARIANTS],
        "An unknown discriminator (\"withdraw\") is none of deposit, voucher, authorization, refund.",
        wire("payload", json!({ "type": "withdraw", "channelConfig": cfg(), "voucher": honest_voucher(1_000) })),
        rej(RejectCode::InvalidPayload),
    ).build();
    batch_wire_payload_missing_voucher_signature_reject => wire_case(
        "batch-wire-payload-missing-voucher-signature-reject", s("4.2 Shared Wire Objects and Program Mapping", "| `signature` | string | Base58 Ed25519 signature by `channelConfig.payerAuthorizer`. |"), &[PAYLOAD_VARIANTS],
        "A BatchVoucher without its signature field is malformed.",
        wire("payload", voucher_payload(&cfg(), without(honest_voucher(1_000), "signature"))),
        rej(RejectCode::InvalidPayload),
    ).build();
    batch_wire_redemption_claim_frozen => wire_case(
        "batch-wire-redemption-claim-frozen", claims_spec(), &[CLAIMS_ONE_TO_FOUR],
        "claim payload with two entries, each channelId + full channelConfig + the latest BatchVoucher.",
        wire("redemption", json!({ "type": "claim", "claims": [claim_entry(&cfg(), 5_000), claim_entry(&with(with(cfg(), "salt", json!("43")), "openSlot", json!(341_000_050)), 7_000)] })),
        json_pin(),
    ).build();
    batch_wire_redemption_claim_empty_reject => wire_case(
        "batch-wire-redemption-claim-empty-reject", claims_spec(), &[CLAIMS_ONE_TO_FOUR],
        "claims: [] is below the one-entry minimum.",
        wire("redemption", json!({ "type": "claim", "claims": [] })),
        rej(RejectCode::InvalidPayload),
    ).authored(None).build();
    batch_wire_redemption_claim_five_entries_reject => wire_case(
        "batch-wire-redemption-claim-five-entries-reject", claims_spec(), &[CLAIMS_ONE_TO_FOUR],
        "Five claims exceed the four entries one legacy transaction can carry.",
        wire("redemption", json!({ "type": "claim", "claims": (0..5).map(|i| claim_entry(&with(cfg(), "salt", json!((100 + i).to_string())), 1_000)).collect::<Vec<_>>() })),
        rej(RejectCode::InvalidPayload),
    ).authored(None).build();
    batch_wire_redemption_claim_entry_without_config_reject => wire_case(
        "batch-wire-redemption-claim-entry-without-config-reject", s("4.5 Facilitator Interface", "| Claim | `claims[].channelConfig` | `ChannelConfig` | Full channel configuration. |"), &[CLAIMS_ONE_TO_FOUR],
        "A claim entry without its channelConfig cannot be derived or validated.",
        wire("redemption", json!({ "type": "claim", "claims": [without(claim_entry(&cfg(), 5_000), "channelConfig")] })),
        rej(RejectCode::InvalidPayload),
    ).build();
    batch_wire_redemption_settle_frozen => wire_case(
        "batch-wire-redemption-settle-frozen", s("4.5 Facilitator Interface", "`channels[]` MUST contain between one and four entries, the same transaction-size bound as `claims[]`."), &[CLAIMS_ONE_TO_FOUR],
        "settle payload: channels[] of {channelId, channelConfig}.",
        wire("redemption", json!({ "type": "settle", "channels": [{ "channelId": channel(&cfg()), "channelConfig": cfg() }] })),
        json_pin(),
    ).build();
    batch_wire_redemption_seal_frozen => wire_case(
        "batch-wire-redemption-seal-frozen", s("4.5 Facilitator Interface", "| Seal | `closeAuthorization` | `CloseAuthorization` | REQUIRED (section 3)."), &[SEAL_CLOSE_AUTH],
        "seal payload: the tag beside channelId, channelConfig, the latest voucher and closeAuthorization {validBefore, signature}.",
        wire("redemption", json!({ "type": "seal", "channelId": channel(&cfg()), "channelConfig": cfg(), "voucher": honest_voucher(5_000), "closeAuthorization": { "validBefore": 1_785_341_100_i64, "signature": "1111111111111111111111111111111111111111111111111111111111111111" } })),
        json_pin(),
    ).build();
    batch_wire_settlement_response_voucher_acceptance => wire_case(
        "batch-wire-settlement-response-voucher-acceptance", s("4.4 SettlementResponse (in PAYMENT-RESPONSE)", "| `extra.commitmentId` | string | no | MUST be non-empty for voucher acceptance"), &[COMMITMENT_ID],
        "Voucher-acceptance PAYMENT-RESPONSE: transaction and amount are the empty string (not null, not omitted), extra carries commitmentId, chargedAmount and channelState.",
        wire("settlementResponse", json!({ "success": true, "transaction": "", "network": fx::NETWORK, "payer": fx::payer(), "amount": "", "extra": { "commitmentId": format!("{}:5000", channel(&cfg())), "chargedAmount": "1000", "channelState": { "channelId": channel(&cfg()), "balance": "100000", "totalClaimed": "3000", "withdrawRequestedAt": 0, "chargedCumulativeAmount": "5000" } } })),
        json_pin(),
    ).build();
    batch_wire_corrective_payment_required => wire_case(
        "batch-wire-corrective-payment-required", corrective_spec(), &[CORRECTIVE_VERIFY],
        "Corrective 402: error invalid_batch_settlement_svm_cumulative_amount_mismatch and an accept whose extra carries channelState and the signed voucherState proof.",
        wire("paymentRequired", json!({ "x402Version": 2, "error": "invalid_batch_settlement_svm_cumulative_amount_mismatch", "accepts": [corrective_input(3_000, 3_000, 0, fx::PAYER_SEED, None, true)["batchCorrective"]["requirements"].clone()] })),
        json_pin(),
    ).build();
    batch_wire_requirements_transaction_versions => wire_case(
        "batch-wire-requirements-transaction-versions", t("4.1 PaymentRequirements (in PAYMENT-REQUIRED.accepts[])", "Transaction message versions the facilitator accepts, as an array of `0` and/or `1`"), &[TX_SERVER_COPIES],
        "Requirements of a route whose facilitator accepts versions 0 and 1 carry extra.transactionVersions [0, 1].",
        wire("requirements", v1_route().requirements()),
        json_pin(),
    ).build();
    batch_wire_requirements_unknown_transaction_version_reject => wire_case(
        "batch-wire-requirements-unknown-transaction-version-reject", tx_versions_spec("Entries are the integers `0` and `1`, the Wallet Standard `supportedTransactionVersions` vocabulary."), &[TX_SERVER_COPIES],
        "extra.transactionVersions [0, 2]: 2 is not a transaction message version.",
        wire("requirements", requirements_with(&[("transactionVersions", json!([0, 2]))])),
        rej(RejectCode::InvalidPayload),
    ).build();

    // ── client build ──
    batch_build_deposit_open => case(
        "batch-build-deposit-open", "batch-build.json", Mode::BuildTransaction, Role::Client, BugType::Settlement,
        s("Phase 1 - Open or Top Up", "For `open`, the client MUST set `payee = extra.feePayer`, `authorized_signer = channelConfig.payerAuthorizer`, `rent_payer = extra.feePayer`"),
        "Client opens a channel with a 10000 deposit and the first voucher (= amount). The judge checks the spec's open: fee payer, rent_payer and payee are extra.feePayer, the payer slot signed and the sponsor slot empty, the single 100% distribution to payTo, the seller memo AND the receiver-binding memo, a voucher at exactly the amount signed by payerAuthorizer for the derived PDA.",
        terms_input(requirements(), TOKEN_PROGRAM),
        Expect::Accept(Pin::Outcome),
    ).requirements(&[CLIENT_OPEN, OPEN_ENCODE, BINDING_KEY, NO_DIVERSION]).build();
    batch_build_voucher_next => case(
        "batch-build-voucher-next", "batch-build.json", Mode::BuildTransaction, Role::Client, BugType::Settlement,
        s("Phase 2 - Steady-State Request", "In client mode, using the last authenticated `PAYMENT-RESPONSE`, the client sets"),
        "Steady state: the server confirmed 3000 of a 10000 deposit; the next voucher authorizes exactly 4000 with expiresAt 0. Judged structurally and by the Rust server on the same stored record.",
        judged_build("voucher", &route(), json!({ "channel": tracked_channel(3_000, 10_000) }), 3_000, 10_000, 10_000),
        Expect::Accept(Pin::Outcome),
    ).requirements(&[EVERY_PAID_REQUEST, NO_EXPIRY]).build();
    batch_build_voucher_first => case(
        "batch-build-voucher-first", "batch-build.json", Mode::BuildTransaction, Role::Client, BugType::Settlement,
        s("Phase 2 - Steady-State Request", "For a new channel, `chargedCumulativeAmount` starts at zero."),
        "A channel opened with no charge yet: the voucher authorizes exactly the amount.",
        judged_build("voucher", &route(), json!({ "channel": tracked_channel(0, 10_000) }), 0, 10_000, 10_000),
        Expect::Accept(Pin::Outcome),
    ).requirements(&[EVERY_PAID_REQUEST]).build();
    batch_build_top_up => case(
        "batch-build-top-up", "batch-build.json", Mode::BuildTransaction, Role::Client, BugType::Settlement,
        top_up_spec(),
        "Charged 3000 of a 4000 deposit: the client adds 6000 of escrow and authorizes the next request (4000) in one deposit payload. Judged structurally and by the Rust server on the same stored record (canonical top_up, the seller memo, the sponsor slot empty).",
        judged_build("topUp", &route(), json!({ "channel": tracked_channel(TOP_UP_CHARGED, TOP_UP_DEPOSIT), "depositAmount": TOP_UP_AMOUNT_ADDED.to_string() }), TOP_UP_CHARGED, TOP_UP_DEPOSIT, TOP_UP_DEPOSIT),
        Expect::Accept(Pin::Outcome),
    ).requirements(&[TOP_UP_AMOUNT, TOP_UP_FEE_PAYER]).build();
    batch_build_top_up_version_1 => case(
        "batch-build-top-up-version-1", "batch-build.json", Mode::BuildTransaction, Role::Client, BugType::Defaults,
        tx_versions_spec("then build the highest version in that intersection."),
        "The challenge advertises transactionVersions [0, 1] and the signer signs version 1: the top-up is built as version 1 (header compute budget) and the version-1 server accepts it.",
        judged_build("topUp", &v1_route(), json!({ "channel": tracked_channel(TOP_UP_CHARGED, TOP_UP_DEPOSIT), "depositAmount": TOP_UP_AMOUNT_ADDED.to_string() }), TOP_UP_CHARGED, TOP_UP_DEPOSIT, TOP_UP_DEPOSIT),
        Expect::Accept(Pin::Outcome),
    ).requirements(&[TX_CLIENT_INTERSECT]).build();
    batch_build_refund => case(
        "batch-build-refund", "batch-build.json", Mode::BuildTransaction, Role::Client, BugType::Settlement,
        refund_voucher_spec(),
        "Client-mode refund of a channel charged 3000: the payload carries the accepted voucher at 3000 and no amount. The judge requires the voucher (spec §4.3).",
        judged_build("refund", &route(), json!({ "channel": tracked_channel(3_000, 10_000) }), 3_000, 10_000, 10_000),
        Expect::Accept(Pin::Outcome),
    ).requirements(&[REFUND_VOUCHER, REFUND_NO_AMOUNT]).build();
    batch_build_terms_token_program_not_mint_owner_reject => terms_case(
        "batch-build-terms-token-program-not-mint-owner-reject", spec(SVM, "4.2 Shared Wire Objects and Program Mapping", "The client and facilitator MUST confirm `extra.tokenProgram` equals the onchain owner of `channelConfig.token`"), &[TOKEN_PROGRAM_OWNER, TOKEN_PROGRAM_VERIFY],
        "extra.tokenProgram is SPL Token but the mint is owned by Token-2022 onchain: the client refuses before deriving any ATA.",
        terms_input(requirements(), TOKEN_2022_PROGRAM),
        rej(RejectCode::TokenProgram),
    );
    batch_build_terms_unsupported_token_program_reject => terms_case(
        "batch-build-terms-unsupported-token-program-reject", s("4.1 PaymentRequirements (in PAYMENT-REQUIRED.accepts[])", "SPL Token (`Tokenkeg...`) or Token-2022 (`TokenzQ...`) program that owns `asset`."), &[TOKEN_PROGRAM_VERIFY],
        "extra.tokenProgram names the System program: not a supported SPL token program.",
        terms_input(requirements_with(&[("tokenProgram", json!(keys::SYSTEM_PROGRAM))]), TOKEN_PROGRAM),
        rej(RejectCode::TokenProgram),
    );
    batch_build_terms_payment_flow_upfront_reject => terms_case(
        "batch-build-terms-payment-flow-upfront-reject", s("4.1 PaymentRequirements (in PAYMENT-REQUIRED.accepts[])", "| `paymentFlow` | string | no | When present, MUST be `\"authorization\"`."), &[PAYMENT_FLOW, PAYMENT_FLOW_EMIT],
        "extra.paymentFlow \"upfront\": the scheme resolves only to the authorization flow.",
        terms_input(requirements_with(&[("paymentFlow", json!("upfront"))]), TOKEN_PROGRAM),
        rej(RejectCode::PaymentFlow),
    );
    batch_build_terms_payment_flow_authorization => case(
        "batch-build-terms-payment-flow-authorization", "batch-build.json", Mode::BuildTransaction, Role::Client, BugType::Defaults,
        s("4.1 PaymentRequirements (in PAYMENT-REQUIRED.accepts[])", "| `paymentFlow` | string | no | When present, MUST be `\"authorization\"`."),
        "Paired accept: an explicit extra.paymentFlow \"authorization\" is the protocol default and builds.",
        terms_input(requirements_with(&[("paymentFlow", json!("authorization"))]), TOKEN_PROGRAM),
        Expect::Accept(Pin::Outcome),
    ).requirements(&[PAYMENT_FLOW]).build();
    batch_build_terms_withdraw_delay_below_range_reject => terms_case(
        "batch-build-terms-withdraw-delay-below-range-reject", withdraw_spec(), &[WITHDRAW_RANGE, WITHDRAW_ENFORCED],
        "withdrawDelay 899 is one second under the 900-second minimum.",
        terms_input(requirements_with(&[("withdrawDelay", json!(899))]), TOKEN_PROGRAM),
        rej(RejectCode::WithdrawDelayOutOfRange),
    );
    batch_build_terms_withdraw_delay_above_range_reject => terms_case(
        "batch-build-terms-withdraw-delay-above-range-reject", withdraw_spec(), &[WITHDRAW_RANGE],
        "withdrawDelay 2592001 is one second over the 30-day maximum.",
        terms_input(requirements_with(&[("withdrawDelay", json!(2_592_001))]), TOKEN_PROGRAM),
        rej(RejectCode::WithdrawDelayOutOfRange),
    );
    batch_build_terms_withdraw_delay_below_max_timeout_reject => terms_case(
        "batch-build-terms-withdraw-delay-below-max-timeout-reject", withdraw_spec(), &[WITHDRAW_RANGE],
        "withdrawDelay 900 with maxTimeoutSeconds 901: the grace period must outlast the HTTP completion window.",
        terms_input({ let mut r = requirements_with(&[("withdrawDelay", json!(900))]); r["maxTimeoutSeconds"] = json!(901); r }, TOKEN_PROGRAM),
        rej(RejectCode::WithdrawDelayOutOfRange),
    );
    batch_build_terms_withdraw_delay_fractional_reject => terms_case_authored(
        "batch-build-terms-withdraw-delay-fractional-reject", withdraw_spec(), &[WITHDRAW_RANGE],
        "withdrawDelay 900.5 is not an integer from 900 through 2592000.",
        terms_input(requirements_with(&[("withdrawDelay", json!(900.5))]), TOKEN_PROGRAM),
        rej(RejectCode::WithdrawDelayOutOfRange),
    );
    batch_build_terms_server_signed_untrusted_reject => terms_case(
        "batch-build-terms-server-signed-untrusted-reject", s("8. Security Properties", "Absent a grant the client MUST refuse the server-mode accept"), &[NO_GRANT, OPT_IN],
        "A server-mode accept (voucherSigner \"server\", extra.operator) without a local operator grant: the client refuses it rather than delegate voucher authority on a 402's word.",
        terms_input(requirements_with(&[("voucherSigner", json!("server")), ("operator", json!(fx::addr(fx::OPERATOR_SEED)))]), TOKEN_PROGRAM),
        rej(RejectCode::InvalidChallenge),
    );
    batch_build_terms_operator_in_client_mode_reject => terms_case(
        "batch-build-terms-operator-in-client-mode-reject", s("4.1 PaymentRequirements (in PAYMENT-REQUIRED.accepts[])", "REQUIRED when `voucherSigner == \"server\"`; MUST be absent in client mode."), &[OPERATOR_CLIENT_MODE],
        "extra.operator on a client-mode accept (no voucherSigner).",
        terms_input(requirements_with(&[("operator", json!(fx::addr(fx::OPERATOR_SEED)))]), TOKEN_PROGRAM),
        rej(RejectCode::InvalidChallenge),
    );
    batch_build_deposit_payer_is_fee_payer_reject => case(
        "batch-build-deposit-payer-is-fee-payer-reject", "batch-build.json", Mode::BuildTransaction, Role::Client, BugType::AuthBypass,
        s("4.2 Shared Wire Objects and Program Mapping", "MUST NOT equal `feePayer`, because the program requires distinct payer and payee accounts."),
        "The client's own key is the challenge's extra.feePayer: it cannot be both the channel payer and the sponsor.",
        with(terms_input(requirements(), TOKEN_PROGRAM), "batchClient", with(terms_input(requirements(), TOKEN_PROGRAM)["batchClient"].clone(), "secretKey", keys::secret_json(fx::FEE_PAYER_SEED))),
        rej(RejectCode::FeePayerMismatch),
    ).requirements(&[PAYER_NOT_FEE_PAYER, CONFIG_NOT_FEE_PAYER]).build();
    batch_build_version_intersection_empty_reject => terms_case(
        "batch-build-version-intersection-empty-reject", tx_versions_spec("It MUST fail with `unsupported_transaction_version` when the intersection is empty."), &[TX_CLIENT_EMPTY],
        "The challenge advertises only version 1 and the client's signer signs up to version 0: the intersection is empty.",
        { let mut i = terms_input(requirements_with(&[("transactionVersions", json!([1]))]), TOKEN_PROGRAM); i["batchClient"]["maxTransactionVersion"] = json!(0); i },
        rej(RejectCode::UnsupportedVersion),
    );

    // ── corrective 402 (client) ──
    batch_corrective_adopt_own_signature => corrective_case(
        "batch-corrective-adopt-own-signature",
        "The server's corrective snapshot charges 3000 and proves it with the client's own voucher signature at 3000: the client adopts 3000 as its cumulative base.",
        corrective_input(3_000, 3_000, 0, fx::PAYER_SEED, None, true),
        Expect::Accept(Pin::Outcome),
    );
    batch_corrective_charged_below_signed => corrective_case(
        "batch-corrective-charged-below-signed",
        "chargedCumulativeAmount 2000 under a proof signed at 3000 is adoptable (charged may not exceed the proof).",
        corrective_input(2_000, 3_000, 0, fx::PAYER_SEED, None, true),
        Expect::Accept(Pin::Outcome),
    );
    batch_corrective_foreign_signature_reject => corrective_case(
        "batch-corrective-foreign-signature-reject",
        "The voucherState signature is by a key other than the client's payerAuthorizer: the snapshot is not proven and must not be adopted.",
        corrective_input(3_000, 3_000, 0, fx::STRANGER_SEED, None, true),
        rej(RejectCode::VoucherSignature),
    );
    batch_corrective_charged_exceeds_signed_reject => corrective_case(
        "batch-corrective-charged-exceeds-signed-reject",
        "chargedCumulativeAmount 4000 over a proof signed at 3000: the server claims more than the client ever signed.",
        corrective_input(4_000, 3_000, 0, fx::PAYER_SEED, None, true),
        rej(RejectCode::CumulativeAmountMismatch),
    );
    batch_corrective_nonzero_expiry_reject => corrective_case(
        "batch-corrective-nonzero-expiry-reject",
        "A voucherState with a nonzero expiresAt is not a voucher of this scheme, even if correctly signed.",
        corrective_input(3_000, 3_000, 1_758_215_100, fx::PAYER_SEED, None, true),
        rej(RejectCode::VoucherExpiry),
    );
    batch_corrective_without_proof_reject => corrective_case(
        "batch-corrective-without-proof-reject",
        "A corrective snapshot without voucherState proves nothing: the client must not adopt its chargedCumulativeAmount (it resynchronizes from onchain state instead).",
        corrective_input(3_000, 3_000, 0, fx::PAYER_SEED, None, false),
        rej(RejectCode::CumulativeAmountMismatch),
    );
    batch_corrective_other_channel_reject => corrective_case(
        "batch-corrective-other-channel-reject",
        "The snapshot names another channel than the client's: the proof is reconstructed from the derived channelId, so it cannot be adopted.",
        corrective_input(3_000, 3_000, 0, fx::PAYER_SEED, Some(keys::X402_OTHER_PAY_TO.to_string()), true),
        rej(RejectCode::ChannelIdMismatch),
    );

    // ── server verify: voucher ──
    batch_verify_voucher_accept => voucher_case(
        "batch-verify-voucher-accept", cumulative_spec(), BugType::Settlement,
        "Charged 3000 of a 10000 deposit, channel Open onchain: the voucher at 3000 + 1000 = 4000, expiresAt 0, signed by payerAuthorizer for the derived PDA, is accepted.",
        voucher_input(&cfg(), honest_voucher(4_000), 3_000, 10_000, ChannelAccount::default()),
        Expect::Accept(Pin::Outcome),
    ).requirements(&[EVERY_PAID_REQUEST, AUTHORIZER_IS_SIGNER]).build();
    batch_verify_voucher_one_below_reject => voucher_case(
        "batch-verify-voucher-one-below-reject", cumulative_spec(), BugType::Settlement,
        "Charged 3000, amount 1000: a voucher at 3999 underpays by one unit.",
        voucher_input(&cfg(), honest_voucher(3_999), 3_000, 10_000, ChannelAccount::default()),
        rej(RejectCode::CumulativeAmountMismatch),
    ).requirements(&[EVERY_PAID_REQUEST]).build();
    batch_verify_voucher_one_above_reject => voucher_case(
        "batch-verify-voucher-one-above-reject", cumulative_spec(), BugType::Settlement,
        "A voucher at 4001: in client mode each fresh voucher advances the cumulative by exactly the amount, not at least it (a stateless facilitator floor would accept it; the server rule is equality, RULINGS B1).",
        voucher_input(&cfg(), honest_voucher(4_001), 3_000, 10_000, ChannelAccount::default()),
        rej(RejectCode::CumulativeAmountMismatch),
    ).requirements(&[EVERY_PAID_REQUEST]).build();
    batch_verify_voucher_stale_reject => voucher_case(
        "batch-verify-voucher-stale-reject", cumulative_spec(), BugType::Replay,
        "A voucher at the already-charged 3000 (no stored voucher with that signature): stale, not a fresh authorization.",
        voucher_input(&cfg(), honest_voucher(3_000), 3_000, 10_000, ChannelAccount::default()),
        rej(RejectCode::CumulativeAmountMismatch),
    ).requirements(&[EVERY_PAID_REQUEST]).build();
    batch_verify_voucher_at_deposit => voucher_case(
        "batch-verify-voucher-at-deposit", cumulative_spec(), BugType::Settlement,
        "Charged 9000 of 10000: the voucher at exactly the deposit (10000) is accepted (<=).",
        voucher_input(&cfg(), honest_voucher(10_000), 9_000, 10_000, ChannelAccount::default()),
        Expect::Accept(Pin::Outcome),
    ).requirements(&[EVERY_PAID_REQUEST]).build();
    batch_verify_voucher_exceeds_deposit_reject => voucher_case(
        "batch-verify-voucher-exceeds-deposit-reject", cumulative_spec(), BugType::Settlement,
        "Charged 9500 of 10000: the next voucher (10500) is the correct step but exceeds the escrow; the client must top up.",
        voucher_input(&cfg(), honest_voucher(10_500), 9_500, 10_000, ChannelAccount::default()),
        rej(RejectCode::CumulativeExceedsDeposit),
    ).requirements(&[EVERY_PAID_REQUEST]).build();
    batch_verify_voucher_nonzero_expiry_reject => voucher_case(
        "batch-verify-voucher-nonzero-expiry-reject", expiry_spec(), BugType::Settlement,
        "The accept case with expiresAt 1758215100 (re-signed): a correctly signed voucher with any expiry is rejected.",
        voucher_input(&cfg(), fx::voucher(&channel(&cfg()), 4_000, 1_758_215_100, fx::PAYER_SEED), 3_000, 10_000, ChannelAccount::default()),
        rej(RejectCode::VoucherExpiry),
    ).requirements(&[NO_EXPIRY, EXPIRES_ZERO]).build();
    batch_verify_voucher_foreign_signature_reject => voucher_case(
        "batch-verify-voucher-foreign-signature-reject", signature_spec(), BugType::AuthBypass,
        "The voucher is signed by a key other than channelConfig.payerAuthorizer.",
        voucher_input(&cfg(), fx::voucher(&channel(&cfg()), 4_000, 0, fx::STRANGER_SEED), 3_000, 10_000, ChannelAccount::default()),
        rej(RejectCode::VoucherSignature),
    ).requirements(&[EVERY_PAID_REQUEST, AUTHORIZER_IS_SIGNER]).build();
    batch_verify_voucher_signature_over_other_amount_reject => voucher_case(
        "batch-verify-voucher-signature-over-other-amount-reject", signature_spec(), BugType::Malleability,
        "maxClaimableAmount 4000 carrying the payer's signature over 3000: the signature does not cover the claimed amount.",
        voucher_input(&cfg(), with(honest_voucher(4_000), "signature", json!(fx::sign_voucher(&channel(&cfg()), 3_000, 0, fx::PAYER_SEED))), 3_000, 10_000, ChannelAccount::default()),
        rej(RejectCode::VoucherSignature),
    ).requirements(&[EVERY_PAID_REQUEST]).build();
    batch_verify_voucher_channel_id_mismatch_reject => voucher_case(
        "batch-verify-voucher-channel-id-mismatch-reject", channel_id_spec(), BugType::AuthBypass,
        "voucher.channelId names the channel of salt 43 (validly signed for it) while channelConfig derives the salt-42 PDA.",
        voucher_input(&cfg(), fx::voucher(&channel(&with(cfg(), "salt", json!("43"))), 4_000, 0, fx::PAYER_SEED), 3_000, 10_000, ChannelAccount::default()),
        rej(RejectCode::ChannelIdMismatch),
    ).requirements(&[EVERY_PAID_REQUEST]).build();
    batch_verify_voucher_unknown_channel_reject => voucher_case(
        "batch-verify-voucher-unknown-channel-reject", bindings_spec(), BugType::AuthBypass,
        "A validly signed voucher for a channel neither the server nor the chain knows.",
        verify_input(&route(), &requirements(), &voucher_payload(&cfg(), honest_voucher(1_000)), None, fx::rpc_fixtures(None, Atas::Healthy, TOKEN_PROGRAM)),
        rej(RejectCode::ChannelState),
    ).requirements(&[EVERY_PAID_REQUEST]).build();
    batch_verify_voucher_closing_channel_reject => voucher_case(
        "batch-verify-voucher-closing-channel-reject", closing_spec(), BugType::Settlement,
        "The payer broadcast request_close: the channel account is Closing (closure_started_at set). An otherwise valid voucher is refused with channel_closing; the server collects through seal instead.",
        voucher_input(&cfg(), honest_voucher(4_000), 3_000, 10_000, ChannelAccount { status: 2, closure_started_at: 1_785_000_000, ..Default::default() }),
        rej(RejectCode::ChannelClosing),
    ).requirements(&[CLOSING]).build();
    batch_verify_voucher_close_pending_in_store_reject => voucher_case(
        "batch-verify-voucher-close-pending-in-store-reject", s("4.5 Facilitator Interface", "For this unilateral path, the server MUST mark the channel close-pending and reject further paid requests."), BugType::Settlement,
        "The server already marked the channel close-pending (a sponsored request_close confirmed): further paid requests are refused.",
        { let mut i = voucher_input(&cfg(), honest_voucher(4_000), 3_000, 10_000, ChannelAccount::default()); i["batchServerChannel"]["closeRequestedAt"] = json!(1_785_000_000_u64); i },
        rej(RejectCode::ChannelClosing),
    ).requirements(&[CLOSE_PENDING, CLOSING]).build();
    batch_verify_voucher_onchain_closed_account_reject => voucher_case(
        "batch-verify-voucher-onchain-closed-account-reject", bindings_spec(), BugType::AuthBypass,
        "The account at the channel address carries the ClosedChannel discriminator (2): it is not an open channel, whatever the server's record says.",
        voucher_input(&cfg(), honest_voucher(4_000), 3_000, 10_000, ChannelAccount { discriminator: 2, ..Default::default() }),
        rej(RejectCode::ChannelState),
    ).requirements(&[EVERY_PAID_REQUEST, "X402-46d0a12f84"]).authored(None).build();
    batch_verify_voucher_onchain_payee_reject => voucher_case(
        "batch-verify-voucher-onchain-payee-reject", bindings_spec(), BugType::AuthBypass,
        "The onchain channel's payee is not extra.feePayer (the sponsor does not hold the lifecycle seat this scheme requires).",
        voucher_input(&cfg(), honest_voucher(4_000), 3_000, 10_000, ChannelAccount { payee: fx::stranger(), ..Default::default() }),
        rej(RejectCode::ChannelState),
    ).requirements(&[EVERY_PAID_REQUEST, "X402-46d0a12f84"]).build();
    batch_verify_voucher_onchain_distribution_reject => voucher_case(
        "batch-verify-voucher-onchain-distribution-reject", bindings_spec(), BugType::AuthBypass,
        "The onchain distribution hash commits 100% to another receiver: settled funds would not reach payTo.",
        voucher_input(&cfg(), honest_voucher(4_000), 3_000, 10_000, ChannelAccount { distribution_to: keys::X402_OTHER_PAY_TO.to_string(), ..Default::default() }),
        rej(RejectCode::ChannelState),
    ).requirements(&[EVERY_PAID_REQUEST, NO_DIVERSION]).build();
    batch_verify_voucher_onchain_empty_distribution_reject => voucher_case(
        "batch-verify-voucher-onchain-empty-distribution-reject", bindings_spec(), BugType::AuthBypass,
        "The onchain distribution hash is all zeros: no distribution to payTo is committed.",
        voucher_input(&cfg(), honest_voucher(4_000), 3_000, 10_000, ChannelAccount { empty_distribution: true, ..Default::default() }),
        rej(RejectCode::ChannelState),
    ).requirements(&[EVERY_PAID_REQUEST, NO_DIVERSION]).build();
    batch_verify_voucher_payer_is_fee_payer_reject => voucher_case(
        "batch-verify-voucher-payer-is-fee-payer-reject", fee_payer_spec(), BugType::AuthBypass,
        "channelConfig.payer is extra.feePayer.",
        voucher_input(&with(cfg(), "payer", json!(fx::fee_payer())), honest_voucher(4_000), 3_000, 10_000, ChannelAccount::default()),
        rej(RejectCode::FeePayerMismatch),
    ).requirements(&[PAYER_NOT_FEE_PAYER, CONFIG_NOT_FEE_PAYER]).build();
    batch_verify_voucher_authorizer_is_fee_payer_reject => voucher_case(
        "batch-verify-voucher-authorizer-is-fee-payer-reject", fee_payer_spec(), BugType::AuthBypass,
        "channelConfig.payerAuthorizer is extra.feePayer, whose sponsor could then sign its own claims (voucher signed by the fee payer).",
        voucher_input(&with(cfg(), "payerAuthorizer", json!(fx::fee_payer())), fx::voucher(&channel(&with(cfg(), "payerAuthorizer", json!(fx::fee_payer()))), 4_000, 0, fx::FEE_PAYER_SEED), 3_000, 10_000, ChannelAccount::default()),
        rej(RejectCode::FeePayerMismatch),
    ).requirements(&[AUTHORIZER_NOT_FEE_PAYER, CONFIG_NOT_FEE_PAYER]).build();
    batch_verify_voucher_receiver_not_pay_to_reject => voucher_case(
        "batch-verify-voucher-receiver-not-pay-to-reject", bindings_spec(), BugType::AuthBypass,
        "channelConfig.receiver is not payTo (receiver is no PDA seed, so the voucher's channelId still matches).",
        voucher_input(&with(cfg(), "receiver", json!(keys::X402_OTHER_PAY_TO)), honest_voucher(4_000), 3_000, 10_000, ChannelAccount::default()),
        rej(RejectCode::ChannelState),
    ).requirements(&[RECEIVER_IS_PAY_TO]).build();
    batch_verify_voucher_token_not_asset_reject => voucher_case(
        "batch-verify-voucher-token-not-asset-reject", bindings_spec(), BugType::AuthBypass,
        "channelConfig.token is another mint than the asset (voucher signed for that config's PDA).",
        voucher_input(&with(cfg(), "token", json!(OTHER_MINT)), fx::voucher(&channel(&with(cfg(), "token", json!(OTHER_MINT))), 4_000, 0, fx::PAYER_SEED), 3_000, 10_000, ChannelAccount::default()),
        rej(RejectCode::ChannelState),
    ).requirements(&[TOKEN_IS_ASSET]).build();
    batch_verify_voucher_withdraw_delay_mismatch_reject => voucher_case(
        "batch-verify-voucher-withdraw-delay-mismatch-reject", s("Phase 3 - Voucher Acceptance (before serving)", "`grace_period == channelConfig.withdrawDelay == extra.withdrawDelay`"), BugType::AuthBypass,
        "channelConfig.withdrawDelay 7200 against extra.withdrawDelay 3600.",
        voucher_input(&with(cfg(), "withdrawDelay", json!(7_200)), honest_voucher(4_000), 3_000, 10_000, ChannelAccount::default()),
        rej(RejectCode::WithdrawDelayMismatch),
    ).requirements(&[WITHDRAW_EQUAL]).build();
    batch_verify_voucher_receiver_authorizer_mismatch_reject => voucher_case(
        "batch-verify-voucher-receiver-authorizer-mismatch-reject", ra_spec(), BugType::AuthBypass,
        "channelConfig.receiverAuthorizer names a key other than extra.receiverAuthorizer.",
        voucher_input(&with(cfg(), "receiverAuthorizer", json!(fx::stranger())), honest_voucher(4_000), 3_000, 10_000, ChannelAccount::default()),
        rej(RejectCode::ReceiverAuthorizerMismatch),
    ).requirements(&[RA_EQUAL]).build();
    batch_verify_voucher_receiver_authorizer_missing_reject => voucher_case(
        "batch-verify-voucher-receiver-authorizer-missing-reject", ra_spec(), BugType::AuthBypass,
        "channelConfig omits receiverAuthorizer while the requirements advertise one: both MUST be present and equal.",
        voucher_input(&without(cfg(), "receiverAuthorizer"), honest_voucher(4_000), 3_000, 10_000, ChannelAccount::default()),
        rej(RejectCode::ReceiverAuthorizerMismatch),
    ).requirements(&[RA_EQUAL, RA_BOTH_PRESENT]).build();
    batch_verify_voucher_server_mode_config_reject => voucher_case(
        "batch-verify-voucher-server-mode-config-reject", s("4.2 Shared Wire Objects and Program Mapping", "Omitted or `\"client\"` selects client mode; `\"server\"` selects server mode and MUST equal `extra.voucherSigner`."), BugType::AuthBypass,
        "channelConfig.voucherSigner \"server\" on a client-mode route: the mode must equal extra.voucherSigner.",
        voucher_input(&with(cfg(), "voucherSigner", json!("server")), honest_voucher(4_000), 3_000, 10_000, ChannelAccount::default()),
        rej(RejectCode::ChannelState),
    ).requirements(&["X402-22712c36e1"]).build();
    batch_verify_accepted_amount_mismatch_reject => voucher_case(
        "batch-verify-accepted-amount-mismatch-reject", accepted_spec(), BugType::Precedence,
        "accepted.amount \"500\" while the route charges 1000 (voucher otherwise valid at 4000).",
        verify_input(&route(), &with(requirements(), "amount", json!("500")), &voucher_payload(&cfg(), honest_voucher(4_000)), Some(fx::store_record(&cfg(), 3_000, 10_000)), fx::rpc_fixtures(Some((&cfg(), &ChannelAccount::default())), Atas::Healthy, TOKEN_PROGRAM)),
        rej(RejectCode::AcceptedMismatch),
    ).requirements(&[ACCEPTED_EQUAL]).authored(None).build();
    batch_verify_accepted_pay_to_mismatch_reject => voucher_case(
        "batch-verify-accepted-pay-to-mismatch-reject", accepted_spec(), BugType::Precedence,
        "accepted.payTo names another merchant than the route's paymentRequirements.",
        verify_input(&route(), &with(requirements(), "payTo", json!(keys::X402_OTHER_PAY_TO)), &voucher_payload(&cfg(), honest_voucher(4_000)), Some(fx::store_record(&cfg(), 3_000, 10_000)), fx::rpc_fixtures(Some((&cfg(), &ChannelAccount::default())), Atas::Healthy, TOKEN_PROGRAM)),
        rej(RejectCode::AcceptedMismatch),
    ).requirements(&[ACCEPTED_EQUAL]).authored(None).build();
    batch_verify_accepted_network_mismatch_reject => voucher_case(
        "batch-verify-accepted-network-mismatch-reject", accepted_spec(), BugType::Precedence,
        "accepted.network is mainnet while the route is devnet.",
        verify_input(&route(), &with(requirements(), "network", json!(keys::MAINNET_CAIP2)), &voucher_payload(&cfg(), honest_voucher(4_000)), Some(fx::store_record(&cfg(), 3_000, 10_000)), fx::rpc_fixtures(Some((&cfg(), &ChannelAccount::default())), Atas::Healthy, TOKEN_PROGRAM)),
        rej(RejectCode::AcceptedMismatch),
    ).requirements(&[ACCEPTED_EQUAL]).authored(None).build();
    batch_verify_unsupported_scheme_reject => voucher_case(
        "batch-verify-unsupported-scheme-reject", accepted_spec(), BugType::Precedence,
        "accepted.scheme \"exact\": a batch-settlement route does not verify another scheme's envelope.",
        verify_input(&route(), &with(requirements(), "scheme", json!("exact")), &voucher_payload(&cfg(), honest_voucher(4_000)), Some(fx::store_record(&cfg(), 3_000, 10_000)), fx::rpc_fixtures(Some((&cfg(), &ChannelAccount::default())), Atas::Healthy, TOKEN_PROGRAM)),
        rej(RejectCode::UnsupportedScheme),
    ).requirements(&[ACCEPTED_EQUAL]).build();
    batch_verify_x402_version_1_reject => voucher_case(
        "batch-verify-x402-version-1-reject", s("4.5 Facilitator Interface", "| `x402Version` | number | yes | MUST be `2`. |"), BugType::Wire,
        "The accept case's envelope with x402Version 1.",
        { let mut i = voucher_input(&cfg(), honest_voucher(4_000), 3_000, 10_000, ChannelAccount::default()); i["x402PaymentHeader"] = json!(fx::envelope_header(&json!({ "x402Version": 1, "accepted": requirements(), "payload": voucher_payload(&cfg(), honest_voucher(4_000)) }))); i },
        rej(RejectCode::UnsupportedVersion),
    ).requirements(&[VERSION_TWO]).authored(None).build();
    batch_verify_authorization_on_client_route_reject => voucher_case(
        "batch-verify-authorization-on-client-route-reject", s("4.3 Client PaymentPayload Variants", "| `channelConfig` | `ChannelConfig` | MUST select server mode. |"), BugType::AuthBypass,
        "An authorization payload (server-mode payer proof) on a client-mode route whose channelConfig selects client mode: not a valid variant here.",
        verify_input(&route(), &requirements(), &json!({ "type": "authorization", "channelConfig": cfg(), "authorization": { "type": "proof", "channelId": channel(&cfg()), "payer": fx::payer(), "requestId": "req-1", "authorizedAmount": "1000", "expiresAt": 4_102_444_800_i64, "signature": fx::sign_voucher(&channel(&cfg()), 1, 0, fx::PAYER_SEED) } }), Some(fx::store_record(&cfg(), 3_000, 10_000)), fx::rpc_fixtures(Some((&cfg(), &ChannelAccount::default())), Atas::Healthy, TOKEN_PROGRAM)),
        rej(RejectCode::PayloadType),
    ).requirements(&["X402-62a1b36ba4", PAYLOAD_VARIANTS]).build();
    batch_verify_deposit_without_voucher_reject => voucher_case(
        "batch-verify-deposit-without-voucher-reject", s("4.3 Client PaymentPayload Variants", "REQUIRED in client mode and absent in server mode."), BugType::AuthBypass,
        "A client-mode deposit carrying a payer proof instead of its voucher.",
        verify_input(&route(), &requirements(), &json!({ "type": "deposit", "channelConfig": cfg(), "deposit": { "amount": "6000", "transaction": top_up_tx(vec![], 6_000, memo()) }, "authorization": { "type": "proof", "channelId": channel(&cfg()), "payer": fx::payer(), "requestId": "req-1", "authorizedAmount": "1000", "expiresAt": 4_102_444_800_i64, "signature": fx::sign_voucher(&channel(&cfg()), 1, 0, fx::PAYER_SEED) } }), Some(fx::store_record(&cfg(), 3_000, 4_000)), fx::rpc_fixtures(Some((&cfg(), &ChannelAccount { deposit: 4_000, ..Default::default() })), Atas::Healthy, TOKEN_PROGRAM)),
        rej(RejectCode::PayloadType),
    ).requirements(&[DEPOSIT_VOUCHER, "X402-492eabbfab"]).build();

    // ── server verify: top-up (deposit) and the sponsor's policy ──
    batch_verify_top_up_accept => policy_case(
        "batch-verify-top-up-accept", top_up_spec(), &[TOP_UP_AMOUNT, STATIC_VALIDATE, LAYOUT],
        "Charged 3000 of a 4000 deposit: a canonical top_up of 6000 (6 accounts, 9 data bytes, payer signed, sponsor slot empty) with the seller memo, plus the voucher at 4000 <= 10000.",
        top_up_tx(vec![], TOP_UP_AMOUNT_ADDED, memo()),
        Expect::Accept(Pin::Outcome),
    );
    batch_verify_top_up_compute_budget_prefix => policy_case(
        "batch-verify-top-up-compute-budget-prefix", policy_spec("If both are present, the limit MUST precede the price."), &[LAYOUT, LIMIT_BEFORE_PRICE, CB_LIMIT, CB_PRICE],
        "Paired accept: SetComputeUnitLimit 400000 then SetComputeUnitPrice 5000000 (both at the cap) before the top_up.",
        top_up_tx(vec![fx::compute_ix(&fx::unit_limit(400_000)), fx::compute_ix(&fx::unit_price(5_000_000))], TOP_UP_AMOUNT_ADDED, memo()),
        Expect::Accept(Pin::Outcome),
    );
    batch_verify_top_up_three_lighthouse => policy_case(
        "batch-verify-top-up-three-lighthouse", policy_spec("and at most three Lighthouse instructions"), &[LAYOUT, ALLOWLIST],
        "Paired accept: the memo followed by three Lighthouse assertions in the suffix.",
        top_up_tx(vec![], TOP_UP_AMOUNT_ADDED, { let mut s = memo(); s.extend((0..3).map(|i| fx::lighthouse_ix(&[i]))); s }),
        Expect::Accept(Pin::Outcome),
    );
    batch_verify_top_up_legacy_message => policy_case(
        "batch-verify-top-up-legacy-message", policy_spec("The message MAY be legacy or version `0`, but it MUST NOT contain Address Lookup Table lookups."), &[STATIC_VALIDATE],
        "The canonical top_up compiled as a legacy (unversioned) message: accepted and policed like version 0.",
        fx::sponsored_legacy(vec![fx::top_up_ix(&cfg(), TOP_UP_AMOUNT_ADDED), fx::memo_ix(fx::MEMO)]),
        Expect::Accept(Pin::Outcome),
    );
    batch_verify_top_up_amount_mismatch_reject => policy_case(
        "batch-verify-top-up-amount-mismatch-reject", top_up_spec(), &[TOP_UP_AMOUNT],
        "deposit.amount says 6000 but the decoded top_up funds 5000.",
        top_up_tx(vec![], 5_000, memo()),
        rej(RejectCode::SetupTransaction),
    );
    batch_verify_top_up_exceeds_deposit_reject => case(
        "batch-verify-top-up-exceeds-deposit-reject", "batch-verify-setup-policy.json", Mode::VerifyTransaction, Role::Server, BugType::Settlement,
        s("Phase 3 - Voucher Acceptance (before serving)", "for `top_up`, against the existing onchain channel with its deposit increased by `payload.deposit.amount`."),
        "Charged 3500 of a 4000 deposit: the next voucher (4500) is the correct step, but the top-up of 400 raises the ceiling only to 4400, below the voucher.",
        { let route = route(); let config = fx::config(&route); let payload = json!({ "type": "deposit", "channelConfig": config, "voucher": fx::voucher(&channel(&config), 4_500, 0, fx::PAYER_SEED), "deposit": { "amount": "400", "transaction": top_up_tx(vec![], 400, memo()) } }); verify_input(&route, &requirements(), &payload, Some(fx::store_record(&config, 3_500, 4_000)), fx::rpc_fixtures(Some((&config, &ChannelAccount { deposit: 4_000, ..Default::default() })), Atas::Healthy, TOKEN_PROGRAM)) },
        rej(RejectCode::CumulativeExceedsDeposit),
    ).requirements(&[EVERY_PAID_REQUEST]).build();
    batch_verify_top_up_smuggled_transfer_reject => policy_case(
        "batch-verify-top-up-smuggled-transfer-reject", policy_spec("No other top-level instruction or program is allowed."), &[NO_SMUGGLING, LAYOUT],
        "A System transfer of 1 SOL from the sponsor appended after the memo: the sponsor's signature would authorize a drain.",
        top_up_tx(vec![], TOP_UP_AMOUNT_ADDED, { let mut s = memo(); s.push(solana_instruction::Instruction { program_id: keys::pubkey(keys::SYSTEM_PROGRAM), accounts: vec![solana_instruction::AccountMeta::new(keys::pubkey(&fx::fee_payer()), true), solana_instruction::AccountMeta::new(keys::pubkey(&fx::payer()), false)], data: { let mut d = 2u32.to_le_bytes().to_vec(); d.extend_from_slice(&1_000_000_000u64.to_le_bytes()); d } }); s }),
        rej(RejectCode::SetupTransaction),
    );
    batch_verify_top_up_second_setup_instruction_reject => policy_case(
        "batch-verify-top-up-second-setup-instruction-reject", policy_spec("In particular, a top-level associated-token-account instruction, arbitrary wallet program, second payment-channel instruction, or duplicate setup instruction MUST cause rejection."), &[NO_SMUGGLING],
        "Two top_up instructions in one transaction (a duplicate setup instruction).",
        top_up_tx(vec![fx::top_up_ix(&cfg(), TOP_UP_AMOUNT_ADDED)], TOP_UP_AMOUNT_ADDED, memo()),
        rej(RejectCode::SetupTransaction),
    );
    batch_verify_top_up_ata_instruction_reject => policy_case(
        "batch-verify-top-up-ata-instruction-reject", policy_spec("In particular, a top-level associated-token-account instruction, arbitrary wallet program, second payment-channel instruction, or duplicate setup instruction MUST cause rejection."), &[NO_SMUGGLING],
        "A top-level CreateIdempotent ATA instruction before the top_up.",
        top_up_tx(vec![{ let mut ix = solana_pay_kit::core::payment_channels::build_create_associated_token_account_instruction(&keys::pubkey(&fx::payer()), &keys::pubkey(X402_PAY_TO), &keys::pubkey(MINT), &keys::pubkey(TOKEN_PROGRAM)); ix.data = vec![1]; ix }], TOP_UP_AMOUNT_ADDED, memo()),
        rej(RejectCode::SetupTransaction),
    );
    batch_verify_top_up_memo_mismatch_reject => policy_case(
        "batch-verify-top-up-memo-mismatch-reject", policy_spec("The Memo data MUST be `extra.memo` as UTF-8 when supplied"), &[MEMO_DATA],
        "The memo reads \"invoice-43\" while extra.memo is \"invoice-42\".",
        top_up_tx(vec![], TOP_UP_AMOUNT_ADDED, vec![fx::memo_ix("invoice-43")]),
        rej(RejectCode::SetupTransaction),
    );
    batch_verify_top_up_missing_memo_reject => policy_case(
        "batch-verify-top-up-missing-memo-reject", policy_spec("A suffix containing exactly one SPL Memo instruction"), &[MEMO_DATA, LAYOUT],
        "The top_up carries no Memo: the sponsor cannot correlate what it paid for.",
        top_up_tx(vec![], TOP_UP_AMOUNT_ADDED, vec![]),
        rej(RejectCode::SetupTransaction),
    );
    batch_verify_top_up_two_memos_reject => policy_case(
        "batch-verify-top-up-two-memos-reject", policy_spec("A suffix containing exactly one SPL Memo instruction"), &[LAYOUT],
        "Two seller memos on a top-up (a top-up carries no binding memo: it does not re-bind).",
        top_up_tx(vec![], TOP_UP_AMOUNT_ADDED, vec![fx::memo_ix(fx::MEMO), fx::memo_ix(fx::MEMO)]),
        rej(RejectCode::SetupTransaction),
    );
    batch_verify_top_up_oversized_memo_reject => policy_case(
        "batch-verify-top-up-oversized-memo-reject", s("4.1 PaymentRequirements (in PAYMENT-REQUIRED.accepts[])", "Seller-defined UTF-8 payment reference for the setup transaction's Memo instruction. Maximum 256 bytes."), &[MEMO_DATA],
        "A 257-byte memo (over the 256-byte maximum, and not extra.memo).",
        top_up_tx(vec![], TOP_UP_AMOUNT_ADDED, vec![fx::memo_ix(&"m".repeat(257))]),
        rej(RejectCode::SetupTransaction),
    );
    batch_verify_top_up_compute_limit_over_cap_reject => policy_case(
        "batch-verify-top-up-compute-limit-over-cap-reject", policy_spec("MUST set a compute-unit limit no greater than `400000`"), &[CB_LIMIT],
        "SetComputeUnitLimit 400001: one unit over the cap.",
        top_up_tx(vec![fx::compute_ix(&fx::unit_limit(400_001))], TOP_UP_AMOUNT_ADDED, memo()),
        rej(RejectCode::SetupTransaction),
    );
    batch_verify_top_up_compute_price_over_cap_reject => policy_case(
        "batch-verify-top-up-compute-price-over-cap-reject", policy_spec("MUST set a compute-unit price no greater than `5000000` microlamports per compute unit."), &[CB_PRICE],
        "SetComputeUnitPrice 5000001 µlamports: one over the cap.",
        top_up_tx(vec![fx::compute_ix(&fx::unit_price(5_000_001))], TOP_UP_AMOUNT_ADDED, memo()),
        rej(RejectCode::SetupTransaction),
    );
    batch_verify_top_up_price_before_limit_reject => policy_case(
        "batch-verify-top-up-price-before-limit-reject", policy_spec("If both are present, the limit MUST precede the price."), &[LIMIT_BEFORE_PRICE],
        "SetComputeUnitPrice before SetComputeUnitLimit (both within the caps).",
        top_up_tx(vec![fx::compute_ix(&fx::unit_price(1_000)), fx::compute_ix(&fx::unit_limit(200_000))], TOP_UP_AMOUNT_ADDED, memo()),
        rej(RejectCode::SetupTransaction),
    );
    batch_verify_top_up_unsupported_compute_budget_reject => policy_case(
        "batch-verify-top-up-unsupported-compute-budget-reject", policy_spec("MUST use only discriminator `2` (`SetComputeUnitLimit`, exactly 5 data bytes) or discriminator `3`"), &[CB_DISCRIMINATOR],
        "SetLoadedAccountsDataSizeLimit (discriminator 4) in the prefix.",
        top_up_tx(vec![fx::compute_ix(&[4, 0, 0, 0, 1])], TOP_UP_AMOUNT_ADDED, memo()),
        rej(RejectCode::SetupTransaction),
    );
    batch_verify_top_up_duplicate_limit_reject => policy_case(
        "batch-verify-top-up-duplicate-limit-reject", policy_spec("An optional Compute Budget prefix containing at most one `SetComputeUnitLimit` instruction"), &[LAYOUT],
        "Two SetComputeUnitLimit instructions.",
        top_up_tx(vec![fx::compute_ix(&fx::unit_limit(200_000)), fx::compute_ix(&fx::unit_limit(200_000))], TOP_UP_AMOUNT_ADDED, memo()),
        rej(RejectCode::SetupTransaction),
    );
    batch_verify_top_up_four_lighthouse_reject => policy_case(
        "batch-verify-top-up-four-lighthouse-reject", policy_spec("and at most three Lighthouse instructions"), &[LAYOUT],
        "Four Lighthouse assertions after the memo.",
        top_up_tx(vec![], TOP_UP_AMOUNT_ADDED, { let mut s = memo(); s.extend((0..4).map(|i| fx::lighthouse_ix(&[i]))); s }),
        rej(RejectCode::SetupTransaction),
    );
    batch_verify_top_up_fee_payer_in_memo_reject => policy_case(
        "batch-verify-top-up-fee-payer-in-memo-reject", policy_spec("Lighthouse and Memo instructions are allowed only in the final suffix and MUST NOT reference `extra.feePayer` as an account or as the invoked program."), &[SUFFIX_NO_FEE_PAYER],
        "The memo lists the sponsor as a signer account.",
        top_up_tx(vec![], TOP_UP_AMOUNT_ADDED, vec![{ let mut ix = fx::memo_ix(fx::MEMO); ix.accounts.push(solana_instruction::AccountMeta::new_readonly(keys::pubkey(&fx::fee_payer()), true)); ix }]),
        rej(RejectCode::SetupTransaction),
    );
    batch_verify_top_up_fee_payer_not_sponsor_reject => policy_case(
        "batch-verify-top-up-fee-payer-not-sponsor-reject", policy_spec("The transaction fee payer MUST equal `extra.feePayer`."), &[FEE_PAYER_IS_TX_FEE_PAYER],
        "The client is its own transaction fee payer (single signer).",
        fx::v0_tx(vec![fx::top_up_ix(&cfg(), TOP_UP_AMOUNT_ADDED), fx::memo_ix(fx::MEMO)], &fx::payer(), &[fx::PAYER_SEED]),
        rej(RejectCode::SetupTransaction),
    );
    batch_verify_top_up_extra_signer_reject => policy_case(
        "batch-verify-top-up-extra-signer-reject", policy_spec("The complete required-signer set MUST equal the distinct addresses in `{ channelConfig.payer, extra.feePayer }`."), &[SIGNER_SET],
        "A third required signer (a read-only signer on the memo), signed.",
        { let mut s = vec![fx::with_signer(fx::memo_ix(fx::MEMO), &fx::stranger())]; let mut ixs = vec![fx::top_up_ix(&cfg(), TOP_UP_AMOUNT_ADDED)]; ixs.append(&mut s); fx::v0_tx(ixs, &fx::fee_payer(), &[fx::PAYER_SEED, fx::STRANGER_SEED]) },
        rej(RejectCode::SetupTransaction),
    );
    batch_verify_top_up_missing_payer_signature_reject => policy_case(
        "batch-verify-top-up-missing-payer-signature-reject", policy_spec("The payer signature MUST be present and valid before the sponsor signs."), &[PAYER_SIGNATURE],
        "The canonical top_up with the payer slot left empty.",
        fx::v0_tx(vec![fx::top_up_ix(&cfg(), TOP_UP_AMOUNT_ADDED), fx::memo_ix(fx::MEMO)], &fx::fee_payer(), &[]),
        rej(RejectCode::SetupTransaction),
    );
    batch_verify_top_up_wrong_channel_reject => policy_case(
        "batch-verify-top-up-wrong-channel-reject", s("Canonical top_up", "contain exactly these six accounts in order, and contain no remaining accounts:"), &[TOP_UP_LAYOUT],
        "The top_up funds the salt-43 channel instead of the channel the payload names.",
        fx::sponsored(vec![fx::top_up_ix(&with(cfg(), "salt", json!("43")), TOP_UP_AMOUNT_ADDED), fx::memo_ix(fx::MEMO)]),
        rej(RejectCode::SetupTransaction),
    );
    batch_verify_top_up_trailing_bytes_reject => policy_case(
        "batch-verify-top-up-trailing-bytes-reject", s("Canonical open", "The facilitator MUST fully decode the instruction data, reject truncated data or trailing bytes"), &[FULL_DECODE],
        "top_up data with one trailing byte (10 bytes instead of 9).",
        fx::sponsored(vec![{ let mut ix = fx::top_up_ix(&cfg(), TOP_UP_AMOUNT_ADDED); ix.data.push(0); ix }, fx::memo_ix(fx::MEMO)]),
        rej(RejectCode::SetupTransaction),
    );
    batch_verify_top_up_fee_payer_as_account_reject => policy_case(
        "batch-verify-top-up-fee-payer-as-account-reject", s("Canonical top_up", "In this form `extra.feePayer` authorizes only the bounded transaction fee and MUST NOT be an instruction account, authority, source, or delegate."), &[TOP_UP_FEE_PAYER, "X402-9ca40ae469"],
        "The top_up names the sponsor as its payer_token_account.",
        fx::sponsored(vec![{ let mut ix = fx::top_up_ix(&cfg(), TOP_UP_AMOUNT_ADDED); ix.accounts[2] = solana_instruction::AccountMeta::new(keys::pubkey(&fx::fee_payer()), false); ix }, fx::memo_ix(fx::MEMO)]),
        rej(RejectCode::SetupTransaction),
    );
    batch_verify_top_up_token_program_not_mint_owner_reject => case(
        "batch-verify-top-up-token-program-not-mint-owner-reject", "batch-verify-setup-policy.json", Mode::VerifyTransaction, Role::Server, BugType::Defaults,
        s("4.2 Shared Wire Objects and Program Mapping", "The client and facilitator MUST confirm `extra.tokenProgram` equals the onchain owner of `channelConfig.token`"),
        "The accept top-up, but the mint is owned by Token-2022 onchain while the route advertises SPL Token.",
        top_up_input_with(&route(), top_up_tx(vec![], TOP_UP_AMOUNT_ADDED, memo()), "6000", 4_000, Atas::Healthy, TOKEN_2022_PROGRAM),
        rej(RejectCode::TokenProgram),
    ).requirements(&[TOKEN_PROGRAM_OWNER]).build();
    batch_verify_top_up_missing_receiver_ata_reject => case(
        "batch-verify-top-up-missing-receiver-ata-reject", "batch-verify-setup-policy.json", Mode::VerifyTransaction, Role::Server, BugType::Settlement,
        s("Canonical top_up", "it MUST reject before escrowing when a settlement account is missing, frozen, has the wrong owner or mint"),
        "The payTo recipient ATA does not exist: the escrow could never be distributed.",
        top_up_input_with(&route(), top_up_tx(vec![], TOP_UP_AMOUNT_ADDED, memo()), "6000", 4_000, Atas::MissingReceiver, TOKEN_PROGRAM),
        rej(RejectCode::SettlementSimulation),
    ).requirements(&[SETTLEMENT_ACCOUNTS]).authored(None).build();
    batch_verify_top_up_frozen_payer_ata_reject => case(
        "batch-verify-top-up-frozen-payer-ata-reject", "batch-verify-setup-policy.json", Mode::VerifyTransaction, Role::Server, BugType::Settlement,
        s("Canonical top_up", "it MUST reject before escrowing when a settlement account is missing, frozen, has the wrong owner or mint"),
        "The payer's return ATA is frozen: the unused escrow could not be returned at close.",
        top_up_input_with(&route(), top_up_tx(vec![], TOP_UP_AMOUNT_ADDED, memo()), "6000", 4_000, Atas::FrozenPayer, TOKEN_PROGRAM),
        rej(RejectCode::SettlementSimulation),
    ).requirements(&[SETTLEMENT_ACCOUNTS, "X402-fbdea947ae"]).authored(None).build();

    // ── server verify: open ──
    batch_verify_open_accept => open_case(
        "batch-verify-open-accept", s("Top-level instruction layout", "An `open` suffix also carries exactly one binding Memo from section 3."), &[OPEN_ENCODE, MEMO_EXACT, BINDING_KEY],
        "A canonical open (14 accounts, sponsor as rent_payer and payee, 100% to payTo, openSlot inside the window of the fixture slot) with the seller memo and the receiver-binding memo, and the first voucher (1000 <= 10000).",
        open_tx(honest_open(), open_suffix()),
        Expect::AcceptAuthored(json!({})),
    ).authored(None).build();
    batch_verify_open_missing_binding_memo_reject => open_case(
        "batch-verify-open-missing-binding-memo-reject", s("Top-level instruction layout", "An `open` suffix also carries exactly one binding Memo from section 3."), &[MEMO_EXACT, BINDING_KEY],
        "The open carries only the seller memo: without the binding memo the channel is bound to no receiver authorizer.",
        open_tx(honest_open(), vec![fx::memo_ix(fx::MEMO)]),
        rej(RejectCode::SetupTransaction),
    ).authored(None).build();
    batch_verify_open_foreign_binding_reject => open_case(
        "batch-verify-open-foreign-binding-reject", s("3. Payment-Channel Method", "The server MUST reject an open whose binding Memo is not its own key before forwarding the deposit."), &[SERVER_REJECTS_FOREIGN_BINDING, BINDING_KEY],
        "The binding memo names a key other than the server's receiverAuthorizer.",
        open_tx(honest_open(), vec![fx::memo_ix(fx::MEMO), fx::memo_ix(&fx::binding_memo(&fx::stranger()))]),
        rej(RejectCode::ReceiverAuthorizerMismatch),
    ).authored(None).build();
    batch_verify_open_diverting_distribution_reject => open_case(
        "batch-verify-open-diverting-distribution-reject", s("4.1 PaymentRequirements (in PAYMENT-REQUIRED.accepts[])", "The channel distribution for this scheme MUST NOT assign any portion of settled funds away from `payTo`."), &[NO_DIVERSION, OPEN_ENCODE],
        "The open's single distribution entry pays another receiver at 100%.",
        open_tx(fx::open_ix(&cfg(), 10_000, keys::X402_OTHER_PAY_TO), open_suffix()),
        rej(RejectCode::SetupTransaction),
    ).build();
    batch_verify_open_deposit_mismatch_reject => open_case(
        "batch-verify-open-deposit-mismatch-reject", s("4.2 Shared Wire Objects and Program Mapping", "For a new channel, the `open` instruction MUST encode:"), &[OPEN_ENCODE],
        "The open escrows 9000 while deposit.amount says 10000.",
        open_tx(fx::open_ix(&cfg(), 9_000, X402_PAY_TO), open_suffix()),
        rej(RejectCode::SetupTransaction),
    ).build();
    batch_verify_open_grace_period_mismatch_reject => open_case(
        "batch-verify-open-grace-period-mismatch-reject", s("4.2 Shared Wire Objects and Program Mapping", "For a new channel, the `open` instruction MUST encode:"), &[OPEN_ENCODE, WITHDRAW_EQUAL],
        "The open's grace_period is 7200 while channelConfig.withdrawDelay is 3600 (the PDA does not depend on it).",
        open_tx(fx::open_ix(&with(cfg(), "withdrawDelay", json!(7_200)), 10_000, X402_PAY_TO), open_suffix()),
        rej(RejectCode::WithdrawDelayMismatch),
    ).authored(None).build();
    batch_verify_open_stale_slot_reject => case(
        "batch-verify-open-stale-slot-reject", "batch-verify-open.json", Mode::VerifyTransaction, Role::Server, BugType::Settlement,
        s("Phase 1 - Open or Top Up", "The facilitator MUST reject an expired transaction blockhash and an `openSlot` outside the program's accepted window."),
        "openSlot 341000000 while the cluster is at slot 341001501, one past the 1500-slot window.",
        with(open_input(open_tx(honest_open(), open_suffix())), "rpcFixtures", with(fx::rpc_fixtures(None, Atas::Healthy, TOKEN_PROGRAM), "slot", json!(341_001_501_u64))),
        rej(RejectCode::SetupTransaction),
    ).requirements(&[OPEN_SLOT_WINDOW]).build();
    batch_verify_open_future_slot_reject => case(
        "batch-verify-open-future-slot-reject", "batch-verify-open.json", Mode::VerifyTransaction, Role::Server, BugType::Settlement,
        s("Phase 1 - Open or Top Up", "The facilitator MUST reject an expired transaction blockhash and an `openSlot` outside the program's accepted window."),
        "openSlot 341000000 ahead of the cluster's slot 340999999.",
        with(open_input(open_tx(honest_open(), open_suffix())), "rpcFixtures", with(fx::rpc_fixtures(None, Atas::Healthy, TOKEN_PROGRAM), "slot", json!(340_999_999_u64))),
        rej(RejectCode::SetupTransaction),
    ).requirements(&[OPEN_SLOT_WINDOW]).build();
    batch_verify_open_first_voucher_above_amount_reject => case(
        "batch-verify-open-first-voucher-above-amount-reject", "batch-verify-open.json", Mode::VerifyTransaction, Role::Server, BugType::Settlement, cumulative_spec(),
        "A new channel's first voucher authorizes 2000 for a 1000 request (charged starts at 0).",
        { let mut i = open_input(open_tx(honest_open(), open_suffix())); let payload = json!({ "type": "deposit", "channelConfig": cfg(), "voucher": honest_voucher(2_000), "deposit": { "amount": "10000", "transaction": open_tx(honest_open(), open_suffix()) } }); i["x402PaymentHeader"] = json!(fx::header(&requirements(), &payload)); i },
        rej(RejectCode::CumulativeAmountMismatch),
    ).requirements(&[EVERY_PAID_REQUEST]).build();
    batch_verify_open_channel_pda_mismatch_reject => open_case(
        "batch-verify-open-channel-pda-mismatch-reject", s("Canonical open", "and enforce the exact salt, deposit, grace period, open slot, single-recipient distribution, and PDA derivation specified in sections 4.1 and"), &[FULL_DECODE],
        "The open instruction's args are for salt 43 while its channel account and the payload are the salt-42 PDA.",
        open_tx({ let mut ix = honest_open(); ix.data[1..9].copy_from_slice(&43u64.to_le_bytes()); ix }, open_suffix()),
        rej(RejectCode::SetupTransaction),
    ).build();

    // ── server verify: refund ──
    batch_verify_refund_request_close => case(
        "batch-verify-refund-request-close", "batch-verify-refund.json", Mode::VerifyTransaction, Role::Server, BugType::Settlement,
        s("4.5 Facilitator Interface", "When the binding is unavailable, the facilitator MUST validate and co-sign the client's `request_close` transaction with `extra.feePayer`"),
        "Client-mode refund retried with a payer-signed request_close (binding unavailable): the voucher equals the accepted cumulative (3000), the transaction is exactly request_close(payer, channel) plus the seller memo, the channel is Open and the payer's return ATA healthy.",
        refund_input_with(refund_payload(Some(honest_voucher(3_000)), Some(request_close(memo()))), ChannelAccount::default()),
        Expect::AcceptAuthored(json!({})),
    ).requirements(&[BINDING_UNAVAILABLE, RC_ONE_INSTRUCTION, REFUND_STATUS]).authored(None).build();
    batch_verify_refund_without_voucher_reject => case(
        "batch-verify-refund-without-voucher-reject", "batch-verify-refund.json", Mode::VerifyTransaction, Role::Server, BugType::AuthBypass,
        refund_voucher_spec(),
        "A client-mode refund carrying only the request_close and no voucher.",
        refund_input_with(refund_payload(None, Some(request_close(memo()))), ChannelAccount::default()),
        rej(RejectCode::PayloadType),
    ).requirements(&[REFUND_VOUCHER]).authored(None).build();
    batch_verify_refund_voucher_not_accepted_cumulative_reject => case(
        "batch-verify-refund-voucher-not-accepted-cumulative-reject", "batch-verify-refund.json", Mode::VerifyTransaction, Role::Server, BugType::Settlement,
        s("4.5 Facilitator Interface", "In client mode it MUST reject a voucher whose `maxClaimableAmount` differs from its accepted cumulative amount."),
        "The refund's voucher is at 2000 while the server accepted 3000: a payer cannot close at an older watermark.",
        refund_input_with(refund_payload(Some(honest_voucher(2_000)), Some(request_close(memo()))), ChannelAccount::default()),
        rej(RejectCode::CloseState),
    ).requirements(&[REFUND_CUMULATIVE]).authored(None).build();
    batch_verify_refund_with_amount_reject => case(
        "batch-verify-refund-with-amount-reject", "batch-verify-refund.json", Mode::VerifyTransaction, Role::Server, BugType::Settlement,
        s("4.3 Client PaymentPayload Variants", "the payload MUST NOT contain an `amount`."),
        "A refund naming amount \"1500\" (a partial refund): only the full unused escrow returns.",
        refund_input_with(with(refund_payload(Some(honest_voucher(3_000)), Some(request_close(memo()))), "amount", json!("1500")), ChannelAccount::default()),
        rej(RejectCode::CloseAmountUnsupported),
    ).requirements(&[REFUND_NO_AMOUNT]).build();
    batch_verify_refund_sealed_channel_reject => case(
        "batch-verify-refund-sealed-channel-reject", "batch-verify-refund.json", Mode::VerifyTransaction, Role::Server, BugType::Settlement,
        s("4.5 Facilitator Interface", "The channel MUST be `Open` or still within its `Closing` grace period"),
        "The channel is already Sealed: it cannot be closed again.",
        refund_input_with(refund_payload(Some(honest_voucher(3_000)), Some(request_close(memo()))), ChannelAccount { status: 1, ..Default::default() }),
        rej(RejectCode::CloseState),
    ).requirements(&[REFUND_STATUS]).authored(None).build();
    batch_verify_refund_extra_instruction_reject => refund_case(
        "batch-verify-refund-extra-instruction-reject", refund_spec("The refund transaction MUST contain exactly one canonical payment-channels `request_close` instruction for the PDA derived from `channelConfig`."), &[RC_ONE_INSTRUCTION],
        "A seal instruction rides along after request_close.",
        request_close({ let mut s = vec![solana_pay_kit::core::payment_channels::build_seal_instruction(&fx::channel_id(&cfg()), &solana_pay_kit::core::payment_channels::default_program_id())]; s.extend(memo()); s }),
        rej(RejectCode::RefundTransaction),
    );
    batch_verify_refund_prefix_only_reject => refund_case(
        "batch-verify-refund-prefix-only-reject", refund_spec("The refund transaction MUST contain exactly one canonical payment-channels `request_close` instruction for the PDA derived from `channelConfig`."), &[RC_ONE_INSTRUCTION],
        "Only a ComputeBudget prefix and a memo: no request_close at all.",
        fx::sponsored(vec![fx::with_signer(fx::compute_ix(&fx::unit_limit(200_000)), &fx::payer()), fx::memo_ix(fx::MEMO)]),
        rej(RejectCode::RefundTransaction),
    );
    batch_verify_refund_compute_price_over_cap_reject => refund_case(
        "batch-verify-refund-compute-price-over-cap-reject", refund_spec("It MAY also contain the bounded Compute Budget prefix allowed above"), &[RC_SUFFIX, CB_PRICE],
        "An out-of-policy ComputeBudget prefix (price 5000001) before request_close.",
        fx::sponsored(vec![fx::compute_ix(&fx::unit_price(5_000_001)), fx::request_close_ix(&cfg()), fx::memo_ix(fx::MEMO)]),
        rej(RejectCode::RefundTransaction),
    );
    batch_verify_refund_disallowed_suffix_reject => refund_case(
        "batch-verify-refund-disallowed-suffix-reject", refund_spec("The suffix uses the same program and fee-payer-isolation rules as setup transactions; when `extra.memo` is present, a supplied Memo MUST match it."), &[RC_SUFFIX],
        "A System-program instruction in the suffix (outside the Memo/Lighthouse allowlist).",
        request_close({ let mut s = memo(); s.push(solana_instruction::Instruction { program_id: keys::pubkey(keys::SYSTEM_PROGRAM), accounts: vec![], data: vec![9] }); s }),
        rej(RejectCode::RefundTransaction),
    );
    batch_verify_refund_memo_mismatch_reject => refund_case(
        "batch-verify-refund-memo-mismatch-reject", refund_spec("The suffix uses the same program and fee-payer-isolation rules as setup transactions; when `extra.memo` is present, a supplied Memo MUST match it."), &[RC_SUFFIX],
        "The supplied memo differs from extra.memo.",
        request_close(vec![fx::memo_ix("invoice-43")]),
        rej(RejectCode::RefundTransaction),
    );
    batch_verify_refund_fee_payer_not_sponsor_reject => refund_case(
        "batch-verify-refund-fee-payer-not-sponsor-reject", refund_spec("The transaction MUST contain the payer signature and `extra.feePayer` as fee payer; no other signer or address lookup table is permitted."), &[RC_SIGNERS],
        "The payer is its own fee payer: the sponsor's slot is not the fee-payer slot.",
        fx::v0_tx(vec![fx::request_close_ix(&cfg()), fx::memo_ix(fx::MEMO)], &fx::payer(), &[fx::PAYER_SEED]),
        rej(RejectCode::RefundTransaction),
    );
    batch_verify_refund_invalid_payer_signature_reject => refund_case(
        "batch-verify-refund-invalid-payer-signature-reject", refund_spec("The transaction MUST contain the payer signature and `extra.feePayer` as fee payer; no other signer or address lookup table is permitted."), &[RC_SIGNERS],
        "The payer slot holds a signature by another key.",
        { let tx = fx::sponsored(vec![fx::request_close_ix(&cfg()), fx::memo_ix(fx::MEMO)]); let mut decoded = crate::tx::decode_b64(&tx).unwrap(); decoded.signatures[1] = solana_signature::Signature::from([7u8; 64]); crate::tx::encode_b64(&decoded).unwrap() },
        rej(RejectCode::RefundTransaction),
    );
    batch_verify_refund_extra_account_reject => refund_case(
        "batch-verify-refund-extra-account-reject", refund_spec("The instruction MUST use discriminator `5`, contain exactly these two accounts in order, and contain no remaining accounts:"), &[RC_ACCOUNTS],
        "request_close with a third (remaining) account.",
        fx::sponsored(vec![{ let mut ix = fx::request_close_ix(&cfg()); ix.accounts.push(solana_instruction::AccountMeta::new_readonly(keys::pubkey(X402_PAY_TO), false)); ix }, fx::memo_ix(fx::MEMO)]),
        rej(RejectCode::RefundTransaction),
    );
    batch_verify_refund_wrong_channel_reject => refund_case(
        "batch-verify-refund-wrong-channel-reject", refund_spec("The refund transaction MUST contain exactly one canonical payment-channels `request_close` instruction for the PDA derived from `channelConfig`."), &[RC_ONE_INSTRUCTION],
        "request_close for the salt-43 channel instead of the derived PDA.",
        fx::sponsored(vec![fx::request_close_ix(&with(cfg(), "salt", json!("43"))), fx::memo_ix(fx::MEMO)]),
        rej(RejectCode::RefundTransaction),
    );

    // ── transaction versions (x402-txv1) ──
    batch_txv1_top_up_v1_advertised => txv1_case(
        "batch-txv1-top-up-v1-advertised", tx_versions_spec("A version-1 transaction carries its compute budget in the message `TransactionConfig`."), &[TX_ADVERTISED, TX_DEPOSIT_VERSION, TX_V1_BUDGET],
        "The route advertises transactionVersions [0, 1]: a version-1 top_up with computeUnitLimit, loadedAccountsDataSizeLimit and a priorityFee within the cap in its header, no ComputeBudget instruction, is accepted.",
        v1_input(&v1_route(), v1_top_up(fx::v1_budget(), vec![])),
        Expect::Accept(Pin::Outcome),
    ).build();
    batch_txv1_top_up_v1_not_advertised_reject => txv1_case(
        "batch-txv1-top-up-v1-not-advertised-reject", tx_versions_spec("The facilitator MUST reject a message whose version is outside the set it accepts, before inspecting any instruction, with `unsupported_transaction_version`."), &[TX_FACILITATOR_REJECTS, TX_ADVERTISED],
        "The same version-1 top_up on a route that accepts only version 0 (no transactionVersions advertised).",
        v1_input(&route(), v1_top_up(fx::v1_budget(), vec![])),
        rej(RejectCode::UnsupportedVersion),
    ).authored(None).build();
    batch_txv1_top_up_v0_on_v1_route => txv1_case(
        "batch-txv1-top-up-v0-on-v1-route", tx_versions_spec("Absent means `[0]`."), &[TX_ADVERTISED],
        "A version-0 top_up on a route accepting [0, 1]: version 0 stays accepted and policed as before.",
        v1_input(&v1_route(), top_up_tx(vec![], TOP_UP_AMOUNT_ADDED, memo())),
        Expect::Accept(Pin::Outcome),
    ).build();
    batch_txv1_top_up_v1_compute_budget_instruction_reject => txv1_case(
        "batch-txv1-top-up-v1-compute-budget-instruction-reject", t("Top-level instruction layout", "A version-1 transaction that contains a Compute Budget instruction MUST be rejected."), &[TX_V1_NO_CB],
        "A version-1 top_up that also carries a SetComputeUnitLimit instruction.",
        v1_input(&v1_route(), v1_top_up(fx::v1_budget(), vec![fx::compute_ix(&fx::unit_limit(200_000))])),
        rej(RejectCode::SetupTransaction),
    ).build();
    batch_txv1_top_up_v1_missing_unit_limit_reject => txv1_case(
        "batch-txv1-top-up-v1-missing-unit-limit-reject", t("Top-level instruction layout", "`computeUnitLimit` MUST be present and MUST NOT exceed `400000`"), &[TX_V1_CAPS, TX_V1_BUDGET],
        "A version-1 top_up whose header config omits computeUnitLimit (it would be budgeted zero).",
        v1_input(&v1_route(), v1_top_up(solana_message::v1::TransactionConfig::empty().with_loaded_accounts_data_size_limit(64 * 1024 * 1024), vec![])),
        rej(RejectCode::SetupTransaction),
    ).build();
    batch_txv1_top_up_v1_missing_loaded_limit_reject => txv1_case(
        "batch-txv1-top-up-v1-missing-loaded-limit-reject", t("Top-level instruction layout", "`loadedAccountsDataSizeLimit` MUST be present"), &[TX_V1_CAPS, TX_V1_BUDGET],
        "A version-1 top_up whose header config omits loadedAccountsDataSizeLimit.",
        v1_input(&v1_route(), v1_top_up(solana_message::v1::TransactionConfig::empty().with_compute_unit_limit(200_000), vec![])),
        rej(RejectCode::SetupTransaction),
    ).build();
    batch_txv1_top_up_v1_loaded_limit_below_max => txv1_case(
        "batch-txv1-top-up-v1-loaded-limit-below-max", t("Top-level instruction layout", "`loadedAccountsDataSizeLimit` MUST be present"), &[TX_V1_CAPS, TX_V1_BUDGET],
        "A version-1 top_up whose header sets loadedAccountsDataSizeLimit 32 MiB (present, below the runtime maximum): the spec requires the field, not a particular value, and a sponsor may only tighten caps it names.",
        v1_input(&v1_route(), v1_top_up(fx::v1_budget().with_loaded_accounts_data_size_limit(32 * 1024 * 1024), vec![])),
        Expect::AcceptAuthored(json!({})),
    ).authored(None).build();
    batch_txv1_top_up_v1_unit_limit_over_cap_reject => txv1_case(
        "batch-txv1-top-up-v1-unit-limit-over-cap-reject", t("Top-level instruction layout", "`computeUnitLimit` MUST be present and MUST NOT exceed `400000`"), &[TX_V1_CAPS],
        "Header computeUnitLimit 400001.",
        v1_input(&v1_route(), v1_top_up(fx::v1_budget().with_compute_unit_limit(400_001), vec![])),
        rej(RejectCode::SetupTransaction),
    ).build();
    batch_txv1_top_up_v1_priority_fee_over_cap_reject => txv1_case(
        "batch-txv1-top-up-v1-priority-fee-over-cap-reject", t("Top-level instruction layout", "`priorityFee * 1000000 <= 5000000 * computeUnitLimit`"), &[TX_V1_CAPS],
        "priorityFee 1000001 lamports at computeUnitLimit 200000: 1000001 × 10^6 > 5000000 × 200000 (one lamport over the cap).",
        v1_input(&v1_route(), v1_top_up(fx::v1_budget().with_priority_fee(1_000_001), vec![])),
        rej(RejectCode::SetupTransaction),
    ).build();
    batch_txv1_top_up_v1_priority_fee_at_cap => txv1_case(
        "batch-txv1-top-up-v1-priority-fee-at-cap", t("Top-level instruction layout", "`priorityFee * 1000000 <= 5000000 * computeUnitLimit`"), &[TX_V1_CAPS],
        "Paired accept: priorityFee 1000000 lamports at computeUnitLimit 200000 is exactly the cap.",
        v1_input(&v1_route(), v1_top_up(fx::v1_budget().with_priority_fee(1_000_000), vec![])),
        Expect::Accept(Pin::Outcome),
    ).build();
    batch_txv1_top_up_v0_over_1232_bytes_reject => txv1_case(
        "batch-txv1-top-up-v0-over-1232-bytes-reject", tx_versions_spec("A legacy or version-0 transaction MUST NOT exceed 1232 serialized bytes; a version-1 transaction MUST NOT exceed 4096 serialized bytes."), &[TX_SIZE],
        "A version-0 top_up whose three 330-byte Lighthouse assertions push it past 1232 serialized bytes.",
        v1_input(&v1_route(), { let mut s = memo(); s.extend(heavy_lighthouse()); fx::sponsored({ let mut ixs = vec![fx::top_up_ix(&cfg(), TOP_UP_AMOUNT_ADDED)]; ixs.extend(s); ixs }) }),
        rej(RejectCode::SetupTransaction),
    ).build();
    batch_txv1_top_up_v1_over_1232_bytes => txv1_case(
        "batch-txv1-top-up-v1-over-1232-bytes", tx_versions_spec("A legacy or version-0 transaction MUST NOT exceed 1232 serialized bytes; a version-1 transaction MUST NOT exceed 4096 serialized bytes."), &[TX_SIZE],
        "Paired accept: the same instructions as version 1 (limit 4096 bytes) on a route that advertises it.",
        v1_input(&v1_route(), fx::sponsored_v1({ let mut ixs = vec![fx::top_up_ix(&cfg(), TOP_UP_AMOUNT_ADDED)]; ixs.extend(memo()); ixs.extend(heavy_lighthouse()); ixs }, fx::v1_budget())),
        Expect::Accept(Pin::Outcome),
    ).build();
    batch_txv1_top_up_legacy_policed_as_v0_reject => txv1_case(
        "batch-txv1-top-up-legacy-policed-as-v0-reject", tx_versions_spec("A facilitator MAY keep accepting legacy messages from existing clients for backward compatibility"), &[TX_ADVERTISED],
        "A legacy top_up with SetComputeUnitPrice 5000001: a tolerated legacy message gets the version-0 caps, not a free pass.",
        v1_input(&v1_route(), fx::sponsored_legacy(vec![fx::compute_ix(&fx::unit_price(5_000_001)), fx::top_up_ix(&cfg(), TOP_UP_AMOUNT_ADDED), fx::memo_ix(fx::MEMO)])),
        rej(RejectCode::SetupTransaction),
    ).build();
    batch_txv1_refund_v1_not_advertised_reject => txv1_case(
        "batch-txv1-refund-v1-not-advertised-reject", t("4.3 Client PaymentPayload Variants", "Its message version MUST be one advertised in `extra.transactionVersions`."), &[TX_REFUND_VERSION, TX_FACILITATOR_REJECTS],
        "A client-mode refund whose request_close is version 1 on a route that accepts only version 0.",
        refund_input_with(refund_payload(Some(honest_voucher(3_000)), Some(fx::sponsored_v1(vec![fx::request_close_ix(&cfg()), fx::memo_ix(fx::MEMO)], fx::v1_budget()))), ChannelAccount::default()),
        rej(RejectCode::UnsupportedVersion),
    ).authored(None).build();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixture_channel_account_decodes_with_the_kit_type() {
        let config = cfg();
        let account = fx::channel_account(&config, &ChannelAccount::default());
        use base64::Engine;
        let data = base64::engine::general_purpose::STANDARD
            .decode(account["data"].as_str().unwrap())
            .unwrap();
        let channel =
            solana_pay_kit::core::payment_channels::generated::generated::accounts::Channel::from_bytes(&data)
                .unwrap();
        assert_eq!(channel.deposit, 10_000);
        assert_eq!(channel.grace_period, fx::WITHDRAW_DELAY);
    }

    // The open rejects pin the spec's suffix (seller memo plus binding
    // memo); the kit must refuse each one for the check its case names, not
    // at the memo scan, so the vectors discriminate.
    #[test]
    fn the_kit_refuses_each_open_reject_for_its_own_check() {
        let at_slot = |slot: u64| {
            with(
                open_input(open_tx(honest_open(), open_suffix())),
                "rpcFixtures",
                with(
                    fx::rpc_fixtures(None, Atas::Healthy, TOKEN_PROGRAM),
                    "slot",
                    json!(slot),
                ),
            )
        };
        let voucher_above = {
            let tx = open_tx(honest_open(), open_suffix());
            let mut i = open_input(tx.clone());
            let payload = json!({ "type": "deposit", "channelConfig": cfg(), "voucher": honest_voucher(2_000), "deposit": { "amount": "10000", "transaction": tx } });
            i["x402PaymentHeader"] = json!(fx::header(&requirements(), &payload));
            i
        };
        let cases: Vec<(&str, Value, RejectCode, &str)> = vec![
            (
                "diverting distribution",
                open_input(open_tx(
                    fx::open_ix(&cfg(), 10_000, keys::X402_OTHER_PAY_TO),
                    open_suffix(),
                )),
                RejectCode::SetupTransaction,
                "open distribution must pay 100%",
            ),
            (
                "deposit mismatch",
                open_input(open_tx(
                    fx::open_ix(&cfg(), 9_000, X402_PAY_TO),
                    open_suffix(),
                )),
                RejectCode::SetupTransaction,
                "open deposit 9000",
            ),
            (
                "grace period",
                open_input(open_tx(
                    fx::open_ix(
                        &with(cfg(), "withdrawDelay", json!(7_200)),
                        10_000,
                        X402_PAY_TO,
                    ),
                    open_suffix(),
                )),
                RejectCode::WithdrawDelayMismatch,
                "grace_period 7200",
            ),
            (
                "stale slot",
                at_slot(341_001_501),
                RejectCode::SetupTransaction,
                "outside the 1500-slot window",
            ),
            (
                "future slot",
                at_slot(340_999_999),
                RejectCode::SetupTransaction,
                "ahead of the current slot",
            ),
            (
                "first voucher above amount",
                voucher_above,
                RejectCode::CumulativeAmountMismatch,
                "first voucher must authorize exactly",
            ),
        ];
        let rt = tokio::runtime::Runtime::new().unwrap();
        let accept = rt.block_on(crate::realize::run(
            Intent::X402BatchSettlement,
            Mode::VerifyTransaction,
            &open_input(open_tx(honest_open(), open_suffix())),
        ));
        assert!(
            matches!(accept, crate::realize::Observed::Accept(_)),
            "{}",
            accept.summary()
        );
        for (name, input, code, check) in cases {
            match rt.block_on(crate::realize::run(
                Intent::X402BatchSettlement,
                Mode::VerifyTransaction,
                &input,
            )) {
                crate::realize::Observed::Reject {
                    code: Some(got),
                    message,
                } => {
                    assert_eq!(got, code, "{name}: {message}");
                    assert!(message.contains(check), "{name}: {message}");
                }
                other => panic!("{name}: {}", other.summary()),
            }
        }
    }

    #[test]
    fn heavy_lighthouse_crosses_only_the_v0_limit() {
        let mut ixs = vec![fx::top_up_ix(&cfg(), TOP_UP_AMOUNT_ADDED)];
        ixs.extend(memo());
        ixs.extend(heavy_lighthouse());
        let v0 = crate::tx::decode_b64(&fx::sponsored(ixs.clone())).unwrap();
        let v1 = crate::tx::decode_b64(&fx::sponsored_v1(ixs, fx::v1_budget())).unwrap();
        let size = |tx| solana_pay_kit::core::tx::serialized_size(tx).unwrap();
        assert!(size(&v0) > 1232, "{}", size(&v0));
        assert!(size(&v1) <= 4096, "{}", size(&v1));
    }
}
