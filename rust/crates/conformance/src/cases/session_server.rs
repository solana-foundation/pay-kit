//! Session (draft-solana-session-00) server verification and client build
//! cases: the `open`, `voucher`, `topUp` and `close` credentials a session
//! server verifies (`sessionServerVerify`), the client's `open` build
//! (`sessionOpenBuild`), and the strict wire shapes (`sessionWire`).
//!
//! Every server case is a credential the kit's client builds and signs, then
//! one tamper (`realize::session::TxTamper`, paired with its reject code) or
//! credential edit; each reject is paired with the accept that differs only
//! in the field under test (named in its description).

use serde_json::{json, Value};

use crate::case::{
    spec, BugType, CaseBuilder, Expect, Input, Intent, Mode, Pin, RejectCode, Role, SpecRef, Suite,
};
use crate::keys;
use crate::mutate::Mutation;
use crate::realize::session::{
    operator, session_signer, Action, Authorized, BuildRecipe, Channel, Edit, OpenArg, OpenBuild,
    OpenParams, Recipe, Server, TxTamper, VoucherSpec, CHALLENGE_ID, FAR_EXPIRY, OPERATOR_SEED,
    PAST_EXPIRY, RECENT_SLOT, SESSION_SIGNER_SEED, STRANGER_SEED,
};

const DOC: &str = "mpp-specs/specs/methods/solana/draft-solana-session-00.md";

const OPEN: &str = "session-server-open.json";
const VOUCHER: &str = "session-server-voucher.json";
const TOPUP: &str = "session-server-topup.json";
const CLOSE: &str = "session-server-close.json";
const BUILD: &str = "session-build.json";
const WIRE: &str = "session-wire-strict.json";

// ── requirement ids (harness/requirements/mpp.toml) ────────────────────────

const R_DERIVE: &str = "MPP-994af38957";
const R_DISAGREE: &str = "MPP-c108029161";
const R_DECODED: &str = "MPP-36fd6945f0";
const R_BINDING: &str = "MPP-a4620e1d52";
const R_RENT_PAYER: &str = "MPP-25dd4709fe";
const R_IDX1: &str = "MPP-1289809c4e";
const R_IDX1_SETTLE: &str = "MPP-eebad15185";
const R_FEE_PAYER_KEY: &str = "MPP-d0a49deec1";
const R_AUTH_SIGNER_FIELD: &str = "MPP-aa166e34b4";
const R_OPEN_SLOT: &str = "MPP-dc4603ccd4";
const R_OPEN_SLOT_PDA: &str = "MPP-73f0b859d9";
const R_OPEN_SLOT_SEED: &str = "MPP-733a58af31";
const R_FUTURE_SLOT: &str = "MPP-664cb0aec6";
const R_WINDOW: &str = "MPP-48e464d2fb";
const R_IDLE_MATCH: &str = "MPP-e436a4d7d5";
const R_IDLE_REJECT: &str = "MPP-1c0ce290f2";
const R_IDLE_PROBLEM: &str = "MPP-ea7a6777e6";
const R_IDLE_FIELD: &str = "MPP-4797b22e1a";
const R_IDLE_CLIENT: &str = "MPP-c20fb92f4d";
const R_SPLITS: &str = "MPP-a9cb73c5b3";
const R_MIN_DEPOSIT: &str = "MPP-d142f89f1c";
const R_DEPOSIT_FIELD: &str = "MPP-ec0236515c";
const R_DEPOSIT_NONZERO: &str = "MPP-e4dc36f3bd";
const R_GRACE_FIELD: &str = "MPP-53a60f6563";
const R_GRACE_CHALLENGED: &str = "MPP-382e76fa94";
const R_PAYEE_FIELD: &str = "MPP-3da59f1464";
const R_MINT_FIELD: &str = "MPP-299460514f";
const R_MINT_LIST: &str = "MPP-bf87a688ef";
const R_TOKEN_PROGRAM: &str = "MPP-b5cf9fcdaa";
const R_OFF_CURVE: &str = "MPP-060fb1362b";
const R_CURVE_OPEN: &str = "MPP-ebbc4c1186";
const R_CURVE: &str = "MPP-4658b373e8";
const R_BUMP: &str = "MPP-427162b59f";
const R_BUMP_REJECT: &str = "MPP-2f056735f6";
const R_NO_VOUCHER: &str = "MPP-89f2059960";
const R_AUTH_FIELD: &str = "MPP-04f98ac67d";
const R_OPERATOR_OPEN: &str = "MPP-7126d3b0b5";
const R_PROOF_VERIFY: &str = "MPP-421303e0b1";
const R_PROOF_BIND: &str = "MPP-85917fe086";
const R_OPERATOR_KEY: &str = "MPP-05f0c337af";
const R_BLOCKHASH: &str = "MPP-ff870e0a38";
const R_BLOCKHASH_USE: &str = "MPP-d235eadc2e";
const R_PAYER_SIGNER: &str = "MPP-16faa7304f";
const R_TX_FIELD: &str = "MPP-a5edb594a1";
const R_OPEN_ACTION: &str = "MPP-48a0bd6cec";

const R_VERIFY_EACH: &str = "MPP-ec9e85084d";
const R_SIGNER: &str = "MPP-89a6d0c5d7";
const R_JSON_BYTES: &str = "MPP-7ba6f01984";
const R_MONOTONIC: &str = "MPP-8ebbf6e151";
const R_REPLAY: &str = "MPP-ae84beeba3";
const R_INCREMENT: &str = "MPP-13061769bf";
const R_FORCED_CLOSE: &str = "MPP-ff8313704f";
const R_STOP: &str = "MPP-a3aff47c7c";
const R_IDENTITY: &str = "MPP-895f62e266";
const R_SIG_TYPE: &str = "MPP-54d28c98f1";
const R_CUMULATIVE_FIELD: &str = "MPP-d26228ea73";
const R_CHANNEL_FIELD: &str = "MPP-389a42bd5e";
const R_OPERATOR_VOUCHER: &str = "MPP-0fee0ce818";
const R_VOUCHER_OBJ: &str = "MPP-ebee0156c7";
const R_SIGNATURE_FIELD: &str = "MPP-56d8994e89";

const R_TOPUP_AMOUNT: &str = "MPP-8ea927661c";
const R_TOPUP_OPEN: &str = "MPP-632d3435dd";
const R_TOPUP_CLOSING: &str = "MPP-cb6b8e2000";
const R_TOPUP_ADDITIONAL: &str = "MPP-3e70e39f13";
const R_TOPUP_TX: &str = "MPP-dfaa074bfa";
const R_TOPUP_ACTION: &str = "MPP-4d3fa28dc4";

const R_CLOSE_VOUCHER: &str = "MPP-c74d298862";
const R_CLOSE_AUTH: &str = "MPP-bcea8a5303";
const R_CLOSE_OPERATOR: &str = "MPP-2d69701867";
const R_CLOSE_CLIENT: &str = "MPP-8c63a2fb5d";
const R_CLOSE_AT_OR_BELOW: &str = "MPP-a1180cd750";
const R_CLOSE_ACTION: &str = "MPP-146a845b55";

const R_FEE_KEY_PRESENT: &str = "MPP-d5da84fe70";
const R_RECENT_PAIR: &str = "MPP-69c0a4f95f";
const R_PROGRAM_CHECK: &str = "MPP-ecdf5de619";
const R_PROGRAM_TRUST: &str = "MPP-abf416b62c";
const R_NATIVE_SOL: &str = "MPP-3719d666e8";
const R_TOKEN_PROGRAM_SET: &str = "MPP-43d1f3332b";
const R_NETWORK: &str = "MPP-ec29292f9d";
const R_GRACE_POSITIVE: &str = "MPP-374b81ceaa";
const R_OPERATOR_PRESENT: &str = "MPP-5eae297bd5";
const R_DECIMALS: &str = "MPP-a3d2da92ea";

const R_VOUCHER_SIGNER_VALUES: &str = "MPP-391cb5b326";
const R_NETWORK_EXPLICIT: &str = "MPP-bb80675c8e";
const R_SALT_FIELD: &str = "MPP-a9eb047d07";
const R_USE_ACTION: &str = "MPP-06150f0fd1";
const R_USE_CHANNEL: &str = "MPP-3a413603bc";
const R_USE_AUTH: &str = "MPP-2d5c87a7f3";
const R_PROOF_TYPE: &str = "MPP-9edde7b556";
const R_PROOF_CHALLENGE: &str = "MPP-b23323ead0";
const R_PROOF_PAYER: &str = "MPP-f8ce7faac8";
const R_PROOF_SIG: &str = "MPP-d7767fee2b";

// ── spec references ────────────────────────────────────────────────────────

fn s(section: &str, quote: &str) -> SpecRef {
    spec(DOC, section, quote)
}

fn open_settlement(quote: &str) -> SpecRef {
    s("Open", quote)
}

fn open_action(quote: &str) -> SpecRef {
    s("Action: \"open\"", quote)
}

fn derive_spec() -> SpecRef {
    s(
        "Channel State",
        "Clients and servers MUST derive the expected channelId from the channel program ID and the seed components above and MUST verify that the open transaction creates and funds exactly that PDA.",
    )
}

fn disagree_spec() -> SpecRef {
    open_action(
        "Servers MUST reject Action: \"open\" credentials when the challenge, HTTP payload, decoded transaction, derived PDA, escrow ATA, token program, or confirmed on-chain state disagree.",
    )
}

fn verification_spec() -> SpecRef {
    s(
        "Voucher Verification",
        "The server MUST verify each voucher:",
    )
}

// ── case constructors ──────────────────────────────────────────────────────

fn accept() -> Expect {
    Expect::Accept(Pin::Outcome)
}

fn rej(code: RejectCode) -> Expect {
    Expect::Reject { code, reason: None }
}

#[allow(clippy::too_many_arguments)]
fn server_case(
    id: &str,
    file: &'static str,
    bug: BugType,
    spec: SpecRef,
    reqs: &[&str],
    description: &str,
    recipe: Recipe,
    expect: Expect,
) -> CaseBuilder {
    let description = match recipe.describe() {
        Some(what) => format!("{description} Mutation: {what}."),
        None => description.to_string(),
    };
    CaseBuilder::new(
        id,
        file,
        Suite::Session,
        Intent::Session,
        Mode::VerifyTransaction,
        Role::Server,
        bug,
        spec,
        &description,
        Input::Session(Box::new(recipe)),
        expect,
    )
    .requirements(reqs)
}

fn open_case(
    id: &str,
    spec: SpecRef,
    reqs: &[&str],
    description: &str,
    recipe: Recipe,
    expect: Expect,
) -> CaseBuilder {
    server_case(
        id,
        OPEN,
        BugType::AuthBypass,
        spec,
        reqs,
        &format!("{description} The open is the kit client's open action for the challenge the server issues; the server runs every check it makes before broadcasting."),
        recipe,
        expect,
    )
}

fn voucher_case(
    id: &str,
    bug: BugType,
    spec: SpecRef,
    reqs: &[&str],
    description: &str,
    recipe: Recipe,
    expect: Expect,
) -> CaseBuilder {
    server_case(
        id,
        VOUCHER,
        bug,
        spec,
        reqs,
        &format!("{description} The server's channel holds a deposit of 1000 with 100 accepted and spent; the challenged amount is 25."),
        recipe,
        expect,
    )
}

fn topup_case(
    id: &str,
    spec: SpecRef,
    reqs: &[&str],
    description: &str,
    recipe: Recipe,
    expect: Expect,
) -> CaseBuilder {
    server_case(
        id,
        TOPUP,
        BugType::Settlement,
        spec,
        reqs,
        &format!("{description} The top-up is a client-signed transaction for the stored channel; the server runs every check it makes before broadcasting."),
        recipe,
        expect,
    )
}

fn close_case(
    id: &str,
    bug: BugType,
    spec: SpecRef,
    reqs: &[&str],
    description: &str,
    recipe: Recipe,
    expect: Expect,
) -> CaseBuilder {
    server_case(
        id,
        CLOSE,
        bug,
        spec,
        reqs,
        &format!("{description} The server's channel holds a deposit of 1000 and its highest accepted voucher is 100."),
        recipe,
        expect,
    )
}

fn build_case(
    id: &str,
    spec: SpecRef,
    reqs: &[&str],
    description: &str,
    recipe: BuildRecipe,
    expect: Expect,
) -> CaseBuilder {
    let description = if recipe.edits.is_empty() {
        description.to_string()
    } else {
        let edits: Vec<String> = recipe.edits.iter().map(Edit::describe).collect();
        format!(
            "{description} Challenge edit: {}.",
            edits.join("; ").replace("credential ", "challenge ")
        )
    };
    CaseBuilder::new(
        id,
        BUILD,
        Suite::Session,
        Intent::Session,
        Mode::BuildTransaction,
        Role::Client,
        BugType::Defaults,
        spec,
        &description,
        Input::SessionBuild(Box::new(recipe)),
        expect,
    )
    .requirements(reqs)
}

fn wire_case(
    id: &str,
    spec: SpecRef,
    reqs: &[&str],
    description: &str,
    shape: &str,
    value: Value,
    expect: Expect,
) -> CaseBuilder {
    CaseBuilder::new(
        id,
        WIRE,
        Suite::Session,
        Intent::Session,
        Mode::CanonicalBytes,
        Role::Both,
        BugType::Wire,
        spec,
        description,
        Input::Static(json!({ "sessionWire": { "shape": shape, "value": value } })),
        expect,
    )
    .requirements(reqs)
}

fn golden() -> Expect {
    Expect::Accept(Pin::ExactBytes(vec!["canonicalJson", "base64Url"]))
}

fn invalid(reason: &str) -> Expect {
    Expect::Reject {
        code: RejectCode::InvalidPayload,
        reason: Some(reason.to_string()),
    }
}

// ── fixtures ───────────────────────────────────────────────────────────────

fn server() -> Server {
    Server::default()
}

fn sponsored() -> Server {
    Server {
        sponsored: true,
        ..Server::default()
    }
}

fn operator_server() -> Server {
    Server {
        voucher_signer: "operator",
        ..Server::default()
    }
}

fn with_splits() -> Server {
    Server {
        splits: vec![(keys::SPLIT_RECIPIENT_2, 500)],
        ..Server::default()
    }
}

fn idle_options() -> Server {
    Server {
        idle_timeout_options: Some(vec![60, 300, 900]),
        ..Server::default()
    }
}

fn open_built(
    verify: Server,
    build: OpenBuild,
    built_from: Option<Server>,
    verify_slot: u64,
) -> Recipe {
    Recipe::new(
        verify,
        Action::Open {
            build,
            built_from,
            verify_slot,
        },
    )
}

fn open_with(verify: Server, build: OpenBuild) -> Recipe {
    open_built(verify, build, None, RECENT_SLOT)
}

fn operator_build() -> OpenBuild {
    OpenBuild {
        proof_for: Some(CHALLENGE_ID),
        ..OpenBuild::default()
    }
}

/// The channel PDA of the default open with another salt.
fn other_channel() -> solana_pubkey::Pubkey {
    let mut params = OpenParams::client(&server()).params();
    params.salt += 1;
    solana_pay_kit::core::payment_channels::derive_channel_addresses(&params).channel
}

fn other_escrow() -> String {
    keys::ata(
        &other_channel().to_string(),
        keys::MINT,
        keys::TOKEN_PROGRAM,
    )
    .to_string()
}

fn client_proof() -> Value {
    serde_json::to_value(Channel::client(0).proof().expect("proof")).expect("proof json")
}

fn voucher_recipe(channel: Channel, voucher: VoucherSpec) -> Recipe {
    Recipe::new(server(), Action::Voucher { channel, voucher })
}

fn topup_recipe(server: Server, channel: Channel, amount: u64) -> Recipe {
    Recipe::new(server, Action::TopUp { channel, amount })
}

fn close_recipe(channel: Channel, voucher: Option<VoucherSpec>, authentication: bool) -> Recipe {
    let server = if channel.voucher_signer == "operator" {
        operator_server()
    } else {
        server()
    };
    Recipe::new(
        server,
        Action::Close {
            channel,
            voucher,
            authentication,
        },
    )
}

fn sponsored_channel() -> Channel {
    let mut channel = Channel::client(100);
    channel.open = OpenParams::client(&sponsored());
    channel
}

fn closing(mut channel: Channel) -> Channel {
    channel.closure_started_at = Some(1_800_000_000);
    channel
}

fn sealed(mut channel: Channel) -> Channel {
    channel.closed = true;
    channel
}

fn build_recipe(server: Server) -> BuildRecipe {
    BuildRecipe {
        server,
        authorized: Authorized::SessionKey,
        edits: vec![],
    }
}

fn build_edit(edit: Edit) -> BuildRecipe {
    BuildRecipe {
        edits: vec![edit],
        ..build_recipe(server())
    }
}

fn build_summary() -> Expect {
    Expect::Accept(Pin::ExactBytes(vec![
        "channelId",
        "payer",
        "payee",
        "mint",
        "authorizedSigner",
        "salt",
        "depositAmount",
        "gracePeriodSeconds",
        "openSlot",
        "distributionSplits",
        "feePayer",
        "recentBlockhash",
        "signatureSlots",
    ]))
}

fn invalid_challenge() -> Expect {
    rej(RejectCode::InvalidChallenge)
}

const CHANNEL: &str = "cGfHiC6Kgg3FpFZvgwGcswsCRtp4aBP2fzuXRQPizuN";
const SIGNATURE: &str =
    "AKAh9LUoWFG2sxAMotzmLNpKwPTCiG6Q4YTwAinZMnkvYKPAKVPwYSfoQDp8XLKWzpbCNx66XB1BrcD1ZUPqU39";

fn open_wire() -> Value {
    json!({"action": "open", "authorizedSigner": "Config1111111111111111111111111111111111111", "channelId": CHANNEL, "depositAmount": "5000", "gracePeriodSeconds": 900, "mint": "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU", "openSlot": "250000000", "payee": "Stake11111111111111111111111111111111111111", "payer": "Vote111111111111111111111111111111111111111", "salt": "7777", "transaction": "AQID"})
}

fn voucher_wire() -> Value {
    json!({"action": "voucher", "channelId": CHANNEL, "voucher": {"signature": SIGNATURE, "signatureType": "ed25519", "signer": "Config1111111111111111111111111111111111111", "voucher": {"channelId": CHANNEL, "cumulativeAmount": "250", "expiresAt": 4102444800_i64}}})
}

fn request_wire() -> Value {
    json!({"amount": "100", "currency": "USDC", "methodDetails": {"channelProgram": "CHNLxYvVA28MJP9PrFuDXccuoGXAx7jBacfLEkahyGsX", "decimals": 6, "gracePeriodSeconds": 900, "network": "devnet", "recentBlockhash": "EkSnNWid2cvwEVnVx9aBqawnmiCNiDgp3gUdkDPTKN1N", "recentSlot": "250000000", "tokenProgram": "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"}, "recipient": "11111111111111111111111111111111"})
}

fn with(mut value: Value, pointer: &str, new: Value) -> Value {
    let (parent, leaf) = pointer.rsplit_once('/').expect("pointer");
    value
        .pointer_mut(parent)
        .and_then(Value::as_object_mut)
        .expect("parent")
        .insert(leaf.to_string(), new);
    value
}

fn without(mut value: Value, pointer: &str) -> Value {
    let (parent, leaf) = pointer.rsplit_once('/').expect("pointer");
    value
        .pointer_mut(parent)
        .and_then(Value::as_object_mut)
        .expect("parent")
        .remove(leaf);
    value
}

crate::registry! {
    // ── open: accepts ──────────────────────────────────────────────────────
    session_open_client_paid_accept => open_case(
        "session-open-client-paid-accept",
        derive_spec(),
        &[R_DERIVE, R_DECODED, R_OPEN_ACTION],
        "Client-paid open (the payer is fee payer and rentPayer) of a delegated session key, deposit 1000, the challenged recentSlot as openSlot and the challenged blockhash: every field agrees, so the server accepts. The baseline every open reject pairs with.",
        Recipe::open(server()),
        accept(),
    ).build();
    session_open_sponsored_accept => open_case(
        "session-open-sponsored-accept",
        s("open", "MUST be the operator / fee-payer key already in scope (the same key that co-signs open as fee payer); a single operator signature satisfies both the fee-payer and rentPayer signer roles."),
        &[R_RENT_PAYER, R_FEE_PAYER_KEY, R_IDX1, R_IDX1_SETTLE],
        "feePayer: the challenge names the operator as feePayerKey, the client builds the open with the operator as fee payer and rentPayer (account 1) and leaves its slot empty; the server co-signs.",
        Recipe::open(sponsored()),
        accept(),
    ).build();
    session_open_payer_signer_accept => open_case(
        "session-open-payer-signer-accept",
        open_action("| authorizedSigner | string | REQUIRED | Base58 public key bound into the PDA seeds as the voucher signer; MAY equal payer or a delegated signer |"),
        &[R_AUTH_SIGNER_FIELD, R_DERIVE],
        "The payer authorizes itself as voucher signer (no delegation). Pair: session-open-client-paid-accept (a delegated key).",
        open_with(server(), OpenBuild { authorized: Authorized::Payer, ..OpenBuild::default() }),
        accept(),
    ).build();
    session_open_earlier_open_slot_accept => open_case(
        "session-open-earlier-open-slot-accept",
        open_action("| openSlot | string | REQUIRED | Decimal u64 per-incarnation epoch encoded into the open instruction as open_slot; MUST be no greater than the challenge's methodDetails.recentSlot and MUST satisfy the on-chain window rule of {{channel-closure}} when the transaction executes."),
        &[R_OPEN_SLOT],
        "openSlot back-dated 100 slots below the challenged recentSlot (a client MAY choose an earlier openSlot).",
        open_with(server(), OpenBuild { open_slot: Some(RECENT_SLOT - 100), ..OpenBuild::default() }),
        accept(),
    ).build();
    session_open_open_slot_window_edge_accept => open_case(
        "session-open-open-slot-window-edge-accept",
        open_settlement("Verify the credential's openSlot equals the decoded open_slot and satisfies the open-slot window relative to both the challenged recentSlot (openSlot <= recentSlot and recentSlot - openSlot <= OPEN_SLOT_WINDOW)"),
        &[R_OPEN_SLOT, R_WINDOW],
        "openSlot exactly OPEN_SLOT_WINDOW (1500) slots below the challenged recentSlot: the last slot inside the window.",
        open_with(server(), OpenBuild { open_slot: Some(RECENT_SLOT - 1_500), ..OpenBuild::default() }),
        accept(),
    ).build();
    session_open_idle_timeout_offered_accept => open_case(
        "session-open-idle-timeout-offered-accept",
        s("Server-Initiated Idle Close", "A client-selected value MUST exactly match an offered value."),
        &[R_IDLE_MATCH, R_IDLE_FIELD],
        "The challenge offers idleTimeoutOptionsSeconds [60, 300, 900]; the client selects 300.",
        open_with(idle_options(), OpenBuild { idle_timeout_seconds: Some(300), ..OpenBuild::default() }),
        accept(),
    ).build();
    session_open_splits_accept => open_case(
        "session-open-splits-accept",
        open_action("| distributionSplits | array | OPTIONAL | Splits preimage (see the challenge's methodDetails.distributionSplits); MUST byte-match the splits proposed in the 402 challenge |"),
        &[R_SPLITS],
        "The challenge proposes one co-recipient at 500 bps; the open commits exactly that preimage.",
        Recipe::open(with_splits()),
        accept(),
    ).build();
    session_open_deposit_at_minimum_accept => open_case(
        "session-open-deposit-at-minimum-accept",
        s("Shared Fields", "Servers MUST reject POST /channel/open payloads with depositAmount < minimumDeposit."),
        &[R_MIN_DEPOSIT, R_DEPOSIT_FIELD],
        "depositAmount 100 equals the challenged minimumDeposit 100.",
        open_with(server(), OpenBuild { deposit: Some(100), ..OpenBuild::default() }),
        accept(),
    ).build();
    session_open_deposit_one_accept => open_case(
        "session-open-deposit-one-accept",
        s("open", "| deposit | u64 | Initial deposit in base units; MUST be non-zero |"),
        &[R_DEPOSIT_NONZERO],
        "No minimumDeposit and a deposit of 1 base unit.",
        open_with(Server { minimum_deposit: None, ..Server::default() }, OpenBuild { deposit: Some(1), ..OpenBuild::default() }),
        accept(),
    ).build();
    session_open_operator_accept => open_case(
        "session-open-operator-accept",
        s("Session Bearer Proof", "The proof's challengeId, channelId, and payer MUST equal the opening challenge ID, declared and derived channel ID, and transaction payer."),
        &[R_PROOF_VERIFY, R_PROOF_BIND, R_OPERATOR_OPEN, R_OPERATOR_KEY],
        "voucherSigner operator: authorizedSigner is the challenged operator and the open carries the payer's bearer proof signed for the opening challenge and the derived channel.",
        open_with(operator_server(), operator_build()),
        accept(),
    ).build();
    session_open_token_2022_accept => open_case(
        "session-open-token-2022-accept",
        open_settlement("If the challenge supplied tokenProgram, the decoded token program MUST match it; otherwise it MUST be a supported token program for the mint."),
        &[R_TOKEN_PROGRAM],
        "A Token-2022 mint with tokenProgram Token-2022 in the challenge; the open's token program and escrow ATA are Token-2022's.",
        Recipe::open(Server { currency: keys::MINT_2022, token_program: Some(keys::TOKEN_2022_PROGRAM), ..Server::default() }),
        accept(),
    ).build();

    // ── open: the envelope disagrees with the challenge ───────────────────
    session_open_deposit_below_minimum_reject => open_case(
        "session-open-deposit-below-minimum-reject",
        s("Shared Fields", "Servers MUST reject POST /channel/open payloads with depositAmount < minimumDeposit."),
        &[R_MIN_DEPOSIT, R_DEPOSIT_FIELD],
        "depositAmount 99 against minimumDeposit 100 (the open is built for a challenge without the floor). Pair: session-open-deposit-at-minimum-accept.",
        open_built(server(), OpenBuild { deposit: Some(99), ..OpenBuild::default() }, Some(Server { minimum_deposit: None, ..Server::default() }), RECENT_SLOT),
        rej(RejectCode::AmountMismatch),
    ).build();
    session_open_deposit_zero_reject => open_case(
        "session-open-deposit-zero-reject",
        s("open", "| deposit | u64 | Initial deposit in base units; MUST be non-zero |"),
        &[R_DEPOSIT_NONZERO],
        "A deposit of 0 with no minimumDeposit. Pair: session-open-deposit-one-accept.",
        open_with(Server { minimum_deposit: None, ..Server::default() }, OpenBuild { deposit: Some(0), ..OpenBuild::default() }),
        rej(RejectCode::AmountMismatch),
    ).build();
    session_open_deposit_envelope_mismatch_reject => open_case(
        "session-open-deposit-envelope-mismatch-reject",
        open_action("| depositAmount | string | REQUIRED | Initial deposit in base units; MUST equal the decoded open deposit and satisfy depositAmount >= minimumDeposit (when the challenge sets one) |"),
        &[R_DEPOSIT_FIELD, R_DECODED, R_BINDING],
        "The envelope claims depositAmount 999 while the signed open deposits 1000. Pair: session-open-client-paid-accept.",
        Recipe::open(server()).edit(Edit::Set("/depositAmount", json!("999"))),
        rej(RejectCode::OpenBindingMismatch),
    ).build();
    session_open_deposit_argument_reject => open_case(
        "session-open-deposit-argument-reject",
        open_settlement("Verify the decoded deposit equals depositAmount, satisfies methodDetails.minimumDeposit (when set), and that the resulting distributionHash matches the digest of the canonical preimage of the splits proposed in the 402 challenge."),
        &[R_DEPOSIT_FIELD, R_DECODED, R_BINDING],
        "The signed open deposits 5000 while the envelope says 1000. Pair: session-open-client-paid-accept.",
        Recipe::open(server()).tx(TxTamper::OpenArg(OpenArg::Deposit(5_000))),
        rej(RejectCode::OpenBindingMismatch),
    ).build();
    session_open_grace_period_mismatch_reject => open_case(
        "session-open-grace-period-mismatch-reject",
        s("Grace Period Security", "Servers MUST verify that a new channel uses the challenged gracePeriodSeconds."),
        &[R_GRACE_FIELD, R_GRACE_CHALLENGED],
        "The open (envelope and instruction) binds a 600-second grace period; the challenge says 900. Pair: session-open-client-paid-accept.",
        open_built(server(), OpenBuild::default(), Some(Server { grace_period_seconds: 600, ..Server::default() }), RECENT_SLOT),
        rej(RejectCode::OpenBindingMismatch),
    ).build();
    session_open_grace_period_argument_reject => open_case(
        "session-open-grace-period-argument-reject",
        s("Grace Period Security", "Servers MUST verify that a new channel uses the challenged gracePeriodSeconds."),
        &[R_GRACE_CHALLENGED, R_DECODED],
        "The envelope says 900 but the signed open's grace_period is 1 second. Pair: session-open-client-paid-accept.",
        Recipe::open(server()).tx(TxTamper::OpenArg(OpenArg::GracePeriod(1))),
        rej(RejectCode::OpenBindingMismatch),
    ).build();
    session_open_payee_mismatch_reject => open_case(
        "session-open-payee-mismatch-reject",
        open_action("| payee | string | REQUIRED | Base58 public key of the channel payee (matches recipient in the 402 challenge) |"),
        &[R_PAYEE_FIELD, R_DISAGREE],
        "The open pays another payee than the challenged recipient. Pair: session-open-client-paid-accept.",
        open_built(server(), OpenBuild::default(), Some(Server { recipient: keys::X402_OTHER_PAY_TO, ..Server::default() }), RECENT_SLOT),
        rej(RejectCode::OpenBindingMismatch),
    ).build();
    session_open_mint_not_challenged_reject => open_case(
        "session-open-mint-not-challenged-reject",
        s("Mint Allow-List", "The server MUST set the 402 challenge currency only to an allow-listed mint and MUST reject any open whose decoded mint is not on the list."),
        &[R_MINT_LIST, R_MINT_FIELD, R_DISAGREE],
        "The open escrows a mint the server never challenged. Pair: session-open-client-paid-accept.",
        open_built(server(), OpenBuild::default(), Some(Server { currency: keys::OTHER_MINT, ..Server::default() }), RECENT_SLOT),
        rej(RejectCode::OpenBindingMismatch),
    ).build();
    session_open_splits_not_challenged_reject => open_case(
        "session-open-splits-not-challenged-reject",
        open_action("| distributionSplits | array | OPTIONAL | Splits preimage (see the challenge's methodDetails.distributionSplits); MUST byte-match the splits proposed in the 402 challenge |"),
        &[R_SPLITS, R_DISAGREE],
        "The open commits a co-recipient split the challenge did not propose. Pair: session-open-client-paid-accept.",
        open_built(server(), OpenBuild::default(), Some(with_splits()), RECENT_SLOT),
        rej(RejectCode::OpenBindingMismatch),
    ).build();
    session_open_splits_dropped_reject => open_case(
        "session-open-splits-dropped-reject",
        open_action("| distributionSplits | array | OPTIONAL | Splits preimage (see the challenge's methodDetails.distributionSplits); MUST byte-match the splits proposed in the 402 challenge |"),
        &[R_SPLITS, R_DISAGREE],
        "The challenge proposes a split; the open commits none. Pair: session-open-splits-accept.",
        open_built(with_splits(), OpenBuild::default(), Some(server()), RECENT_SLOT),
        rej(RejectCode::OpenBindingMismatch),
    ).build();
    session_open_open_slot_ahead_reject => open_case(
        "session-open-open-slot-ahead-reject",
        s("Reincarnation Replay", "Future openSlot values MUST be strictly rejected at open."),
        &[R_OPEN_SLOT, R_FUTURE_SLOT],
        "openSlot 10 slots past the challenged recentSlot (the open was built for a later challenge). Pair: session-open-client-paid-accept.",
        open_built(server(), OpenBuild { recent_slot: RECENT_SLOT + 10, ..OpenBuild::default() }, None, RECENT_SLOT),
        rej(RejectCode::OpenBindingMismatch),
    ).build();
    session_open_open_slot_outside_window_reject => open_case(
        "session-open-open-slot-outside-window-reject",
        open_settlement("Verify the credential's openSlot equals the decoded open_slot and satisfies the open-slot window relative to both the challenged recentSlot (openSlot <= recentSlot and recentSlot - openSlot <= OPEN_SLOT_WINDOW)"),
        &[R_OPEN_SLOT, R_WINDOW],
        "openSlot 1501 slots below the challenged recentSlot. Pair: session-open-open-slot-window-edge-accept.",
        open_with(server(), OpenBuild { open_slot: Some(RECENT_SLOT - 1_501), ..OpenBuild::default() }),
        rej(RejectCode::OpenBindingMismatch),
    ).build();
    session_open_open_slot_envelope_reject => open_case(
        "session-open-open-slot-envelope-reject",
        s("open", "A PDA seed: it is a derivation input for the channel address, and servers MUST include it when re-deriving or validating channelId."),
        &[R_OPEN_SLOT_SEED, R_OPEN_SLOT_PDA, R_DERIVE],
        "The envelope's openSlot is one slot earlier than the signed open's (channelId unchanged), so the PDA re-derived from the envelope is not the declared channel. Pair: session-open-client-paid-accept.",
        Recipe::open(server()).edit(Edit::Set("/openSlot", json!((RECENT_SLOT - 1).to_string()))),
        rej(RejectCode::ChannelIdMismatch),
    ).build();
    session_open_salt_envelope_reject => open_case(
        "session-open-salt-envelope-reject",
        derive_spec(),
        &[R_DERIVE, R_SALT_FIELD],
        "The envelope's salt is 8 while the signed open (and channelId) use 7. Pair: session-open-client-paid-accept.",
        Recipe::open(server()).edit(Edit::Set("/salt", json!("8"))),
        rej(RejectCode::ChannelIdMismatch),
    ).build();
    session_open_channel_id_not_derived_reject => open_case(
        "session-open-channel-id-not-derived-reject",
        derive_spec(),
        &[R_DERIVE, R_IDENTITY],
        "The envelope declares the PDA of another salt as channelId; relying on a client-declared channelId alone is not sufficient. Pair: session-open-client-paid-accept.",
        Recipe::open(server()).edit(Edit::Set("/channelId", json!(other_channel().to_string()))),
        rej(RejectCode::ChannelIdMismatch),
    ).build();
    session_open_channel_account_swapped_reject => open_case(
        "session-open-channel-account-swapped-reject",
        open_settlement("Recompute the expected PDA from the decoded payer, payee, mint, authorized signer, salt, and open_slot plus the channel program ID. Verify it equals both the decoded channel account and the declared channelId."),
        &[R_DERIVE, R_DISAGREE],
        "The open instruction's channel account (5) is another PDA while the envelope declares the derived one. Pair: session-open-client-paid-accept.",
        Recipe::open(server()).tx(TxTamper::OpenAccount(5, other_channel())),
        rej(RejectCode::ChannelIdMismatch),
    ).build();
    session_open_escrow_ata_swapped_reject => open_case(
        "session-open-escrow-ata-swapped-reject",
        open_settlement("Verify the decoded escrow account is the associated token account for (channelId, mint, tokenProgram)."),
        &[R_DISAGREE],
        "The escrow token account (7) is another channel's ATA. Pair: session-open-client-paid-accept.",
        Recipe::open(server()).tx(TxTamper::OpenAccount(7, keys::pubkey(&other_escrow()))),
        rej(RejectCode::OpenBindingMismatch),
    ).build();
    session_open_token_program_swapped_reject => open_case(
        "session-open-token-program-swapped-reject",
        open_settlement("If the challenge supplied tokenProgram, the decoded token program MUST match it; otherwise it MUST be a supported token program for the mint."),
        &[R_TOKEN_PROGRAM, R_DISAGREE],
        "The open's token program account (8) is Token-2022 for a Tokenkeg mint. Pair: session-open-client-paid-accept.",
        Recipe::open(server()).tx(TxTamper::OpenAccount(8, keys::pubkey(keys::TOKEN_2022_PROGRAM))),
        rej(RejectCode::OpenBindingMismatch),
    ).build();
    session_open_rent_payer_not_fee_payer_reject => open_case(
        "session-open-rent-payer-not-fee-payer-reject",
        s("open", "Verifiers that read open accounts by fixed index MUST account for rentPayer at index 1 and the resulting +1 shift of every account after payer, and MUST verify that accounts[1] equals the operator / fee-payer key."),
        &[R_IDX1, R_IDX1_SETTLE],
        "accounts[1] (rentPayer) is a third key, not the transaction fee payer. Pair: session-open-client-paid-accept.",
        Recipe::open(server()).tx(TxTamper::OpenAccount(1, crate::realize::session::stranger())),
        rej(RejectCode::OpenBindingMismatch),
    ).build();
    session_open_writable_mint_reject => open_case(
        "session-open-writable-mint-reject",
        disagree_spec(),
        &[R_DISAGREE, R_BINDING],
        "The mint account (3) made writable: the account privileges are no longer the committed open's. Pair: session-open-client-paid-accept.",
        Recipe::open(server()).tx(TxTamper::OpenWritable(3)),
        rej(RejectCode::OpenBindingMismatch),
    ).build();
    session_open_extra_account_reject => open_case(
        "session-open-extra-account-reject",
        s("Account Shapes and Events", "Every instruction takes an exact account list and rejects transactions with missing OR extra accounts."),
        &[R_DISAGREE, R_BINDING],
        "A fifteenth account appended to the open instruction. Pair: session-open-client-paid-accept.",
        Recipe::open(server()).tx(TxTamper::OpenExtraAccount),
        rej(RejectCode::OpenBindingMismatch),
    ).build();
    session_open_authorized_signer_off_curve_reject => open_case(
        "session-open-authorized-signer-off-curve-reject",
        open_settlement("The decoded authorizedSigner MUST equal the credential's authorizedSigner and MUST be a valid Ed25519 public-key point; reject non-curve values."),
        &[R_OFF_CURVE, R_CURVE_OPEN, R_CURVE],
        "authorizedSigner is a PDA (not a curve point); the open instruction, channelId and escrow are re-derived for it, so only the curve check refuses it. Pair: session-open-client-paid-accept.",
        Recipe::open(server()).tx(TxTamper::OffCurveSigner),
        rej(RejectCode::OpenBindingMismatch),
    ).build();
    session_open_authorized_signer_envelope_reject => open_case(
        "session-open-authorized-signer-envelope-reject",
        open_settlement("The decoded authorizedSigner MUST equal the credential's authorizedSigner and MUST be a valid Ed25519 public-key point; reject non-curve values."),
        &[R_OFF_CURVE, R_DERIVE],
        "The envelope names the payer as authorizedSigner while the signed open binds the delegated session key. Pair: session-open-client-paid-accept.",
        Recipe::open(server()).edit(Edit::Set("/authorizedSigner", json!(keys::CLIENT))),
        rej(RejectCode::ChannelIdMismatch),
    ).build();
    session_open_bump_field_reject => open_case(
        "session-open-bump-field-reject",
        open_action("Servers MUST reject open envelopes that include a bump field using the malformed-credential problem type."),
        &[R_BUMP, R_BUMP_REJECT],
        "The open envelope carries bump: 255. Pair: session-open-client-paid-accept.",
        Recipe::open(server()).edit(Edit::Set("/bump", json!(255))),
        rej(RejectCode::InvalidPayload),
    ).build();
    session_open_initial_voucher_reject => open_case(
        "session-open-initial-voucher-reject",
        open_action("Action: \"open\" MUST NOT carry an initial voucher."),
        &[R_NO_VOUCHER],
        "The open envelope carries a signed voucher for the new channel. Pair: session-open-client-paid-accept.",
        Recipe::open(server()).edit(Edit::Set("/voucher", crate::realize::session::signed_voucher(&OpenParams::client(&server()).channel(), 25, Some(FAR_EXPIRY), SESSION_SIGNER_SEED).expect("voucher"))),
        rej(RejectCode::InvalidPayload),
    ).build();
    session_open_client_mode_authentication_reject => open_case(
        "session-open-client-mode-authentication-reject",
        open_action("| authentication | object | Conditionally REQUIRED | Reusable proof from {{session-bearer-proof}}; REQUIRED for operator and MUST be absent for client |"),
        &[R_AUTH_FIELD],
        "voucherSigner client, yet the open carries a (valid) bearer proof. Pair: session-open-client-paid-accept.",
        Recipe::open(server()).edit(Edit::Set("/authentication", client_proof())),
        rej(RejectCode::AuthenticationInvalid),
    ).build();
    session_open_operator_missing_authentication_reject => open_case(
        "session-open-operator-missing-authentication-reject",
        open_action("For operator, authorizedSigner MUST equal the challenged operator, and the server MUST verify authentication before broadcasting the open transaction."),
        &[R_AUTH_FIELD, R_OPERATOR_OPEN],
        "voucherSigner operator and an open without the bearer proof. Pair: session-open-operator-accept.",
        open_with(operator_server(), OpenBuild::default()),
        rej(RejectCode::AuthenticationInvalid),
    ).build();
    session_open_operator_proof_other_challenge_reject => open_case(
        "session-open-operator-proof-other-challenge-reject",
        s("Session Bearer Proof", "The proof's challengeId, channelId, and payer MUST equal the opening challenge ID, declared and derived channel ID, and transaction payer."),
        &[R_PROOF_BIND, R_PROOF_VERIFY],
        "The bearer proof is validly signed, but for another session challenge. Pair: session-open-operator-accept.",
        open_with(operator_server(), OpenBuild { proof_for: Some("c_session_other_challenge"), ..OpenBuild::default() }),
        rej(RejectCode::AuthenticationInvalid),
    ).build();
    session_open_operator_proof_tampered_reject => open_case(
        "session-open-operator-proof-tampered-reject",
        s("Session Bearer Proof", "At open, the server MUST verify the session challenge and signature."),
        &[R_PROOF_VERIFY],
        "The bearer proof names the opening challenge but its signature is the payer's proof for another channel. Pair: session-open-operator-accept.",
        open_with(operator_server(), operator_build()).edit(Edit::Set("/authentication/signature", client_proof()["signature"].clone())),
        rej(RejectCode::AuthenticationInvalid),
    ).build();
    session_open_operator_signer_not_operator_reject => open_case(
        "session-open-operator-signer-not-operator-reject",
        s("Method Details", "Base58-encoded Ed25519 public key that MUST equal the channel's authorizedSigner."),
        &[R_OPERATOR_KEY, R_OPERATOR_OPEN],
        "voucherSigner operator, but the open binds the client's session key as authorizedSigner. Pair: session-open-operator-accept.",
        open_built(operator_server(), OpenBuild::default(), Some(server()), RECENT_SLOT),
        rej(RejectCode::OpenBindingMismatch),
    ).build();
    session_open_idle_timeout_not_offered_reject => open_case(
        "session-open-idle-timeout-not-offered-reject",
        s("Server-Initiated Idle Close", "The server MUST reject an unsupported selection and MUST NOT silently clamp, replace, or otherwise reinterpret it."),
        &[R_IDLE_MATCH, R_IDLE_REJECT, R_IDLE_PROBLEM],
        "The challenge offers [60, 300, 900]; the client selects 120. Pair: session-open-idle-timeout-offered-accept.",
        open_with(idle_options(), OpenBuild { idle_timeout_seconds: Some(120), ..OpenBuild::default() }),
        rej(RejectCode::OpenBindingMismatch),
    ).build();
    session_open_idle_timeout_without_options_reject => open_case(
        "session-open-idle-timeout-without-options-reject",
        s("Server-Initiated Idle Close", "The client MUST NOT include this field when the challenge omits idleTimeoutOptionsSeconds."),
        &[R_IDLE_CLIENT, R_IDLE_FIELD, R_IDLE_REJECT],
        "The challenge offers no idle-timeout options; the open selects 300 anyway. Pair: session-open-client-paid-accept.",
        open_with(server(), OpenBuild { idle_timeout_seconds: Some(300), ..OpenBuild::default() }),
        rej(RejectCode::OpenBindingMismatch),
    ).build();

    // ── open: the transaction ──────────────────────────────────────────────
    session_open_wrong_blockhash_reject => open_case(
        "session-open-wrong-blockhash-reject",
        open_action("Clients SHOULD set openSlot to the challenge's methodDetails.recentSlot and MUST use the challenged recentBlockhash in the transaction."),
        &[R_BLOCKHASH, R_BLOCKHASH_USE],
        "The open transaction uses a blockhash the challenge did not carry. Pair: session-open-client-paid-accept.",
        Recipe::open(server()).tx(TxTamper::Blockhash(crate::realize::session::OTHER_BLOCKHASH)),
        rej(RejectCode::OpenBindingMismatch),
    ).build();
    session_open_foreign_instruction_reject => open_case(
        "session-open-foreign-instruction-reject",
        s("Open Transaction Binding", "Servers that sponsor or submit open transactions MUST treat the decoded transaction contents as the committed request."),
        &[R_BINDING, R_DECODED],
        "A Memo instruction after the open: the transaction carries an instruction outside the open. Pair: session-open-client-paid-accept.",
        Recipe::open(server()).tx(TxTamper::Op(Mutation::AddProgramInstruction { program: keys::MEMO_PROGRAM, data: b"invoice-7" })),
        rej(RejectCode::UnexpectedInstruction),
    ).build();
    session_open_sponsor_drain_reject => open_case(
        "session-open-sponsor-drain-reject",
        s("Open Transaction Binding", "Servers that sponsor or submit open transactions MUST treat the decoded transaction contents as the committed request."),
        &[R_BINDING, R_DISAGREE],
        "Sponsored open plus a System transfer of 1 SOL from the sponsor (the fee payer) to a third key. Pair: session-open-sponsored-accept.",
        Recipe::open(sponsored()).tx(TxTamper::Op(Mutation::FeePayerSystemTransfer { to: keys::X402_OTHER_PAY_TO, lamports: 1_000_000_000 })),
        rej(RejectCode::UnexpectedInstruction),
    ).build();
    session_open_duplicate_open_reject => open_case(
        "session-open-duplicate-open-reject",
        open_settlement("Decode the open transaction before signing, paying fees, or broadcasting. Verify it contains the expected channel program instruction and that the instruction uses the open discriminator"),
        &[R_DECODED, R_BINDING],
        "The open instruction appears twice. Pair: session-open-client-paid-accept.",
        Recipe::open(server()).tx(TxTamper::DuplicateOpen),
        rej(RejectCode::UnexpectedInstruction),
    ).build();
    session_open_missing_open_reject => open_case(
        "session-open-missing-open-reject",
        open_settlement("Decode the open transaction before signing, paying fees, or broadcasting. Verify it contains the expected channel program instruction and that the instruction uses the open discriminator"),
        &[R_DECODED, R_DERIVE],
        "The open instruction removed; only the ComputeBudget prefix remains. Pair: session-open-client-paid-accept.",
        Recipe::open(server()).tx(TxTamper::DropOpen),
        rej(RejectCode::UnexpectedInstruction),
    ).build();
    session_open_wrong_program_reject => open_case(
        "session-open-wrong-program-reject",
        open_settlement("Verify the instruction targets the challenged channel program and encodes the challenged payer, payee, mint, authorizedSigner, salt, deposit, grace_period, open_slot, and canonical distributionSplits preimage."),
        &[R_DISAGREE, R_DECODED],
        "The open instruction is invoked on another program than the challenged channelProgram. Pair: session-open-client-paid-accept.",
        Recipe::open(server()).tx(TxTamper::OpenProgram(keys::pubkey("CHNLxBtXw7VPqd5GMcbtVoEbn4ehyaSoiHj56Ao5sWkJ"))),
        rej(RejectCode::UnexpectedInstruction),
    ).build();
    session_open_wrong_discriminator_reject => open_case(
        "session-open-wrong-discriminator-reject",
        open_settlement("Decode the open transaction before signing, paying fees, or broadcasting. Verify it contains the expected channel program instruction and that the instruction uses the open discriminator"),
        &[R_DECODED],
        "The channel-program instruction carries the topUp discriminator (3) instead of open (1). Pair: session-open-client-paid-accept.",
        Recipe::open(server()).tx(TxTamper::OpenDiscriminator(3)),
        rej(RejectCode::UnexpectedInstruction),
    ).build();
    session_open_fee_payer_swapped_reject => open_case(
        "session-open-fee-payer-swapped-reject",
        open_settlement("Verifiers that read the open accounts by fixed index MUST account for the rentPayer account at index 1 (payer=0, rentPayer=1, payee=2, mint=3, authorizedSigner=4, channel=5, with every account after payer shifted by +1) and MUST verify that accounts[1] equals the operator / fee-payer key."),
        &[R_IDX1_SETTLE, R_IDX1],
        "Client-paid challenge, but a third key (which signs) is the transaction fee payer; rentPayer is still the payer. Pair: session-open-client-paid-accept.",
        Recipe::open(server()).tx(TxTamper::FeePayer(STRANGER_SEED)),
        rej(RejectCode::FeePayerMismatch),
    ).build();
    session_open_sponsored_client_pays_reject => open_case(
        "session-open-sponsored-client-pays-reject",
        open_settlement("if feePayer is true, the fee payer MUST equal feePayerKey;"),
        &[R_FEE_PAYER_KEY, R_RENT_PAYER],
        "The challenge sponsors fees (feePayerKey = the operator) but the client pays them itself (built for a client-paid challenge). Pair: session-open-sponsored-accept.",
        open_built(sponsored(), OpenBuild::default(), Some(server()), RECENT_SLOT),
        rej(RejectCode::FeePayerMismatch),
    ).build();
    session_open_payer_signature_missing_reject => open_case(
        "session-open-payer-signature-missing-reject",
        s("open", "The payer MUST be a signer."),
        &[R_PAYER_SIGNER],
        "The payer's signature slot is zeroed. Pair: session-open-client-paid-accept.",
        Recipe::open(server()).tx(TxTamper::Op(Mutation::DropSignature)),
        rej(RejectCode::InvalidPayload),
    ).build();
    session_open_payer_signature_forged_reject => open_case(
        "session-open-payer-signature-forged-reject",
        s("open", "The payer MUST be a signer."),
        &[R_PAYER_SIGNER],
        "The payer's slot holds the payer's signature over another message. Pair: session-open-client-paid-accept.",
        Recipe::open(server()).tx(TxTamper::Op(Mutation::ForgeSignature)),
        rej(RejectCode::InvalidPayload),
    ).build();
    session_open_transaction_not_base64_reject => open_case(
        "session-open-transaction-not-base64-reject",
        open_action("| transaction | string | REQUIRED | Base64-encoded (standard alphabet, padded) signed or partially signed transaction |"),
        &[R_TX_FIELD],
        "The open's transaction field is not base64. Pair: session-open-client-paid-accept.",
        Recipe::open(server()).edit(Edit::Set("/transaction", json!("not a transaction!"))),
        rej(RejectCode::InvalidPayload),
    ).build();
    session_open_missing_transaction_reject => open_case(
        "session-open-missing-transaction-reject",
        open_action("| transaction | string | REQUIRED | Base64-encoded (standard alphabet, padded) signed or partially signed transaction |"),
        &[R_TX_FIELD],
        "The open envelope has no transaction. Pair: session-open-client-paid-accept.",
        Recipe::open(server()).edit(Edit::Remove("/transaction")),
        rej(RejectCode::InvalidPayload),
    ).build();

    // ── voucher ────────────────────────────────────────────────────────────
    session_voucher_verify_accept => voucher_case(
        "session-voucher-verify-accept",
        BugType::Settlement,
        verification_spec(),
        &[R_VERIFY_EACH, R_SIGNER, R_INCREMENT],
        "A voucher for cumulative 125 signed by the channel's authorized signer: a 25 increment over the accepted 100, the challenged price. The baseline every voucher reject pairs with.",
        voucher_recipe(Channel::client(100), VoucherSpec::new(125)),
        accept(),
    ).build();
    session_voucher_verify_no_expiry_accept => voucher_case(
        "session-voucher-verify-no-expiry-accept",
        BugType::Settlement,
        s("Voucher Data", "| expiresAt | integer | OPTIONAL | Voucher expiration as a Unix timestamp in seconds (i64); 0 or omitted means no expiration."),
        &[R_VERIFY_EACH],
        "The voucher omits expiresAt (never expires). Pair: session-voucher-verify-accept.",
        voucher_recipe(Channel::client(100), VoucherSpec { expires_at: None, ..VoucherSpec::new(125) }),
        accept(),
    ).build();
    session_voucher_verify_up_to_deposit_accept => voucher_case(
        "session-voucher-verify-up-to-deposit-accept",
        BugType::Settlement,
        verification_spec(),
        &[R_VERIFY_EACH],
        "cumulative 1000 equals the escrowed deposit (cumulativeAmount <= escrowedAmount).",
        voucher_recipe(Channel::client(100), VoucherSpec::new(1_000)),
        accept(),
    ).build();
    session_voucher_verify_first_voucher_accept => voucher_case(
        "session-voucher-verify-first-voucher-accept",
        BugType::Settlement,
        verification_spec(),
        &[R_VERIFY_EACH, R_INCREMENT],
        "The first voucher on a fresh channel (nothing accepted yet) for exactly the challenged price.",
        voucher_recipe(Channel::client(0), VoucherSpec::new(25)),
        accept(),
    ).build();
    session_voucher_verify_payer_signer_accept => voucher_case(
        "session-voucher-verify-payer-signer-accept",
        BugType::AuthBypass,
        s("Channel State", "Once a channel is opened, vouchers for that channel MUST verify under the channel's authorizedSigner."),
        &[R_SIGNER],
        "The channel's authorizedSigner is the payer and the payer signs. Pair: session-voucher-verify-wrong-signer-reject.",
        voucher_recipe(
            Channel { open: OpenParams { authorized_signer: keys::CLIENT_SEED, ..OpenParams::client(&server()) }, highest: None, ..Channel::client(100) },
            VoucherSpec { signer_seed: keys::CLIENT_SEED, ..VoucherSpec::new(125) },
        ),
        accept(),
    ).build();
    session_voucher_verify_channel_id_mismatch_reject => voucher_case(
        "session-voucher-verify-channel-id-mismatch-reject",
        BugType::AuthBypass,
        s("Voucher Data", "Implementations MUST NOT accept vouchers for channels whose identity cannot be recomputed from the program ID and channel open parameters."),
        &[R_IDENTITY, R_CHANNEL_FIELD, R_VOUCHER_OBJ],
        "The action's top-level channelId routes to another channel than the one the signed voucher names. Pair: session-voucher-verify-accept.",
        voucher_recipe(Channel::client(100), VoucherSpec::new(125)).edit(Edit::Set("/channelId", json!(other_channel().to_string()))),
        rej(RejectCode::ChannelIdMismatch),
    ).build();
    session_voucher_verify_unknown_channel_reject => voucher_case(
        "session-voucher-verify-unknown-channel-reject",
        BugType::AuthBypass,
        s("Voucher Data", "Implementations MUST NOT accept vouchers for channels whose identity cannot be recomputed from the program ID and channel open parameters."),
        &[R_IDENTITY],
        "A voucher (and routing key) for a channel the server never opened. Pair: session-voucher-verify-accept.",
        voucher_recipe(Channel::client(100), VoucherSpec { channel: Some(other_channel()), ..VoucherSpec::new(125) }),
        rej(RejectCode::ChannelState),
    ).build();
    session_voucher_verify_wrong_signer_reject => voucher_case(
        "session-voucher-verify-wrong-signer-reject",
        BugType::AuthBypass,
        s("Channel State", "Once a channel is opened, vouchers for that channel MUST verify under the channel's authorizedSigner."),
        &[R_SIGNER, R_VERIFY_EACH],
        "The payer, not the delegated authorized signer, signs (and names itself as signer). Pair: session-voucher-verify-accept.",
        voucher_recipe(Channel::client(100), VoucherSpec { signer_seed: keys::CLIENT_SEED, ..VoucherSpec::new(125) }),
        rej(RejectCode::VoucherSignature),
    ).build();
    session_voucher_verify_signer_claim_forged_reject => voucher_case(
        "session-voucher-verify-signer-claim-forged-reject",
        BugType::AuthBypass,
        s("Channel State", "Once a channel is opened, vouchers for that channel MUST verify under the channel's authorizedSigner."),
        &[R_SIGNER, R_VERIFY_EACH],
        "The payer signs but the voucher claims the authorized signer as signer: the signature does not verify under it. Pair: session-voucher-verify-accept.",
        voucher_recipe(Channel::client(100), VoucherSpec { signer_seed: keys::CLIENT_SEED, ..VoucherSpec::new(125) }).edit(Edit::Set("/voucher/signer", json!(session_signer().to_string()))),
        rej(RejectCode::VoucherSignature),
    ).build();
    session_voucher_verify_cumulative_tampered_reject => voucher_case(
        "session-voucher-verify-cumulative-tampered-reject",
        BugType::Malleability,
        s("Voucher Signing", "The HTTP JSON shape is a transport view; clients and servers MUST NOT influence what bytes are signed via the JSON."),
        &[R_JSON_BYTES, R_VERIFY_EACH],
        "Signed for 125, the JSON cumulativeAmount is raised to 200. Pair: session-voucher-verify-accept.",
        voucher_recipe(Channel::client(100), VoucherSpec::new(125)).edit(Edit::Set("/voucher/voucher/cumulativeAmount", json!("200"))),
        rej(RejectCode::VoucherSignature),
    ).build();
    session_voucher_verify_expiry_tampered_reject => voucher_case(
        "session-voucher-verify-expiry-tampered-reject",
        BugType::Malleability,
        s("Voucher Signing", "The HTTP JSON shape is a transport view; clients and servers MUST NOT influence what bytes are signed via the JSON."),
        &[R_JSON_BYTES],
        "Signed with expiresAt 4102444800, the JSON drops expiresAt (never expires). Pair: session-voucher-verify-accept.",
        voucher_recipe(Channel::client(100), VoucherSpec::new(125)).edit(Edit::Remove("/voucher/voucher/expiresAt")),
        rej(RejectCode::VoucherSignature),
    ).build();
    session_voucher_verify_equal_to_accepted_reject => voucher_case(
        "session-voucher-verify-equal-to-accepted-reject",
        BugType::Replay,
        s("Voucher Verification", "Equal or lower amounts MUST be rejected for metered voucher acceptance unless they are exact idempotent replays handled per \"Concurrency and Idempotency\"."),
        &[R_MONOTONIC, R_REPLAY],
        "A freshly signed voucher (another expiry) for exactly the accepted 100. Pair: session-voucher-verify-accept.",
        voucher_recipe(Channel::client(100), VoucherSpec { expires_at: Some(FAR_EXPIRY - 1), ..VoucherSpec::new(100) }),
        rej(RejectCode::CumulativeAmountMismatch),
    ).build();
    session_voucher_verify_below_accepted_reject => voucher_case(
        "session-voucher-verify-below-accepted-reject",
        BugType::Replay,
        s("Voucher Verification", "Equal or lower amounts MUST be rejected for metered voucher acceptance unless they are exact idempotent replays handled per \"Concurrency and Idempotency\"."),
        &[R_MONOTONIC, R_REPLAY],
        "A voucher for 50, below the accepted 100. Pair: session-voucher-verify-accept.",
        voucher_recipe(Channel::client(100), VoucherSpec::new(50)),
        rej(RejectCode::CumulativeAmountMismatch),
    ).build();
    session_voucher_verify_exact_replay_reject => voucher_case(
        "session-voucher-verify-exact-replay-reject",
        BugType::Replay,
        s("Concurrency and Idempotency", "Voucher submissions with cumulativeAmount <= acceptedCumulative and no matching cached idempotent response MUST be rejected and MUST NOT reduce channel state."),
        &[R_REPLAY, R_MONOTONIC],
        "The exact highest voucher already accepted (same cumulative 100 and signature), with no idempotency key: a new request cannot be paid with it. Pair: session-voucher-verify-accept.",
        voucher_recipe(Channel::client(100), VoucherSpec::new(100)),
        rej(RejectCode::CumulativeAmountMismatch),
    ).build();
    session_voucher_verify_exceeds_deposit_reject => voucher_case(
        "session-voucher-verify-exceeds-deposit-reject",
        BugType::Settlement,
        verification_spec(),
        &[R_VERIFY_EACH],
        "cumulative 1001 against an escrowed deposit of 1000. Pair: session-voucher-verify-up-to-deposit-accept.",
        voucher_recipe(Channel::client(100), VoucherSpec::new(1_001)),
        rej(RejectCode::CumulativeExceedsDeposit),
    ).build();
    session_voucher_verify_increment_below_price_reject => voucher_case(
        "session-voucher-verify-increment-below-price-reject",
        BugType::Settlement,
        s("Voucher Verification", "The accepted increment cumulativeAmount − acceptedCumulative MUST correspond to the resource cost charged for the accompanying request, not merely be a positive advance."),
        &[R_INCREMENT],
        "cumulative 110: a 10 increment for a request priced at 25. Pair: session-voucher-verify-accept.",
        voucher_recipe(Channel::client(100), VoucherSpec::new(110)),
        rej(RejectCode::AmountMismatch),
    ).build();
    session_voucher_verify_close_pending_reject => voucher_case(
        "session-voucher-verify-close-pending-reject",
        BugType::Settlement,
        s("Grace Period Security", "Servers MUST stop accepting new service vouchers once closureStartedAt is set."),
        &[R_STOP, R_FORCED_CLOSE],
        "The channel has a pending forced close (closureStartedAt set). Pair: session-voucher-verify-accept.",
        voucher_recipe(closing(Channel::client(100)), VoucherSpec::new(125)),
        rej(RejectCode::ChannelClosing),
    ).build();
    session_voucher_verify_sealed_reject => voucher_case(
        "session-voucher-verify-sealed-reject",
        BugType::Settlement,
        verification_spec(),
        &[R_VERIFY_EACH],
        "The channel is closed (sealed). Pair: session-voucher-verify-accept.",
        voucher_recipe(sealed(Channel::client(100)), VoucherSpec::new(125)),
        rej(RejectCode::CloseState),
    ).build();
    session_voucher_verify_expired_reject => voucher_case(
        "session-voucher-verify-expired-reject",
        BugType::Settlement,
        s("Voucher Verification", "If expiresAt is present and non-zero, verify now < expiresAt (with configurable clock skew tolerance)."),
        &[R_VERIFY_EACH],
        "expiresAt 1000000000 (2001), long past. Pair: session-voucher-verify-accept.",
        voucher_recipe(Channel::client(100), VoucherSpec { expires_at: Some(PAST_EXPIRY), ..VoucherSpec::new(125) }),
        rej(RejectCode::VoucherExpired),
    ).build();
    session_voucher_verify_signature_type_reject => voucher_case(
        "session-voucher-verify-signature-type-reject",
        BugType::Wire,
        s("Signed Voucher", "| signatureType | string | REQUIRED | \"ed25519\" |"),
        &[R_SIG_TYPE],
        "signatureType secp256r1 on an Ed25519 voucher. Pair: session-voucher-verify-accept.",
        voucher_recipe(Channel::client(100), VoucherSpec::new(125)).edit(Edit::Set("/voucher/signatureType", json!("secp256r1"))),
        rej(RejectCode::InvalidPayload),
    ).build();
    session_voucher_verify_signature_not_base58_reject => voucher_case(
        "session-voucher-verify-signature-not-base58-reject",
        BugType::Wire,
        s("Signed Voucher", "| signature | string | REQUIRED | Base58-encoded Ed25519 signature |"),
        &[R_SIGNATURE_FIELD],
        "The signature is not base58. Pair: session-voucher-verify-accept.",
        voucher_recipe(Channel::client(100), VoucherSpec::new(125)).edit(Edit::Set("/voucher/signature", json!("0OIl-not-base58"))),
        rej(RejectCode::InvalidPayload),
    ).build();
    session_voucher_verify_cumulative_not_decimal_reject => voucher_case(
        "session-voucher-verify-cumulative-not-decimal-reject",
        BugType::Wire,
        s("Voucher Data", "| cumulativeAmount | string | REQUIRED | Total authorized spend (base units) |"),
        &[R_CUMULATIVE_FIELD],
        "cumulativeAmount \"1.25e2\" is not a base-unit integer. Pair: session-voucher-verify-accept.",
        voucher_recipe(Channel::client(100), VoucherSpec::new(125)).edit(Edit::Set("/voucher/voucher/cumulativeAmount", json!("1.25e2"))),
        rej(RejectCode::InvalidPayload),
    ).build();
    session_voucher_verify_missing_channel_id_reject => voucher_case(
        "session-voucher-verify-missing-channel-id-reject",
        BugType::Wire,
        s("Action: \"voucher\"", "| channelId | string | REQUIRED | Existing channel identifier |"),
        &[R_CHANNEL_FIELD],
        "The voucher action has no top-level channelId. Pair: session-voucher-verify-accept.",
        voucher_recipe(Channel::client(100), VoucherSpec::new(125)).edit(Edit::Remove("/channelId")),
        rej(RejectCode::InvalidPayload),
    ).build();
    session_voucher_verify_operator_channel_reject => voucher_case(
        "session-voucher-verify-operator-channel-reject",
        BugType::AuthBypass,
        s("Action: \"voucher\"", "In operator mode, vouchers are operator-generated settlement artifacts and MUST NOT authenticate the caller."),
        &[R_OPERATOR_VOUCHER],
        "An operator-signed channel and a voucher action carrying a valid operator-signed voucher for 125 (a settlement artifact anyone could replay): it must not authenticate the request. Pair: session-voucher-verify-accept.",
        Recipe::new(operator_server(), Action::Voucher { channel: Channel::operator(100), voucher: VoucherSpec { signer_seed: OPERATOR_SEED, ..VoucherSpec::new(125) } }),
        rej(RejectCode::AuthenticationInvalid),
    ).build();

    // ── topUp ──────────────────────────────────────────────────────────────
    session_topup_client_paid_accept => topup_case(
        "session-topup-client-paid-accept",
        s("Action: \"topUp\"", "| transaction | string | REQUIRED | Base64-encoded signed topUp transaction |"),
        &[R_TOPUP_ACTION, R_TOPUP_TX, R_TOPUP_ADDITIONAL],
        "A 500 top-up of the open channel, signed and fee-paid by the payer. The baseline every top-up reject pairs with.",
        topup_recipe(server(), Channel::client(100), 500),
        accept(),
    ).build();
    session_topup_sponsored_accept => topup_case(
        "session-topup-sponsored-accept",
        s("Action: \"topUp\"", "| transaction | string | REQUIRED | Base64-encoded signed topUp transaction |"),
        &[R_TOPUP_TX, R_TOPUP_ADDITIONAL],
        "A sponsored channel (rentPayer is the operator): the client partially signs, the operator is fee payer and co-signs.",
        topup_recipe(sponsored(), sponsored_channel(), 500),
        accept(),
    ).build();
    session_topup_amount_mismatch_reject => topup_case(
        "session-topup-amount-mismatch-reject",
        s("Action: \"topUp\"", "| additionalAmount | string | REQUIRED | Amount to add in base units |"),
        &[R_TOPUP_ADDITIONAL],
        "The envelope claims additionalAmount 400 while the signed top-up adds 500. Pair: session-topup-client-paid-accept.",
        topup_recipe(server(), Channel::client(100), 500).edit(Edit::Set("/additionalAmount", json!("400"))),
        rej(RejectCode::AmountMismatch),
    ).build();
    session_topup_amount_argument_reject => topup_case(
        "session-topup-amount-argument-reject",
        s("Action: \"topUp\"", "| additionalAmount | string | REQUIRED | Amount to add in base units |"),
        &[R_TOPUP_ADDITIONAL, R_TOPUP_TX],
        "The signed top-up adds 600 while the envelope says 500. Pair: session-topup-client-paid-accept.",
        topup_recipe(server(), Channel::client(100), 500).tx(TxTamper::TopUpAmount(600)),
        rej(RejectCode::AmountMismatch),
    ).build();
    session_topup_zero_amount_reject => topup_case(
        "session-topup-zero-amount-reject",
        s("topUp", "| amount | u64 | Amount to add in base units; MUST be non-zero |"),
        &[R_TOPUP_AMOUNT],
        "A top-up of 0. Pair: session-topup-client-paid-accept.",
        topup_recipe(server(), Channel::client(100), 0),
        rej(RejectCode::AmountMismatch),
    ).build();
    session_topup_other_channel_reject => topup_case(
        "session-topup-other-channel-reject",
        s("Action: \"topUp\"", "| transaction | string | REQUIRED | Base64-encoded signed topUp transaction |"),
        &[R_TOPUP_TX],
        "The signed top-up funds another channel (and its escrow) than the one the action names. Pair: session-topup-client-paid-accept.",
        topup_recipe(server(), Channel::client(100), 500).tx(TxTamper::TopUpChannel(other_channel())),
        rej(RejectCode::ChannelIdMismatch),
    ).build();
    session_topup_unknown_channel_reject => topup_case(
        "session-topup-unknown-channel-reject",
        s("topUp", "topUp requires status == Open and MUST be rejected when status == Closing."),
        &[R_TOPUP_OPEN],
        "The action names a channel the server never opened. Pair: session-topup-client-paid-accept.",
        topup_recipe(server(), Channel::client(100), 500).edit(Edit::Set("/channelId", json!(other_channel().to_string()))),
        rej(RejectCode::ChannelState),
    ).build();
    session_topup_close_pending_reject => topup_case(
        "session-topup-close-pending-reject",
        s("topUp", "topUp requires status == Open and MUST be rejected when status == Closing."),
        &[R_TOPUP_OPEN, R_TOPUP_CLOSING],
        "The channel has a pending forced close. Pair: session-topup-client-paid-accept.",
        topup_recipe(server(), closing(Channel::client(100)), 500),
        rej(RejectCode::ChannelClosing),
    ).build();
    session_topup_extra_instruction_reject => topup_case(
        "session-topup-extra-instruction-reject",
        s("Action: \"topUp\"", "| transaction | string | REQUIRED | Base64-encoded signed topUp transaction |"),
        &[R_TOPUP_TX],
        "A Memo instruction after the top-up. Pair: session-topup-client-paid-accept.",
        topup_recipe(server(), Channel::client(100), 500).tx(TxTamper::Op(Mutation::AddProgramInstruction { program: keys::MEMO_PROGRAM, data: b"invoice-7" })),
        rej(RejectCode::UnexpectedInstruction),
    ).build();
    session_topup_fee_payer_swapped_reject => topup_case(
        "session-topup-fee-payer-swapped-reject",
        s("TopUp", "Verify the top-up transaction targets the expected channel PDA and channel program and only increases deposit for that channel."),
        &[R_TOPUP_TX],
        "A client-paid channel whose top-up is fee-paid by a third key (which signs). Pair: session-topup-client-paid-accept.",
        topup_recipe(server(), Channel::client(100), 500).tx(TxTamper::FeePayer(STRANGER_SEED)),
        rej(RejectCode::FeePayerMismatch),
    ).build();
    session_topup_payer_signature_missing_reject => topup_case(
        "session-topup-payer-signature-missing-reject",
        s("topUp", "The payer MUST be a signer."),
        &[R_PAYER_SIGNER, R_TOPUP_TX],
        "The payer's signature slot is zeroed. Pair: session-topup-client-paid-accept.",
        topup_recipe(server(), Channel::client(100), 500).tx(TxTamper::Op(Mutation::DropSignature)),
        rej(RejectCode::InvalidPayload),
    ).build();
    session_topup_additional_amount_not_decimal_reject => topup_case(
        "session-topup-additional-amount-not-decimal-reject",
        s("Action: \"topUp\"", "| additionalAmount | string | REQUIRED | Amount to add in base units |"),
        &[R_TOPUP_ADDITIONAL],
        "additionalAmount \"5e2\". Pair: session-topup-client-paid-accept.",
        topup_recipe(server(), Channel::client(100), 500).edit(Edit::Set("/additionalAmount", json!("5e2"))),
        rej(RejectCode::InvalidPayload),
    ).build();
    session_topup_missing_transaction_reject => topup_case(
        "session-topup-missing-transaction-reject",
        s("Action: \"topUp\"", "| transaction | string | REQUIRED | Base64-encoded signed topUp transaction |"),
        &[R_TOPUP_TX],
        "The topUp action has no transaction. Pair: session-topup-client-paid-accept.",
        topup_recipe(server(), Channel::client(100), 500).edit(Edit::Remove("/transaction")),
        rej(RejectCode::InvalidPayload),
    ).build();

    // ── close ──────────────────────────────────────────────────────────────
    session_close_final_voucher_accept => close_case(
        "session-close-final-voucher-accept",
        BugType::Settlement,
        s("Action: \"close\"", "For client, the server MUST verify the voucher signature and channel binding."),
        &[R_CLOSE_CLIENT, R_CLOSE_VOUCHER, R_CLOSE_ACTION],
        "A client close with a final voucher for 150 (advances settlement). The baseline every client close reject pairs with.",
        close_recipe(Channel::client(100), Some(VoucherSpec::new(150)), false),
        accept(),
    ).build();
    session_close_accepted_voucher_accept => close_case(
        "session-close-accepted-voucher-accept",
        BugType::Settlement,
        s("Action: \"close\"", "A voucher at or below settled MUST equal the server's acceptedCumulative, authenticates close only, and MUST NOT be submitted as a settlement update."),
        &[R_CLOSE_AT_OR_BELOW, R_CLOSE_CLIENT],
        "Nothing more is due: the close presents the highest accepted voucher (100) only to authenticate. Pair: session-close-below-accepted-reject.",
        close_recipe(Channel::client(100), Some(VoucherSpec::new(100)), false),
        accept(),
    ).build();
    session_close_operator_accept => close_case(
        "session-close-operator-accept",
        BugType::AuthBypass,
        s("Action: \"close\"", "For operator, the server MUST verify authentication against the channel before initiating cooperative close."),
        &[R_CLOSE_OPERATOR, R_CLOSE_AUTH],
        "An operator-signed channel closed with the bearer proof bound at open and no voucher.",
        close_recipe(Channel::operator(100), None, true),
        accept(),
    ).build();
    session_close_channel_id_mismatch_reject => close_case(
        "session-close-channel-id-mismatch-reject",
        BugType::AuthBypass,
        s("Action: \"close\"", "For client, the server MUST verify the voucher signature and channel binding."),
        &[R_CLOSE_CLIENT],
        "The final voucher is signed for another channel than the one being closed. Pair: session-close-final-voucher-accept.",
        close_recipe(Channel::client(100), Some(VoucherSpec { channel: Some(other_channel()), ..VoucherSpec::new(150) }), false),
        rej(RejectCode::ChannelIdMismatch),
    ).build();
    session_close_missing_voucher_reject => close_case(
        "session-close-missing-voucher-reject",
        BugType::AuthBypass,
        s("Action: \"close\"", "| voucher | object | Conditionally REQUIRED | REQUIRED for client and MUST be absent for operator; authenticates close and MAY advance settlement (see {{voucher-format}}) |"),
        &[R_CLOSE_VOUCHER],
        "A client close without a voucher. Pair: session-close-final-voucher-accept.",
        close_recipe(Channel::client(100), None, false),
        rej(RejectCode::CloseAuthorization),
    ).build();
    session_close_client_authentication_reject => close_case(
        "session-close-client-authentication-reject",
        BugType::AuthBypass,
        s("Action: \"close\"", "| authentication | object | Conditionally REQUIRED | Reusable proof; REQUIRED for operator and MUST be absent for client |"),
        &[R_CLOSE_AUTH],
        "A client close carrying a bearer proof next to its final voucher. Pair: session-close-final-voucher-accept.",
        close_recipe(Channel::client(100), Some(VoucherSpec::new(150)), true),
        rej(RejectCode::CloseAuthorization),
    ).build();
    session_close_wrong_signer_reject => close_case(
        "session-close-wrong-signer-reject",
        BugType::AuthBypass,
        s("Action: \"close\"", "For client, the server MUST verify the voucher signature and channel binding."),
        &[R_CLOSE_CLIENT, R_SIGNER],
        "The final voucher is signed by the payer, not the channel's authorized signer. Pair: session-close-final-voucher-accept.",
        close_recipe(Channel::client(100), Some(VoucherSpec { signer_seed: keys::CLIENT_SEED, ..VoucherSpec::new(150) }), false),
        rej(RejectCode::VoucherSignature),
    ).build();
    session_close_cumulative_tampered_reject => close_case(
        "session-close-cumulative-tampered-reject",
        BugType::Malleability,
        s("Action: \"close\"", "For client, the server MUST verify the voucher signature and channel binding."),
        &[R_CLOSE_CLIENT, R_JSON_BYTES],
        "Signed for 150, the final voucher's JSON cumulativeAmount says 900. Pair: session-close-final-voucher-accept.",
        close_recipe(Channel::client(100), Some(VoucherSpec::new(150)), false).edit(Edit::Set("/voucher/voucher/cumulativeAmount", json!("900"))),
        rej(RejectCode::VoucherSignature),
    ).build();
    session_close_exceeds_deposit_reject => close_case(
        "session-close-exceeds-deposit-reject",
        BugType::Settlement,
        s("Cumulative Amount Safety", "The channel program enforces that settlements never exceed the deposit."),
        &[R_CLOSE_CLIENT],
        "A final voucher for 1001 against a deposit of 1000. Pair: session-close-final-voucher-accept.",
        close_recipe(Channel::client(100), Some(VoucherSpec::new(1_001)), false),
        rej(RejectCode::CumulativeExceedsDeposit),
    ).build();
    session_close_below_accepted_reject => close_case(
        "session-close-below-accepted-reject",
        BugType::Settlement,
        s("Action: \"close\"", "A voucher at or below settled MUST equal the server's acceptedCumulative, authenticates close only, and MUST NOT be submitted as a settlement update."),
        &[R_CLOSE_AT_OR_BELOW],
        "A final voucher for 50, below the accepted 100 (RULINGS SC1). Pair: session-close-accepted-voucher-accept.",
        close_recipe(Channel::client(100), Some(VoucherSpec::new(50)), false),
        rej(RejectCode::CumulativeAmountMismatch),
    ).build();
    session_close_already_pending_reject => close_case(
        "session-close-already-pending-reject",
        BugType::Settlement,
        s("Action: \"close\"", "For client, the server MUST verify the voucher signature and channel binding."),
        &[R_CLOSE_CLIENT],
        "A close is already pending on the channel. Pair: session-close-final-voucher-accept.",
        close_recipe(closing(Channel::client(100)), Some(VoucherSpec::new(150)), false),
        rej(RejectCode::ChannelClosing),
    ).build();
    session_close_sealed_reject => close_case(
        "session-close-sealed-reject",
        BugType::Settlement,
        s("Action: \"close\"", "For client, the server MUST verify the voucher signature and channel binding."),
        &[R_CLOSE_CLIENT],
        "The channel is already closed (sealed). Pair: session-close-final-voucher-accept.",
        close_recipe(sealed(Channel::client(100)), Some(VoucherSpec::new(150)), false),
        rej(RejectCode::CloseState),
    ).build();
    session_close_expired_voucher_reject => close_case(
        "session-close-expired-voucher-reject",
        BugType::Settlement,
        s("Voucher Verification", "If expiresAt is present and non-zero, verify now < expiresAt (with configurable clock skew tolerance)."),
        &[R_CLOSE_CLIENT, R_VERIFY_EACH],
        "The final voucher expired in 2001. Pair: session-close-final-voucher-accept.",
        close_recipe(Channel::client(100), Some(VoucherSpec { expires_at: Some(PAST_EXPIRY), ..VoucherSpec::new(150) }), false),
        rej(RejectCode::VoucherExpired),
    ).build();
    session_close_operator_voucher_reject => close_case(
        "session-close-operator-voucher-reject",
        BugType::AuthBypass,
        s("Action: \"close\"", "| voucher | object | Conditionally REQUIRED | REQUIRED for client and MUST be absent for operator; authenticates close and MAY advance settlement (see {{voucher-format}}) |"),
        &[R_CLOSE_VOUCHER],
        "An operator close carrying a voucher next to the bearer proof. Pair: session-close-operator-accept.",
        close_recipe(Channel::operator(100), Some(VoucherSpec { signer_seed: OPERATOR_SEED, ..VoucherSpec::new(150) }), true),
        rej(RejectCode::CloseAuthorization),
    ).build();
    session_close_operator_missing_proof_reject => close_case(
        "session-close-operator-missing-proof-reject",
        BugType::AuthBypass,
        s("Action: \"close\"", "| authentication | object | Conditionally REQUIRED | Reusable proof; REQUIRED for operator and MUST be absent for client |"),
        &[R_CLOSE_AUTH, R_CLOSE_OPERATOR],
        "An operator close without the bearer proof. Pair: session-close-operator-accept.",
        close_recipe(Channel::operator(100), None, false),
        rej(RejectCode::CloseAuthorization),
    ).build();
    session_close_operator_wrong_proof_reject => close_case(
        "session-close-operator-wrong-proof-reject",
        BugType::AuthBypass,
        s("Action: \"close\"", "For operator, the server MUST verify authentication against the channel before initiating cooperative close."),
        &[R_CLOSE_OPERATOR],
        "The bearer proof names another session challenge than the one bound at open. Pair: session-close-operator-accept.",
        close_recipe(Channel::operator(100), None, true).edit(Edit::Set("/authentication/challengeId", json!("c_session_other_challenge"))),
        rej(RejectCode::AuthenticationInvalid),
    ).build();
    session_close_unknown_channel_reject => close_case(
        "session-close-unknown-channel-reject",
        BugType::AuthBypass,
        s("Voucher Data", "Implementations MUST NOT accept vouchers for channels whose identity cannot be recomputed from the program ID and channel open parameters."),
        &[R_IDENTITY],
        "A close (and final voucher) for a channel the server never opened. Pair: session-close-final-voucher-accept.",
        close_recipe(Channel::client(100), Some(VoucherSpec { channel: Some(other_channel()), ..VoucherSpec::new(150) }), false).edit(Edit::Set("/channelId", json!(other_channel().to_string()))),
        rej(RejectCode::ChannelState),
    ).build();

    // ── client build ───────────────────────────────────────────────────────
    session_build_open_client_paid => build_case(
        "session-build-open-client-paid",
        open_action("Clients SHOULD set openSlot to the challenge's methodDetails.recentSlot and MUST use the challenged recentBlockhash in the transaction."),
        &[R_BLOCKHASH, R_DERIVE, R_OPEN_SLOT],
        "The client opens a channel for a client-paid challenge: the payer pays fees and rent and signs, the delegated session key is authorizedSigner, openSlot is the challenged recentSlot, the blockhash is the challenged one and channelId is the PDA of those seeds (salt 7, the vector's).",
        build_recipe(server()),
        build_summary(),
    ).build();
    session_build_open_sponsored => build_case(
        "session-build-open-sponsored",
        s("Fee Sponsorship", "The client builds the open transaction with the server's feePayerKey as fee payer, partially signs (deposit transfer authority only), and sends via transaction in the open credential."),
        &[R_RENT_PAYER, R_FEE_KEY_PRESENT],
        "feePayer: the client builds with feePayerKey as fee payer and rentPayer and leaves that slot empty for the server.",
        build_recipe(sponsored()),
        build_summary(),
    ).build();
    session_build_open_splits => build_case(
        "session-build-open-splits",
        open_action("| distributionSplits | array | OPTIONAL | Splits preimage (see the challenge's methodDetails.distributionSplits); MUST byte-match the splits proposed in the 402 challenge |"),
        &[R_SPLITS],
        "The challenge proposes a co-recipient split; the client commits exactly that preimage.",
        build_recipe(with_splits()),
        build_summary(),
    ).build();
    session_build_open_token_2022 => build_case(
        "session-build-open-token-2022",
        s("Method Details", "MUST be either the SPL Token Program or the Token-2022 Program when present."),
        &[R_TOKEN_PROGRAM_SET],
        "A Token-2022 mint with tokenProgram Token-2022: the escrow and payer token accounts are Token-2022 ATAs.",
        build_recipe(Server { currency: keys::MINT_2022, token_program: Some(keys::TOKEN_2022_PROGRAM), ..Server::default() }),
        build_summary(),
    ).build();
    session_build_open_payer_signer => build_case(
        "session-build-open-payer-signer",
        open_action("| authorizedSigner | string | REQUIRED | Base58 public key bound into the PDA seeds as the voucher signer; MAY equal payer or a delegated signer |"),
        &[R_AUTH_SIGNER_FIELD],
        "The client's voucher key is the payer itself.",
        BuildRecipe { authorized: Authorized::Payer, ..build_recipe(server()) },
        build_summary(),
    ).build();
    session_build_missing_recent_blockhash_reject => build_case(
        "session-build-missing-recent-blockhash-reject",
        s("Method Details", "The server MUST obtain it from the selected network, and the client MUST use it as the transaction message's recent blockhash."),
        &[R_RECENT_PAIR, R_BLOCKHASH_USE],
        "A new-channel challenge without recentBlockhash: the client has no blockhash it may use. Pair: session-build-open-client-paid.",
        build_edit(Edit::Remove("/methodDetails/recentBlockhash")),
        invalid_challenge(),
    ).build();
    session_build_missing_recent_slot_reject => build_case(
        "session-build-missing-recent-slot-reject",
        s("Method Details", "Conditionally REQUIRED when channelId is absent and MUST be absent when resuming an existing channel."),
        &[R_RECENT_PAIR],
        "A new-channel challenge without recentSlot. Pair: session-build-open-client-paid.",
        build_edit(Edit::Remove("/methodDetails/recentSlot")),
        invalid_challenge(),
    ).build();
    session_build_fee_payer_without_key_reject => build_case(
        "session-build-fee-payer-without-key-reject",
        s("Method Details", "When true, feePayerKey MUST also be present."),
        &[R_FEE_KEY_PRESENT],
        "feePayer true without feePayerKey. Pair: session-build-open-sponsored.",
        build_edit(Edit::Set("/methodDetails/feePayer", json!(true))),
        invalid_challenge(),
    ).build();
    session_build_unknown_channel_program_reject => build_case(
        "session-build-unknown-channel-program-reject",
        s("Channel Program Trust", "Clients MUST verify the methodDetails.channelProgram in the challenge matches a known, audited program before depositing funds."),
        &[R_PROGRAM_CHECK, R_PROGRAM_TRUST],
        "channelProgram is an unknown program. Pair: session-build-open-client-paid.",
        build_edit(Edit::Set("/methodDetails/channelProgram", json!(keys::X402_OTHER_PAY_TO))),
        invalid_challenge(),
    ).build();
    session_build_native_sol_reject => build_case(
        "session-build-native-sol-reject",
        s("Shared Fields", "Native SOL is not supported; clients wishing to pay in SOL MUST wrap it to wSOL (So11111111111111111111111111111111111111112) before opening a channel."),
        &[R_NATIVE_SOL],
        "currency \"sol\". Pair: session-build-open-client-paid.",
        build_edit(Edit::Set("/currency", json!("sol"))),
        invalid_challenge(),
    ).build();
    session_build_token_program_not_spl_reject => build_case(
        "session-build-token-program-not-spl-reject",
        s("Method Details", "MUST be either the SPL Token Program or the Token-2022 Program when present."),
        &[R_TOKEN_PROGRAM_SET],
        "tokenProgram is the System Program. Pair: session-build-open-client-paid.",
        build_edit(Edit::Set("/methodDetails/tokenProgram", json!(keys::SYSTEM_PROGRAM))),
        invalid_challenge(),
    ).build();
    session_build_unknown_network_reject => build_case(
        "session-build-unknown-network-reject",
        s("Method Details", "MUST be one of \"mainnet\", \"devnet\", or \"localnet\"."),
        &[R_NETWORK],
        "network \"testnet\". Pair: session-build-open-client-paid.",
        build_edit(Edit::Set("/methodDetails/network", json!("testnet"))),
        invalid_challenge(),
    ).build();
    session_build_zero_grace_period_reject => build_case(
        "session-build-zero-grace-period-reject",
        s("Method Details", "The value MUST be greater than zero."),
        &[R_GRACE_POSITIVE],
        "gracePeriodSeconds 0. Pair: session-build-open-client-paid.",
        build_edit(Edit::Set("/methodDetails/gracePeriodSeconds", json!(0))),
        invalid_challenge(),
    ).build();
    session_build_operator_without_key_reject => build_case(
        "session-build-operator-without-key-reject",
        s("Method Details", "Conditionally REQUIRED when voucherSigner is operator."),
        &[R_OPERATOR_PRESENT],
        "voucherSigner operator with no operator key. Pair: session-build-open-client-paid.",
        build_edit(Edit::Set("/methodDetails/voucherSigner", json!("operator"))),
        invalid_challenge(),
    ).build();
    session_build_missing_decimals_reject => build_case(
        "session-build-missing-decimals-reject",
        s("Method Details", "MUST be present when currency is a mint address."),
        &[R_DECIMALS],
        "The challenge omits decimals for its mint. Pair: session-build-open-client-paid.",
        build_edit(Edit::Remove("/methodDetails/decimals")),
        invalid_challenge(),
    ).build();

    // ── strict wire shapes ─────────────────────────────────────────────────
    session_wire_action_open_bump_reject => wire_case(
        "session-wire-action-open-bump-reject",
        open_action("Action: \"open\" MUST NOT carry a bump field."),
        &[R_BUMP, R_BUMP_REJECT],
        "The frozen open payload plus bump: 254. The SDK's open schema must refuse it (malformed credential), not ignore the field.",
        "action",
        with(open_wire(), "/bump", json!(254)),
        invalid("open payload with a bump field"),
    ).build();
    session_wire_action_open_initial_voucher_reject => wire_case(
        "session-wire-action-open-initial-voucher-reject",
        open_action("Action: \"open\" MUST NOT carry an initial voucher."),
        &[R_NO_VOUCHER],
        "The frozen open payload plus a signed voucher.",
        "action",
        with(open_wire(), "/voucher", voucher_wire()["voucher"].clone()),
        invalid("open payload with an initial voucher"),
    ).build();
    session_wire_action_open_numeric_open_slot_reject => wire_case(
        "session-wire-action-open-numeric-open-slot-reject",
        open_action("| openSlot | string | REQUIRED | Decimal u64 per-incarnation epoch encoded into the open instruction as open_slot; MUST be no greater than the challenge's methodDetails.recentSlot and MUST satisfy the on-chain window rule of {{channel-closure}} when the transaction executes."),
        &[R_OPEN_SLOT],
        "openSlot as a JSON number instead of a decimal string.",
        "action",
        with(open_wire(), "/openSlot", json!(250000000_u64)),
        invalid("numeric openSlot"),
    ).build();
    session_wire_action_open_numeric_salt_reject => wire_case(
        "session-wire-action-open-numeric-salt-reject",
        open_action("| salt | string | REQUIRED | Decimal u64 PDA disambiguator |"),
        &[R_SALT_FIELD],
        "salt as a JSON number instead of a decimal string.",
        "action",
        with(open_wire(), "/salt", json!(7777)),
        invalid("numeric salt"),
    ).build();
    session_wire_action_open_missing_transaction_reject => wire_case(
        "session-wire-action-open-missing-transaction-reject",
        open_action("| transaction | string | REQUIRED | Base64-encoded (standard alphabet, padded) signed or partially signed transaction |"),
        &[R_TX_FIELD],
        "The frozen open payload without transaction.",
        "action",
        without(open_wire(), "/transaction"),
        invalid("open payload without transaction"),
    ).build();
    session_wire_action_voucher_missing_channel_id_reject => wire_case(
        "session-wire-action-voucher-missing-channel-id-reject",
        s("Action: \"voucher\"", "| channelId | string | REQUIRED | Existing channel identifier |"),
        &[R_CHANNEL_FIELD],
        "The frozen voucher action without its top-level channelId routing key.",
        "action",
        without(voucher_wire(), "/channelId"),
        invalid("voucher action without channelId"),
    ).build();
    session_wire_action_voucher_signature_type_reject => wire_case(
        "session-wire-action-voucher-signature-type-reject",
        s("Signed Voucher", "| signatureType | string | REQUIRED | \"ed25519\" |"),
        &[R_SIG_TYPE],
        "signatureType secp256r1: the base specification defines ed25519 only.",
        "action",
        with(voucher_wire(), "/voucher/signatureType", json!("secp256r1")),
        invalid("signatureType other than ed25519"),
    ).build();
    session_wire_action_voucher_numeric_cumulative_reject => wire_case(
        "session-wire-action-voucher-numeric-cumulative-reject",
        s("Voucher Data", "| cumulativeAmount | string | REQUIRED | Total authorized spend (base units) |"),
        &[R_CUMULATIVE_FIELD],
        "cumulativeAmount as a JSON number instead of a string.",
        "action",
        with(voucher_wire(), "/voucher/voucher/cumulativeAmount", json!(250)),
        invalid("numeric cumulativeAmount"),
    ).build();
    session_wire_action_voucher_missing_signature_type_reject => wire_case(
        "session-wire-action-voucher-missing-signature-type-reject",
        s("Signed Voucher", "| signatureType | string | REQUIRED | \"ed25519\" |"),
        &[R_SIG_TYPE],
        "The signed voucher without signatureType.",
        "action",
        without(voucher_wire(), "/voucher/signatureType"),
        invalid("signed voucher without signatureType"),
    ).build();
    session_wire_action_topup_frozen => wire_case(
        "session-wire-action-topup-frozen",
        s("Action: \"topUp\"", "| additionalAmount | string | REQUIRED | Amount to add in base units |"),
        &[R_TOPUP_ACTION, R_TOPUP_ADDITIONAL, R_TOPUP_TX],
        "topUp action payload (channelId, additionalAmount as a decimal string, transaction), frozen byte-for-byte through the SDK's session action schema.",
        "action",
        json!({"action": "topUp", "additionalAmount": "500", "channelId": CHANNEL, "transaction": "AQID"}),
        golden(),
    ).build();
    session_wire_action_topup_missing_amount_reject => wire_case(
        "session-wire-action-topup-missing-amount-reject",
        s("Action: \"topUp\"", "| additionalAmount | string | REQUIRED | Amount to add in base units |"),
        &[R_TOPUP_ADDITIONAL],
        "topUp without additionalAmount.",
        "action",
        json!({"action": "topUp", "channelId": CHANNEL, "transaction": "AQID"}),
        invalid("topUp without additionalAmount"),
    ).build();
    session_wire_action_use_frozen => wire_case(
        "session-wire-action-use-frozen",
        s("Action: \"use\"", "| authentication | object | REQUIRED | Reusable proof bound at open, as defined in {{session-bearer-proof}} |"),
        &[R_USE_ACTION, R_USE_CHANNEL, R_USE_AUTH, R_PROOF_TYPE],
        "use action payload with the bearer proof (type proof, challengeId, payer, signature), frozen through the SDK's session action schema.",
        "action",
        json!({"action": "use", "authentication": {"challengeId": CHALLENGE_ID, "payer": keys::CLIENT, "signature": SIGNATURE, "type": "proof"}, "channelId": CHANNEL}),
        golden(),
    ).build();
    session_wire_action_use_proof_type_reject => wire_case(
        "session-wire-action-use-proof-type-reject",
        s("Session Bearer Proof", "| type | string | REQUIRED | The string \"proof\" |"),
        &[R_PROOF_TYPE],
        "A use action whose authentication type is \"signature\".",
        "action",
        json!({"action": "use", "authentication": {"challengeId": CHALLENGE_ID, "payer": keys::CLIENT, "signature": SIGNATURE, "type": "signature"}, "channelId": CHANNEL}),
        invalid("authentication type other than proof"),
    ).build();
    session_wire_action_close_operator_frozen => wire_case(
        "session-wire-action-close-operator-frozen",
        s("Action: \"close\"", "| authentication | object | Conditionally REQUIRED | Reusable proof; REQUIRED for operator and MUST be absent for client |"),
        &[R_CLOSE_AUTH, R_CLOSE_ACTION],
        "An operator close: the bearer proof and no voucher, frozen through the SDK's session action schema.",
        "action",
        json!({"action": "close", "authentication": {"challengeId": CHALLENGE_ID, "payer": keys::CLIENT, "signature": SIGNATURE, "type": "proof"}, "channelId": CHANNEL}),
        golden(),
    ).build();
    session_wire_request_operator_sponsored_frozen => wire_case(
        "session-wire-request-operator-sponsored-frozen",
        s("Method Details", "Conditionally REQUIRED when voucherSigner is operator."),
        &[R_OPERATOR_PRESENT, R_FEE_KEY_PRESENT],
        "A sponsored operator-signed challenge (feePayer, feePayerKey, voucherSigner operator, operator, idleTimeoutOptionsSeconds, distributionSplits, minVoucherDelta), frozen through the SDK's session request schema.",
        "request",
        json!({"amount": "25", "currency": "USDC", "methodDetails": {"channelProgram": "CHNLxYvVA28MJP9PrFuDXccuoGXAx7jBacfLEkahyGsX", "decimals": 6, "distributionSplits": [{"recipient": keys::SPLIT_RECIPIENT_2, "shareBps": 500}], "feePayer": true, "feePayerKey": operator().to_string(), "gracePeriodSeconds": 900, "idleTimeoutOptionsSeconds": [60, 300, 900], "minVoucherDelta": "25", "network": "devnet", "operator": operator().to_string(), "recentBlockhash": "EkSnNWid2cvwEVnVx9aBqawnmiCNiDgp3gUdkDPTKN1N", "recentSlot": "250000000", "voucherSigner": "operator"}, "recipient": keys::X402_PAY_TO}),
        golden(),
    ).build();
    session_wire_request_missing_network_reject => wire_case(
        "session-wire-request-missing-network-reject",
        s("Method Details", "There is no default; the challenge MUST state the cluster explicitly."),
        &[R_NETWORK_EXPLICIT],
        "A session request without methodDetails.network.",
        "request",
        without(request_wire(), "/methodDetails/network"),
        invalid("request without network"),
    ).build();
    session_wire_request_numeric_recent_slot_reject => wire_case(
        "session-wire-request-numeric-recent-slot-reject",
        s("Method Details", "Conditionally REQUIRED when channelId is absent and MUST be absent when resuming an existing channel."),
        &[R_RECENT_PAIR],
        "recentSlot as a JSON number instead of a decimal string.",
        "request",
        with(request_wire(), "/methodDetails/recentSlot", json!(250000000_u64)),
        invalid("numeric recentSlot"),
    ).build();
    session_wire_request_voucher_signer_unknown_reject => wire_case(
        "session-wire-request-voucher-signer-unknown-reject",
        s("Method Details", "MUST be either client or operator."),
        &[R_VOUCHER_SIGNER_VALUES],
        "voucherSigner \"server\".",
        "request",
        with(request_wire(), "/methodDetails/voucherSigner", json!("server")),
        invalid("voucherSigner other than client or operator"),
    ).build();
    session_wire_request_missing_channel_program_reject => wire_case(
        "session-wire-request-missing-channel-program-reject",
        s("Method Details", "Clients MUST verify this matches their expected program for that cluster before depositing funds."),
        &[R_PROGRAM_CHECK],
        "A session request without methodDetails.channelProgram.",
        "request",
        without(request_wire(), "/methodDetails/channelProgram"),
        invalid("request without channelProgram"),
    ).build();
    session_wire_authentication_message_frozen => CaseBuilder::new(
        "session-wire-authentication-message-frozen",
        WIRE,
        Suite::Session,
        Intent::Session,
        Mode::CanonicalBytes,
        Role::Both,
        BugType::Wire,
        s("Session Bearer Proof", "| challengeId | string | REQUIRED | Session challenge ID signed as sessionChallengeId |"),
        "The bearer-proof message the payer signs: the JCS serialization of { channelId, domain: \"mpp-session-auth-v1\", payer, sessionChallengeId }. Frozen byte-for-byte; a key out of order, a renamed key or another domain string diverges and no verifier accepts the proof.",
        Input::Static(json!({ "sessionAuthenticationMessage": { "challengeId": CHALLENGE_ID, "channelId": CHANNEL, "payer": keys::CLIENT } })),
        golden(),
    )
    .requirements(&[R_PROOF_CHALLENGE, R_PROOF_PAYER, R_PROOF_SIG])
    .build();
}
