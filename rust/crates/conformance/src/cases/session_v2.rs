//! MPP session (Solana) V2 channel profile: lifecycle hooks, from the pinned
//! draft (`external/mpp-specs-v2`, solana-foundation/mpp-specs
//! docs/mpp-v2-channel-profiles) and the program it describes
//! (payment-channels#102).
//!
//! A V2 server advertises `channelVersion: 2` and an immutable `channelHooks`
//! policy; the client's `open` is `openWithHooks` (discriminator 10) with the
//! compact hook configuration appended to the V1 payload and the callback
//! bundle (target program, callback authority, committed extras) appended to
//! the V1 accounts. The V1 `open` (1) never creates a hooked channel and a
//! hooked `open` never lands on a V1 server.
//!
//! Three layers, as for transaction versions: the challenge wire
//! (`sessionWire`), the server's verification of a client-submitted hooked
//! `open` (`sessionServerVerify`), and the client's build of that `open`
//! (`sessionOpenBuild`). The hook policy is the credit-provider pair the
//! payment-channels example commits (`preFund` and `postDistribute`, four
//! accounts); the hook programs are never executed offline.

use serde_json::{json, Value};

use crate::case::{
    spec, BugType, CaseBuilder, Expect, Input, Intent, Mode, Pin, RejectCode, Role, SpecRef, Suite,
};
use crate::realize::session::{
    provider_hooks, stranger, Action, Authorized, BuildRecipe, Edit, OpenBuild, Recipe, Server,
    TxTamper, RECENT_SLOT,
};

const DOC: &str = "mpp-specs-v2/specs/methods/solana/draft-solana-session-00.md";

const OPEN: &str = "session-v2-server-open.json";
const BUILD: &str = "session-v2-build.json";
const WIRE: &str = "session-v2-wire.json";

// ── requirement ids (harness/requirements/mpp-v2.toml) ─────────────────────

const R_NO_RETRY_AS_V1: &str = "MPPV2-beb9ad1cbe";
const R_BIND_TUPLE: &str = "MPPV2-6e96639589";
const R_VERIFY_TUPLE: &str = "MPPV2-2f5424f79b";
const R_NO_V2_IN_V1: &str = "MPPV2-5f4438c84d";
const R_HOOKS_NEED_V2: &str = "MPPV2-f05cec9a26";
const R_NOT_V1_LAYOUT: &str = "MPPV2-7eb724a2ed";
const R_MANDATORY: &str = "MPPV2-cdcaf6309f";
const R_MISSING_FAILS: &str = "MPPV2-1cb0b76d43";
const R_PARTITION: &str = "MPPV2-71270a9762";
const R_APPROVE_AT_OPEN: &str = "MPPV2-7c7e5b0e73";
const R_DESCRIPTOR_BINDS: &str = "MPPV2-77f41c09b9";

// ── spec references ────────────────────────────────────────────────────────

fn profiles(quote: &str) -> SpecRef {
    spec(DOC, "Versioned Channel Profiles", quote)
}

fn hooks_spec(quote: &str) -> SpecRef {
    spec(DOC, "V2 Lifecycle Hooks", quote)
}

fn abi_spec(quote: &str) -> SpecRef {
    spec(DOC, "V2 Channel ABI", quote)
}

// ── servers ────────────────────────────────────────────────────────────────

/// A V1 server, the pair of every V2 case: same price, deposit, recipient
/// and sponsorship, no channel version.
fn v1_server() -> Server {
    Server {
        sponsored: true,
        ..Server::default()
    }
}

/// A V2 server advertising the credit-provider hook pair.
fn hooked_server() -> Server {
    let base = v1_server();
    Server {
        channel_version: Some(2),
        channel_hooks: Some(provider_hooks(&base)),
        ..base
    }
}

/// A V2 server with every hook slot disabled: still the hooked instruction
/// family, with no callback bundle.
fn unhooked_v2_server() -> Server {
    Server {
        channel_version: Some(2),
        channel_hooks: Some(json!({})),
        ..v1_server()
    }
}

// ── case constructors ──────────────────────────────────────────────────────

fn accept() -> Expect {
    Expect::Accept(Pin::Outcome)
}

fn rej(code: RejectCode) -> Expect {
    Expect::Reject { code, reason: None }
}

fn open_case(
    id: &str,
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
        OPEN,
        Suite::Session,
        Intent::Session,
        Mode::VerifyTransaction,
        Role::Server,
        BugType::AuthBypass,
        spec,
        &format!("{description} The open is the kit client's open action for the challenge the server issues; the server runs every check it makes before broadcasting."),
        Input::Session(Box::new(recipe)),
        expect,
    )
    .requirements(reqs)
}

/// The kit client's open for `built_for`'s challenge, verified by `server`.
fn open_built_for(server: Server, built_for: Server) -> Recipe {
    Recipe::new(
        server,
        Action::Open {
            build: OpenBuild::default(),
            built_from: Some(built_for),
            verify_slot: RECENT_SLOT,
        },
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

fn build_recipe(server: Server) -> BuildRecipe {
    BuildRecipe {
        server,
        authorized: Authorized::SessionKey,
        edits: vec![],
        client_blockhash: None,
        signer_max_version: None,
    }
}

fn hooked_build_edit(edit: Edit) -> BuildRecipe {
    BuildRecipe {
        edits: vec![edit],
        ..build_recipe(hooked_server())
    }
}

/// The open summary plus the channel instruction's tag and account count:
/// a hooked open is `openWithHooks` (10) carrying its callback bundle.
fn hooked_build_summary() -> Expect {
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
        "openDiscriminator",
        "openAccountCount",
    ]))
}

fn wire_case(
    id: &str,
    spec: SpecRef,
    reqs: &[&str],
    description: &str,
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
        Input::Static(json!({ "sessionWire": { "shape": "request", "value": value } })),
        expect,
    )
    .requirements(reqs)
}

fn golden() -> Expect {
    Expect::Accept(Pin::ExactBytes(vec!["canonicalJson", "base64Url"]))
}

fn invalid_payload(reason: &str) -> Expect {
    Expect::Reject {
        code: RejectCode::InvalidPayload,
        reason: Some(reason.to_string()),
    }
}

/// A fresh V2 session challenge (the session-wire golden's request) whose
/// methodDetails carry `channelVersion: 2` and `hooks` as `channelHooks`.
fn hooked_request(version: Value, hooks: Value) -> Value {
    json!({
        "amount": "100",
        "currency": "USDC",
        "description": "metered inference",
        "methodDetails": {
            "channelProgram": "CHNLxYvVA28MJP9PrFuDXccuoGXAx7jBacfLEkahyGsX",
            "channelVersion": version,
            "channelHooks": hooks,
            "decimals": 6,
            "feePayer": true,
            "feePayerKey": "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY",
            "gracePeriodSeconds": 900,
            "network": "devnet",
            "recentBlockhash": "EkSnNWid2cvwEVnVx9aBqawnmiCNiDgp3gUdkDPTKN1N",
            "recentSlot": "250000000",
            "tokenProgram": "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
            "voucherSigner": "client"
        },
        "minimumDeposit": "1000",
        "recipient": "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY",
        "suggestedDeposit": "5000",
        "unitType": "request"
    })
}

/// The hook pair as the challenge advertises it, with the descriptor edited.
fn wire_hooks(edit: impl Fn(&mut Value)) -> Value {
    let mut hooks = provider_hooks(&v1_server());
    for slot in ["preFund", "postDistribute"] {
        edit(&mut hooks[slot]);
    }
    hooks
}

crate::registry! {
    // ── the server verifying a hooked open ──
    session_v2_server_open_hooked_accept => open_case(
        "session-v2-server-open-hooked-accept",
        profiles("Clients and servers MUST bind the selected network, channel version, `channelProgram`, and supported state, instruction, voucher and hook ABIs as one configured tuple."),
        &[R_BIND_TUPLE, R_VERIFY_TUPLE, R_APPROVE_AT_OPEN],
        "The V2 server advertises channelVersion 2 and the credit-provider hook pair (preFund and postDistribute, four committed accounts each); the kit client opens with openWithHooks (discriminator 10), the compact hook configuration after the V1 open payload and the preFund bundle (target program, callback authority, extras) after the 14 V1 accounts. Control for every reject in this file.",
        Recipe::open(hooked_server()),
        accept(),
    ).build();
    session_v2_server_open_empty_hooks_accept => open_case(
        "session-v2-server-open-empty-hooks-accept",
        profiles("The V1 layouts and encodings in this document MUST NOT be reused for V2 without an explicit ABI definition."),
        &[R_NOT_V1_LAYOUT, R_BIND_TUPLE],
        "A V2 server whose four hook slots are all disabled (channelHooks {}): account version selects the instruction family, so the open is still openWithHooks (10) with four zero slot tags and no callback bundle, never the V1 open.",
        Recipe::open(unhooked_v2_server()),
        accept(),
    ).build();
    session_v2_server_open_v1_discriminator_reject => open_case(
        "session-v2-server-open-v1-discriminator-reject",
        profiles("Implementations MUST reject malformed or unsupported versions and MUST NOT retry a rejected V2 credential as V1."),
        &[R_NOT_V1_LAYOUT, R_NO_RETRY_AS_V1],
        "The hooked open's discriminator rewritten to the V1 open tag (1): the server rebuilds openWithHooks (10) and does not recognise the instruction; it must not fall back to V1 verification. Pair: session-v2-server-open-hooked-accept.",
        Recipe::open(hooked_server()).tx(TxTamper::OpenDiscriminator(1)),
        rej(RejectCode::UnexpectedInstruction),
    ).build();
    session_v2_server_open_plain_open_reject => open_case(
        "session-v2-server-open-plain-open-reject",
        hooks_spec("Missing configuration or required accounts MUST fail, not disable hooks."),
        &[R_MISSING_FAILS, R_NOT_V1_LAYOUT],
        "A well-formed V1 open (discriminator 1, no hook configuration, 14 accounts) presented to the V2 server for the same channel: the credential's fields agree with the challenge, but the transaction funds an unhooked channel, which the server must refuse rather than accept without hooks. Pair: session-v2-server-open-hooked-accept.",
        open_built_for(hooked_server(), v1_server()),
        rej(RejectCode::UnexpectedInstruction),
    ).build();
    session_v2_server_open_hook_bundle_dropped_reject => open_case(
        "session-v2-server-open-hook-bundle-dropped-reject",
        hooks_spec("Recipient accounts and each hook's accounts MUST have an unambiguous partition."),
        &[R_MISSING_FAILS, R_PARTITION],
        "The hooked open's account list truncated to the 14 V1 accounts: the preFund bundle (target program, callback authority, four extras) is missing, so the instruction cannot run its mandatory callback. Pair: session-v2-server-open-hooked-accept.",
        Recipe::open(hooked_server()).tx(TxTamper::OpenTruncateAccounts(14)),
        rej(RejectCode::OpenBindingMismatch),
    ).build();
    session_v2_server_open_hook_account_substituted_reject => open_case(
        "session-v2-server-open-hook-account-substituted-reject",
        hooks_spec("Recipient accounts and each hook's accounts MUST have an unambiguous partition."),
        &[R_PARTITION, R_VERIFY_TUPLE],
        "The first committed extra account of the preFund bundle (account 16, the provider's credit ledger) replaced by a stranger: the bundle no longer matches the configuration the server advertised. Pair: session-v2-server-open-hooked-accept.",
        Recipe::open(hooked_server()).tx(TxTamper::OpenAccount(16, stranger())),
        rej(RejectCode::OpenBindingMismatch),
    ).build();
    session_v2_server_open_hook_config_altered_reject => open_case(
        "session-v2-server-open-hook-config-altered-reject",
        hooks_spec("Payer and sponsor MUST approve configuration at opening; merchants MUST accept its policy before providing service."),
        &[R_APPROVE_AT_OPEN, R_BIND_TUPLE],
        "The last byte of the compact hook configuration (the writable flag of the postDistribute descriptor's fourth account, the token program) flipped to writable: the committed policy differs from the one the merchant advertised. Pair: session-v2-server-open-hooked-accept.",
        Recipe::open(hooked_server()).tx(TxTamper::OpenDataByte(0, 1)),
        rej(RejectCode::OpenBindingMismatch),
    ).build();
    session_v2_server_v1_rejects_hooked_open => open_case(
        "session-v2-server-v1-rejects-hooked-open",
        profiles("V1 challenges and credentials MUST NOT carry V2 hook configuration."),
        &[R_NO_V2_IN_V1, R_NOT_V1_LAYOUT],
        "The kit client's hooked open (built for the V2 server's challenge) presented to the V1 server for the same channel: the V1 server expects the V1 open (1) and must not accept openWithHooks (10). Pair: session-v2-server-open-hooked-accept (the V2 server accepting the same open).",
        open_built_for(v1_server(), hooked_server()),
        rej(RejectCode::UnexpectedInstruction),
    ).build();

    // ── the client building a hooked open ──
    session_v2_build_hooked_open => build_case(
        "session-v2-build-hooked-open",
        hooks_spec("Payer and sponsor MUST approve configuration at opening; merchants MUST accept its policy before providing service."),
        &[R_APPROVE_AT_OPEN, R_BIND_TUPLE, R_MANDATORY],
        "The client opens for a V2 challenge: openWithHooks (discriminator 10) with the challenge's channelHooks encoded after the V1 payload and the preFund bundle after the 14 V1 accounts (20 accounts), sponsored by feePayerKey, the session key as authorizedSigner, openSlot the challenged recentSlot and channelId the PDA of the V1 seeds (salt 7).",
        build_recipe(hooked_server()),
        hooked_build_summary(),
    ).build();
    session_v2_build_hooks_without_version_reject => build_case(
        "session-v2-build-hooks-without-version-reject",
        profiles("A receiver MUST reject hook configuration paired with an absent or V1 channel version; it MUST NOT ignore that configuration and fund an unhooked channel instead."),
        &[R_HOOKS_NEED_V2],
        "A challenge carrying channelHooks with no channelVersion: an absent version is V1, which cannot carry hooks; the client must refuse rather than open an unhooked V1 channel. Pair: session-v2-build-hooked-open.",
        hooked_build_edit(Edit::Remove("/methodDetails/channelVersion")),
        rej(RejectCode::InvalidChallenge),
    ).build();
    session_v2_build_unsupported_version_reject => build_case(
        "session-v2-build-unsupported-version-reject",
        profiles("Implementations MUST reject malformed or unsupported versions and MUST NOT retry a rejected V2 credential as V1."),
        &[R_NO_RETRY_AS_V1],
        "A challenge advertising channelVersion 3: the client knows versions 1 and 2 and must refuse, not downgrade. Pair: session-v2-build-hooked-open.",
        hooked_build_edit(Edit::Set("/methodDetails/channelVersion", json!(3))),
        rej(RejectCode::InvalidChallenge),
    ).build();

    // ── the challenge wire ──
    session_v2_wire_request_hooked_frozen => wire_case(
        "session-v2-wire-request-hooked-frozen",
        profiles("Clients and servers MUST bind the selected network, channel version, `channelProgram`, and supported state, instruction, voucher and hook ABIs as one configured tuple."),
        &[R_BIND_TUPLE],
        "A V2 session challenge SessionRequest: methodDetails.channelVersion is the integer 2 and channelHooks carries the credit-provider pair (preFund and postDistribute: programId, 8-byte entrypoint as a byte array, four {address, writable} accounts, empty staticData; postFund and preDistribute absent). Frozen byte-for-byte through the production parser and JCS; an SDK without the V2 fields drops them and diverges.",
        hooked_request(json!(2), provider_hooks(&v1_server())),
        golden(),
    ).build();
    session_v2_wire_request_version_string_reject => wire_case(
        "session-v2-wire-request-version-string-reject",
        profiles("Implementations MUST reject malformed or unsupported versions and MUST NOT retry a rejected V2 credential as V1."),
        &[R_NO_RETRY_AS_V1],
        "channelVersion carried as the string \"2\": the field is an integer; a parser that coerces it (or ignores it and reads the hooks as V1) is wrong. Pair: session-v2-wire-request-hooked-frozen.",
        hooked_request(json!("2"), provider_hooks(&v1_server())),
        invalid_payload("channelVersion must be a JSON integer"),
    ).build();
    session_v2_wire_request_hook_entrypoint_length_reject => wire_case(
        "session-v2-wire-request-hook-entrypoint-length-reject",
        hooks_spec("Each descriptor MUST bind its target program, versioned entrypoint, ordered accounts or deterministic derivations, exact permissions and bounded static context."),
        &[R_DESCRIPTOR_BINDS],
        "A descriptor whose entrypoint has seven bytes: the callback entrypoint is exactly eight bytes; the parser must refuse the descriptor rather than pad or truncate it. Pair: session-v2-wire-request-hooked-frozen.",
        hooked_request(json!(2), wire_hooks(|d| d["entrypoint"] = json!(b"credit!".to_vec()))),
        invalid_payload("hook descriptor entrypoint must be exactly 8 bytes"),
    ).build();
    session_v2_wire_request_hook_signer_flag_reject => wire_case(
        "session-v2-wire-request-hook-signer-flag-reject",
        abi_spec("Extra accounts are not signers; their writable flags come from the descriptor."),
        &[R_DESCRIPTOR_BINDS],
        "A descriptor account carrying a signer flag: the descriptor grammar has address and writable only; extra accounts never sign, and an unknown field is a malformed configuration, not a hint to ignore. Pair: session-v2-wire-request-hooked-frozen.",
        hooked_request(json!(2), wire_hooks(|d| d["accounts"][0]["signer"] = json!(true))),
        invalid_payload("hook descriptor accounts carry address and writable only"),
    ).build();
}
