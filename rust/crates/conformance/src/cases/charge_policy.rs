//! MPP charge (Solana) verification rules from draft-solana-charge-00 that
//! the first registry did not cover: split arithmetic, split-recipient ATA
//! creation, fee-payer placement and isolation, the instruction allowlist,
//! and the client-side challenge checks. Chosen from the `pkc req-lint`
//! gap list (verification-side MUSTs expressible as offline vectors).
//!
//! Verify cases pin a kit-built transaction. Where the rule is about the
//! challenge itself (splits that consume the amount, an SPL-only flag on a
//! SOL charge, a fee payer the transaction does not use) the transaction is
//! built from a well-formed request (`built_from`) and verified against the
//! offending one, so the server sees exactly one violation.

use serde_json::{json, Value};

use super::charge::{
    build_case, input, reject, shape, sol_request, spl_request, verify_case, CHARGE,
    ONLY_EXPECTED_INSTRUCTIONS, SPL_LEG_MISSING, UNEXPECTED_REJECTED,
};
use crate::case::{
    spec, BugType, Case, CaseBuilder, Expect, Input, Intent, Mode, Pin, RejectCode, Role, SpecRef,
    Suite,
};
use crate::keys::{
    CHARGE_RECIPIENT, CLIENT, OTHER_MINT, SPLIT_RECIPIENT, SPLIT_RECIPIENT_2, TOKEN_2022_PROGRAM,
    TOKEN_PROGRAM, X402_OFFER_FEE_PAYER,
};
use crate::mutate::{AtaEdit, Mutation};

const VERIFY: &str = "charge-verify-policy.json";
const BUILD: &str = "charge-build-policy.json";

/// The server fee payer of the fee-sponsored cases. Its slot stays empty.
const SERVER_FEE_PAYER: &str = X402_OFFER_FEE_PAYER;

const SPLITS_VERIFIED: &str = "MPP-1180595e82";
const SPLITS_CONSUME_REJECTED: &str = "MPP-95730a55e2";
const SPLITS_NOT_EXCEED: &str = "MPP-73af393543";
const SPLIT_TRANSFER_EACH: &str = "MPP-4b02ff0c39";
const ATA_SPL_ONLY: &str = "MPP-b769615b39";
const ATA_REQUIRED_CREATE: &str = "MPP-6d81f2478f";
const ATA_REQUIRED_BEFORE_TRANSFER: &str = "MPP-b333c50e7e";
const ATA_IDEMPOTENT: &str = "MPP-ab401714b4";
const ATA_OWNER_IN_SPLITS: &str = "MPP-681f5e090f";
const ATA_MINT: &str = "MPP-0399450c79";
const ATA_TOKEN_PROGRAM: &str = "MPP-438c3bfb12";
const ATA_CANONICAL: &str = "MPP-74cf327879";
const ATA_PAYER: &str = "MPP-304370cfc4";
const ATA_NOT_FEE_FUNDED_UNMARKED: &str = "MPP-baa94f08cb";
const ATA_SPONSORED_ONLY_MARKED: &str = "MPP-1fe20b9485";
const ATA_NOT_TOP_LEVEL: &str = "MPP-d63913e921";
const ATA_NOT_TOP_LEVEL_CLIENT: &str = "MPP-5b4687796d";
const SERVER_FEE_PAYER_SET: &str = "MPP-c1ed754e32";
const PAYLOAD_SERVER_FEE_PAYER: &str = "MPP-d5e5d796c6";
const CLIENT_SETS_FEE_PAYER: &str = "MPP-837333ec9f";
const CLIENT_SPONSORED: &str = "MPP-de0815e07c";
const FEE_PAYER_SLOT_EMPTY: &str = "MPP-b4a76cab12";
const VERIFY_BEFORE_SIGNING: &str = "MPP-2d30d806c0";
const MEMO_LIMIT: &str = "MPP-3d2ad6ef40";
const SOL_DISTINCT_LEGS: &str = "MPP-1659a03107";
const SPL_DISTINCT_LEGS: &str = "MPP-4f9c5997c8";
const TOKEN_PROGRAM_ABSENT_FOR_SOL: &str = "MPP-fde6ebf8c7";
const FEE_PAYER_KEY_PRESENT: &str = "MPP-58f2b1922a";
const AMOUNT_POSITIVE_U64: &str = "MPP-a6f3950ec9";
const NETWORK_ENUM: &str = "MPP-ec29292f9d";

fn method_details(quote: &str) -> SpecRef {
    spec(CHARGE, "Method Details", quote)
}

fn ata_spec(quote: &str) -> SpecRef {
    spec(CHARGE, "Split Recipient ATA Creation", quote)
}

fn two_splits(sol: bool) -> Value {
    let splits = json!([
        { "recipient": SPLIT_RECIPIENT, "amount": "100" },
        { "recipient": SPLIT_RECIPIENT_2, "amount": "150" }
    ]);
    if sol {
        input(sol_request("1000", json!({ "splits": splits })))
    } else {
        input(spl_request("1000", json!({ "splits": splits })))
    }
}

/// An SPL charge whose single split requires its ATA, optionally
/// fee-sponsored by [`SERVER_FEE_PAYER`].
fn ata_required(sponsored: bool) -> Value {
    let mut details = json!({ "splits": [{
        "recipient": SPLIT_RECIPIENT,
        "amount": "250",
        "ataCreationRequired": true
    }] });
    if sponsored {
        details["feePayer"] = json!(true);
        details["feePayerKey"] = json!(SERVER_FEE_PAYER);
    }
    input(spl_request("1000", details))
}

fn sponsored_spl(details: Value) -> Value {
    let mut md = json!({ "feePayer": true, "feePayerKey": SERVER_FEE_PAYER });
    if let Value::Object(extra) = details {
        for (k, v) in extra {
            md[k] = v;
        }
    }
    input(spl_request("1000", md))
}

fn ata_case(
    id: &str,
    quote: &str,
    reqs: &[&str],
    description: &str,
    base: Value,
    m: Mutation,
) -> Case {
    verify_case(
        id,
        VERIFY,
        BugType::Settlement,
        ata_spec(quote),
        reqs,
        description,
        base,
        Some(m),
        Pin::Outcome,
        None,
    )
    .build()
}

/// A verify case whose transaction the kit builds from `built_from`; the
/// vector's challenge is `base`.
#[allow(clippy::too_many_arguments)]
fn mismatch_case(
    id: &str,
    bug: BugType,
    spec: SpecRef,
    reqs: &[&str],
    description: &str,
    base: Value,
    built_from: Value,
    code: RejectCode,
    reason: &str,
) -> Case {
    CaseBuilder::new(
        id,
        VERIFY,
        Suite::Charge,
        Intent::Charge,
        Mode::VerifyTransaction,
        Role::Server,
        bug,
        spec,
        description,
        Input::ChargeTransaction {
            base,
            mutation: None,
            built_from: Some(built_from),
        },
        reject(code, reason),
    )
    .requirements(reqs)
    .build()
}

fn nine_splits() -> Value {
    let splits: Vec<Value> = (0..9)
        .map(|i| {
            json!({
                "recipient": if i % 2 == 0 { SPLIT_RECIPIENT } else { SPLIT_RECIPIENT_2 },
                "amount": "10",
            })
        })
        .collect();
    json!(splits)
}

fn eight_splits() -> Value {
    let mut splits = nine_splits();
    splits.as_array_mut().unwrap().pop();
    splits
}

/// RequestHeapFrame (discriminator 1) of 32 KiB: a ComputeBudget
/// instruction a payment never needs.
const REQUEST_HEAP_FRAME: &[u8] = &[1, 0x00, 0x80, 0x00, 0x00];

/// Lighthouse (assertion program wallets inject); in a charge it is an
/// instruction the challenge does not call for.
const LIGHTHOUSE: &str = "L2TExMFKdjpN9kozasaurPirfHy9P8sbXoAN1qA3S95";

crate::registry! {
    charge_verify_split_transfer_missing_reject => verify_case(
        "charge-verify-split-transfer-missing-reject",
        VERIFY,
        BugType::Settlement,
        method_details("Servers MUST verify each split transfer on-chain during credential verification."),
        &[SPLITS_VERIFIED, SPL_LEG_MISSING],
        "Two SPL splits to different recipients; the second split's transferChecked is missing while the primary and first split are paid. A verifier that checks only the primary leg (or only the first split) under-collects.",
        two_splits(false),
        Some(Mutation::DropTransfer { transfer: 2 }),
        Pin::Outcome,
        None,
    )
    .build();
    charge_verify_two_splits_accept => verify_case(
        "charge-verify-two-splits-accept",
        VERIFY,
        BugType::Settlement,
        spec(CHARGE, "SPL Token Verification", "Each required payment leg MUST be matched to a distinct transferChecked instruction."),
        &[SPLITS_VERIFIED, SPL_DISTINCT_LEGS],
        "Positive control for charge-verify-split-transfer-missing-reject: the kit's build pays the primary (750) and both splits (100, 150), each with its own transferChecked.",
        two_splits(false),
        None,
        shape(true, false, false, &[]),
        None,
    )
    .build();
    charge_verify_sol_split_transfer_missing_reject => verify_case(
        "charge-verify-sol-split-transfer-missing-reject",
        VERIFY,
        BugType::Settlement,
        spec(CHARGE, "Native SOL Verification", "Each required payment leg MUST be matched to a distinct transfer instruction."),
        &[SPLITS_VERIFIED, SOL_DISTINCT_LEGS],
        "Native SOL with two splits; the second split's System transfer is missing.",
        two_splits(true),
        Some(Mutation::DropTransfer { transfer: 2 }),
        Pin::Outcome,
        None,
    )
    .build();
    charge_verify_splits_consume_amount_reject => mismatch_case(
        "charge-verify-splits-consume-amount-reject",
        BugType::Settlement,
        method_details("Servers MUST reject challenges where splits consume the entire amount."),
        &[SPLITS_CONSUME_REJECTED],
        "The challenge's single split equals the whole amount (primary remainder zero). The transaction is the kit's build for the same split with a 1001 total (split 1000, primary 1); the server must refuse the challenge rather than accept a zero primary leg.",
        input(spl_request("1000", json!({ "splits": [{ "recipient": SPLIT_RECIPIENT, "amount": "1000" }] }))),
        input(spl_request("1001", json!({ "splits": [{ "recipient": SPLIT_RECIPIENT, "amount": "1000" }] }))),
        RejectCode::SplitsExceedAmount,
        "splits consume the entire amount",
    );
    charge_verify_splits_exceed_amount_reject => mismatch_case(
        "charge-verify-splits-exceed-amount-reject",
        BugType::Settlement,
        method_details("The sum of all split amounts MUST NOT exceed amount."),
        &[SPLITS_NOT_EXCEED],
        "The challenge's splits (600 + 600) exceed its amount (1000). The transaction is the kit's build for a 1300 total with the same splits; a verifier that computes the primary leg with wrapping or signed arithmetic, or skips the check, would look for a bogus primary amount instead of refusing.",
        input(spl_request("1000", json!({ "splits": [
            { "recipient": SPLIT_RECIPIENT, "amount": "600" },
            { "recipient": SPLIT_RECIPIENT_2, "amount": "600" }
        ] }))),
        input(spl_request("1300", json!({ "splits": [
            { "recipient": SPLIT_RECIPIENT, "amount": "600" },
            { "recipient": SPLIT_RECIPIENT_2, "amount": "600" }
        ] }))),
        RejectCode::SplitsExceedAmount,
        "split amounts exceed the total amount",
    );
    charge_verify_too_many_splits_reject => mismatch_case(
        "charge-verify-too-many-splits-reject",
        BugType::Defaults,
        method_details("OPTIONAL. An array of at most 8 additional payment splits."),
        &[SPLITS_VERIFIED],
        "Nine splits, one over the \"at most 8\" bound of methodDetails.splits. The transaction is the kit's build for the first eight; the server must refuse the oversized challenge (the bound has no MUST keyword, so this maps the split-verification requirement it protects).",
        input(spl_request("1000", json!({ "splits": nine_splits() }))),
        input(spl_request("1000", json!({ "splits": eight_splits() }))),
        RejectCode::TooManySplits,
        "more than 8 splits",
    );
    charge_verify_sol_ata_creation_required_reject => mismatch_case(
        "charge-verify-sol-ata-creation-required-reject",
        BugType::Defaults,
        method_details("This field MUST NOT be true unless currency is an SPL token mint address."),
        &[ATA_SPL_ONLY],
        "A native SOL challenge whose split sets ataCreationRequired: true. The transaction is the kit's build for the same SOL split without the flag; the server must refuse the challenge.",
        input(sol_request("1000", json!({ "splits": [{ "recipient": SPLIT_RECIPIENT, "amount": "100", "ataCreationRequired": true }] }))),
        input(sol_request("1000", json!({ "splits": [{ "recipient": SPLIT_RECIPIENT, "amount": "100" }] }))),
        RejectCode::InvalidChallenge,
        "ataCreationRequired on a SOL charge",
    );
    charge_verify_ata_for_top_level_recipient_reject => ata_case(
        "charge-verify-ata-for-top-level-recipient-reject",
        "Clients MUST NOT include ATA creation instructions for the top-level recipient or any other owner.",
        &[ATA_NOT_TOP_LEVEL, ATA_OWNER_IN_SPLITS, UNEXPECTED_REJECTED],
        "Client-paid SPL charge with no splits; the transaction also creates (idempotently) the top-level recipient's ATA. ATA creation is permitted only for split recipients.",
        input(spl_request("1000", json!({}))),
        Mutation::AddCreateAta { owner: CHARGE_RECIPIENT },
    );
    charge_verify_ata_for_arbitrary_owner_reject => ata_case(
        "charge-verify-ata-for-arbitrary-owner-reject",
        "The instruction owner MUST be a recipient listed in splits, subject to the fee payer restrictions below.",
        &[ATA_OWNER_IN_SPLITS, ATA_NOT_TOP_LEVEL],
        "Client-paid SPL charge with one split; the transaction also creates an ATA for an owner that is neither the recipient nor in splits.",
        input(spl_request("1000", json!({ "splits": [{ "recipient": SPLIT_RECIPIENT, "amount": "100" }] }))),
        Mutation::AddCreateAta { owner: SPLIT_RECIPIENT_2 },
    );
    charge_verify_sponsored_ata_unmarked_split_reject => ata_case(
        "charge-verify-sponsored-ata-unmarked-split-reject",
        "Clients MUST NOT include fee-payer-funded ATA creation instructions for the top-level recipient, unmarked split recipients, or arbitrary owners.",
        &[ATA_NOT_FEE_FUNDED_UNMARKED, ATA_SPONSORED_ONLY_MARKED],
        "Fee-sponsored SPL charge with a split that does not set ataCreationRequired; the transaction makes the server fee payer fund that split recipient's ATA. Only marked splits authorize fee-payer-funded ATA creation (rent drain otherwise).",
        sponsored_spl(json!({ "splits": [{ "recipient": SPLIT_RECIPIENT, "amount": "100" }] })),
        Mutation::AddCreateAta { owner: SPLIT_RECIPIENT },
    );
    charge_verify_sponsored_ata_top_level_reject => ata_case(
        "charge-verify-sponsored-ata-top-level-reject",
        "When feePayer is true, the client MUST include an idempotent ATA creation instruction for each split recipient whose split entry sets ataCreationRequired to true, and MUST NOT include ATA creation instructions for the top-level recipient, unmarked split recipients, or arbitrary owners.",
        &[ATA_SPONSORED_ONLY_MARKED, ATA_NOT_TOP_LEVEL_CLIENT, ATA_NOT_FEE_FUNDED_UNMARKED],
        "Fee-sponsored SPL charge; the transaction makes the server fee payer fund the top-level recipient's ATA.",
        sponsored_spl(json!({})),
        Mutation::AddCreateAta { owner: CHARGE_RECIPIENT },
    );
    charge_verify_ata_required_missing_reject => ata_case(
        "charge-verify-ata-required-missing-reject",
        "The client MUST include an ATA creation instruction for that split recipient before the split transfer.",
        &[ATA_REQUIRED_BEFORE_TRANSFER, ATA_REQUIRED_CREATE],
        "The split sets ataCreationRequired: true but the transaction omits its ATA creation (the split transfer is still present). On-chain the split transfer would fail into a missing account.",
        ata_required(false),
        Mutation::DropCreateAta { index: 0 },
    );
    charge_verify_ata_wrong_mint_reject => ata_case(
        "charge-verify-ata-wrong-mint-reject",
        "The instruction mint MUST be the challenge currency.",
        &[ATA_MINT],
        "The required split ATA creation names another mint (address re-derived for it), so the server would fund rent for an unrelated token account.",
        ata_required(false),
        Mutation::EditCreateAta { index: 0, edit: AtaEdit::Mint(OTHER_MINT) },
    );
    charge_verify_ata_wrong_token_program_reject => ata_case(
        "charge-verify-ata-wrong-token-program-reject",
        "The instruction token program MUST be the challenge tokenProgram.",
        &[ATA_TOKEN_PROGRAM],
        "The challenge pins the Token Program; the required split ATA creation uses Token-2022 (address re-derived for it).",
        ata_required(false),
        Mutation::EditCreateAta { index: 0, edit: AtaEdit::TokenProgram(TOKEN_2022_PROGRAM) },
    );
    charge_verify_ata_noncanonical_address_reject => ata_case(
        "charge-verify-ata-noncanonical-address-reject",
        "The ATA address MUST be the canonical Associated Token Account PDA for the owner, mint, and token program.",
        &[ATA_CANONICAL],
        "The required split ATA creation names the split recipient as owner but another owner's ATA as the address.",
        ata_required(false),
        Mutation::EditCreateAta { index: 0, edit: AtaEdit::Address { owner: SPLIT_RECIPIENT_2 } },
    );
    charge_verify_ata_payer_not_fee_payer_reject => ata_case(
        "charge-verify-ata-payer-not-fee-payer-reject",
        "The instruction payer MUST be the transaction fee payer.",
        &[ATA_PAYER],
        "Fee-sponsored charge whose split requires its ATA; the ATA creation's rent payer is the client, not the transaction fee payer.",
        ata_required(true),
        Mutation::EditCreateAta { index: 0, edit: AtaEdit::Payer(CLIENT) },
    );
    charge_verify_ata_not_idempotent_reject => ata_case(
        "charge-verify-ata-not-idempotent-reject",
        "The instruction MUST be the Associated Token Program's idempotent create instruction.",
        &[ATA_IDEMPOTENT],
        "The required split ATA creation is the non-idempotent Create, which fails (and burns the sponsor's fee) when the account already exists.",
        ata_required(false),
        Mutation::EditCreateAta { index: 0, edit: AtaEdit::NonIdempotent },
    );
    charge_verify_sponsored_ata_required_accept => verify_case(
        "charge-verify-sponsored-ata-required-accept",
        VERIFY,
        BugType::Settlement,
        ata_spec("When a split sets ataCreationRequired: true:"),
        &[ATA_REQUIRED_CREATE, ATA_SPONSORED_ONLY_MARKED, SERVER_FEE_PAYER_SET],
        "Positive control for the fee-sponsored ATA rejects: the kit's build for a fee-sponsored charge whose split requires its ATA (fee payer = server key, slot empty, ATA creation paid by the fee payer).",
        ata_required(true),
        None,
        shape(true, false, false, &[]),
        None,
    )
    .build();
    charge_verify_fee_payer_not_server_key_reject => mismatch_case(
        "charge-verify-fee-payer-not-server-key-reject",
        BugType::AuthBypass,
        spec(CHARGE, "Pull Mode Verification", "The transaction MUST have the server's feePayerKey set as the fee payer account."),
        &[SERVER_FEE_PAYER_SET, PAYLOAD_SERVER_FEE_PAYER],
        "Fee-sponsored challenge (feePayerKey = the server key) answered with a client-paid transaction: the client is the fee payer. The server must refuse instead of co-signing a transaction whose fee payer it does not control.",
        sponsored_spl(json!({})),
        input(spl_request("1000", json!({}))),
        RejectCode::InvalidPayload,
        "transaction fee payer is not feePayerKey",
    );
    charge_verify_sponsored_sol_fee_payer_source_reject => verify_case(
        "charge-verify-sponsored-sol-fee-payer-source-reject",
        VERIFY,
        BugType::AuthBypass,
        spec(CHARGE, "Server Requirements", "MUST verify the transaction contents before signing"),
        &[VERIFY_BEFORE_SIGNING, ONLY_EXPECTED_INSTRUCTIONS],
        "Fee-sponsored native SOL charge whose payment transfer is funded by the server fee payer: co-signing would pay the merchant out of the sponsor's own lamports.",
        input(sol_request("1000000", json!({ "feePayer": true, "feePayerKey": SERVER_FEE_PAYER }))),
        Some(Mutation::FeePayerAsSolSource { transfer: 0 }),
        Pin::Outcome,
        None,
    )
    .build();
    charge_verify_sponsored_fee_payer_drain_reject => verify_case(
        "charge-verify-sponsored-fee-payer-drain-reject",
        VERIFY,
        BugType::AuthBypass,
        spec(CHARGE, "Server Requirements", "MUST verify the transaction contents before signing"),
        &[VERIFY_BEFORE_SIGNING, UNEXPECTED_REJECTED],
        "Fee-sponsored SPL charge that also moves 1 SOL from the server fee payer to the client in a System transfer that is no payment leg.",
        sponsored_spl(json!({})),
        Some(Mutation::FeePayerSystemTransfer { to: CLIENT, lamports: 1_000_000_000 }),
        Pin::Outcome,
        None,
    )
    .build();
    charge_verify_compute_budget_heap_frame_reject => verify_case(
        "charge-verify-compute-budget-heap-frame-reject",
        VERIFY,
        BugType::Settlement,
        spec(CHARGE, "Transaction Payload Security", "Servers MUST verify that the transaction contains only the expected instructions: transfer instruction(s) matching the challenge parameters, ATA creation (idempotent), and optionally compute budget instructions."),
        &[ONLY_EXPECTED_INSTRUCTIONS, UNEXPECTED_REJECTED],
        "A ComputeBudget RequestHeapFrame (discriminator 1). Compute budget instructions are allowed to set the unit limit and price (discriminators 2 and 3); others expand execution cost without serving the payment.",
        input(spl_request("1000", json!({}))),
        Some(Mutation::AddComputeBudget { data: REQUEST_HEAP_FRAME }),
        Pin::Outcome,
        None,
    )
    .build();
    charge_verify_unknown_program_reject => verify_case(
        "charge-verify-unknown-program-reject",
        VERIFY,
        BugType::Settlement,
        spec(CHARGE, "Transaction Payload Security", "Any unexpected instructions MUST cause rejection."),
        &[UNEXPECTED_REJECTED, ONLY_EXPECTED_INSTRUCTIONS],
        "An instruction of a program the charge does not call for (Lighthouse, which x402 wallets inject) after the payment.",
        input(spl_request("1000", json!({}))),
        Some(Mutation::AddProgramInstruction { program: LIGHTHOUSE, data: &[0] }),
        Pin::Outcome,
        None,
    )
    .build();
    charge_verify_external_id_over_memo_limit_reject => mismatch_case(
        "charge-verify-external-id-over-memo-limit-reject",
        BugType::Defaults,
        spec(CHARGE, "Shared Fields", "MUST NOT exceed 566 bytes (Solana Memo Program limit)."),
        &[MEMO_LIMIT],
        "The challenge's externalId is 567 bytes, one over the Memo Program limit; the transaction is the kit's build carrying a 566-byte memo of the same prefix. The server must refuse the out-of-range challenge.",
        input(spl_request_with("1000", json!({}), &"x".repeat(567))),
        input(spl_request_with("1000", json!({}), &"x".repeat(566))),
        RejectCode::InvalidPayload,
        "externalId exceeds 566 bytes",
    );
    charge_build_two_splits => build_case(
        "charge-build-two-splits",
        BUILD,
        BugType::Settlement,
        method_details("When present, the client MUST include a transfer instruction for each split in addition to the primary transfer to recipient."),
        &[SPLIT_TRANSFER_EACH],
        "SPL charge with two splits: the client must build the primary transferChecked (750) and one per split (100, 150).",
        two_splits(false),
        Expect::Accept(shape(true, false, false, &[])),
    );
    charge_build_sponsored_fee_payer => build_case(
        "charge-build-sponsored-fee-payer",
        BUILD,
        BugType::AuthBypass,
        spec(CHARGE, "Client Requirements", "When feePayer is true: clients MUST set feePayerKey from methodDetails as the transaction fee payer and MUST sign only with the transfer authority key."),
        &[CLIENT_SPONSORED, CLIENT_SETS_FEE_PAYER, FEE_PAYER_SLOT_EMPTY],
        "Fee-sponsored SPL charge: the client must set the server's feePayerKey as fee payer and sign only as transfer authority, leaving the fee payer's slot empty (the pinned shape includes the fee payer; the judge checks the signatures).",
        sponsored_spl(json!({})),
        Expect::Accept(shape(true, false, false, &[])),
    );
    charge_build_splits_exceed_amount_reject => build_case(
        "charge-build-splits-exceed-amount-reject",
        BUILD,
        BugType::Settlement,
        method_details("The sum of all split amounts MUST NOT exceed amount."),
        &[SPLITS_NOT_EXCEED],
        "Client refuses a challenge whose splits (600 + 600) exceed its amount (1000) instead of building a transfer for a wrapped or negative primary amount.",
        input(spl_request("1000", json!({ "splits": [
            { "recipient": SPLIT_RECIPIENT, "amount": "600" },
            { "recipient": SPLIT_RECIPIENT_2, "amount": "600" }
        ] }))),
        reject(RejectCode::SplitsExceedAmount, "split amounts exceed the total amount"),
    );
    charge_build_too_many_splits_reject => build_case(
        "charge-build-too-many-splits-reject",
        BUILD,
        BugType::Defaults,
        method_details("OPTIONAL. An array of at most 8 additional payment splits."),
        &[SPLIT_TRANSFER_EACH],
        "Client refuses a challenge with nine splits, one over the \"at most 8\" bound.",
        input(spl_request("1000", json!({ "splits": nine_splits() }))),
        reject(RejectCode::TooManySplits, "more than 8 splits"),
    );
    charge_build_sol_ata_creation_required_reject => build_case(
        "charge-build-sol-ata-creation-required-reject",
        BUILD,
        BugType::Defaults,
        method_details("This field MUST NOT be true unless currency is an SPL token mint address."),
        &[ATA_SPL_ONLY],
        "Client refuses a native SOL challenge whose split sets ataCreationRequired: true (an ATA has no meaning for lamports).",
        input(sol_request("1000", json!({ "splits": [{ "recipient": SPLIT_RECIPIENT, "amount": "100", "ataCreationRequired": true }] }))),
        reject(RejectCode::InvalidChallenge, "ataCreationRequired on a SOL charge"),
    );
    charge_build_sol_token_program_reject => diverges(build_case(
        "charge-build-sol-token-program-reject",
        BUILD,
        BugType::Defaults,
        method_details("MUST NOT be present when currency is \"sol\"."),
        &[TOKEN_PROGRAM_ABSENT_FOR_SOL],
        "Client refuses a native SOL challenge that carries methodDetails.tokenProgram.",
        input(sol_request("1000", json!({ "tokenProgram": TOKEN_PROGRAM }))),
        reject(RejectCode::InvalidChallenge, "tokenProgram on a SOL charge"),
    ), "the Rust kit builds the SOL transfer and ignores tokenProgram (rust/crates/kit/src/mpp/client/charge.rs:376); see FINDINGS.md#charge-client-sol-token-program-ignored");
    charge_build_fee_payer_without_key_reject => diverges(build_case(
        "charge-build-fee-payer-without-key-reject",
        BUILD,
        BugType::Defaults,
        method_details("When true, the feePayerKey field MUST also be present."),
        &[FEE_PAYER_KEY_PRESENT],
        "Client refuses a fee-sponsored challenge (feePayer: true) that names no feePayerKey rather than paying fees itself or guessing a key.",
        input(spl_request("1000", json!({ "feePayer": true }))),
        reject(RejectCode::InvalidChallenge, "feePayer without feePayerKey"),
    ), "the Rust kit builds a client-paid transaction when feePayer is true without feePayerKey (rust/crates/kit/src/mpp/client/charge.rs:333); see FINDINGS.md#charge-client-fee-payer-without-key");
    charge_build_zero_amount_reject => build_case(
        "charge-build-zero-amount-reject",
        BUILD,
        BugType::Defaults,
        spec(CHARGE, "Shared Fields", "The value MUST be a positive integer that fits in a 64-bit unsigned integer"),
        &[AMOUNT_POSITIVE_U64],
        "Client refuses a challenge whose amount is \"0\".",
        input(spl_request("0", json!({}))),
        reject(RejectCode::SplitsExceedAmount, "amount 0 leaves no positive primary amount (every SDK reports it as splits consuming the amount)"),
    );
    charge_build_amount_overflow_reject => build_case(
        "charge-build-amount-overflow-reject",
        BUILD,
        BugType::Defaults,
        spec(CHARGE, "Shared Fields", "The value MUST be a positive integer that fits in a 64-bit unsigned integer"),
        &[AMOUNT_POSITIVE_U64],
        "Client refuses a challenge whose amount is 2^64, one past the u64 range (a parser that wraps or saturates would pay a different amount).",
        input(spl_request("18446744073709551616", json!({}))),
        reject(RejectCode::InvalidChallenge, "amount does not fit in u64"),
    );
    charge_build_unknown_network_reject => build_case(
        "charge-build-unknown-network-reject",
        BUILD,
        BugType::Defaults,
        method_details("MUST be one of \"mainnet\", \"devnet\", or \"localnet\"."),
        &[NETWORK_ENUM],
        "Client refuses a challenge whose methodDetails.network is \"testnet\", which is not one of the three defined clusters.",
        input(spl_request("1000", json!({ "network": "testnet" }))),
        reject(RejectCode::InvalidChallenge, "unknown network"),
    );
}

/// The case's expectation comes from the spec text and the Rust kit
/// currently disagrees (asserted by the positive-control test, so fixing
/// the kit forces the entry's removal).
fn diverges(mut case: Case, reason: &str) -> Case {
    case.provenance = crate::case::Provenance::Authored {
        kit_divergence: Some(reason.to_string()),
    };
    case
}

/// [`spl_request`] with a top-level `externalId`.
fn spl_request_with(amount: &str, details: Value, external_id: &str) -> Value {
    let mut request = spl_request(amount, details);
    request["externalId"] = json!(external_id);
    request
}
