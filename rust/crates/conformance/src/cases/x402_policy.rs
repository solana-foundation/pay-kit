//! x402 `exact` (SVM) rules from scheme_exact_svm.md the first registry did
//! not cover: the §3.1 static layout's instruction set, wallet-injected
//! Lighthouse instructions, sponsor fund safety and signer-set integrity
//! (§2.1.3, §2.1.4), single-memo enforcement, and the client's use of
//! `extra.memo`. Chosen from the `pkc req-lint` gap list.

use serde_json::json;

use super::x402_exact::{
    build_case, build_input, devnet_route, header, offer, verify_case, CLIENT_MEMO,
    FEE_PAYER_NOT_IN_ACCOUNTS, MEMO_ENFORCED, SPONSOR_BEFORE_SIGNING, SVM, V2_SHAPE,
};
use crate::case::{spec, BugType, Case, Expect, Pin, SpecRef, Suite, X402HeaderSpec, X402Route};
use crate::keys::{CLIENT, DEVNET_CAIP2, MINT};
use crate::mutate::Mutation;

const VERIFY: &str = "x402-verify-policy.json";
const BUILD: &str = "x402-build-policy.json";

const STATIC_LAYOUT: &str = "X402-a8bd75d71b";
const LIGHTHOUSE_ALLOWED: &str = "X402-a1cf65b0f0";
const FUND_SAFETY: &str = "X402-985ecc1ea3";
const SIGNATURE_ONLY_FOR_FEES: &str = "X402-0ad718daab";
const NO_EXTRA_SIGNERS: &str = "X402-9b240d95a0";
const EXTRA_SIGNATURES_NOT_REQUIRED: &str = "X402-27bff260c3";
const USE_EXTRA_MEMO: &str = "X402-d5f1ded529";
const SPONSORSHIP_ABUSE: &str = "X402-fc2225a882";
const PAYMENT_BINDING: &str = "X402-8fcdf05fbf";
const ONCHAIN_EFFECTS: &str = "X402-d844c67736";

const LIGHTHOUSE: &str = "L2TExMFKdjpN9kozasaurPirfHy9P8sbXoAN1qA3S95";
/// A program on neither the static layout nor the smart-wallet allowlist.
const STAKE_PROGRAM: &str = "Stake11111111111111111111111111111111111111";
/// RequestHeapFrame (discriminator 1) of 32 KiB.
const REQUEST_HEAP_FRAME: &[u8] = &[1, 0x00, 0x80, 0x00, 0x00];
/// A third key the filler signs with (not the client, not the sponsor).
const THIRD_SIGNER_SEED: [u8; 32] = [13; 32];

const SECTION_LAYOUT: &str = "3.1 Path 1 — Static Layout Verification (standard wallets)";

fn layout_spec(quote: &str) -> SpecRef {
    spec(SVM, SECTION_LAYOUT, quote)
}

fn mutated(route: X402Route, mutation: Mutation) -> X402HeaderSpec {
    X402HeaderSpec {
        mutation: Some(mutation),
        ..header(route)
    }
}

fn reject_case(
    id: &str,
    bug: BugType,
    spec: SpecRef,
    reqs: &[&str],
    description: &str,
    h: X402HeaderSpec,
) -> Case {
    let code = h
        .mutation
        .as_ref()
        .and_then(|m| m.expected(Suite::X402Exact))
        .unwrap_or_else(|| panic!("{id}: no x402 reject code for its mutation"));
    verify_case(
        id,
        VERIFY,
        bug,
        spec,
        reqs,
        description,
        h,
        Expect::Reject { code, reason: None },
    )
    .build()
}

crate::registry! {
    x402_exact_verify_lighthouse_accept => verify_case(
        "x402-exact-verify-lighthouse-accept",
        VERIFY,
        BugType::Defaults,
        layout_spec("These are wallet-injected user protection mechanisms and MUST be allowed."),
        &[LIGHTHOUSE_ALLOWED, STATIC_LAYOUT],
        "A Lighthouse assertion instruction (as Phantom and Solflare inject) between the TransferChecked and the Memo. The static layout allows Lighthouse in positions 4 to 6; a verifier that rejects it turns away standard wallets.",
        mutated(devnet_route(), Mutation::AddProgramInstruction { program: LIGHTHOUSE, data: &[0] }),
        Expect::Accept(Pin::Envelope(V2_SHAPE.to_vec())),
    )
    .build();
    x402_exact_verify_unknown_program_reject => reject_case(
        "x402-exact-verify-unknown-program-reject",
        BugType::Settlement,
        layout_spec("The decompiled transaction MUST contain 3 to 7 instructions in this order:"),
        &[STATIC_LAYOUT],
        "An instruction of a program that is neither Lighthouse nor Memo (the Stake program) in an optional position of the static layout.",
        mutated(devnet_route(), Mutation::AddProgramInstruction { program: STAKE_PROGRAM, data: &[0] }),
    );
    x402_exact_verify_compute_heap_frame_reject => reject_case(
        "x402-exact-verify-compute-heap-frame-reject",
        BugType::Settlement,
        layout_spec("The decompiled transaction MUST contain 3 to 7 instructions in this order:"),
        &[STATIC_LAYOUT],
        "Position 1 must be SetComputeUnitLimit (ComputeBudget discriminator 2); here it is RequestHeapFrame (discriminator 1). Only unit limit and unit price are accepted compute budget instructions.",
        mutated(devnet_route(), Mutation::SetComputeBudgetData { index: 0, data: REQUEST_HEAP_FRAME }),
    );
    x402_exact_verify_extra_compute_budget_reject => reject_case(
        "x402-exact-verify-extra-compute-budget-reject",
        BugType::Settlement,
        layout_spec("The decompiled transaction MUST contain 3 to 7 instructions in this order:"),
        &[STATIC_LAYOUT],
        "A third ComputeBudget instruction (RequestHeapFrame) ahead of the unit limit and price, so the transfer is no longer at position 3.",
        mutated(devnet_route(), Mutation::AddComputeBudget { data: REQUEST_HEAP_FRAME }),
    );
    x402_exact_verify_fee_payer_sol_drain_reject => reject_case(
        "x402-exact-verify-fee-payer-sol-drain-reject",
        BugType::AuthBypass,
        spec(SVM, "2.1.3 Fee Payer Fund Safety (MUST)", "The sponsor MUST reject any transaction in which the sponsor's funds could be debited beyond the network fee"),
        &[FUND_SAFETY, SIGNATURE_ONLY_FOR_FEES, FEE_PAYER_NOT_IN_ACCOUNTS, SPONSOR_BEFORE_SIGNING],
        "A System transfer of 1 SOL from the sponsor (fee payer) to the client after the payment. Signing as fee payer would also authorize the drain.",
        mutated(devnet_route(), Mutation::FeePayerSystemTransfer { to: CLIENT, lamports: 1_000_000_000 }),
    );
    x402_exact_verify_extra_required_signer_reject => reject_case(
        "x402-exact-verify-extra-required-signer-reject",
        BugType::AuthBypass,
        spec(SVM, "2.1.4 Signer Set Integrity (MUST)", "The transaction MUST NOT require any signatures beyond the client and the sponsor (feePayer)."),
        &[NO_EXTRA_SIGNERS, EXTRA_SIGNATURES_NOT_REQUIRED],
        "A third key is a required signer (a signer account of the Memo instruction), signed by that key. The sponsor would pay for a signature it did not ask for and the payment depends on a party outside the client and sponsor.",
        mutated(devnet_route(), Mutation::ExtraSigner { memo: 0, seed: THIRD_SIGNER_SEED }),
    );
    x402_exact_verify_duplicate_memo_reject => reject_case(
        "x402-exact-verify-duplicate-memo-reject",
        BugType::Settlement,
        layout_spec("If extra.memo is present, the facilitator MUST verify that exactly one Memo instruction exists and that its data matches extra.memo encoded as UTF-8."),
        &[MEMO_ENFORCED],
        "The route sets extra.memo and the transaction carries it twice: both match, but exactly one Memo instruction is required.",
        mutated(X402Route { memo: Some("pi_conformance_0001"), ..devnet_route() }, Mutation::DuplicateMemo { memo: 0 }),
    );
    x402_exact_verify_priority_fee_over_cap_reject => reject_case(
        "x402-exact-verify-priority-fee-over-cap-reject",
        BugType::Settlement,
        spec(SVM, "2.2.1 Compute Budget Controls (SHOULD)", "Sponsors SHOULD bound their fee exposure by enforcing maximum compute unit limits and maximum compute unit (priority fee) price on any `ComputeBudgetProgram` instructions."),
        &[SPONSORSHIP_ABUSE],
        "The static layout's 200,000 compute unit limit paired with a 5,000,000 micro-lamport unit price: each is within its own cap, but the sponsor would pay a 1,000,000 lamport priority fee. The sponsor bounds the fee it pays as limit times price (RULINGS S6). Differs from x402-exact-v2-verify-accept only in the price.",
        mutated(devnet_route(), Mutation::SetComputeUnitPrice { micro_lamports: 5_000_000 }),
    );
    // RULINGS SIG1: the client's signature verifies over this message
    // before the sponsor claims, co-signs or sends it.
    x402_exact_verify_forged_client_signature_reject => reject_case(
        "x402-exact-verify-forged-client-signature-reject",
        BugType::AuthBypass,
        spec(SVM, "3.4 Post-Settlement Verification (TOCTOU defense)", "Settlement success MUST reflect actual on-chain effects, not simulation alone."),
        &[ONCHAIN_EFFECTS, PAYMENT_BINDING],
        "The client's slot holds its signature of another transaction, as a copied landed signature would. A sponsor that keys its replay or pending record on that signature and reconciles by its on-chain status grants the resource for a payment that never happened (RULINGS SIG1). Differs from x402-exact-v2-verify-accept only in that signature.",
        mutated(devnet_route(), Mutation::ForgeSignature),
    );
    x402_exact_verify_truncated_signatures_reject => reject_case(
        "x402-exact-verify-truncated-signatures-reject",
        BugType::AuthBypass,
        spec(SVM, "3.4 Post-Settlement Verification (TOCTOU defense)", "Settlement success MUST reflect actual on-chain effects, not simulation alone."),
        &[ONCHAIN_EFFECTS, PAYMENT_BINDING],
        "The signature list stops after the sponsor's empty slot: the message requires the client's signature and the payload carries none, so checking only the signatures present verifies nothing (RULINGS SIG1). Differs from x402-exact-v2-verify-accept only in the signature list.",
        mutated(devnet_route(), Mutation::TruncateSignatures { keep: 1 }),
    );
    x402_exact_build_uses_extra_memo => build_case(
        "x402-exact-build-uses-extra-memo",
        BUILD,
        spec(SVM, "PaymentRequirements for exact", "When present, the client MUST use this value as the Memo instruction data instead of a random nonce."),
        &[USE_EXTRA_MEMO, CLIENT_MEMO],
        "The offer sets extra.memo; the client must write exactly that text as the Memo instruction data (the judge compares the decoded instructions, memo text included, with the kit's build).",
        build_input(Some(2), with_extra(offer(DEVNET_CAIP2, "1000", MINT, 300), "memo", "pi_conformance_build_01"), MINT, json!({})),
        V2_SHAPE.to_vec(),
    );
}

fn with_extra(mut offer: serde_json::Value, key: &str, value: &str) -> serde_json::Value {
    offer["extra"][key] = json!(value);
    offer
}
