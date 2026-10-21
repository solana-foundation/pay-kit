//! Map the Rust kit's reject messages onto the shared [`RejectCode`]
//! vocabulary.
//!
//! This is the filler's half of the reject contract: a generated reject case
//! declares a code, and its positive-control test passes only when the kit's
//! actual error classifies to it. The table mirrors
//! `harness/src/conformance/reject.ts` (the categories' meaning) plus the
//! kit's x402 `invalid_exact_svm_payload_*` reasons, which all contain the
//! word "payload" and would otherwise fall through to `invalid-payload`.

use crate::case::RejectCode;

pub fn classify(message: &str) -> Option<RejectCode> {
    use RejectCode::*;
    let m = message.to_ascii_lowercase();
    let has = |needle: &str| m.contains(needle);
    // Ordered: specific x402 verifier reasons first, then the reject.ts
    // patterns, then the generic fallback.
    let code = if has("compute_price_instruction_too_high")
        || (has("compute unit price") && (has("exceed") || has("cap") || has("maximum")))
    {
        ComputePriceOverCap
    } else if has("compute_limit_instruction_too_high")
        || (has("compute unit limit") && (has("exceed") || has("cap") || has("maximum")))
    {
        ComputeLimitOverCap
    } else if has("fee payer cannot fund") || has("fee payer token account cannot fund") {
        // The charge verifier's SOL / SPL funding-source checks.
        FeePayerIsFundsSource
    } else if has("primary amount is zero after splits") || has("split amounts exceed") {
        SplitsExceedAmount
    } else if has("splits exceed maximum") {
        TooManySplits
    } else if has("ata creation owner is not authorized")
        || has("unsupported compute budget")
        || has("unexpected_signer")
    {
        // ATA creation for an owner the challenge does not authorize, a
        // ComputeBudget instruction other than unit limit / unit price, a
        // required signer beyond the client and the sponsor.
        UnexpectedInstruction
    } else if has("atacreationrequired requires")
        || has("unsupported challenge network")
        || has("invalid amount")
        || has("requires feepayerkey")
    {
        // The challenge itself is out of spec: an SPL-only flag on a SOL
        // charge, a cluster outside mainnet/devnet/localnet, an amount that
        // is not a u64, feePayer without feePayerKey.
        InvalidChallenge
    } else if has("ata creation")
        || has("ata payer")
        || has("transaction fee payer must be")
        || has("transaction fee payer mismatch")
        || has("memo cannot exceed")
    {
        // A malformed ATA creation for an authorized owner, a missing
        // required one, the wrong transaction fee payer, an oversized memo.
        InvalidPayload
    } else if has("invalid challenge")
        || has("decimals is required")
        || has("failed to determine token program")
        || has("token program lookup")
        || has("failed to fetch mint account")
        || has("unsupported token program")
    {
        InvalidChallenge
    } else if has("fee payer cannot authorize")
        || has("fee_payer_transferring_funds")
        || has("fee_payer_included_in_instruction_accounts")
    {
        FeePayerNotAuthority
    } else if has("fee payer") && (has("funding source") || has("funds source")) {
        FeePayerIsFundsSource
    } else if has("splits consume the entire amount") {
        SplitsExceedAmount
    } else if has("too many splits") {
        TooManySplits
    } else if has("credential claims a different recipient")
        || has("currency mismatch")
        || has("structurally match")
        || has("does not match any offered")
        || (has("amount mismatch: expected") && !has("_amount_mismatch"))
    {
        // The v2 credential's `accepted` disagrees with the route (the
        // kit's targeted checks in verify_envelope_payload, then its
        // structural backstop).
        AcceptedMismatch
    } else if has("unsupported x402 version") {
        UnsupportedVersion
    } else if has("network mismatch") {
        WrongNetwork
    } else if has("payment-identifier") || has("payment identifier") {
        PaymentIdentifierRequired
    } else if has("voucher has expired") {
        VoucherExpired
    } else if has("settlement window") {
        VoucherExpiresBeforeSettlement
    } else if has("_amount_mismatch")
        || (has("amount") && (has("mismatch") || has("does not match")))
    {
        AmountMismatch
    } else if has("_decimals_mismatch") {
        DecimalsMismatch
    } else if has("_recipient_mismatch")
        || has("_mint_mismatch")
        || has("no_transfer_instruction")
        || has("recipient mismatch")
        || has("currency mismatch")
        || (has("no matching") && has("transfer"))
        || has("missing split transfer")
    {
        NoMatchingTransfer
    } else if (has("unknown_") && has("instruction"))
        || has("instructions_length")
        || (has("unexpected") && (has("instruction") || has("transfer")))
    {
        UnexpectedInstruction
    } else if has("invalid")
        || has("malformed")
        || has("decode")
        || has("payload")
        || has("memo")
        || has("signature")
    {
        InvalidPayload
    } else {
        return None;
    };
    Some(code)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kit_messages_classify() {
        let table = [
            (
                "Amount mismatch: expected 1000, got 1",
                RejectCode::AcceptedMismatch,
            ),
            (
                "Recipient mismatch: credential claims a different recipient",
                RejectCode::AcceptedMismatch,
            ),
            (
                "invalid_exact_svm_payload_amount_mismatch",
                RejectCode::AmountMismatch,
            ),
            (
                "invalid_exact_svm_payload_recipient_mismatch",
                RejectCode::NoMatchingTransfer,
            ),
            (
                "invalid_exact_svm_payload_mint_mismatch",
                RejectCode::NoMatchingTransfer,
            ),
            (
                "invalid_exact_svm_payload_no_transfer_instruction",
                RejectCode::NoMatchingTransfer,
            ),
            (
                "invalid_exact_svm_payload_unknown_fourth_instruction",
                RejectCode::UnexpectedInstruction,
            ),
            (
                "invalid_exact_svm_payload_memo_mismatch",
                RejectCode::InvalidPayload,
            ),
            (
                "invalid_exact_svm_payload_transaction_fee_payer_transferring_funds",
                RejectCode::FeePayerNotAuthority,
            ),
            (
                "Missing split transfer to X",
                RejectCode::NoMatchingTransfer,
            ),
            (
                "No matching SPL transferChecked of 1000 to X",
                RejectCode::NoMatchingTransfer,
            ),
            (
                "Network mismatch: expected a, got b",
                RejectCode::WrongNetwork,
            ),
            (
                "Unsupported x402 version: 3",
                RejectCode::UnsupportedVersion,
            ),
            (
                "methodDetails.decimals is required for SPL charges (spec §7.2)",
                RejectCode::InvalidChallenge,
            ),
            (
                "Fee payer cannot fund the SOL payment transfer",
                RejectCode::FeePayerIsFundsSource,
            ),
            (
                "Primary amount is zero after splits",
                RejectCode::SplitsExceedAmount,
            ),
            (
                "ATA creation owner is not authorized by the challenge",
                RejectCode::UnexpectedInstruction,
            ),
            (
                "Unsupported compute budget instruction",
                RejectCode::UnexpectedInstruction,
            ),
            (
                "ATA payer must match the transaction fee payer",
                RejectCode::InvalidPayload,
            ),
            (
                "Missing required ATA creation instruction for split recipient X",
                RejectCode::InvalidPayload,
            ),
        ];
        for (message, code) in table {
            assert_eq!(classify(message), Some(code), "{message}");
        }
        assert_eq!(classify("something else entirely"), None);
    }
}
