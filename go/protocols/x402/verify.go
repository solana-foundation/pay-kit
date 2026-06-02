package x402

import (
	"encoding/binary"
	"fmt"

	solana "github.com/gagliardetto/solana-go"
	"github.com/solana-foundation/pay-kit/go/paycore"
	"github.com/solana-foundation/pay-kit/go/paycore/solanatx"
)

// Program IDs the structural verifier recognises. Mirror the Rust
// reference (rust/crates/x402/src/protocol/schemes/exact/types.rs).
const (
	computeBudgetProgram = "ComputeBudget111111111111111111111111111111"
	lighthouseProgram    = "L2TExMFKdjpN9kozasaurPirfHy9P8sbXoAN1qA3S95"
)

// maxComputeUnitPriceMicroLamports caps the priority fee a submitted
// transaction may carry. Matches the Rust verifier's bound.
const maxComputeUnitPriceMicroLamports uint64 = 5_000_000

// verifyError carries a canonical x402 reason code plus a human
// message. The settle path surfaces Code verbatim as the
// PaymentError.Code, matching the Rust verifier's specific
// invalid_exact_svm_payload_* reasons (verify.rs:235-418) instead of
// collapsing every structural failure to charge_request_mismatch.
type verifyError struct {
	Code string
	msg  string
}

func (e *verifyError) Error() string {
	if e.msg != "" {
		return "x402: " + e.msg
	}
	return "x402: " + e.Code
}

// verifyFail builds a verifyError with a canonical code and message.
func verifyFail(code, msg string) error { return &verifyError{Code: code, msg: msg} }

// transferRequirements is the subset of the advertised accept entry the
// structural verifier checks the on-wire transaction against.
type transferRequirements struct {
	payTo        solana.PublicKey
	mint         solana.PublicKey
	tokenProgram solana.PublicKey
	amount       uint64
	feePayer     solana.PublicKey // the operator; must not be the transfer authority
	// expectedMemo, when non-empty, is the advertised extra.memo. The x402
	// SVM spec requires the verifier to confirm exactly one Memo instruction
	// whose data equals it.
	expectedMemo string
}

// verifyExactTransaction runs the canonical x402 "exact" structural
// checks against a decoded Solana transaction BEFORE the facilitator
// cosigns or broadcasts it. Port of Rust's verify_exact_instructions
// (rust/crates/x402/src/protocol/schemes/exact/verify.rs):
//
//  1. instruction count in [3, 6]
//  2. ix[0] = ComputeBudget SetComputeUnitLimit
//  3. ix[1] = ComputeBudget SetComputeUnitPrice, <= cap
//  4. ix[2] = transferChecked to ATA(payTo, mint, program) for the
//     exact amount + mint, authority != fee-payer
//  5. ix[3..] = only Memo or Lighthouse programs
//
// Returns a *paykit.PaymentError-friendly error string on the first
// rule it fails so the caller can surface a canonical code.
func verifyExactTransaction(tx *solana.Transaction, req transferRequirements) error {
	msg := &tx.Message
	ixs := msg.Instructions
	if len(ixs) < 3 || len(ixs) > 6 {
		return verifyFail("invalid_exact_svm_payload_transaction_instructions_length",
			fmt.Sprintf("instruction count %d outside [3,6]", len(ixs)))
	}
	keys := msg.AccountKeys

	if err := verifyComputeLimit(ixs[0], keys); err != nil {
		return err
	}
	if err := verifyComputePrice(ixs[1], keys); err != nil {
		return err
	}
	if err := verifyTransfer(ixs[2], keys, req); err != nil {
		return err
	}
	// Optional trailing instructions: memo / lighthouse only. Wallets inject
	// Lighthouse guard instructions (Phantom 1, Solflare 2) so those MUST be
	// allowed; everything else (System / Token / ATA-create / unknown) is
	// rejected, which keeps a Create-ATA out of the optional slots per spec.
	// Canonical reason codes are positional (fourth/fifth/sixth), matching
	// invalid_reason_by_index (verify.rs:257-274).
	invalidReasonByIndex := []string{
		"invalid_exact_svm_payload_unknown_fourth_instruction",
		"invalid_exact_svm_payload_unknown_fifth_instruction",
		"invalid_exact_svm_payload_unknown_sixth_instruction",
	}
	memoCount := 0
	for i := 3; i < len(ixs); i++ {
		prog, err := programIDForIx(ixs[i], keys)
		if err != nil {
			return err
		}
		switch prog.String() {
		case paycore.MemoProgram:
			memoCount++
			continue
		case lighthouseProgram:
			continue
		default:
			code := "invalid_exact_svm_payload_unknown_optional_instruction"
			if idx := i - 3; idx < len(invalidReasonByIndex) {
				code = invalidReasonByIndex[idx]
			}
			return verifyFail(code, fmt.Sprintf("unexpected instruction %d program %s", i, prog))
		}
	}
	// When the offer pins extra.memo, exactly one matching Memo instruction
	// must be present and its data must equal the pinned value.
	if req.expectedMemo != "" {
		if memoCount != 1 {
			return verifyFail("invalid_exact_svm_payload_memo_count",
				fmt.Sprintf("expected exactly one memo matching extra.memo, found %d", memoCount))
		}
		for i := 3; i < len(ixs); i++ {
			prog, err := programIDForIx(ixs[i], keys)
			if err != nil {
				return err
			}
			if prog.String() == paycore.MemoProgram && string(ixs[i].Data) != req.expectedMemo {
				return verifyFail("invalid_exact_svm_payload_memo_mismatch",
					fmt.Sprintf("memo instruction %d does not match extra.memo", i))
			}
		}
	}
	return nil
}

func verifyComputeLimit(ix solana.CompiledInstruction, keys solana.PublicKeySlice) error {
	prog, err := programIDForIx(ix, keys)
	if err != nil {
		return err
	}
	if prog.String() != computeBudgetProgram || len(ix.Data) != 5 || ix.Data[0] != 2 {
		return verifyFail("invalid_exact_svm_payload_transaction_instructions_compute_limit_instruction",
			"ix[0] is not a ComputeBudget SetComputeUnitLimit")
	}
	return nil
}

func verifyComputePrice(ix solana.CompiledInstruction, keys solana.PublicKeySlice) error {
	prog, err := programIDForIx(ix, keys)
	if err != nil {
		return err
	}
	if prog.String() != computeBudgetProgram || len(ix.Data) != 9 || ix.Data[0] != 3 {
		return verifyFail("invalid_exact_svm_payload_transaction_instructions_compute_price_instruction",
			"ix[1] is not a ComputeBudget SetComputeUnitPrice")
	}
	microLamports := binary.LittleEndian.Uint64(ix.Data[1:9])
	if microLamports > maxComputeUnitPriceMicroLamports {
		return verifyFail("invalid_exact_svm_payload_transaction_instructions_compute_price_instruction_too_high",
			fmt.Sprintf("compute unit price %d exceeds cap %d", microLamports, maxComputeUnitPriceMicroLamports))
	}
	return nil
}

func verifyTransfer(ix solana.CompiledInstruction, keys solana.PublicKeySlice, req transferRequirements) error {
	prog, err := programIDForIx(ix, keys)
	if err != nil {
		return err
	}
	progStr := prog.String()
	if progStr != paycore.TokenProgram && progStr != paycore.Token2022Program {
		return verifyFail("invalid_exact_svm_payload_no_transfer_instruction",
			"ix[2] is not an SPL token transfer")
	}
	// transferChecked: discriminator 12, then u64 amount, then u8 decimals.
	if len(ix.Accounts) < 4 || len(ix.Data) != 10 || ix.Data[0] != 12 {
		return verifyFail("invalid_exact_svm_payload_no_transfer_instruction",
			"ix[2] is not a transferChecked")
	}
	mint, err := keyForIndex(ix.Accounts[1], keys)
	if err != nil {
		return err
	}
	destination, err := keyForIndex(ix.Accounts[2], keys)
	if err != nil {
		return err
	}
	authority, err := keyForIndex(ix.Accounts[3], keys)
	if err != nil {
		return err
	}
	// The fee-payer (operator) must not be the one moving the customer's
	// funds — that would let a malicious server drain the operator.
	if authority.Equals(req.feePayer) {
		return verifyFail("invalid_exact_svm_payload_transaction_fee_payer_transferring_funds",
			"transfer authority is the fee-payer")
	}
	if !mint.Equals(req.mint) {
		return verifyFail("invalid_exact_svm_payload_mint_mismatch",
			fmt.Sprintf("mint mismatch: got %s want %s", mint, req.mint))
	}
	expectedDest, err := solanatx.FindAssociatedTokenAddressWithProgram(req.payTo, req.mint, req.tokenProgram)
	if err != nil {
		return fmt.Errorf("x402: derive recipient ATA: %w", err)
	}
	if !destination.Equals(expectedDest) {
		return verifyFail("invalid_exact_svm_payload_recipient_mismatch",
			fmt.Sprintf("recipient ATA mismatch: got %s want %s", destination, expectedDest))
	}
	amount := binary.LittleEndian.Uint64(ix.Data[1:9])
	if amount != req.amount {
		return verifyFail("invalid_exact_svm_payload_amount_mismatch",
			fmt.Sprintf("amount mismatch: got %d want %d", amount, req.amount))
	}
	return nil
}

func programIDForIx(ix solana.CompiledInstruction, keys solana.PublicKeySlice) (solana.PublicKey, error) {
	return keyForIndex(ix.ProgramIDIndex, keys)
}

func keyForIndex[T ~uint8 | ~uint16](index T, keys solana.PublicKeySlice) (solana.PublicKey, error) {
	i := int(index)
	if i < 0 || i >= len(keys) {
		return solana.PublicKey{}, fmt.Errorf("x402: account index %d out of range (%d keys)", i, len(keys))
	}
	return keys[i], nil
}
