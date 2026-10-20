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
	ComputeBudgetProgram = "ComputeBudget111111111111111111111111111111"
	LighthouseProgram    = "L2TExMFKdjpN9kozasaurPirfHy9P8sbXoAN1qA3S95"
)

// MaxComputeUnitPriceMicroLamports caps the priority fee a submitted
// transaction may carry. Matches the Rust verifier's bound.
const MaxComputeUnitPriceMicroLamports uint64 = 5_000_000

// VerifyError carries a canonical x402 reason code plus a human
// message. The settle path surfaces Code verbatim as the
// PaymentError.Code, matching the Rust verifier's specific
// invalid_exact_svm_payload_* reasons (verify.rs:235-418) instead of
// collapsing every structural failure to charge_request_mismatch.
type VerifyError struct {
	Code string
	Msg  string
}

func (e *VerifyError) Error() string {
	if e.Msg != "" {
		return "x402: " + e.Msg
	}
	return "x402: " + e.Code
}

// VerifyFail builds a VerifyError with a canonical code and message.
func VerifyFail(code, msg string) error { return &VerifyError{Code: code, Msg: msg} }

// TransferRequirements is the subset of the advertised accept entry the
// structural verifier checks the on-wire transaction against.
type TransferRequirements struct {
	PayTo        solana.PublicKey
	Mint         solana.PublicKey
	TokenProgram solana.PublicKey
	Amount       uint64
	FeePayer     solana.PublicKey // the operator; must not be the transfer authority
	// ExpectedMemo, when non-empty, is the advertised extra.memo. The x402
	// SVM spec requires the verifier to confirm exactly one Memo instruction
	// whose data equals it.
	ExpectedMemo string
}

// maxExactInstructions is the static-layout cap (scheme_exact_svm.md §3.1):
// compute limit, compute price, TransferChecked, up to three Lighthouse or
// Memo instructions, and a final Memo.
const maxExactInstructions = 7

// VerifyExactTransaction runs the x402 "exact" SVM checks against a decoded
// Solana transaction BEFORE the sponsor cosigns or broadcasts it. It is the
// static-layout verification path (scheme_exact_svm.md §3.1) plus the §1
// payment outcome and §2.1 sponsor MUSTs:
//
//  1. instruction count in [3, 7]
//  2. ix[0] = ComputeBudget SetComputeUnitLimit
//  3. ix[1] = ComputeBudget SetComputeUnitPrice, <= cap
//  4. ix[2] = transferChecked of the route mint to ATA(payTo, mint,
//     program) for AT LEAST amount (overpayment tolerated, §1.4), with an
//     authority other than the fee payer
//  5. exactly one transferChecked across the transaction matches (§1.4)
//  6. the fee payer appears in no instruction's accounts and is never
//     invoked as a program (§2.1.1)
//  7. ix[3..5] = Memo or Lighthouse only, ix[6] = Memo only
//  8. when extra.memo is set, exactly one Memo and it matches
//
// It returns a *VerifyError carrying a canonical reason code on the first
// rule it fails.
func VerifyExactTransaction(tx *solana.Transaction, req TransferRequirements) error {
	msg := &tx.Message
	ixs := msg.Instructions
	if len(ixs) < 3 || len(ixs) > maxExactInstructions {
		return VerifyFail("invalid_exact_svm_payload_transaction_instructions_length",
			fmt.Sprintf("instruction count %d outside [3,%d]", len(ixs), maxExactInstructions))
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
	matching, err := countMatchingTransfers(ixs, keys, req)
	if err != nil {
		return err
	}
	if matching != 1 {
		return VerifyFail("invalid_exact_svm_payload_multiple_matching_transfers",
			fmt.Sprintf("expected exactly one matching transferChecked, found %d", matching))
	}
	if err := verifyFeePayerIsolation(ixs, keys, req.FeePayer); err != nil {
		return err
	}
	// Optional trailing instructions: memo / lighthouse only. Wallets inject
	// Lighthouse guard instructions (Phantom up to 3, Solflare 2) so those
	// MUST be allowed in slots 4-6; slot 7 is Memo only. Everything else
	// (System / Token / ATA-create / unknown) is rejected, which keeps a
	// Create-ATA out of the optional slots per spec. Canonical reason codes
	// are positional, matching invalid_reason_by_index (verify.rs:257-274).
	invalidReasonByIndex := []string{
		"invalid_exact_svm_payload_unknown_fourth_instruction",
		"invalid_exact_svm_payload_unknown_fifth_instruction",
		"invalid_exact_svm_payload_unknown_sixth_instruction",
		"invalid_exact_svm_payload_unknown_seventh_instruction",
	}
	memoCount := 0
	for i := 3; i < len(ixs); i++ {
		prog, err := programIDForIx(ixs[i], keys)
		if err != nil {
			return err
		}
		switch {
		case prog.String() == paycore.MemoProgram:
			memoCount++
			continue
		case prog.String() == LighthouseProgram && i < maxExactInstructions-1:
			continue
		default:
			return VerifyFail(invalidReasonByIndex[i-3], fmt.Sprintf("unexpected instruction %d program %s", i, prog))
		}
	}
	// When the offer pins extra.memo, exactly one matching Memo instruction
	// must be present and its data must equal the pinned value.
	if req.ExpectedMemo != "" {
		if memoCount != 1 {
			return VerifyFail("invalid_exact_svm_payload_memo_count",
				fmt.Sprintf("expected exactly one memo matching extra.memo, found %d", memoCount))
		}
		for i := 3; i < len(ixs); i++ {
			prog, err := programIDForIx(ixs[i], keys)
			if err != nil {
				return err
			}
			if prog.String() == paycore.MemoProgram && string(ixs[i].Data) != req.ExpectedMemo {
				return VerifyFail("invalid_exact_svm_payload_memo_mismatch",
					fmt.Sprintf("memo instruction %d does not match extra.memo", i))
			}
		}
	}
	return nil
}

// countMatchingTransfers counts the top-level transferChecked instructions
// that pay the route: correct mint, destination ATA(payTo, mint, program)
// and amount >= required (§1.4). A second match is an ambiguous or double
// payment and is rejected by the caller.
func countMatchingTransfers(ixs []solana.CompiledInstruction, keys solana.PublicKeySlice, req TransferRequirements) (int, error) {
	expectedDest, err := solanatx.FindAssociatedTokenAddressWithProgram(req.PayTo, req.Mint, req.TokenProgram)
	if err != nil {
		return 0, fmt.Errorf("x402: derive recipient ATA: %w", err)
	}
	count := 0
	for _, ix := range ixs {
		prog, err := programIDForIx(ix, keys)
		if err != nil {
			return 0, err
		}
		if !prog.Equals(req.TokenProgram) || len(ix.Accounts) < 4 || len(ix.Data) != 10 || ix.Data[0] != 12 {
			continue
		}
		mint, err := keyForIndex(ix.Accounts[1], keys)
		if err != nil {
			return 0, err
		}
		destination, err := keyForIndex(ix.Accounts[2], keys)
		if err != nil {
			return 0, err
		}
		if mint.Equals(req.Mint) && destination.Equals(expectedDest) && binary.LittleEndian.Uint64(ix.Data[1:9]) >= req.Amount {
			count++
		}
	}
	return count, nil
}

// verifyFeePayerIsolation enforces §2.1.1: the fee payer must not be invoked
// as a program and must not appear in any instruction's accounts. The one
// allowance, receiving as payTo when feePayer == payTo, needs no carve-out
// here: a token payment is received by ATA(payTo), never by payTo itself.
func verifyFeePayerIsolation(ixs []solana.CompiledInstruction, keys solana.PublicKeySlice, feePayer solana.PublicKey) error {
	if feePayer.IsZero() {
		return nil
	}
	for i, ix := range ixs {
		prog, err := programIDForIx(ix, keys)
		if err != nil {
			return err
		}
		if prog.Equals(feePayer) {
			return VerifyFail("invalid_exact_svm_payload_transaction_fee_payer_included_in_instruction_accounts",
				fmt.Sprintf("instruction %d invokes the fee payer as a program", i))
		}
		for _, index := range ix.Accounts {
			account, err := keyForIndex(index, keys)
			if err != nil {
				return err
			}
			if account.Equals(feePayer) {
				return VerifyFail("invalid_exact_svm_payload_transaction_fee_payer_included_in_instruction_accounts",
					fmt.Sprintf("instruction %d references the fee payer in its accounts", i))
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
	if prog.String() != ComputeBudgetProgram || len(ix.Data) != 5 || ix.Data[0] != 2 {
		return VerifyFail("invalid_exact_svm_payload_transaction_instructions_compute_limit_instruction",
			"ix[0] is not a ComputeBudget SetComputeUnitLimit")
	}
	return nil
}

func verifyComputePrice(ix solana.CompiledInstruction, keys solana.PublicKeySlice) error {
	prog, err := programIDForIx(ix, keys)
	if err != nil {
		return err
	}
	if prog.String() != ComputeBudgetProgram || len(ix.Data) != 9 || ix.Data[0] != 3 {
		return VerifyFail("invalid_exact_svm_payload_transaction_instructions_compute_price_instruction",
			"ix[1] is not a ComputeBudget SetComputeUnitPrice")
	}
	microLamports := binary.LittleEndian.Uint64(ix.Data[1:9])
	if microLamports > MaxComputeUnitPriceMicroLamports {
		return VerifyFail("invalid_exact_svm_payload_transaction_instructions_compute_price_instruction_too_high",
			fmt.Sprintf("compute unit price %d exceeds cap %d", microLamports, MaxComputeUnitPriceMicroLamports))
	}
	return nil
}

func verifyTransfer(ix solana.CompiledInstruction, keys solana.PublicKeySlice, req TransferRequirements) error {
	prog, err := programIDForIx(ix, keys)
	if err != nil {
		return err
	}
	progStr := prog.String()
	if progStr != paycore.TokenProgram && progStr != paycore.Token2022Program {
		return VerifyFail("invalid_exact_svm_payload_no_transfer_instruction",
			"ix[2] is not an SPL token transfer")
	}
	// transferChecked: discriminator 12, then u64 amount, then u8 decimals.
	if len(ix.Accounts) < 4 || len(ix.Data) != 10 || ix.Data[0] != 12 {
		return VerifyFail("invalid_exact_svm_payload_no_transfer_instruction",
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
	if authority.Equals(req.FeePayer) {
		return VerifyFail("invalid_exact_svm_payload_transaction_fee_payer_transferring_funds",
			"transfer authority is the fee-payer")
	}
	if !mint.Equals(req.Mint) {
		return VerifyFail("invalid_exact_svm_payload_mint_mismatch",
			fmt.Sprintf("mint mismatch: got %s want %s", mint, req.Mint))
	}
	expectedDest, err := solanatx.FindAssociatedTokenAddressWithProgram(req.PayTo, req.Mint, req.TokenProgram)
	if err != nil {
		return fmt.Errorf("x402: derive recipient ATA: %w", err)
	}
	if !destination.Equals(expectedDest) {
		return VerifyFail("invalid_exact_svm_payload_recipient_mismatch",
			fmt.Sprintf("recipient ATA mismatch: got %s want %s", destination, expectedDest))
	}
	// §1.4: at least the required amount; overpayment is tolerated.
	amount := binary.LittleEndian.Uint64(ix.Data[1:9])
	if amount < req.Amount {
		return VerifyFail("invalid_exact_svm_payload_amount_mismatch",
			fmt.Sprintf("amount mismatch: got %d, want at least %d", amount, req.Amount))
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
