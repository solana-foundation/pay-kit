package x402

import (
	"encoding/binary"
	"errors"
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

// transferRequirements is the subset of the advertised accept entry the
// structural verifier checks the on-wire transaction against.
type transferRequirements struct {
	payTo        solana.PublicKey
	mint         solana.PublicKey
	tokenProgram solana.PublicKey
	amount       uint64
	feePayer     solana.PublicKey // the operator; must not be the transfer authority
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
		return fmt.Errorf("x402: instruction count %d outside [3,6]", len(ixs))
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
	// Optional trailing instructions: memo / lighthouse only.
	for i := 3; i < len(ixs); i++ {
		prog, err := programIDForIx(ixs[i], keys)
		if err != nil {
			return err
		}
		switch prog.String() {
		case paycore.MemoProgram, lighthouseProgram:
			continue
		default:
			return fmt.Errorf("x402: unexpected instruction %d program %s", i, prog)
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
		return errors.New("x402: ix[0] is not a ComputeBudget SetComputeUnitLimit")
	}
	return nil
}

func verifyComputePrice(ix solana.CompiledInstruction, keys solana.PublicKeySlice) error {
	prog, err := programIDForIx(ix, keys)
	if err != nil {
		return err
	}
	if prog.String() != computeBudgetProgram || len(ix.Data) != 9 || ix.Data[0] != 3 {
		return errors.New("x402: ix[1] is not a ComputeBudget SetComputeUnitPrice")
	}
	microLamports := binary.LittleEndian.Uint64(ix.Data[1:9])
	if microLamports > maxComputeUnitPriceMicroLamports {
		return fmt.Errorf("x402: compute unit price %d exceeds cap %d", microLamports, maxComputeUnitPriceMicroLamports)
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
		return errors.New("x402: ix[2] is not an SPL token transfer")
	}
	// transferChecked: discriminator 12, then u64 amount, then u8 decimals.
	if len(ix.Accounts) < 4 || len(ix.Data) != 10 || ix.Data[0] != 12 {
		return errors.New("x402: ix[2] is not a transferChecked")
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
		return errors.New("x402: transfer authority is the fee-payer")
	}
	if !mint.Equals(req.mint) {
		return fmt.Errorf("x402: mint mismatch: got %s want %s", mint, req.mint)
	}
	expectedDest, err := solanatx.FindAssociatedTokenAddressWithProgram(req.payTo, req.mint, req.tokenProgram)
	if err != nil {
		return fmt.Errorf("x402: derive recipient ATA: %w", err)
	}
	if !destination.Equals(expectedDest) {
		return fmt.Errorf("x402: recipient ATA mismatch: got %s want %s", destination, expectedDest)
	}
	amount := binary.LittleEndian.Uint64(ix.Data[1:9])
	if amount != req.amount {
		return fmt.Errorf("x402: amount mismatch: got %d want %d", amount, req.amount)
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
