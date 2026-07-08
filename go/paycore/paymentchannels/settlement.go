package paymentchannels

// Server-side settlement instruction builders for the payment-channel close
// paths: the Ed25519 signature-verification precompile, permissionless settle,
// cooperative settle_and_seal, distribute, and permissionless reclaim.
//
// The instruction bytes built here must stay identical across the language
// SDKs; the cross-language harness pins them.

import (
	"encoding/binary"
	"fmt"
	"math"

	solana "github.com/gagliardetto/solana-go"

	generated "github.com/solana-foundation/pay-kit/go/protocols/programs/paymentchannels"
)

// Ed25519ProgramID is the Ed25519 signature-verification native precompile
// program id.
const Ed25519ProgramID = "Ed25519SigVerify111111111111111111111111111"

// ed25519ProgramPubkey is the parsed precompile program id.
var ed25519ProgramPubkey = solana.MustPublicKeyFromBase58(Ed25519ProgramID)

// Ed25519ProgramPubkey returns the parsed Ed25519 precompile program id.
func Ed25519ProgramPubkey() solana.PublicKey {
	return ed25519ProgramPubkey
}

// TreasuryOwner returns the treasury owner baked into the deployed
// (mainnet-build) payment-channels program; distribute checks the treasury ATA
// against ATA(TreasuryOwner, mint, token_program).
func TreasuryOwner() solana.PublicKey {
	return solana.MustPublicKeyFromBase58("Cs2zdfUNonRdRGsiZUQQLdTxzxVvJZmgiX2mpLYKuEqP")
}

// BuildEd25519VerifyInstruction builds an Ed25519 precompile instruction
// verifying signature over message against authorizedSigner, with the
// signature material embedded in the instruction itself (every
// instruction-index field is 0xFFFF, "current instruction"). The data layout
// is the precompile's fixed header (public key at offset 16, signature at 48,
// message at 112) followed by the message bytes.
func BuildEd25519VerifyInstruction(authorizedSigner solana.PublicKey, signature [64]byte, message []byte) (solana.Instruction, error) {
	const publicKeyOffset = 16
	const signatureOffset = publicKeyOffset + 32   // 48
	const messageDataOffset = signatureOffset + 64 // 112
	const currentInstruction = uint16(math.MaxUint16)

	if len(message) > math.MaxUint16 {
		return nil, fmt.Errorf("voucher message too long: %d bytes", len(message))
	}

	data := make([]byte, messageDataOffset+len(message))
	data[0] = 1 // num_signatures
	data[1] = 0 // padding
	binary.LittleEndian.PutUint16(data[2:4], signatureOffset)
	binary.LittleEndian.PutUint16(data[4:6], currentInstruction)
	binary.LittleEndian.PutUint16(data[6:8], publicKeyOffset)
	binary.LittleEndian.PutUint16(data[8:10], currentInstruction)
	binary.LittleEndian.PutUint16(data[10:12], messageDataOffset)
	binary.LittleEndian.PutUint16(data[12:14], uint16(len(message)))
	binary.LittleEndian.PutUint16(data[14:16], currentInstruction)
	copy(data[publicKeyOffset:], authorizedSigner.Bytes())
	copy(data[signatureOffset:], signature[:])
	copy(data[messageDataOffset:], message)

	return solana.NewInstruction(ed25519ProgramPubkey, solana.AccountMetaSlice{}, data), nil
}

// SettleParams carries the inputs required to build the permissionless settle
// instruction sequence.
type SettleParams struct {
	// Channel is the payment-channel address being settled.
	Channel solana.PublicKey

	// AuthorizedSigner is the voucher signing key recorded at open.
	AuthorizedSigner solana.PublicKey

	// Signature is the Ed25519 signature of the voucher.
	Signature [64]byte

	// CumulativeAmount is the settled watermark committed on-chain.
	CumulativeAmount uint64

	// ExpiresAt is the expiry of the settled voucher (Unix seconds).
	ExpiresAt int64

	// ProgramID is the payment-channels program targeted by this settle. The
	// zero value resolves to the package program id.
	ProgramID solana.PublicKey
}

// BuildSettleInstructions builds the permissionless settle sequence: an
// Ed25519 precompile instruction over the canonical voucher message followed
// immediately by the settle instruction that reads it through the instructions
// sysvar.
func BuildSettleInstructions(params SettleParams) ([]solana.Instruction, error) {
	programID := resolveProgram(params.ProgramID)
	message, err := VoucherMessageBytes(params.Channel, params.CumulativeAmount, params.ExpiresAt)
	if err != nil {
		return nil, err
	}
	verify, err := BuildEd25519VerifyInstruction(params.AuthorizedSigner, params.Signature, message)
	if err != nil {
		return nil, err
	}
	builder := generated.NewSettleInstructionBuilder().
		SetChannelAccount(params.Channel).
		SetInstructionsSysvarAccount(solana.SysVarInstructionsPubkey)
	if _, err := builder.ValidateAndBuild(); err != nil {
		return nil, fmt.Errorf("build settle instruction: %w", err)
	}
	settle, err := materialize(builder, builder.GetAccounts(), programID)
	if err != nil {
		return nil, err
	}
	return []solana.Instruction{verify, settle}, nil
}

// SettleAndSealParams carries the inputs required to build the
// settle_and_seal instruction sequence.
type SettleAndSealParams struct {
	// Payee is the signer authorized to settle the channel (the channel
	// payee recorded at open; named "merchant" before the upstream rename).
	Payee solana.PublicKey

	// Channel is the payment-channel address being settled.
	Channel solana.PublicKey

	// AuthorizedSigner is the voucher signing key recorded at open. Only
	// read when Signature is set.
	AuthorizedSigner solana.PublicKey

	// Signature is the Ed25519 signature of the highest accepted voucher.
	// Nil settles without a voucher (hasVoucher = 0, no precompile).
	Signature *[64]byte

	// CumulativeAmount is the settled watermark committed on-chain.
	CumulativeAmount uint64

	// ExpiresAt is the expiry of the settled voucher (Unix seconds).
	ExpiresAt int64

	// ProgramID is the payment-channels program targeted by this settle. The
	// zero value resolves to the package program id.
	ProgramID solana.PublicKey
}

// BuildSettleAndSealInstructions builds the instruction sequence for an
// on-chain settle_and_seal. When a voucher signature is provided, an
// Ed25519 precompile instruction over the canonical 50-byte voucher message
// is placed immediately before the settle_and_seal instruction, which
// references it through the instructions sysvar, and hasVoucher is set to 1.
func BuildSettleAndSealInstructions(params SettleAndSealParams) ([]solana.Instruction, error) {
	programID := resolveProgram(params.ProgramID)
	instructions := make([]solana.Instruction, 0, 2)
	hasVoucher := uint8(0)

	if params.Signature != nil {
		message, err := VoucherMessageBytes(params.Channel, params.CumulativeAmount, params.ExpiresAt)
		if err != nil {
			return nil, err
		}
		verify, err := BuildEd25519VerifyInstruction(params.AuthorizedSigner, *params.Signature, message)
		if err != nil {
			return nil, err
		}
		instructions = append(instructions, verify)
		hasVoucher = 1
	}

	builder := generated.NewSettleAndSealInstructionBuilder().
		SetPayeeAccount(params.Payee).
		SetChannelAccount(params.Channel).
		SetInstructionsSysvarAccount(solana.SysVarInstructionsPubkey).
		SetSettleAndSealArgs(generated.SettleAndSealArgs{
			HasVoucher: hasVoucher,
		})
	if _, err := builder.ValidateAndBuild(); err != nil {
		return nil, fmt.Errorf("build settle_and_seal instruction: %w", err)
	}
	settle, err := materialize(builder, builder.GetAccounts(), programID)
	if err != nil {
		return nil, err
	}
	return append(instructions, settle), nil
}

// DistributeParams carries the inputs required to build a Distribute
// instruction.
type DistributeParams struct {
	// Channel is the settled payment-channel address.
	Channel solana.PublicKey

	// Payer is the original channel payer, refunded the unsettled remainder.
	Payer solana.PublicKey

	// RentPayer is the operator / fee payer recorded at open: it reclaims the
	// channel PDA + escrow ATA rent at seal. It is writable (not a signer)
	// on distribute and must be the operator already in scope (the channel's
	// recorded rentPayer). Not a wire/payload field.
	RentPayer solana.PublicKey

	// Payee is the primary payment recipient.
	Payee solana.PublicKey

	// Treasury is the treasury owner of the program deployment. The zero
	// value resolves to TreasuryOwner().
	Treasury solana.PublicKey

	// Mint is the SPL mint locked in the channel.
	Mint solana.PublicKey

	// Recipients are the basis-point splits distributed at close.
	Recipients []Distribution

	// TokenProgram owning the mint (Token or Token-2022).
	TokenProgram solana.PublicKey

	// ProgramID is the payment-channels program targeted by this distribute.
	// The zero value resolves to the package program id.
	ProgramID solana.PublicKey
}

// BuildDistributeInstruction derives the channel/payer/payee/treasury ATAs
// plus one ATA per split recipient and builds the Distribute instruction:
// the 10 fixed accounts in the exact order the on-chain program expects,
// followed by one writable recipient token account per split.
func BuildDistributeInstruction(params DistributeParams) (solana.Instruction, error) {
	programID := resolveProgram(params.ProgramID)
	if params.RentPayer.IsZero() {
		return nil, fmt.Errorf("rent_payer is required (the operator recorded as the channel rent_payer at open)")
	}
	treasury := params.Treasury
	if treasury.IsZero() {
		treasury = TreasuryOwner()
	}

	channelToken, _, err := solana.FindAssociatedTokenAddressWithProgram(params.Channel, params.Mint, params.TokenProgram)
	if err != nil {
		return nil, fmt.Errorf("derive channel token account: %w", err)
	}
	payerToken, _, err := solana.FindAssociatedTokenAddressWithProgram(params.Payer, params.Mint, params.TokenProgram)
	if err != nil {
		return nil, fmt.Errorf("derive payer token account: %w", err)
	}
	payeeToken, _, err := solana.FindAssociatedTokenAddressWithProgram(params.Payee, params.Mint, params.TokenProgram)
	if err != nil {
		return nil, fmt.Errorf("derive payee token account: %w", err)
	}
	treasuryToken, _, err := solana.FindAssociatedTokenAddressWithProgram(treasury, params.Mint, params.TokenProgram)
	if err != nil {
		return nil, fmt.Errorf("derive treasury token account: %w", err)
	}
	eventAuthority, _, err := FindEventAuthorityPDAForProgram(programID)
	if err != nil {
		return nil, err
	}

	entries := make([]generated.DistributionEntry, 0, len(params.Recipients))
	recipientTokenAccounts := make([]*solana.AccountMeta, 0, len(params.Recipients))
	for _, entry := range params.Recipients {
		recipientToken, _, err := solana.FindAssociatedTokenAddressWithProgram(entry.Recipient, params.Mint, params.TokenProgram)
		if err != nil {
			return nil, fmt.Errorf("derive recipient token account for %s: %w", entry.Recipient, err)
		}
		recipientTokenAccounts = append(recipientTokenAccounts, solana.Meta(recipientToken).WRITE())
		entries = append(entries, generated.DistributionEntry{
			Recipient: entry.Recipient,
			Bps:       entry.Bps,
		})
	}

	builder := generated.NewDistributeInstructionBuilder().
		SetChannelAccount(params.Channel).
		SetPayerAccount(params.Payer).
		SetRentPayerAccount(params.RentPayer).
		SetChannelTokenAccountAccount(channelToken).
		SetPayerTokenAccountAccount(payerToken).
		SetPayeeTokenAccountAccount(payeeToken).
		SetTreasuryTokenAccountAccount(treasuryToken).
		SetMintAccount(params.Mint).
		SetTokenProgramAccount(params.TokenProgram).
		SetEventAuthorityAccount(eventAuthority).
		SetSelfProgramAccount(programID).
		SetDistributeArgs(generated.DistributeArgs{Recipients: entries})

	if _, err := builder.ValidateAndBuild(); err != nil {
		return nil, fmt.Errorf("build distribute instruction: %w", err)
	}
	accounts := make([]*solana.AccountMeta, 0, len(builder.GetAccounts())+len(recipientTokenAccounts))
	accounts = append(accounts, builder.GetAccounts()...)
	accounts = append(accounts, recipientTokenAccounts...)
	return materialize(builder, accounts, programID)
}

// ReclaimParams carries the inputs required to build a Reclaim instruction.
type ReclaimParams struct {
	// Channel is the distributed payment-channel address being reclaimed.
	Channel solana.PublicKey

	// RentPayer is the rent destination recorded as the channel rent_payer at
	// open; it receives the channel PDA lamports when the account closes.
	RentPayer solana.PublicKey

	// ProgramID is the payment-channels program targeted by this reclaim.
	// The zero value resolves to the package program id.
	ProgramID solana.PublicKey
}

// BuildReclaimInstruction builds the permissionless reclaim instruction that
// closes a Distributed channel PDA and returns its rent lamports to the
// recorded rent payer. The program only allows it once the channel status is
// Distributed and clock.slot > open_slot + 1500.
func BuildReclaimInstruction(params ReclaimParams) (solana.Instruction, error) {
	builder := generated.NewReclaimInstructionBuilder().
		SetChannelAccount(params.Channel).
		SetRentPayerAccount(params.RentPayer)
	if _, err := builder.ValidateAndBuild(); err != nil {
		return nil, fmt.Errorf("build reclaim instruction: %w", err)
	}
	return materialize(builder, builder.GetAccounts(), resolveProgram(params.ProgramID))
}
