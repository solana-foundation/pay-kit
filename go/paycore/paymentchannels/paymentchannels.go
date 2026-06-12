// Package paymentchannels is the thin, hand-written on-chain glue over the
// codama-generated payment-channels client in
// protocols/programs/paymentchannels. It provides PDA derivation, associated
// token derivation, voucher preimage bytes, and convenience instruction
// builders for the push-mode session flow (open + top_up).
//
// The instruction bytes and PDA derivations built here must stay
// byte-identical across the language SDKs so the on-chain program accepts
// them. In particular the production program id pinned here (GuoKrza...)
// overrides the IDL placeholder baked into the generated package, which is
// not deployed.
package paymentchannels

import (
	"bytes"
	"encoding/binary"
	"fmt"

	ag_binary "github.com/gagliardetto/binary"
	solana "github.com/gagliardetto/solana-go"

	generated "github.com/solana-foundation/pay-kit/go/protocols/programs/paymentchannels"
)

// ProgramID is the canonical payment-channels program id deployed to the
// network. The codama-generated package defaults its ProgramID var to the IDL
// placeholder "CQAyft83tN1w2bRofB5PZ79eVDU2xZUVo43LU1qL4zRg", which is NOT the
// production deployment; every PDA derivation and instruction built here uses
// this value instead.
const ProgramID = "GuoKrzaBiZnW5DvJ3yZVE7xHqbcBvaX9SH6P6Cn9gNvc"

// channelSeed is the channel PDA seed prefix.
const channelSeed = "channel"

// eventAuthoritySeed is the event-authority PDA seed prefix.
const eventAuthoritySeed = "event_authority"

// programPubkey is the parsed production program id used for derivation and
// instruction emission.
var programPubkey = solana.MustPublicKeyFromBase58(ProgramID)

func init() {
	// Pin the generated package's ProgramID to the production deployment so
	// any path that reads generated.ProgramID (e.g. Instruction.ProgramID())
	// observes GuoKrza... rather than the IDL placeholder.
	generated.SetProgramID(programPubkey)
}

// ProgramPubkey returns the parsed production program id.
func ProgramPubkey() solana.PublicKey {
	return programPubkey
}

// SetProgramID overrides the program id used for PDA derivation and instruction
// emission, for SDK consumers targeting a non-mainnet deployment (a devnet or
// localnet program is deployed at a different address). It also pins the
// generated package so Instruction.ProgramID() agrees. The default is the
// canonical mainnet ProgramID; callers on mainnet never need this.
func SetProgramID(id solana.PublicKey) {
	programPubkey = id
	generated.SetProgramID(id)
}

// Distribution is a single payout recipient and its basis-point share.
type Distribution struct {
	// Recipient is the wallet whose associated token account receives this
	// share when settled channel funds are distributed.
	Recipient solana.PublicKey
	// Bps is the recipient's share of distributed funds in basis points
	// (100 bps = 1%).
	Bps uint16
}

// OpenChannelParams carries the inputs required to build an Open instruction.
type OpenChannelParams struct {
	// Payer is the wallet funding the channel deposit; it signs the Open
	// transaction and is a channel PDA seed.
	Payer solana.PublicKey
	// Payee is the counterparty the channel pays out to; a channel PDA seed.
	Payee solana.PublicKey
	// Mint is the SPL token mint the channel escrows (e.g. USDC); a channel
	// PDA seed.
	Mint solana.PublicKey
	// AuthorizedSigner is the key allowed to sign vouchers against this
	// channel; a channel PDA seed.
	AuthorizedSigner solana.PublicKey
	// Salt distinguishes multiple channels sharing the same
	// payer/payee/mint/signer; encoded little-endian as the final channel
	// PDA seed.
	Salt uint64
	// Deposit is the initial escrow amount in token base units
	// (10^-6 USDC per unit for a 6-decimal mint).
	Deposit uint64
	// GracePeriod is the channel close grace period in seconds; the on-chain
	// program rejects zero.
	GracePeriod uint32
	// Recipients is the basis-point payout split applied when settled funds
	// are distributed.
	Recipients []Distribution

	// TokenProgram is the program owning Mint (SPL Token or Token-2022),
	// used to derive the payer and channel associated token accounts.
	TokenProgram solana.PublicKey

	// ProgramID is the payment-channels program targeted by this open. The
	// zero value resolves to the package program id (ProgramPubkey, or the
	// last SetProgramID override).
	ProgramID solana.PublicKey
}

// TopUpParams carries the inputs required to build a TopUp instruction.
type TopUpParams struct {
	// Payer is the wallet whose token account funds the top-up; it signs
	// the TopUp transaction.
	Payer solana.PublicKey
	// Channel is the channel PDA whose escrow receives the deposit.
	Channel solana.PublicKey
	// Mint is the SPL token mint the channel escrows.
	Mint solana.PublicKey
	// Amount is the additional deposit in token base units
	// (10^-6 USDC per unit for a 6-decimal mint).
	Amount uint64
	// TokenProgram is the program owning Mint (SPL Token or Token-2022),
	// used to derive the payer and channel associated token accounts.
	TokenProgram solana.PublicKey

	// ProgramID is the payment-channels program targeted by this top-up. The
	// zero value resolves to the package program id (ProgramPubkey, or the
	// last SetProgramID override).
	ProgramID solana.PublicKey
}

// resolveProgram resolves an optional per-call program id to the package
// program id when unset.
func resolveProgram(programID solana.PublicKey) solana.PublicKey {
	if programID.IsZero() {
		return programPubkey
	}
	return programID
}

// VoucherMessageBytes returns the 48-byte voucher preimage signed by the
// authorized signer: channelId (32) || cumulativeAmount as little-endian u64
// (offset 32) || expiresAt as little-endian i64 (offset 40). This is the exact
// Borsh layout of VoucherArgs.
func VoucherMessageBytes(channelID solana.PublicKey, cumulative uint64, expiresAt int64) ([]byte, error) {
	id := channelID.Bytes()
	if len(id) != 32 {
		return nil, fmt.Errorf("channel id must be exactly 32 bytes, got %d", len(id))
	}
	out := make([]byte, 48)
	copy(out[:32], id)
	binary.LittleEndian.PutUint64(out[32:40], cumulative)
	binary.LittleEndian.PutUint64(out[40:48], uint64(expiresAt))
	return out, nil
}

// FindChannelPDA derives the channel PDA from
// ["channel", payer, payee, mint, authorizedSigner, salt as little-endian u64]
// against the production program id.
func FindChannelPDA(payer, payee, mint, authorizedSigner solana.PublicKey, salt uint64) (solana.PublicKey, uint8, error) {
	return FindChannelPDAForProgram(payer, payee, mint, authorizedSigner, salt, programPubkey)
}

// FindChannelPDAForProgram derives the channel PDA against an explicit program
// id, for callers honoring a per-challenge programId.
func FindChannelPDAForProgram(payer, payee, mint, authorizedSigner solana.PublicKey, salt uint64, programID solana.PublicKey) (solana.PublicKey, uint8, error) {
	saltLE := make([]byte, 8)
	binary.LittleEndian.PutUint64(saltLE, salt)
	addr, bump, err := solana.FindProgramAddress(
		[][]byte{
			[]byte(channelSeed),
			payer.Bytes(),
			payee.Bytes(),
			mint.Bytes(),
			authorizedSigner.Bytes(),
			saltLE,
		},
		resolveProgram(programID),
	)
	if err != nil {
		return solana.PublicKey{}, 0, fmt.Errorf("derive channel pda: %w", err)
	}
	return addr, bump, nil
}

// FindEventAuthorityPDA derives the event-authority PDA from
// ["event_authority"] against the production program id.
func FindEventAuthorityPDA() (solana.PublicKey, uint8, error) {
	return FindEventAuthorityPDAForProgram(programPubkey)
}

// FindEventAuthorityPDAForProgram derives the event-authority PDA against an
// explicit program id, for callers honoring a per-challenge programId.
func FindEventAuthorityPDAForProgram(programID solana.PublicKey) (solana.PublicKey, uint8, error) {
	addr, bump, err := solana.FindProgramAddress(
		[][]byte{[]byte(eventAuthoritySeed)},
		resolveProgram(programID),
	)
	if err != nil {
		return solana.PublicKey{}, 0, fmt.Errorf("derive event-authority pda: %w", err)
	}
	return addr, bump, nil
}

// BuildOpenInstruction derives the channel PDA, payer/channel ATAs, and
// event-authority PDA, then builds the Open instruction with every account set
// in the exact order the on-chain program expects, using the production
// program id.
func BuildOpenInstruction(params OpenChannelParams) (solana.Instruction, error) {
	programID := resolveProgram(params.ProgramID)
	channel, _, err := FindChannelPDAForProgram(params.Payer, params.Payee, params.Mint, params.AuthorizedSigner, params.Salt, programID)
	if err != nil {
		return nil, err
	}
	payerToken, _, err := solana.FindAssociatedTokenAddressWithProgram(params.Payer, params.Mint, params.TokenProgram)
	if err != nil {
		return nil, fmt.Errorf("derive payer token account: %w", err)
	}
	channelToken, _, err := solana.FindAssociatedTokenAddressWithProgram(channel, params.Mint, params.TokenProgram)
	if err != nil {
		return nil, fmt.Errorf("derive channel token account: %w", err)
	}
	eventAuthority, _, err := FindEventAuthorityPDAForProgram(programID)
	if err != nil {
		return nil, err
	}

	recipients := make([]generated.DistributionEntry, 0, len(params.Recipients))
	for _, entry := range params.Recipients {
		recipients = append(recipients, generated.DistributionEntry{
			Recipient: entry.Recipient,
			Bps:       entry.Bps,
		})
	}

	builder := generated.NewOpenInstructionBuilder().
		SetPayerAccount(params.Payer).
		SetPayeeAccount(params.Payee).
		SetMintAccount(params.Mint).
		SetAuthorizedSignerAccount(params.AuthorizedSigner).
		SetChannelAccount(channel).
		SetPayerTokenAccountAccount(payerToken).
		SetChannelTokenAccountAccount(channelToken).
		SetTokenProgramAccount(params.TokenProgram).
		SetSystemProgramAccount(solana.SystemProgramID).
		SetRentAccount(solana.SysVarRentPubkey).
		SetAssociatedTokenProgramAccount(solana.SPLAssociatedTokenAccountProgramID).
		SetEventAuthorityAccount(eventAuthority).
		SetSelfProgramAccount(programID).
		SetOpenArgs(generated.OpenArgs{
			Salt:        params.Salt,
			Deposit:     params.Deposit,
			GracePeriod: params.GracePeriod,
			Recipients:  recipients,
		})

	if _, err := builder.ValidateAndBuild(); err != nil {
		return nil, fmt.Errorf("build open instruction: %w", err)
	}
	return materialize(builder, builder.GetAccounts(), programID)
}

// BuildTopUpInstruction derives the payer/channel ATAs and builds the TopUp
// instruction with every account set in the exact order the on-chain program
// expects, using the production program id.
func BuildTopUpInstruction(params TopUpParams) (solana.Instruction, error) {
	payerToken, _, err := solana.FindAssociatedTokenAddressWithProgram(params.Payer, params.Mint, params.TokenProgram)
	if err != nil {
		return nil, fmt.Errorf("derive payer token account: %w", err)
	}
	channelToken, _, err := solana.FindAssociatedTokenAddressWithProgram(params.Channel, params.Mint, params.TokenProgram)
	if err != nil {
		return nil, fmt.Errorf("derive channel token account: %w", err)
	}

	builder := generated.NewTopUpInstructionBuilder().
		SetPayerAccount(params.Payer).
		SetChannelAccount(params.Channel).
		SetPayerTokenAccountAccount(payerToken).
		SetChannelTokenAccountAccount(channelToken).
		SetMintAccount(params.Mint).
		SetTokenProgramAccount(params.TokenProgram).
		SetTopUpArgs(generated.TopUpArgs{Amount: params.Amount})

	if _, err := builder.ValidateAndBuild(); err != nil {
		return nil, fmt.Errorf("build top_up instruction: %w", err)
	}
	return materialize(builder, builder.GetAccounts(), resolveProgram(params.ProgramID))
}

// materialize borsh-encodes a validated generated instruction implementation
// and returns a solana.GenericInstruction pinned to the production program id.
//
// Two generated-package quirks are handled here:
//   - The instruction implementation (*Open/*TopUp) is encoded directly so its
//     MarshalWithEncoder writes the program's real one-byte discriminator
//     (Open=1, TopUp=3). Wrapping it in the generated Instruction.Data() would
//     prepend a spurious NoTypeID-default byte, corrupting the on-chain data.
//   - The implementation is stored by value inside the generated Instruction,
//     so its Accounts() accessor type-asserts to a pointer-receiver interface
//     and panics; passing the builder's own GetAccounts() avoids that path.
//
// The result's ProgramID() is the resolved per-call program id (the production
// ProgramID by default, a SetProgramID override, or an explicit per-call
// ProgramID for a non-mainnet cluster).
func materialize(impl ag_binary.EncoderDecoder, accounts []*solana.AccountMeta, programID solana.PublicKey) (solana.Instruction, error) {
	buf := new(bytes.Buffer)
	if err := ag_binary.NewBorshEncoder(buf).Encode(impl); err != nil {
		return nil, fmt.Errorf("encode instruction data: %w", err)
	}
	return solana.NewInstruction(programID, accounts, buf.Bytes()), nil
}
