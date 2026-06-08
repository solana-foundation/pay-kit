// Package paymentchannels is the thin, hand-written on-chain glue over the
// codama-generated payment-channels client in
// protocols/programs/paymentchannels. It provides PDA derivation, associated
// token derivation, voucher preimage bytes, and convenience instruction
// builders for the push-mode session flow (open + top_up).
//
// Everything here mirrors rust/crates/mpp/src/program/payment_channels.rs so
// the wire-format and on-chain paths stay byte-identical across language SDKs.
// In particular the production program id pinned here (GuoKrza...) overrides
// the IDL placeholder baked into the generated package, which is not deployed.
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
// this value instead. Mirrors PAYMENT_CHANNELS_PROGRAM_ID in
// rust/crates/mpp/src/program/payment_channels.rs.
const ProgramID = "GuoKrzaBiZnW5DvJ3yZVE7xHqbcBvaX9SH6P6Cn9gNvc"

// channelSeed is the channel PDA seed prefix. Mirrors CHANNEL_SEED in
// rust/crates/mpp/src/program/payment_channels.rs.
const channelSeed = "channel"

// eventAuthoritySeed is the event-authority PDA seed prefix. Mirrors
// EVENT_AUTHORITY_SEED in rust/crates/mpp/src/program/payment_channels.rs.
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

// ProgramPubkey returns the parsed production program id. Mirrors
// default_program_id() in rust/crates/mpp/src/program/payment_channels.rs.
func ProgramPubkey() solana.PublicKey {
	return programPubkey
}

// Distribution is a single payout recipient and its basis-point share.
// Mirrors the Distribution struct in
// rust/crates/mpp/src/program/payment_channels.rs.
type Distribution struct {
	Recipient solana.PublicKey
	Bps       uint16
}

// OpenChannelParams carries the inputs required to build an Open instruction.
// Mirrors OpenChannelParams in
// rust/crates/mpp/src/program/payment_channels.rs.
type OpenChannelParams struct {
	Payer            solana.PublicKey
	Payee            solana.PublicKey
	Mint             solana.PublicKey
	AuthorizedSigner solana.PublicKey
	Salt             uint64
	Deposit          uint64
	GracePeriod      uint32
	Recipients       []Distribution
	TokenProgram     solana.PublicKey
}

// TopUpParams carries the inputs required to build a TopUp instruction.
// Mirrors the build_top_up_instruction arguments in
// rust/crates/mpp/src/program/payment_channels.rs.
type TopUpParams struct {
	Payer        solana.PublicKey
	Channel      solana.PublicKey
	Mint         solana.PublicKey
	Amount       uint64
	TokenProgram solana.PublicKey
}

// VoucherMessageBytes returns the 48-byte voucher preimage signed by the
// authorized signer: channelId (32) || cumulativeAmount as little-endian u64
// (offset 32) || expiresAt as little-endian i64 (offset 40). This is the exact
// Borsh layout of VoucherArgs. Mirrors voucher_message_bytes in
// rust/crates/mpp/src/program/payment_channels.rs.
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
// against the production program id. Mirrors find_channel_pda in
// rust/crates/mpp/src/program/payment_channels.rs.
func FindChannelPDA(payer, payee, mint, authorizedSigner solana.PublicKey, salt uint64) (solana.PublicKey, uint8, error) {
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
		programPubkey,
	)
	if err != nil {
		return solana.PublicKey{}, 0, fmt.Errorf("derive channel pda: %w", err)
	}
	return addr, bump, nil
}

// FindEventAuthorityPDA derives the event-authority PDA from
// ["event_authority"] against the production program id. Mirrors
// find_event_authority_pda in
// rust/crates/mpp/src/program/payment_channels.rs.
func FindEventAuthorityPDA() (solana.PublicKey, uint8, error) {
	addr, bump, err := solana.FindProgramAddress(
		[][]byte{[]byte(eventAuthoritySeed)},
		programPubkey,
	)
	if err != nil {
		return solana.PublicKey{}, 0, fmt.Errorf("derive event-authority pda: %w", err)
	}
	return addr, bump, nil
}

// BuildOpenInstruction derives the channel PDA, payer/channel ATAs, and
// event-authority PDA, then builds the Open instruction with every account set
// in the exact rust order using the production program id. Mirrors
// build_open_instruction in rust/crates/mpp/src/program/payment_channels.rs.
func BuildOpenInstruction(params OpenChannelParams) (solana.Instruction, error) {
	channel, _, err := FindChannelPDA(params.Payer, params.Payee, params.Mint, params.AuthorizedSigner, params.Salt)
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
	eventAuthority, _, err := FindEventAuthorityPDA()
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
		SetSelfProgramAccount(programPubkey).
		SetOpenArgs(generated.OpenArgs{
			Salt:        params.Salt,
			Deposit:     params.Deposit,
			GracePeriod: params.GracePeriod,
			Recipients:  recipients,
		})

	if _, err := builder.ValidateAndBuild(); err != nil {
		return nil, fmt.Errorf("build open instruction: %w", err)
	}
	return materialize(builder, builder.GetAccounts())
}

// BuildTopUpInstruction derives the payer/channel ATAs and builds the TopUp
// instruction with every account set in the exact rust order using the
// production program id. Mirrors build_top_up_instruction in
// rust/crates/mpp/src/program/payment_channels.rs.
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
	return materialize(builder, builder.GetAccounts())
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
// The result's ProgramID() is always GuoKrza... regardless of any package-level
// state.
func materialize(impl ag_binary.EncoderDecoder, accounts []*solana.AccountMeta) (solana.Instruction, error) {
	buf := new(bytes.Buffer)
	if err := ag_binary.NewBorshEncoder(buf).Encode(impl); err != nil {
		return nil, fmt.Errorf("encode instruction data: %w", err)
	}
	return solana.NewInstruction(programPubkey, accounts, buf.Bytes()), nil
}
