package server

// On-chain verification and settlement for the session intent.
//
// Trust model: when no verifier is installed on SessionConfig (the seam is
// nil), transaction signatures and deposit amounts are trusted as
// provided. NewOpenTxVerifier always
// validates an attached open transaction structurally (decode, bind the
// payload signature, check the open instruction against the challenge,
// re-derive the channel PDA); confirming that the transaction actually landed
// additionally requires an RPC client. NewTopUpTxVerifier is purely RPC-backed
// (the top-up payload carries only a signature, no transaction), so without an
// RPC client the top-up seam stays nil and the new deposit is trusted as
// provided.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math"
	"strconv"
	"strings"

	ag_binary "github.com/gagliardetto/binary"
	solana "github.com/solana-foundation/solana-go/v2"
	"github.com/solana-foundation/solana-go/v2/rpc"

	"github.com/solana-foundation/pay-kit/go/paycore"
	"github.com/solana-foundation/pay-kit/go/paycore/paymentchannels"
	"github.com/solana-foundation/pay-kit/go/paycore/solanatx"
	"github.com/solana-foundation/pay-kit/go/protocols/mpp/intents"
	generated "github.com/solana-foundation/pay-kit/go/protocols/programs/paymentchannels"
)

type boundChannel struct {
	Deposit          uint64
	Payer            string
	AuthorizedSigner string
	Payee            string
	Mint             string
	GracePeriod      uint32
	Salt             uint64
	OpenSlot         uint64
}

func fetchAndValidateChannel(
	ctx context.Context,
	rpcClient solanatx.RPCClient,
	channelID solana.PublicKey,
	expectedMint string,
	expectedPayee string,
	expectedOperator string,
	expectedGracePeriod uint32,
	expectedDistributionHash [32]byte,
	requireFresh bool,
	programID *solana.PublicKey,
	minContextSlot uint64,
) (*generated.Channel, error) {
	program := paymentchannels.ProgramPubkey()
	if programID != nil {
		program = *programID
	}
	opts := &rpc.GetAccountInfoOpts{
		Commitment: rpc.CommitmentConfirmed,
		Encoding:   solana.EncodingBase64,
	}
	opts.MinContextSlot = &minContextSlot
	info, err := rpcClient.GetAccountInfoWithOpts(ctx, channelID, opts)
	if err != nil {
		return nil, fmt.Errorf("channel %s account fetch failed: %w", channelID, err)
	}
	if info == nil || info.Value == nil || info.Value.Data == nil {
		return nil, fmt.Errorf("channel %s account not found on-chain", channelID)
	}
	if !info.Value.Owner.Equals(program) {
		return nil, fmt.Errorf("channel %s is not owned by the payment-channels program %s", channelID, program)
	}
	data := info.Value.Data.GetBinary()
	if len(data) != 256 {
		return nil, fmt.Errorf("channel %s account data has invalid length %d", channelID, len(data))
	}
	channel := new(generated.Channel)
	if err := channel.UnmarshalWithDecoder(ag_binary.NewBorshDecoder(data)); err != nil {
		return nil, fmt.Errorf("channel %s decode failed: %w", channelID, err)
	}
	if channel.Discriminator != 1 {
		return nil, fmt.Errorf("channel %s has invalid discriminator %d", channelID, channel.Discriminator)
	}
	if channel.Version != 1 {
		return nil, fmt.Errorf("channel %s has unsupported version %d", channelID, channel.Version)
	}
	if channel.Status != uint8(generated.ChannelStatus_Open) {
		return nil, fmt.Errorf("channel %s is not open on-chain (status %d)", channelID, channel.Status)
	}
	if channel.Mint.String() != expectedMint {
		return nil, fmt.Errorf("on-chain channel mint %s != expected mint %s", channel.Mint, expectedMint)
	}
	if channel.Payee.String() != expectedPayee {
		return nil, fmt.Errorf("on-chain channel payee %s != expected recipient %s", channel.Payee, expectedPayee)
	}
	if expectedOperator == "" || channel.RentPayer.String() != expectedOperator {
		return nil, fmt.Errorf("on-chain channel rentPayer %s != expected operator %s", channel.RentPayer, expectedOperator)
	}
	if requireFresh && (channel.Settlement.Settled != 0 || channel.Settlement.PayoutWatermark != 0) {
		return nil, fmt.Errorf("channel %s has nonzero settlement watermarks", channelID)
	}
	if channel.GracePeriod != expectedGracePeriod {
		return nil, fmt.Errorf("on-chain channel gracePeriod %d != expected %d", channel.GracePeriod, expectedGracePeriod)
	}
	if channel.DistributionHash != expectedDistributionHash {
		return nil, fmt.Errorf("on-chain channel distributionHash does not match session splits")
	}
	return channel, nil
}

func fetchAndBindChannelAccount(
	ctx context.Context,
	rpcClient solanatx.RPCClient,
	channelID solana.PublicKey,
	expectedMint string,
	expectedPayee string,
	expectedOperator string,
	expectedAuthorizedSigner string,
	expectedGracePeriod uint32,
	expectedDistributionHash [32]byte,
	requireFresh bool,
	programID *solana.PublicKey,
	minContextSlot uint64,
) (boundChannel, error) {
	channel, err := fetchAndValidateChannel(ctx, rpcClient, channelID, expectedMint, expectedPayee, expectedOperator, expectedGracePeriod, expectedDistributionHash, requireFresh, programID, minContextSlot)
	if err != nil {
		return boundChannel{}, err
	}
	if channel.AuthorizedSigner.String() != expectedAuthorizedSigner {
		return boundChannel{}, fmt.Errorf(
			"on-chain channel authorizedSigner %s != expected %s", channel.AuthorizedSigner, expectedAuthorizedSigner)
	}
	program := paymentchannels.ProgramPubkey()
	if programID != nil {
		program = *programID
	}
	derivedChannel, _, err := paymentchannels.FindChannelPDAForProgram(
		channel.Payer,
		channel.Payee,
		channel.Mint,
		channel.AuthorizedSigner,
		channel.Salt,
		channel.OpenSlot,
		program,
	)
	if err != nil {
		return boundChannel{}, fmt.Errorf("derive channel PDA from on-chain state: %w", err)
	}
	if !derivedChannel.Equals(channelID) {
		return boundChannel{}, fmt.Errorf("channel account %s != PDA derived from authoritative state %s", channelID, derivedChannel)
	}
	return boundChannel{
		Deposit:          channel.Deposit,
		Payer:            channel.Payer.String(),
		AuthorizedSigner: channel.AuthorizedSigner.String(),
		Payee:            channel.Payee.String(),
		Mint:             channel.Mint.String(),
		GracePeriod:      channel.GracePeriod,
		Salt:             channel.Salt,
		OpenSlot:         channel.OpenSlot,
	}, nil
}

func sessionDistributionHash(splits []Split) [32]byte {
	hasher := sha256.New()
	var count [4]byte
	binary.LittleEndian.PutUint32(count[:], uint32(len(splits)))
	_, _ = hasher.Write(count[:])
	for _, split := range splits {
		_, _ = hasher.Write(split.Recipient.Bytes())
		var bps [2]byte
		binary.LittleEndian.PutUint16(bps[:], split.BPS)
		_, _ = hasher.Write(bps[:])
	}
	var result [32]byte
	copy(result[:], hasher.Sum(nil))
	return result
}

func expectedSessionGracePeriod(config SessionConfig) uint32 {
	if config.SettlementWindowSeconds > 0 && config.SettlementWindowSeconds <= int64(^uint32(0)) {
		return uint32(config.SettlementWindowSeconds)
	}
	return 900
}

// openInstructionDiscriminator is the payment-channel open instruction
// discriminator (single-byte Anchor-numeric form, not the 8-byte sha256
// convention). Matches OPEN_DISCRIMINATOR in the vendored Codama clients.
const (
	openInstructionDiscriminator  = 1
	topUpInstructionDiscriminator = 3
)

// VerifyOpenTxExpected carries the challenge-side values a client-submitted
// open transaction is validated against.
type VerifyOpenTxExpected struct {
	// AuthorizedSigner is the voucher signing key claimed by the open payload
	// (base58); the transaction's authorizedSigner account must match it.
	AuthorizedSigner string

	// Currency is the challenge currency (symbol or mint address).
	Currency string

	// TokenProgram is the authoritative token program committed for the
	// session. Empty resolves the known currency default; arbitrary mint
	// addresses must provide the resolved mint owner.
	TokenProgram string

	// MaxCap is the maximum deposit the server accepts (base units).
	MaxCap uint64

	// Mint optionally overrides the SPL mint; empty resolves it from
	// Currency/Network.
	Mint string

	// Network is the Solana network used for mint resolution.
	Network string

	// Operator is the expected rentPayer: the operator / fee-payer pubkey
	// (base58) that funds the channel rent and co-signs open as fee payer
	// while gasless. It is REQUIRED. The open instruction's rentPayer account
	// (slot 1) must equal it; the rentPayer slot is a security boundary that
	// callers must always prove, so an empty Operator is rejected.
	Operator string

	// ProgramID optionally overrides the payment-channels program id; nil
	// defaults to the canonical program.
	ProgramID *solana.PublicKey

	// Recipient is the primary payment recipient (challenge recipient,
	// base58); the transaction's payee account must match it.
	Recipient string

	// Splits is the ordered payout distribution committed by the challenge.
	// The open instruction must carry the same recipients and basis points.
	Splits []Split

	// GracePeriod is the challenge's expected close grace period. Zero leaves
	// this legacy field unconstrained; configured sessions always populate it.
	GracePeriod uint32

	// RecentSlot is the challenge incarnation when known. An attached open's
	// openSlot must match it.
	RecentSlot *uint64
}

// VerifyOpenTxResult carries the channel facts extracted from a verified open
// transaction.
type VerifyOpenTxResult struct {
	// ChannelID is the channel PDA derived from the open instruction (base58).
	ChannelID string

	// Deposit locked by the open, in base units.
	Deposit uint64

	// GracePeriod is the close grace period in seconds.
	GracePeriod uint32

	// OpenSlot is the slot the open instruction locks into the channel; a
	// channel PDA seed, needed to re-derive the address and drive reclaim.
	OpenSlot uint64

	// Payer is the channel payer (open account 0, base58): the deposit funder
	// and the distribute refund destination (the program enforces it equals
	// channel.payer).
	Payer string

	// Salt is the channel-derivation salt.
	Salt uint64
}

// VerifyOpenTx decodes and validates a client-submitted payment-channel open
// transaction against the session challenge.
//
// Both legacy and v0 transaction encodings are accepted (clients across the
// language SDKs emit either), but a v0 transaction that uses address lookup
// tables is rejected: the account checks below read the static account keys,
// so an ALT could hide the real accounts behind the fee-payer co-sign guard.
// The embedded open
// instruction must target the configured payment-channels program, the payee
// must equal the challenge recipient, the mint must match the challenge
// currency/network, the authorizedSigner must match the payload, the deposit
// must be positive and within the cap, and the channel account must equal
// the PDA re-derived from the instruction's own seeds.
//
// When the payload carries a non-placeholder signature, it must equal the
// transaction's own fee-payer signature: a client must not be able to pair
// an unrelated (but confirmed) signature with different transaction bytes.
// If rpcClient is non-nil, that bound signature is additionally confirmed
// on-chain; nil skips the liveness check (structural validation only).
func VerifyOpenTx(ctx context.Context, expected VerifyOpenTxExpected, payload *intents.OpenPayload, rpcClient solanatx.RPCClient) (VerifyOpenTxResult, error) {
	return verifyOpenTx(ctx, expected, payload, rpcClient, false)
}

// verifyOpenTx permits an unsigned fee-payer slot only for the private
// server-submit pre-broadcast path. Every public verification path requires
// a fully signed transaction bound to payload.Signature.
func verifyOpenTx(ctx context.Context, expected VerifyOpenTxExpected, payload *intents.OpenPayload, rpcClient solanatx.RPCClient, allowUnsignedFeePayer bool) (VerifyOpenTxResult, error) {
	if expected.Operator == "" {
		return VerifyOpenTxResult{}, fmt.Errorf("verify open: expected operator (rentPayer) is required")
	}
	if payload.Transaction == nil || *payload.Transaction == "" {
		return VerifyOpenTxResult{}, fmt.Errorf("openPayload.transaction is required for push-mode open verification")
	}

	tx, err := solanatx.DecodeTransactionBase64(*payload.Transaction)
	if err != nil {
		return VerifyOpenTxResult{}, fmt.Errorf("decode open transaction: %w", err)
	}

	// Reject v0 transactions that use address lookup tables. The fee-payer
	// co-sign guard validates accounts (payee, rentPayer, mint,
	// authorizedSigner, channel) from the STATIC account keys; a versioned
	// transaction could resolve those slots through an ALT and hide the real
	// accounts from this check. Static-key-only transactions keep the guard
	// authoritative. Mirrors the charge-path guard in
	// VerifyChargeTransactionPreBroadcast.
	if len(tx.Message.AddressTableLookups) > 0 {
		return VerifyOpenTxResult{}, fmt.Errorf("open transaction uses address lookup tables, which are not supported")
	}
	if len(tx.Message.Instructions) != 1 {
		return VerifyOpenTxResult{}, fmt.Errorf("open transaction must contain exactly one instruction, found %d", len(tx.Message.Instructions))
	}

	// Bind every required signature to the exact message before trusting the
	// transaction. Server-submit may leave only the fee-payer slot empty; the
	// payer's client signature must still be valid.
	boundSignature := payload.Signature != "" && !isPlaceholderSignature(payload.Signature)
	message, err := tx.Message.MarshalBinary()
	if err != nil {
		return VerifyOpenTxResult{}, fmt.Errorf("encode open transaction message: %w", err)
	}
	signers := tx.Message.Signers()
	if len(signers) == 0 || len(tx.Signatures) < len(signers) {
		return VerifyOpenTxResult{}, fmt.Errorf("open transaction is missing required signatures")
	}
	for i, signer := range signers {
		if tx.Signatures[i].IsZero() {
			if allowUnsignedFeePayer && i == 0 {
				continue
			}
			return VerifyOpenTxResult{}, fmt.Errorf("open transaction has no signature for required signer %s", signer)
		}
		if !tx.Signatures[i].Verify(signer, message) {
			return VerifyOpenTxResult{}, fmt.Errorf("open transaction has an invalid signature for required signer %s", signer)
		}
	}
	if !allowUnsignedFeePayer {
		if !boundSignature {
			return VerifyOpenTxResult{}, fmt.Errorf("openPayload.signature must be a real transaction signature")
		}
		if txSignature := tx.Signatures[0].String(); txSignature != payload.Signature {
			return VerifyOpenTxResult{}, fmt.Errorf("openPayload.signature %s != transaction signature %s", payload.Signature, txSignature)
		}
	}

	programID := paymentchannels.ProgramPubkey()
	if expected.ProgramID != nil {
		programID = *expected.ProgramID
	}
	expectedMint := expected.Mint
	if expectedMint == "" {
		expectedMint = paycore.ResolveMint(expected.Currency, expected.Network)
	}
	if expectedMint == "" {
		return VerifyOpenTxResult{}, fmt.Errorf("could not resolve mint from currency %q", expected.Currency)
	}
	expectedTokenProgram, err := resolveSessionTokenProgram(expected.TokenProgram, expected.Currency, expected.Network)
	if err != nil {
		return VerifyOpenTxResult{}, err
	}

	accountKeys := tx.Message.AccountKeys
	accountAt := func(indices []uint16, slot int, label string) (solana.PublicKey, error) {
		if slot >= len(indices) || int(indices[slot]) >= len(accountKeys) {
			return solana.PublicKey{}, fmt.Errorf("open instruction is missing the %s account at slot %d", label, slot)
		}
		return accountKeys[indices[slot]], nil
	}

	openIx := &tx.Message.Instructions[0]
	if int(openIx.ProgramIDIndex) >= len(accountKeys) || !accountKeys[openIx.ProgramIDIndex].Equals(programID) {
		return VerifyOpenTxResult{}, fmt.Errorf("no payment-channels open instruction found")
	}
	if len(openIx.Data) < 1 || openIx.Data[0] != openInstructionDiscriminator {
		return VerifyOpenTxResult{}, fmt.Errorf("no payment-channels open instruction found")
	}
	if len(tx.Message.Instructions) != 1 {
		return VerifyOpenTxResult{}, fmt.Errorf("open transaction must contain exactly one instruction")
	}

	// Open instruction account layout (matches the generated client):
	// 0 payer, 1 rentPayer, 2 payee, 3 mint, 4 authorizedSigner, 5 channel,
	// 6 payerTokenAccount, 7 channelTokenAccount, 8 tokenProgram, ...
	// rentPayer (slot 1) is pinned to the operator / fee payer.
	if len(openIx.Accounts) < 8 {
		return VerifyOpenTxResult{}, fmt.Errorf("open instruction has too few accounts (%d)", len(openIx.Accounts))
	}
	// Instruction data:
	// [discriminator u8][salt u64][deposit u64][grace u32][openSlot u64][recipients].
	if len(openIx.Data) < 1+8+8+4+8+4 {
		return VerifyOpenTxResult{}, fmt.Errorf("open instruction data too short (%d bytes)", len(openIx.Data))
	}
	if len(openIx.Accounts) < 9 {
		return VerifyOpenTxResult{}, fmt.Errorf("open instruction has too few accounts (%d)", len(openIx.Accounts))
	}
	payer, err := accountAt(openIx.Accounts, 0, "payer")
	if err != nil {
		return VerifyOpenTxResult{}, err
	}
	rentPayer, err := accountAt(openIx.Accounts, 1, "rentPayer")
	if err != nil {
		return VerifyOpenTxResult{}, err
	}
	payee, err := accountAt(openIx.Accounts, 2, "payee")
	if err != nil {
		return VerifyOpenTxResult{}, err
	}
	mint, err := accountAt(openIx.Accounts, 3, "mint")
	if err != nil {
		return VerifyOpenTxResult{}, err
	}
	authorizedSigner, err := accountAt(openIx.Accounts, 4, "authorizedSigner")
	if err != nil {
		return VerifyOpenTxResult{}, err
	}
	channel, err := accountAt(openIx.Accounts, 5, "channel")
	if err != nil {
		return VerifyOpenTxResult{}, err
	}
	tokenProgram, err := accountAt(openIx.Accounts, 8, "tokenProgram")
	if err != nil {
		return VerifyOpenTxResult{}, err
	}

	if payee.String() != expected.Recipient {
		return VerifyOpenTxResult{}, fmt.Errorf("open payee %s != expected recipient %s", payee, expected.Recipient)
	}
	if mint.String() != expectedMint {
		return VerifyOpenTxResult{}, fmt.Errorf("open mint %s != expected mint %s", mint, expectedMint)
	}
	if !tokenProgram.Equals(expectedTokenProgram) {
		return VerifyOpenTxResult{}, fmt.Errorf("open token program %s != expected token program %s", tokenProgram, expectedTokenProgram)
	}
	if authorizedSigner.String() != expected.AuthorizedSigner {
		return VerifyOpenTxResult{}, fmt.Errorf("open authorizedSigner %s != expected %s", authorizedSigner, expected.AuthorizedSigner)
	}
	// rentPayer (slot 1) is pinned to the operator / fee payer. The rentPayer
	// slot is a security boundary, so this check is mandatory (an empty
	// expected operator is rejected above).
	if rentPayer.String() != expected.Operator {
		return VerifyOpenTxResult{}, fmt.Errorf("open rentPayer %s != expected operator %s", rentPayer, expected.Operator)
	}

	var openArgs generated.OpenArgs
	if err := ag_binary.NewBorshDecoder(openIx.Data[1:]).Decode(&openArgs); err != nil {
		return VerifyOpenTxResult{}, fmt.Errorf("decode open instruction args: %w", err)
	}
	salt := openArgs.Salt
	deposit := openArgs.Deposit
	gracePeriod := openArgs.GracePeriod
	openSlot := openArgs.OpenSlot
	if len(openArgs.Recipients) != len(expected.Splits) {
		return VerifyOpenTxResult{}, fmt.Errorf("open recipients length %d != expected splits length %d", len(openArgs.Recipients), len(expected.Splits))
	}
	for i, recipient := range openArgs.Recipients {
		expectedSplit := expected.Splits[i]
		if !recipient.Recipient.Equals(expectedSplit.Recipient) || recipient.Bps != expectedSplit.BPS {
			return VerifyOpenTxResult{}, fmt.Errorf("open recipient[%d] does not match expected split", i)
		}
	}
	if expected.GracePeriod != 0 && openArgs.GracePeriod != expected.GracePeriod {
		return VerifyOpenTxResult{}, fmt.Errorf("open gracePeriod %d != expected %d", openArgs.GracePeriod, expected.GracePeriod)
	}

	if deposit == 0 {
		return VerifyOpenTxResult{}, fmt.Errorf("open deposit must be greater than zero")
	}
	if deposit > expected.MaxCap {
		return VerifyOpenTxResult{}, fmt.Errorf("open deposit %d exceeds max cap %d", deposit, expected.MaxCap)
	}

	// Re-derive the channel PDA from the instruction's own seeds.
	derivedChannel, _, err := paymentchannels.FindChannelPDAForProgram(payer, payee, mint, authorizedSigner, salt, openSlot, programID)
	if err != nil {
		return VerifyOpenTxResult{}, err
	}
	if !derivedChannel.Equals(channel) {
		return VerifyOpenTxResult{}, fmt.Errorf("open channel PDA %s != derived %s", channel, derivedChannel)
	}
	if payload.ChannelID != nil && *payload.ChannelID != channel.String() {
		return VerifyOpenTxResult{}, fmt.Errorf("openPayload.channelId %s != transaction channel %s", *payload.ChannelID, channel)
	}
	if payload.RecentSlot != nil && *payload.RecentSlot != openSlot {
		return VerifyOpenTxResult{}, fmt.Errorf("openPayload.recentSlot %d != transaction openSlot %d", *payload.RecentSlot, openSlot)
	}
	if expected.RecentSlot != nil && *expected.RecentSlot != openSlot {
		return VerifyOpenTxResult{}, fmt.Errorf("transaction openSlot %d != challenge recentSlot %d", openSlot, *expected.RecentSlot)
	}

	// Rebuild the canonical instruction from the verified values. This rejects
	// trailing/malformed Borsh data and pins every account in the fixed layout,
	// including both token accounts, sysvars, event authority, and self-program.
	// Use the token program already read from account 8 and verified against the
	// expected program above, so Token-2022 mints rebuild against their real
	// program rather than the currency default.
	canonical, err := paymentchannels.BuildOpenInstruction(paymentchannels.OpenChannelParams{
		Payer:            payer,
		RentPayer:        rentPayer,
		Payee:            payee,
		Mint:             mint,
		AuthorizedSigner: authorizedSigner,
		Salt:             salt,
		OpenSlot:         openSlot,
		Deposit:          deposit,
		GracePeriod:      gracePeriod,
		Recipients:       openSplits(openArgs.Recipients),
		TokenProgram:     tokenProgram,
		ProgramID:        programID,
	})
	if err != nil {
		return VerifyOpenTxResult{}, fmt.Errorf("build canonical open instruction: %w", err)
	}
	canonicalData, err := canonical.Data()
	if err != nil {
		return VerifyOpenTxResult{}, fmt.Errorf("encode canonical open instruction: %w", err)
	}
	if !bytes.Equal(openIx.Data, canonicalData) {
		return VerifyOpenTxResult{}, fmt.Errorf("open instruction data is not canonical")
	}
	canonicalAccounts := canonical.Accounts()
	if len(canonicalAccounts) != len(openIx.Accounts) {
		return VerifyOpenTxResult{}, fmt.Errorf("open instruction account count %d != canonical count %d", len(openIx.Accounts), len(canonicalAccounts))
	}
	for i, meta := range canonicalAccounts {
		if int(openIx.Accounts[i]) >= len(accountKeys) || !accountKeys[openIx.Accounts[i]].Equals(meta.PublicKey) {
			return VerifyOpenTxResult{}, fmt.Errorf("open instruction account[%d] does not match canonical account %s", i, meta.PublicKey)
		}
	}

	// Optional liveness check: only when the caller provides an RPC client
	// and the client already populated the transaction signature.
	if rpcClient != nil && boundSignature {
		if err := confirmTransactionSignature(ctx, rpcClient, payload.Signature, "open"); err != nil {
			return VerifyOpenTxResult{}, err
		}
	}

	return VerifyOpenTxResult{
		ChannelID:   channel.String(),
		Deposit:     deposit,
		GracePeriod: gracePeriod,
		OpenSlot:    openSlot,
		Payer:       payer.String(),
		Salt:        salt,
	}, nil
}

// NewOpenTxVerifier returns the on-chain open verifier to install on
// SessionConfig.VerifyOpenTx. When the open payload carries a transaction,
// it is structurally validated against the challenge via VerifyOpenTx (with
// an on-chain liveness check when rpcClient is non-nil). When the payload
// carries only a confirmation signature, rpcClient is required and the
// signature is confirmed on-chain via getSignatureStatuses.
func NewOpenTxVerifier(config SessionConfig, rpcClient solanatx.RPCClient) SessionTxVerifier[intents.OpenPayload] {
	return func(ctx context.Context, payload *intents.OpenPayload) (string, error) {
		if payload.Transaction != nil && *payload.Transaction != "" {
			expected := VerifyOpenTxExpected{
				AuthorizedSigner: payload.AuthorizedSigner,
				Currency:         config.Currency,
				TokenProgram:     config.TokenProgram,
				MaxCap:           config.MaxCap,
				Network:          config.Network,
				Operator:         config.Operator,
				ProgramID:        config.ProgramID,
				Recipient:        config.Recipient,
				Splits:           config.Splits,
				GracePeriod:      expectedSessionGracePeriod(config),
			}
			result, err := VerifyOpenTx(ctx, expected, payload, rpcClient)
			return result.Payer, err
		}
		if rpcClient == nil {
			return "", fmt.Errorf("open verification requires a transaction or an RPC client")
		}
		expected := VerifyOpenTxExpected{
			AuthorizedSigner: payload.AuthorizedSigner,
			Currency:         config.Currency,
			TokenProgram:     config.TokenProgram,
			MaxCap:           config.MaxCap,
			Network:          config.Network,
			Operator:         config.Operator,
			ProgramID:        config.ProgramID,
			Recipient:        config.Recipient,
			Splits:           config.Splits,
			GracePeriod:      expectedSessionGracePeriod(config),
		}
		result, _, err := verifySignatureOnlyOpen(ctx, expected, payload, rpcClient)
		return result.Payer, err
	}
}

// NewOpenStateTxVerifier returns the authoritative open verifier used by new
// SessionServer instances. Every payment-channel open must have a real,
// wire-bound signature that is confirmed on-chain before the current channel
// account is read at the confirmed slot; the returned facts come from that
// account rather than from transaction bytes.
func NewOpenStateTxVerifier(config SessionConfig, rpcClient solanatx.RPCClient) SessionOpenStateTxVerifier {
	return func(ctx context.Context, payload *intents.OpenPayload) (VerifyOpenTxResult, error) {
		if payload == nil {
			return VerifyOpenTxResult{}, fmt.Errorf("open state verification requires a payload")
		}
		if rpcClient == nil {
			return VerifyOpenTxResult{}, fmt.Errorf("authoritative open verification requires an RPC client to confirm and bind the channel")
		}

		expected := VerifyOpenTxExpected{
			AuthorizedSigner: payload.AuthorizedSigner,
			Currency:         config.Currency,
			MaxCap:           config.MaxCap,
			Network:          config.Network,
			Operator:         config.Operator,
			ProgramID:        config.ProgramID,
			Recipient:        config.Recipient,
			Splits:           config.Splits,
			GracePeriod:      expectedSessionGracePeriod(config),
		}

		var (
			channelID solana.PublicKey
			verified  *VerifyOpenTxResult
		)
		if payload.Transaction != nil && *payload.Transaction != "" {
			if isPlaceholderSignature(payload.Signature) {
				return VerifyOpenTxResult{}, fmt.Errorf(
					"authoritative open verification requires a real wire-bound confirmed signature; placeholder signatures are accepted only by NewOpenTxVerifier")
			}
			// VerifyOpenTx is deliberately structural here. It binds the real
			// payload signature to the transaction; the status lookup below is
			// the separate confirmation gate for the state-aware path.
			decoded, err := VerifyOpenTx(ctx, expected, payload, nil)
			if err != nil {
				return VerifyOpenTxResult{}, err
			}
			verified = &decoded
			slot, err := confirmedTransactionSlot(ctx, rpcClient, payload.Signature, "open")
			if err != nil {
				return VerifyOpenTxResult{}, err
			}
			channelID, err = solana.PublicKeyFromBase58(decoded.ChannelID)
			if err != nil {
				return VerifyOpenTxResult{}, fmt.Errorf("invalid verified channelId %q: %w", decoded.ChannelID, err)
			}
			bound, err := bindConfirmedOpenChannel(ctx, rpcClient, config, payload, channelID, slot, true)
			if err != nil {
				return VerifyOpenTxResult{}, err
			}
			if err := validateBoundOpenChannel(bound, verified, config.MaxCap); err != nil {
				return VerifyOpenTxResult{}, err
			}
			if err := validateAssertedOpenDeposit(payload, bound.Deposit); err != nil {
				return VerifyOpenTxResult{}, err
			}
			return VerifyOpenTxResult{
				ChannelID: channelID.String(), Deposit: bound.Deposit, OpenSlot: bound.OpenSlot,
				Payer: bound.Payer, Salt: bound.Salt, GracePeriod: bound.GracePeriod,
			}, nil
		}

		if isPlaceholderSignature(payload.Signature) {
			return VerifyOpenTxResult{}, fmt.Errorf(
				"authoritative open verification requires a real confirmed signature; placeholder signatures are accepted only by NewOpenTxVerifier")
		}
		if payload.Mode == intents.SessionModePush && payload.RecentSlot == nil {
			return VerifyOpenTxResult{}, fmt.Errorf("signature-only push open requires recentSlot")
		}
		if payload.ChannelID == nil || *payload.ChannelID == "" {
			return VerifyOpenTxResult{}, fmt.Errorf("signature-only open requires channelId")
		}
		decoded, slot, err := verifySignatureOnlyOpen(ctx, expected, payload, rpcClient)
		if err != nil {
			return VerifyOpenTxResult{}, err
		}
		verified = &decoded
		channelID, err = solana.PublicKeyFromBase58(verified.ChannelID)
		if err != nil {
			return VerifyOpenTxResult{}, fmt.Errorf("invalid verified channelId %q: %w", verified.ChannelID, err)
		}
		bound, err := bindConfirmedOpenChannel(ctx, rpcClient, config, payload, channelID, slot, true)
		if err != nil {
			return VerifyOpenTxResult{}, err
		}
		if err := validateBoundOpenChannel(bound, verified, config.MaxCap); err != nil {
			return VerifyOpenTxResult{}, err
		}
		if err := validateAssertedOpenDeposit(payload, bound.Deposit); err != nil {
			return VerifyOpenTxResult{}, err
		}
		return VerifyOpenTxResult{
			ChannelID: channelID.String(), Deposit: bound.Deposit, OpenSlot: bound.OpenSlot,
			Payer: bound.Payer, Salt: bound.Salt, GracePeriod: bound.GracePeriod,
		}, nil
	}
}

// verifySignatureOnlyOpen fetches the transaction named by a compact open's
// signature and sends that exact wire transaction through VerifyOpenTx. A
// status lookup alone is insufficient: it can confirm an unrelated
// transaction before the channel account is read separately.
func verifySignatureOnlyOpen(
	ctx context.Context,
	expected VerifyOpenTxExpected,
	payload *intents.OpenPayload,
	rpcClient solanatx.RPCClient,
) (VerifyOpenTxResult, uint64, error) {
	if rpcClient == nil {
		return VerifyOpenTxResult{}, 0, fmt.Errorf("signature-only open verification requires an RPC client")
	}
	if payload == nil {
		return VerifyOpenTxResult{}, 0, fmt.Errorf("signature-only open verification requires a payload")
	}
	if isPlaceholderSignature(payload.Signature) {
		return VerifyOpenTxResult{}, 0, fmt.Errorf("signature-only open requires a real confirmed signature")
	}
	if payload.ChannelID == nil || *payload.ChannelID == "" {
		return VerifyOpenTxResult{}, 0, fmt.Errorf("signature-only open requires channelId")
	}

	confirmedSlot, err := confirmedTransactionSlot(ctx, rpcClient, payload.Signature, "open")
	if err != nil {
		return VerifyOpenTxResult{}, 0, err
	}
	parsedSignature, err := solana.SignatureFromBase58(payload.Signature)
	if err != nil {
		return VerifyOpenTxResult{}, 0, fmt.Errorf("invalid open tx signature %q: %w", payload.Signature, err)
	}
	maxSupportedTransactionVersion := uint64(0)
	result, err := rpcClient.GetTransaction(ctx, parsedSignature, &rpc.GetTransactionOpts{
		Commitment:                     rpc.CommitmentConfirmed,
		Encoding:                       solana.EncodingBase64,
		MaxSupportedTransactionVersion: &maxSupportedTransactionVersion,
	})
	if err != nil {
		return VerifyOpenTxResult{}, 0, fmt.Errorf("fetch confirmed open transaction: %w", err)
	}
	if result == nil || result.Transaction == nil {
		return VerifyOpenTxResult{}, 0, fmt.Errorf("confirmed open transaction %q is missing", payload.Signature)
	}
	tx, err := result.Transaction.GetTransaction()
	if err != nil {
		return VerifyOpenTxResult{}, 0, fmt.Errorf("decode confirmed open transaction: %w", err)
	}
	if tx == nil {
		return VerifyOpenTxResult{}, 0, fmt.Errorf("confirmed open transaction %q decoded to nil", payload.Signature)
	}
	if len(tx.Signatures) == 0 || tx.Signatures[0] != parsedSignature {
		return VerifyOpenTxResult{}, 0, fmt.Errorf("confirmed open transaction fee-payer signature does not match payload signature")
	}
	wire, err := solanatx.EncodeTransactionBase64(tx)
	if err != nil {
		return VerifyOpenTxResult{}, 0, fmt.Errorf("encode confirmed open transaction: %w", err)
	}
	boundPayload := *payload
	boundPayload.Transaction = &wire
	verified, err := VerifyOpenTx(ctx, expected, &boundPayload, nil)
	if err != nil {
		return VerifyOpenTxResult{}, 0, fmt.Errorf("verify confirmed open transaction: %w", err)
	}
	return verified, confirmedSlot, nil
}

func bindConfirmedOpenChannel(
	ctx context.Context,
	rpcClient solanatx.RPCClient,
	config SessionConfig,
	payload *intents.OpenPayload,
	channelID solana.PublicKey,
	minContextSlot uint64,
	requireFresh bool,
) (boundChannel, error) {
	mint := paycore.ResolveMint(config.Currency, config.Network)
	if mint == "" {
		return boundChannel{}, fmt.Errorf("payment-channel open requires an SPL token, got currency %q", config.Currency)
	}
	return fetchAndBindChannelAccount(
		ctx, rpcClient, channelID, mint, config.Recipient, config.Operator,
		payload.AuthorizedSigner, expectedSessionGracePeriod(config), sessionDistributionHash(config.Splits), requireFresh,
		config.ProgramID, minContextSlot,
	)
}

func validateBoundOpenChannel(bound boundChannel, verified *VerifyOpenTxResult, maxCap uint64) error {
	if bound.Deposit == 0 {
		return fmt.Errorf("on-chain open channel deposit must be greater than zero")
	}
	if bound.Deposit > maxCap {
		return fmt.Errorf("on-chain open channel deposit %d exceeds max cap %d", bound.Deposit, maxCap)
	}
	if verified == nil {
		return nil
	}
	if bound.Payer != verified.Payer {
		return fmt.Errorf("on-chain channel payer %s != transaction payer %s", bound.Payer, verified.Payer)
	}
	if bound.Deposit != verified.Deposit {
		return fmt.Errorf("on-chain channel deposit %d != transaction deposit %d", bound.Deposit, verified.Deposit)
	}
	if bound.Salt != verified.Salt {
		return fmt.Errorf("on-chain channel salt %d != transaction salt %d", bound.Salt, verified.Salt)
	}
	if bound.OpenSlot != verified.OpenSlot {
		return fmt.Errorf("on-chain channel openSlot %d != transaction openSlot %d", bound.OpenSlot, verified.OpenSlot)
	}
	return nil
}

func validateAssertedOpenDeposit(payload *intents.OpenPayload, authoritativeDeposit uint64) error {
	assertedDeposit, err := payload.DepositAmount()
	if err != nil {
		return err
	}
	if authoritativeDeposit != assertedDeposit {
		return fmt.Errorf("on-chain channel deposit %d != asserted deposit %d", authoritativeDeposit, assertedDeposit)
	}
	return nil
}

func openSplits(entries []generated.DistributionEntry) []paymentchannels.Distribution {
	result := make([]paymentchannels.Distribution, 0, len(entries))
	for _, entry := range entries {
		result = append(result, paymentchannels.Distribution{Recipient: entry.Recipient, Bps: entry.Bps})
	}
	return result
}

// NewTopUpTxVerifier returns the on-chain top-up verifier to install on
// SessionConfig.VerifyTopUpTx. It fetches the confirmed transaction and
// requires a payment-channels top_up instruction for the payload channel with
// an amount exactly equal to the claimed deposit delta.
// A nil rpcClient returns nil so the seam stays unset, and the new deposit is
// trusted as provided; suitable only for unit tests or deployments that
// verify transactions out of band.
func NewTopUpTxVerifier(config SessionConfig, rpcClient solanatx.RPCClient) TopUpTxVerifier {
	if rpcClient == nil {
		return nil
	}
	programID := paymentchannels.ProgramPubkey()
	if config.ProgramID != nil {
		programID = *config.ProgramID
	}
	return func(ctx context.Context, payload *intents.TopUpPayload, currentDeposit uint64) error {
		return verifyTopUpTx(ctx, rpcClient, programID, payload, currentDeposit)
	}
}

func verifyTopUpTx(ctx context.Context, rpcClient solanatx.RPCClient, programID solana.PublicKey, payload *intents.TopUpPayload, currentDeposit uint64) error {
	if payload == nil {
		return fmt.Errorf("top-up payload is required")
	}
	newDeposit, err := strconv.ParseUint(payload.NewDeposit, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid newDeposit: %s", payload.NewDeposit)
	}
	if newDeposit <= currentDeposit {
		return fmt.Errorf("new deposit %d must exceed current deposit %d", newDeposit, currentDeposit)
	}
	channel, err := solana.PublicKeyFromBase58(payload.ChannelID)
	if err != nil {
		return fmt.Errorf("invalid top-up channel id %q: %w", payload.ChannelID, err)
	}
	signature, err := solana.SignatureFromBase58(payload.Signature)
	if err != nil {
		return fmt.Errorf("invalid top-up tx signature %q: %w", payload.Signature, err)
	}
	if err := confirmTransactionSignature(ctx, rpcClient, payload.Signature, "top-up"); err != nil {
		return err
	}
	tx, _, err := solanatx.FetchTransaction(ctx, rpcClient, signature)
	if err != nil {
		return fmt.Errorf("fetch top-up transaction: %w", err)
	}
	if len(tx.Message.AddressTableLookups) > 0 {
		return fmt.Errorf("top-up transaction uses address lookup tables, which are not supported")
	}
	if len(tx.Signatures) == 0 || tx.Signatures[0].IsZero() || tx.Signatures[0] != signature {
		return fmt.Errorf("top-up transaction signature does not match payload signature")
	}

	var funded uint64
	var topUpCount int
	for i := range tx.Message.Instructions {
		ix := &tx.Message.Instructions[i]
		if int(ix.ProgramIDIndex) >= len(tx.Message.AccountKeys) || !tx.Message.AccountKeys[ix.ProgramIDIndex].Equals(programID) {
			continue
		}
		if len(ix.Data) == 0 || ix.Data[0] != topUpInstructionDiscriminator {
			continue
		}
		if len(ix.Data) != 1+8 {
			return fmt.Errorf("top-up instruction data has invalid length %d", len(ix.Data))
		}
		if len(ix.Accounts) < 2 || int(ix.Accounts[1]) >= len(tx.Message.AccountKeys) {
			return fmt.Errorf("top-up instruction is missing the channel account")
		}
		if !tx.Message.AccountKeys[ix.Accounts[1]].Equals(channel) {
			continue
		}
		amount := binary.LittleEndian.Uint64(ix.Data[1:])
		if amount > math.MaxUint64-funded {
			return fmt.Errorf("top-up instruction amount overflows total")
		}
		funded += amount
		topUpCount++
	}
	if topUpCount == 0 {
		return fmt.Errorf("no payment-channels top_up instruction found for channel %s", channel)
	}
	wantDelta := newDeposit - currentDeposit
	if funded != wantDelta {
		return fmt.Errorf("top-up amount %d != claimed deposit delta %d", funded, wantDelta)
	}
	return nil
}

// NewTopUpStateTxVerifier confirms the transaction and binds a top-up to the
// resulting on-chain channel state. New session construction installs this
// stronger state-aware verifier alongside the legacy callback seam.
func NewTopUpStateTxVerifier(config SessionConfig, rpcClient solanatx.RPCClient) SessionTopUpTxVerifier {
	if rpcClient == nil {
		if config.Network == "localnet" {
			return nil
		}
		return func(context.Context, *intents.TopUpPayload, ChannelState) error {
			return fmt.Errorf("payment-channel top-up requires an rpc client to bind the on-chain channel off localnet")
		}
	}
	return func(ctx context.Context, payload *intents.TopUpPayload, current ChannelState) error {
		slot, err := confirmedTransactionSlot(ctx, rpcClient, payload.Signature, "top-up")
		if err != nil {
			return err
		}
		newDeposit, err := strconv.ParseUint(payload.NewDeposit, 10, 64)
		if err != nil {
			return fmt.Errorf("invalid newDeposit: %s", payload.NewDeposit)
		}
		expectedMint := paycore.ResolveMint(config.Currency, config.Network)
		if expectedMint == "" {
			return fmt.Errorf("payment-channel top-up requires an SPL token, got currency %q", config.Currency)
		}
		channelID, err := solana.PublicKeyFromBase58(payload.ChannelID)
		if err != nil {
			return fmt.Errorf("invalid channelId %q: %w", payload.ChannelID, err)
		}
		if config.Network != "localnet" {
			parsedSignature, err := solana.SignatureFromBase58(payload.Signature)
			if err != nil {
				return fmt.Errorf("invalid top-up tx signature %q: %w", payload.Signature, err)
			}
			tx, _, err := solanatx.FetchTransaction(ctx, rpcClient, parsedSignature)
			if err != nil {
				return fmt.Errorf("fetch top-up transaction: %w", err)
			}
			if len(tx.Signatures) == 0 || tx.Signatures[0] != parsedSignature {
				return fmt.Errorf("top-up transaction signature does not match payload signature")
			}
			program := paymentchannels.ProgramPubkey()
			if config.ProgramID != nil {
				program = *config.ProgramID
			}
			var funded uint64
			var matched int
			for _, instruction := range tx.Message.Instructions {
				if int(instruction.ProgramIDIndex) >= len(tx.Message.AccountKeys) ||
					!tx.Message.AccountKeys[instruction.ProgramIDIndex].Equals(program) ||
					len(instruction.Data) != 9 || instruction.Data[0] != topUpInstructionDiscriminator ||
					len(instruction.Accounts) < 2 || int(instruction.Accounts[1]) >= len(tx.Message.AccountKeys) ||
					!tx.Message.AccountKeys[instruction.Accounts[1]].Equals(channelID) {
					continue
				}
				matched++
				if matched > 1 {
					return fmt.Errorf("top-up transaction must contain exactly one payment-channels top_up instruction for channel %s, found %d", channelID, matched)
				}
				funded = binary.LittleEndian.Uint64(instruction.Data[1:])
			}
			if matched != 1 {
				return fmt.Errorf("top-up transaction must contain exactly one payment-channels top_up instruction for channel %s, found %d", channelID, matched)
			}
			if newDeposit <= current.Deposit || funded != newDeposit-current.Deposit {
				return fmt.Errorf("top-up amount %d != claimed deposit delta %d", funded, newDeposit-current.Deposit)
			}
		}
		channel, err := fetchAndValidateChannel(
			ctx, rpcClient, channelID, expectedMint, config.Recipient, config.Operator,
			expectedSessionGracePeriod(config), sessionDistributionHash(config.Splits), false, config.ProgramID, slot,
		)
		if err != nil {
			return err
		}
		if channel.AuthorizedSigner.String() != current.AuthorizedSigner {
			return fmt.Errorf("on-chain channel authorizedSigner %s != stored signer %s", channel.AuthorizedSigner, current.AuthorizedSigner)
		}
		if current.Operator == nil || channel.Payer.String() != *current.Operator {
			return fmt.Errorf("on-chain channel payer %s does not match stored payer", channel.Payer)
		}
		if channel.Deposit != newDeposit {
			return fmt.Errorf("on-chain channel deposit %d != asserted newDeposit %d", channel.Deposit, newDeposit)
		}
		return nil
	}
}

// SettlementInstructions builds the on-chain settlement sequence for a
// channel: settle_and_seal over the stored watermark (preceded by the
// Ed25519 precompile instruction when a voucher was accepted) plus the
// distribute instruction, to be bundled into one merchant-signed
// transaction. Hosts drive this after ProcessClose records the close-pending
// state, then call MarkSealed once the transaction confirms.
//
// The mint is resolved from the configured currency and network. The token
// program comes from the authoritative session configuration (Token-2022
// for known PYUSD/USDG/CASH, or the resolved owner for an arbitrary mint).
func (s *SessionServer) SettlementInstructions(ctx context.Context, channelID string, merchant solana.PublicKey) ([]solana.Instruction, error) {
	if err := s.requireProductionSessionSafety(); err != nil {
		return nil, err
	}
	state, err := s.store.GetChannel(ctx, channelID)
	if err != nil {
		return nil, err
	}
	if state == nil {
		return nil, fmt.Errorf("channel %s not found", channelID)
	}
	return s.settlementInstructionsForState(*state, channelID, merchant)
}

// settlementInstructionsForState derives the settlement instruction sequence
// for an already-read channel snapshot. The distribute payer is the channel
// payer recorded as state.Operator at open (the program pins it to
// channel.payer); when the channel never recorded a payer this returns the
// strict unknown-payer error rather than refunding any other account.
func (s *SessionServer) settlementInstructionsForState(state ChannelState, channelID string, merchant solana.PublicKey) ([]solana.Instruction, error) {
	channel, err := solana.PublicKeyFromBase58(channelID)
	if err != nil {
		return nil, fmt.Errorf("invalid channel id %q: %w", channelID, err)
	}
	programID := paymentchannels.ProgramPubkey()
	if s.config.ProgramID != nil {
		programID = *s.config.ProgramID
	}

	var voucherSignature *[64]byte
	var authorizedSigner solana.PublicKey
	expiresAt := int64(0)
	if state.HighestVoucherSignature != nil {
		signature, err := solana.SignatureFromBase58(*state.HighestVoucherSignature)
		if err != nil {
			return nil, fmt.Errorf("invalid stored voucher signature: %w", err)
		}
		signatureBytes := [64]byte(signature)
		voucherSignature = &signatureBytes
		authorizedSigner, err = solana.PublicKeyFromBase58(state.AuthorizedSigner)
		if err != nil {
			return nil, fmt.Errorf("invalid stored authorized signer %q: %w", state.AuthorizedSigner, err)
		}
		if state.HighestVoucherExpiresAt == nil {
			return nil, fmt.Errorf("channel %s has a voucher signature but no voucher expiry", channelID)
		}
		expiresAt = *state.HighestVoucherExpiresAt
	}

	instructions, err := paymentchannels.BuildSettleAndSealInstructions(paymentchannels.SettleAndSealParams{
		Payee:            merchant,
		Channel:          channel,
		AuthorizedSigner: authorizedSigner,
		Signature:        voucherSignature,
		CumulativeAmount: state.Cumulative,
		ExpiresAt:        expiresAt,
		ProgramID:        programID,
	})
	if err != nil {
		return nil, err
	}

	mintAddress := paycore.ResolveMint(s.config.Currency, s.config.Network)
	if mintAddress == "" {
		return nil, fmt.Errorf("session settlement requires an SPL token, got currency %q", s.config.Currency)
	}
	mint, err := solana.PublicKeyFromBase58(mintAddress)
	if err != nil {
		return nil, fmt.Errorf("invalid mint %q: %w", mintAddress, err)
	}
	tokenProgram, err := resolveSessionTokenProgram(s.config.TokenProgram, s.config.Currency, s.config.Network)
	if err != nil {
		return nil, err
	}
	payerAddress := ""
	if state.Operator != nil {
		payerAddress = *state.Operator
	}
	if payerAddress == "" {
		return nil, fmt.Errorf("channel %s payer is unknown; cannot derive the refund token account", channelID)
	}
	payer, err := solana.PublicKeyFromBase58(payerAddress)
	if err != nil {
		return nil, fmt.Errorf("invalid channel payer %q: %w", payerAddress, err)
	}
	payee, err := solana.PublicKeyFromBase58(s.config.Recipient)
	if err != nil {
		return nil, fmt.Errorf("invalid recipient %q: %w", s.config.Recipient, err)
	}
	// rentPayer reclaims the channel/escrow rent at seal; it is the
	// operator recorded as rentPayer at open.
	rentPayer, err := solana.PublicKeyFromBase58(s.config.Operator)
	if err != nil {
		return nil, fmt.Errorf("invalid operator %q: %w", s.config.Operator, err)
	}

	recipients := make([]paymentchannels.Distribution, 0, len(s.config.Splits))
	for _, split := range s.config.Splits {
		recipients = append(recipients, paymentchannels.Distribution{
			Recipient: split.Recipient,
			Bps:       split.BPS,
		})
	}

	distribute, err := paymentchannels.BuildDistributeInstruction(paymentchannels.DistributeParams{
		Channel:      channel,
		Payer:        payer,
		RentPayer:    rentPayer,
		Payee:        payee,
		Treasury:     paymentchannels.TreasuryOwner(),
		Mint:         mint,
		Recipients:   recipients,
		TokenProgram: tokenProgram,
		ProgramID:    programID,
	})
	if err != nil {
		return nil, err
	}
	return append(instructions, distribute), nil
}

// resolveSessionTokenProgram returns the configured token program, falling
// back to the static known-currency mapping for backwards-compatible session
// configs. Arbitrary mint sessions must provide the owner resolved from RPC;
// otherwise they would silently default to the legacy Token program.
func resolveSessionTokenProgram(configured, currency, network string) (solana.PublicKey, error) {
	program := configured
	if program == "" {
		if paycore.StablecoinSymbol(currency) == "" {
			return solana.PublicKey{}, fmt.Errorf("token program is required for arbitrary mint %q", currency)
		}
		program = paycore.DefaultTokenProgramForCurrency(currency, network)
	}
	parsed, err := solana.PublicKeyFromBase58(program)
	if err != nil {
		return solana.PublicKey{}, fmt.Errorf("invalid session token program %q: %w", program, err)
	}
	if !parsed.Equals(solana.TokenProgramID) && parsed.String() != paycore.Token2022Program {
		return solana.PublicKey{}, fmt.Errorf("unsupported session token program %s", parsed)
	}
	return parsed, nil
}

// SubmitOpenTxResult carries the verified channel facts plus the broadcast
// signature of a server-submitted open.
type SubmitOpenTxResult struct {
	// VerifyOpenTxResult carries the channel facts (channel PDA, deposit,
	// grace period, salt) extracted during pre-broadcast validation.
	VerifyOpenTxResult

	// Signature of the broadcast open transaction (base58).
	Signature string
}

// SubmitOpenTx validates a client-built payment-channel open transaction,
// completes the fee-payer signature when payerSigner is required by the
// transaction, broadcasts it, and waits for at least confirmed commitment.
// Callers must not persist channel state for a transaction that never
// landed. Used when the session is configured with the server open-tx
// submitter.
func SubmitOpenTx(ctx context.Context, expected VerifyOpenTxExpected, payload *intents.OpenPayload, payerSigner solanatx.Signer, rpcClient solanatx.RPCClient) (SubmitOpenTxResult, error) {
	if rpcClient == nil {
		return SubmitOpenTxResult{}, fmt.Errorf("SubmitOpenTx requires an RPC client")
	}
	verified, tx, signature, err := prepareOpenTx(ctx, expected, payload, payerSigner)
	if err != nil {
		return SubmitOpenTxResult{}, err
	}
	sentSignature, err := solanatx.SendTransaction(ctx, rpcClient, tx)
	if err != nil {
		return SubmitOpenTxResult{}, fmt.Errorf("broadcast open transaction: %w", err)
	}
	if sentSignature != signature {
		return SubmitOpenTxResult{}, fmt.Errorf("broadcast open signature %s != prepared signature %s", sentSignature, signature)
	}
	if err := solanatx.WaitForConfirmation(ctx, rpcClient, signature); err != nil {
		return SubmitOpenTxResult{}, fmt.Errorf("confirm open transaction: %w", err)
	}
	return SubmitOpenTxResult{VerifyOpenTxResult: verified, Signature: signature.String()}, nil
}

func prepareOpenTx(ctx context.Context, expected VerifyOpenTxExpected, payload *intents.OpenPayload, payerSigner solanatx.Signer) (VerifyOpenTxResult, *solana.Transaction, solana.Signature, error) {
	// Structural validation only: the transaction may not have been broadcast.
	verified, err := VerifyOpenTx(ctx, expected, payload, nil)
	if err != nil {
		return VerifyOpenTxResult{}, nil, solana.Signature{}, err
	}
	tx, err := solanatx.DecodeTransactionBase64(*payload.Transaction)
	if err != nil {
		return VerifyOpenTxResult{}, nil, solana.Signature{}, fmt.Errorf("decode open transaction: %w", err)
	}
	operator, err := solana.PublicKeyFromBase58(expected.Operator)
	if err != nil {
		return VerifyOpenTxResult{}, nil, solana.Signature{}, fmt.Errorf("invalid expected operator %q: %w", expected.Operator, err)
	}
	if len(tx.Message.AccountKeys) == 0 || !tx.Message.AccountKeys[0].Equals(operator) {
		return VerifyOpenTxResult{}, nil, solana.Signature{}, fmt.Errorf("open transaction fee payer does not match expected operator %s", expected.Operator)
	}
	// Complete the fee-payer signature when the client left the slot for the
	// server (the createServerOpenedPaymentChannelSessionOpener flow builds
	// the open with the operator as fee payer and only partial-signs as the
	// channel payer).
	if payerSigner != nil && signerIsRequired(tx, payerSigner.PublicKey()) {
		if err := solanatx.SignTransaction(tx, payerSigner); err != nil {
			return VerifyOpenTxResult{}, nil, solana.Signature{}, fmt.Errorf("co-sign open transaction: %w", err)
		}
	}
	if len(tx.Signatures) == 0 || tx.Signatures[0].IsZero() {
		return VerifyOpenTxResult{}, nil, solana.Signature{}, fmt.Errorf("open transaction is missing the fee-payer signature")
	}
	return verified, tx, tx.Signatures[0], nil
}

// signerIsRequired reports whether key is one of the transaction's required
// signers.
func signerIsRequired(tx *solana.Transaction, key solana.PublicKey) bool {
	for _, signer := range tx.Message.Signers() {
		if signer.Equals(key) {
			return true
		}
	}
	return false
}

// confirmTransactionSignature checks once via getSignatureStatuses that the
// base58 signature names a known, successful transaction. label names the
// transaction in error messages ("open", "top-up").
func confirmTransactionSignature(ctx context.Context, rpcClient solanatx.RPCClient, signature, label string) error {
	_, err := confirmedTransactionSlot(ctx, rpcClient, signature, label)
	return err
}

func confirmedTransactionSlot(ctx context.Context, rpcClient solanatx.RPCClient, signature, label string) (uint64, error) {
	parsed, err := solana.SignatureFromBase58(signature)
	if err != nil {
		return 0, fmt.Errorf("invalid %s tx signature %q: %w", label, signature, err)
	}
	out, err := rpcClient.GetSignatureStatuses(ctx, true, parsed)
	if err != nil {
		return 0, fmt.Errorf("RPC error verifying %s tx: %w", label, err)
	}
	if out == nil || len(out.Value) == 0 || out.Value[0] == nil {
		return 0, fmt.Errorf("%s tx %q not found; not yet confirmed or does not exist", label, signature)
	}
	if out.Value[0].Err != nil {
		return 0, fmt.Errorf("%s tx %q failed on-chain: %v", label, signature, out.Value[0].Err)
	}
	status := out.Value[0].ConfirmationStatus
	if status != rpc.ConfirmationStatusConfirmed && status != rpc.ConfirmationStatusFinalized {
		return 0, fmt.Errorf("%s tx %q is only %s; confirmed or finalized required", label, signature, status)
	}
	return out.Value[0].Slot, nil
}

// isPlaceholderSignature reports whether the signature is the pending
// placeholder produced by the server-completed open flow (an empty string or
// a run of 40+ '1' characters, the base58 encoding of the all-ones marker).
func isPlaceholderSignature(signature string) bool {
	if signature == "" {
		return true
	}
	if len(signature) < 40 {
		return false
	}
	return strings.Count(signature, "1") == len(signature)
}
