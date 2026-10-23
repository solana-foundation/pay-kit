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
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"strings"

	bin "github.com/gagliardetto/binary"
	solana "github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/rpc"

	"github.com/solana-foundation/pay-kit/go/paycore"
	"github.com/solana-foundation/pay-kit/go/paycore/paymentchannels"
	"github.com/solana-foundation/pay-kit/go/paycore/solanatx"
	"github.com/solana-foundation/pay-kit/go/protocols/mpp/intents"
	pcgen "github.com/solana-foundation/pay-kit/go/protocols/programs/paymentchannels"
)

// openInstructionDiscriminator is the payment-channel open instruction
// discriminator (single-byte Anchor-numeric form, not the 8-byte sha256
// convention). Matches OPEN_DISCRIMINATOR in the vendored Codama clients.
const openInstructionDiscriminator = 1

// channelAccountDiscriminator is the explicit value in
// idl/payment-channels.json (accountDiscriminator.channel). The generated Go
// enum currently drops the IDL's explicit discriminators and starts at zero.
const channelAccountDiscriminator = 1

// VerifyOpenTxExpected carries the challenge-side values a client-submitted
// open transaction is validated against.
type VerifyOpenTxExpected struct {
	// AuthorizedSigner is the voucher signing key claimed by the open payload
	// (base58); the transaction's authorizedSigner account must match it.
	AuthorizedSigner string

	// Currency is the challenge currency (symbol or mint address).
	Currency string

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

	// Splits are the ordered recipients committed by the open transaction.
	Splits []Split
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
// Both legacy and v0 transaction encodings are accepted (clients never build
// legacy any more, but existing ones still may), while a v0 transaction that
// uses address lookup tables is rejected because the account checks below
// read the static account keys, so an ALT could hide the real accounts
// behind the fee-payer co-sign guard.
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
// on-chain and its funded channel account is matched; nil performs structural
// validation only, including payload metadata and distribution binding.
func VerifyOpenTx(ctx context.Context, expected VerifyOpenTxExpected, payload *intents.OpenPayload, rpcClient solanatx.RPCClient) (VerifyOpenTxResult, error) {
	if expected.Operator == "" {
		return VerifyOpenTxResult{}, fmt.Errorf("verify open: expected operator (rentPayer) is required")
	}
	if payload.Transaction == nil || *payload.Transaction == "" {
		return VerifyOpenTxResult{}, fmt.Errorf("openPayload.transaction is required for push-mode open verification")
	}

	tx, err := decodeOpenTransaction(*payload.Transaction)
	if err != nil {
		return VerifyOpenTxResult{}, err
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

	// Bind the claimed signature to this transaction before trusting it.
	boundSignature := payload.Signature != "" && !isPlaceholderSignature(payload.Signature)
	if boundSignature {
		if len(tx.Signatures) == 0 || tx.Signatures[0].IsZero() {
			return VerifyOpenTxResult{}, fmt.Errorf("openPayload.signature is set but the transaction carries no fee-payer signature")
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

	accountKeys := tx.Message.AccountKeys
	accountAt := func(indices []uint16, slot int, label string) (solana.PublicKey, error) {
		if slot >= len(indices) || int(indices[slot]) >= len(accountKeys) {
			return solana.PublicKey{}, fmt.Errorf("open instruction is missing the %s account at slot %d", label, slot)
		}
		return accountKeys[indices[slot]], nil
	}

	var openIx *solana.CompiledInstruction
	for i := range tx.Message.Instructions {
		ix := &tx.Message.Instructions[i]
		if int(ix.ProgramIDIndex) >= len(accountKeys) || !accountKeys[ix.ProgramIDIndex].Equals(programID) {
			continue
		}
		if len(ix.Data) < 1 || ix.Data[0] != openInstructionDiscriminator {
			continue
		}
		openIx = ix
		break
	}
	if openIx == nil {
		return VerifyOpenTxResult{}, fmt.Errorf("no payment-channels open instruction found")
	}

	// Open instruction account layout (matches the generated client):
	// 0 payer, 1 rentPayer, 2 payee, 3 mint, 4 authorizedSigner, 5 channel,
	// 6 payerTokenAccount, 7 channelTokenAccount, 8 tokenProgram, ...
	// rentPayer (slot 1) is pinned to the operator / fee payer.
	if len(openIx.Accounts) < 8 {
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

	if payee.String() != expected.Recipient {
		return VerifyOpenTxResult{}, fmt.Errorf("open payee %s != expected recipient %s", payee, expected.Recipient)
	}
	if mint.String() != expectedMint {
		return VerifyOpenTxResult{}, fmt.Errorf("open mint %s != expected mint %s", mint, expectedMint)
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

	// Instruction data:
	// [discriminator u8][salt u64][deposit u64][grace u32][openSlot u64][recipients].
	if len(openIx.Data) < 1+8+8+4+8 {
		return VerifyOpenTxResult{}, fmt.Errorf("open instruction data too short (%d bytes)", len(openIx.Data))
	}
	salt := binary.LittleEndian.Uint64(openIx.Data[1:9])
	deposit := binary.LittleEndian.Uint64(openIx.Data[9:17])
	gracePeriod := binary.LittleEndian.Uint32(openIx.Data[17:21])
	openSlot := binary.LittleEndian.Uint64(openIx.Data[21:29])

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

	// Validate the claimed metadata even during pre-broadcast validation: the
	// lower-level ProcessOpen persists these fields from the payload.
	verified := VerifyOpenTxResult{
		ChannelID: channel.String(), Deposit: deposit, GracePeriod: gracePeriod,
		OpenSlot: openSlot, Payer: payer.String(), Salt: salt,
	}
	if err := matchOpenPayload(payload, verified, payee.String(), mint.String()); err != nil {
		return VerifyOpenTxResult{}, err
	}
	// Bind the distribution before the operator signs or pays a network fee.
	if len(openIx.Data) != 33+34*len(expected.Splits) ||
		binary.LittleEndian.Uint32(openIx.Data[29:33]) != uint32(len(expected.Splits)) {
		return VerifyOpenTxResult{}, fmt.Errorf("open distribution does not match configured splits")
	}
	for i, split := range expected.Splits {
		offset := 33 + i*34
		if string(openIx.Data[offset:offset+32]) != string(split.Recipient[:]) ||
			binary.LittleEndian.Uint16(openIx.Data[offset+32:offset+34]) != split.BPS {
			return VerifyOpenTxResult{}, fmt.Errorf("open distribution does not match configured splits")
		}
	}
	if rpcClient != nil {
		return readConfirmedOpenChannel(ctx, expected, payload, &verified, rpcClient)
	}
	return verified, nil
}

// matchOpenPayload rejects claims that would otherwise be persisted independently
// of the verified transaction or account. Optional metadata may be omitted.
func matchOpenPayload(payload *intents.OpenPayload, verified VerifyOpenTxResult, payee, mint string) error {
	deposit, err := payload.DepositAmount()
	if err != nil {
		return err
	}
	if deposit != verified.Deposit {
		return fmt.Errorf("openPayload deposit %d != verified deposit %d", deposit, verified.Deposit)
	}
	for _, field := range []struct {
		name     string
		supplied *string
		actual   string
	}{
		{"channelId", payload.ChannelID, verified.ChannelID},
		{"payer", payload.Payer, verified.Payer},
		{"payee", payload.Payee, payee},
		{"mint", payload.Mint, mint},
	} {
		if field.supplied != nil && *field.supplied != field.actual {
			return fmt.Errorf("openPayload %s does not match verified channel", field.name)
		}
	}
	if payload.Salt != nil && *payload.Salt != verified.Salt {
		return fmt.Errorf("openPayload salt does not match verified channel")
	}
	if payload.GracePeriod != nil && *payload.GracePeriod != verified.GracePeriod {
		return fmt.Errorf("openPayload gracePeriod does not match verified channel")
	}
	if payload.RecentSlot != nil && *payload.RecentSlot != verified.OpenSlot {
		return fmt.Errorf("openPayload recentSlot does not match verified channel")
	}
	return nil
}

// readConfirmedOpenChannel proves that the session is backed by an unspent,
// program-owned channel, rather than by an unrelated successful transaction.
func readConfirmedOpenChannel(ctx context.Context, expected VerifyOpenTxExpected, payload *intents.OpenPayload, transaction *VerifyOpenTxResult, rpcClient solanatx.RPCClient) (VerifyOpenTxResult, error) {
	if isPlaceholderSignature(payload.Signature) {
		return VerifyOpenTxResult{}, fmt.Errorf("open requires a confirmed transaction signature")
	}
	status, err := confirmedSignatureStatus(ctx, rpcClient, payload.Signature, "open")
	if err != nil {
		return VerifyOpenTxResult{}, err
	}
	var channelID string
	if transaction != nil {
		channelID = transaction.ChannelID
	} else {
		channelID, err = payload.SessionID()
		if err != nil {
			return VerifyOpenTxResult{}, err
		}
	}
	address, err := solana.PublicKeyFromBase58(channelID)
	if err != nil {
		return VerifyOpenTxResult{}, fmt.Errorf("invalid channel address: %w", err)
	}
	programID := paymentchannels.ProgramPubkey()
	if expected.ProgramID != nil {
		programID = *expected.ProgramID
	}
	info, err := rpcClient.GetAccountInfoWithOpts(ctx, address, &rpc.GetAccountInfoOpts{
		Commitment: rpc.CommitmentConfirmed, Encoding: solana.EncodingBase64, MinContextSlot: &status.Slot,
	})
	if err != nil {
		return VerifyOpenTxResult{}, fmt.Errorf("read confirmed channel: %w", err)
	}
	if info == nil || info.Value == nil || info.Value.Data == nil {
		return VerifyOpenTxResult{}, fmt.Errorf("confirmed channel account is missing")
	}
	if !info.Value.Owner.Equals(programID) || info.Value.Executable {
		return VerifyOpenTxResult{}, fmt.Errorf("confirmed channel account has invalid program ownership")
	}
	data := info.Value.Data.GetBinary()
	// The generated decoder targets the pinned v1 program's 256-byte layout;
	// decoding a different header or trailing extension as v1 is unsafe.
	if len(data) != 256 {
		return VerifyOpenTxResult{}, fmt.Errorf("confirmed channel account has unsupported size %d", len(data))
	}
	var channel pcgen.Channel
	if err := channel.UnmarshalWithDecoder(bin.NewBorshDecoder(data)); err != nil {
		return VerifyOpenTxResult{}, fmt.Errorf("decode confirmed channel: %w", err)
	}
	if channel.Discriminator != channelAccountDiscriminator || channel.Version != 1 {
		return VerifyOpenTxResult{}, fmt.Errorf("confirmed channel account has unsupported discriminator or version")
	}
	if channel.Status != uint8(pcgen.ChannelStatus_Open) || channel.ClosureStartedAt != 0 || channel.PayerWithdrawnAt != 0 ||
		channel.Settlement.Settled != 0 || channel.Settlement.PayoutWatermark != 0 {
		return VerifyOpenTxResult{}, fmt.Errorf("confirmed channel is not an unspent open channel")
	}
	mint := expected.Mint
	if mint == "" {
		mint = paycore.ResolveMint(expected.Currency, expected.Network)
	}
	if channel.Payee.String() != expected.Recipient || channel.Mint.String() != mint ||
		channel.AuthorizedSigner.String() != expected.AuthorizedSigner || channel.RentPayer.String() != expected.Operator {
		return VerifyOpenTxResult{}, fmt.Errorf("confirmed channel parties or mint do not match the session")
	}
	if channel.Deposit == 0 || channel.Deposit > expected.MaxCap {
		return VerifyOpenTxResult{}, fmt.Errorf("confirmed channel deposit is outside the session cap")
	}
	if channel.DistributionHash != sessionDistributionHash(expected.Splits) {
		return VerifyOpenTxResult{}, fmt.Errorf("confirmed channel distribution does not match configured splits")
	}
	derived, bump, err := paymentchannels.FindChannelPDAForProgram(channel.Payer, channel.Payee, channel.Mint, channel.AuthorizedSigner, channel.Salt, channel.OpenSlot, programID)
	if err != nil {
		return VerifyOpenTxResult{}, err
	}
	if !derived.Equals(address) || channel.Bump != bump {
		return VerifyOpenTxResult{}, fmt.Errorf("confirmed channel PDA or bump does not match its seeds")
	}
	verified := VerifyOpenTxResult{
		ChannelID: channelID, Deposit: channel.Deposit, GracePeriod: channel.GracePeriod,
		OpenSlot: channel.OpenSlot, Payer: channel.Payer.String(), Salt: channel.Salt,
	}
	if transaction != nil && *transaction != verified {
		return VerifyOpenTxResult{}, fmt.Errorf("confirmed channel does not match the verified open transaction")
	}
	if err := matchOpenPayload(payload, verified, channel.Payee.String(), channel.Mint.String()); err != nil {
		return VerifyOpenTxResult{}, err
	}
	return verified, nil
}

func sessionDistributionHash(splits []Split) [32]byte {
	hasher := sha256.New()
	var count [4]byte
	binary.LittleEndian.PutUint32(count[:], uint32(len(splits)))
	_, _ = hasher.Write(count[:])
	for _, split := range splits {
		_, _ = hasher.Write(split.Recipient[:])
		var bps [2]byte
		binary.LittleEndian.PutUint16(bps[:], split.BPS)
		_, _ = hasher.Write(bps[:])
	}
	var out [32]byte
	copy(out[:], hasher.Sum(nil))
	return out
}

// NewOpenTxVerifier returns the on-chain open verifier to install on
// SessionConfig.VerifyOpenTx. When the open payload carries a transaction,
// it is structurally validated against the challenge via VerifyOpenTx (with
// confirmed channel-account check when rpcClient is non-nil). Signature-only
// opens require an RPC client and a matching confirmed account. On success the
// returned payer comes from the account, and an omitted payload RecentSlot is
// filled with the account's open slot before ProcessOpen persists state.
func NewOpenTxVerifier(config SessionConfig, rpcClient solanatx.RPCClient) SessionTxVerifier[intents.OpenPayload] {
	return func(ctx context.Context, payload *intents.OpenPayload) (string, error) {
		expected := VerifyOpenTxExpected{
			AuthorizedSigner: payload.AuthorizedSigner, Currency: config.Currency,
			MaxCap: config.MaxCap, Network: config.Network, Operator: config.Operator,
			ProgramID: config.ProgramID, Recipient: config.Recipient, Splits: config.Splits,
		}
		var verified VerifyOpenTxResult
		var err error
		if payload.Transaction != nil && *payload.Transaction != "" {
			verified, err = VerifyOpenTx(ctx, expected, payload, rpcClient)
		} else {
			if rpcClient == nil {
				return "", fmt.Errorf("open verification requires a transaction or an RPC client")
			}
			verified, err = readConfirmedOpenChannel(ctx, expected, payload, nil, rpcClient)
		}
		if err != nil {
			return "", err
		}
		// The verifier seam returns only the payer. Fill an omitted open slot
		// after successful verification so ProcessOpen can retain this PDA seed.
		if payload.RecentSlot == nil {
			payload.RecentSlot = &verified.OpenSlot
		}
		return verified.Payer, nil
	}
}

// NewTopUpTxVerifier returns the on-chain top-up verifier to install on
// SessionConfig.VerifyTopUpTx: it confirms the top-up transaction signature
// on-chain via getSignatureStatuses.
// A nil rpcClient returns nil so the seam stays unset, and the new deposit is
// trusted as provided; suitable only for unit tests or deployments that
// verify transactions out of band.
func NewTopUpTxVerifier(rpcClient solanatx.RPCClient) SessionTxVerifier[intents.TopUpPayload] {
	if rpcClient == nil {
		return nil
	}
	return func(ctx context.Context, payload *intents.TopUpPayload) (string, error) {
		// A top-up carries only a signature, not an open transaction, so it
		// never establishes the channel payer.
		return "", confirmTransactionSignature(ctx, rpcClient, payload.Signature, "top-up")
	}
}

// SettlementInstructions builds the on-chain settlement sequence for a
// channel: settle_and_seal over the stored watermark (preceded by the
// Ed25519 precompile instruction when a voucher was accepted) plus the
// distribute instruction, to be bundled into one merchant-signed
// transaction. Hosts drive this after ProcessClose records the close-pending
// state, then call MarkSealed once the transaction confirms.
//
// The mint and token program are resolved from the configured currency and
// network (Token-2022 for PYUSD/USDG/CASH).
func (s *SessionServer) SettlementInstructions(ctx context.Context, channelID string, merchant solana.PublicKey) ([]solana.Instruction, error) {
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
	tokenProgramID := s.config.TokenProgram
	if tokenProgramID == "" {
		tokenProgramID = paycore.DefaultTokenProgramForCurrency(s.config.Currency, s.config.Network)
	}
	tokenProgram, err := solana.PublicKeyFromBase58(tokenProgramID)
	if err != nil {
		return nil, fmt.Errorf("invalid token program: %w", err)
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
	// Structural validation only: the transaction has not been broadcast yet,
	// so there is no on-chain liveness to check.
	verified, err := VerifyOpenTx(ctx, expected, payload, nil)
	if err != nil {
		return SubmitOpenTxResult{}, err
	}
	tx, err := decodeOpenTransaction(*payload.Transaction)
	if err != nil {
		return SubmitOpenTxResult{}, err
	}
	// Complete the fee-payer signature when the client left the slot for the
	// server (the createServerOpenedPaymentChannelSessionOpener flow builds
	// the open with the operator as fee payer and only partial-signs as the
	// channel payer).
	if payerSigner != nil && signerIsRequired(tx, payerSigner.PublicKey()) {
		if err := solanatx.SignTransaction(tx, payerSigner); err != nil {
			return SubmitOpenTxResult{}, fmt.Errorf("co-sign open transaction: %w", err)
		}
	}
	if len(tx.Signatures) == 0 || tx.Signatures[0].IsZero() {
		return SubmitOpenTxResult{}, fmt.Errorf("open transaction is missing the fee-payer signature")
	}
	// The locally signed transaction identifies the attempt even if the RPC
	// loses its broadcast response or a retry reports "already processed".
	signature := tx.Signatures[0]
	_, broadcastErr := solanatx.SendTransaction(ctx, rpcClient, tx)
	if broadcastErr == nil {
		if err := solanatx.WaitForConfirmation(ctx, rpcClient, signature); err != nil {
			return SubmitOpenTxResult{}, fmt.Errorf("confirm open transaction: %w", err)
		}
	}
	confirmedPayload := *payload
	confirmedPayload.Signature = signature.String()
	confirmed, err := readConfirmedOpenChannel(ctx, expected, &confirmedPayload, &verified, rpcClient)
	if err != nil {
		if broadcastErr != nil {
			return SubmitOpenTxResult{}, fmt.Errorf("broadcast open transaction: %w", broadcastErr)
		}
		return SubmitOpenTxResult{}, err
	}
	return SubmitOpenTxResult{VerifyOpenTxResult: confirmed, Signature: signature.String()}, nil
}

// decodeOpenTransaction decodes a client-submitted open transaction through
// the shared version policy; decode failures name the open transaction.
func decodeOpenTransaction(encoded string) (*solana.Transaction, error) {
	tx, err := solanatx.DecodeTransactionBase64(encoded)
	if err != nil {
		return nil, fmt.Errorf("decode open transaction: %w", err)
	}
	return tx, nil
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
// base58 signature names a successful confirmed/finalized transaction. label names the
// transaction in error messages ("open", "top-up").
func confirmTransactionSignature(ctx context.Context, rpcClient solanatx.RPCClient, signature, label string) error {
	_, err := confirmedSignatureStatus(ctx, rpcClient, signature, label)
	return err
}

func confirmedSignatureStatus(ctx context.Context, rpcClient solanatx.RPCClient, signature, label string) (*rpc.SignatureStatusesResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	parsed, err := solana.SignatureFromBase58(signature)
	if err != nil {
		return nil, fmt.Errorf("invalid %s tx signature %q: %w", label, signature, err)
	}
	out, err := rpcClient.GetSignatureStatuses(ctx, true, parsed)
	if err != nil {
		return nil, fmt.Errorf("RPC error verifying %s tx: %w", label, err)
	}
	if out == nil || len(out.Value) == 0 || out.Value[0] == nil {
		return nil, fmt.Errorf("%s tx %q not found; not yet confirmed or does not exist", label, signature)
	}
	status := out.Value[0]
	if status.Err != nil {
		return nil, fmt.Errorf("%s tx %q failed on-chain: %v", label, signature, status.Err)
	}
	if status.ConfirmationStatus != rpc.ConfirmationStatusConfirmed && status.ConfirmationStatus != rpc.ConfirmationStatusFinalized {
		return nil, fmt.Errorf("%s tx %q is not yet confirmed", label, signature)
	}
	return status, nil
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
