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
	"encoding/binary"
	"fmt"
	"strings"

	solana "github.com/gagliardetto/solana-go"

	"github.com/solana-foundation/pay-kit/go/paycore"
	"github.com/solana-foundation/pay-kit/go/paycore/paymentchannels"
	"github.com/solana-foundation/pay-kit/go/paycore/solanatx"
	"github.com/solana-foundation/pay-kit/go/protocols/mpp/intents"
)

// openInstructionDiscriminator is the payment-channel open instruction
// discriminator (single-byte Anchor-numeric form, not the 8-byte sha256
// convention). Matches OPEN_DISCRIMINATOR in the vendored Codama clients.
const openInstructionDiscriminator = 1

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

	// Instruction data: [discriminator u8][salt u64][deposit u64][grace u32][recipients].
	if len(openIx.Data) < 1+8+8+4 {
		return VerifyOpenTxResult{}, fmt.Errorf("open instruction data too short (%d bytes)", len(openIx.Data))
	}
	salt := binary.LittleEndian.Uint64(openIx.Data[1:9])
	deposit := binary.LittleEndian.Uint64(openIx.Data[9:17])
	gracePeriod := binary.LittleEndian.Uint32(openIx.Data[17:21])

	if deposit == 0 {
		return VerifyOpenTxResult{}, fmt.Errorf("open deposit must be greater than zero")
	}
	if deposit > expected.MaxCap {
		return VerifyOpenTxResult{}, fmt.Errorf("open deposit %d exceeds max cap %d", deposit, expected.MaxCap)
	}

	// Re-derive the channel PDA from the instruction's own seeds.
	derivedChannel, _, err := paymentchannels.FindChannelPDAForProgram(payer, payee, mint, authorizedSigner, salt, programID)
	if err != nil {
		return VerifyOpenTxResult{}, err
	}
	if !derivedChannel.Equals(channel) {
		return VerifyOpenTxResult{}, fmt.Errorf("open channel PDA %s != derived %s", channel, derivedChannel)
	}
	if payload.ChannelID != nil && *payload.ChannelID != channel.String() {
		return VerifyOpenTxResult{}, fmt.Errorf("openPayload.channelId %s != transaction channel %s", *payload.ChannelID, channel)
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
				MaxCap:           config.MaxCap,
				Network:          config.Network,
				Operator:         config.Operator,
				ProgramID:        config.ProgramID,
				Recipient:        config.Recipient,
			}
			result, err := VerifyOpenTx(ctx, expected, payload, rpcClient)
			return result.Payer, err
		}
		if rpcClient == nil {
			return "", fmt.Errorf("open verification requires a transaction or an RPC client")
		}
		return "", confirmTransactionSignature(ctx, rpcClient, payload.Signature, "open")
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
// channel: settle_and_finalize over the stored watermark (preceded by the
// Ed25519 precompile instruction when a voucher was accepted) plus the
// distribute instruction, to be bundled into one merchant-signed
// transaction. Hosts drive this after ProcessClose records the close-pending
// state, then call MarkFinalized once the transaction confirms.
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

	instructions, err := paymentchannels.BuildSettleAndFinalizeInstructions(paymentchannels.SettleAndFinalizeParams{
		Merchant:         merchant,
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
	tokenProgram, err := solana.PublicKeyFromBase58(paycore.DefaultTokenProgramForCurrency(s.config.Currency, s.config.Network))
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
	// rentPayer reclaims the channel/escrow rent at finalize; it is the
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
	tx, err := solanatx.DecodeTransactionBase64(*payload.Transaction)
	if err != nil {
		return SubmitOpenTxResult{}, fmt.Errorf("decode open transaction: %w", err)
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
	signature, err := solanatx.SendTransaction(ctx, rpcClient, tx)
	if err != nil {
		return SubmitOpenTxResult{}, fmt.Errorf("broadcast open transaction: %w", err)
	}
	if err := solanatx.WaitForConfirmation(ctx, rpcClient, signature); err != nil {
		return SubmitOpenTxResult{}, fmt.Errorf("confirm open transaction: %w", err)
	}
	return SubmitOpenTxResult{VerifyOpenTxResult: verified, Signature: signature.String()}, nil
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
	parsed, err := solana.SignatureFromBase58(signature)
	if err != nil {
		return fmt.Errorf("invalid %s tx signature %q: %w", label, signature, err)
	}
	out, err := rpcClient.GetSignatureStatuses(ctx, true, parsed)
	if err != nil {
		return fmt.Errorf("RPC error verifying %s tx: %w", label, err)
	}
	if out == nil || len(out.Value) == 0 || out.Value[0] == nil {
		return fmt.Errorf("%s tx %q not found; not yet confirmed or does not exist", label, signature)
	}
	if out.Value[0].Err != nil {
		return fmt.Errorf("%s tx %q failed on-chain: %v", label, signature, out.Value[0].Err)
	}
	return nil
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
