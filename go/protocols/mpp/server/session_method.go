package server

// HTTP-facing session method.
//
// A Session issues HMAC-bound 402 challenges carrying a SessionRequest
// (Challenge), verifies Authorization credentials whose payload is one of the
// five session actions (VerifyCredential dispatching to open / voucher /
// commit / topUp / close), exposes the reserve/commit metering side channel
// (Routes), and drives on-chain settlement at close when both a merchant
// signer and an RPC client are configured. The lower-level building blocks
// (SessionServer, ChannelStore, the voucher verifier, and the on-chain
// helpers) are composed here.
//
// The close settlement path, the idle-close watchdog, the re-drivable close,
// and the side-channel routes are extensions beyond the draft MPP spec and
// are documented as such where they extend it.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"reflect"
	"strconv"
	"time"

	solana "github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/rpc"

	"github.com/solana-foundation/pay-kit/go/paycore"
	"github.com/solana-foundation/pay-kit/go/paycore/solanatx"
	core "github.com/solana-foundation/pay-kit/go/protocols/mpp/core"
	"github.com/solana-foundation/pay-kit/go/protocols/mpp/intents"
)

// OpenTxSubmitter selects who broadcasts a push-mode payment-channel open
// transaction.
type OpenTxSubmitter string

// SettlementRPC is the additional RPC capability required when a Session is
// configured to settle merchant-signed payment channels. Keeping this separate
// from solanatx.RPCClient avoids breaking verification-only RPC consumers.
type SettlementRPC interface {
	solanatx.RPCClient
	GetBlockHeight(context.Context, rpc.CommitmentType) (uint64, error)
}

const (
	// OpenTxSubmitterClient means the client broadcasts the open transaction
	// itself and the server only verifies it. Default.
	OpenTxSubmitterClient OpenTxSubmitter = "client"

	// OpenTxSubmitterServer means the server completes the fee-payer
	// signature, broadcasts the client-built open transaction, and waits for
	// confirmation before persisting channel state.
	OpenTxSubmitterServer OpenTxSubmitter = "server"
)

// SessionOptions configures NewSession.
type SessionOptions struct {
	// Operator public key (base58), shown to clients in the challenge.
	Operator string

	// Recipient is the primary payment recipient (base58). Required.
	Recipient string

	// Cap is the maximum session cap the server will offer (base units).
	// Required, must be positive.
	Cap uint64

	// Currency identifier (e.g. "USDC" or an SPL mint address). Default USDC.
	Currency string

	// Decimals is the token decimals. Default 6.
	Decimals uint8

	// Network is the Solana network. Default "mainnet".
	Network string

	// SecretKey is the challenge HMAC secret. Defaults to MPP_SECRET_KEY.
	SecretKey string

	// Realm is the challenge realm. Defaults to DetectRealm().
	Realm string

	// ProgramID overrides the payment-channels program id. Nil defaults to
	// the canonical program.
	ProgramID *solana.PublicKey

	// MinVoucherDelta is the minimum voucher increment (base units). 0 = no
	// minimum.
	MinVoucherDelta uint64

	// Modes are the funding modes advertised to clients. Empty means push
	// only.
	Modes []intents.SessionMode

	// PullVoucherStrategy is the voucher authority for pull-mode sessions.
	// Required when Modes includes pull.
	PullVoucherStrategy *intents.SessionPullVoucherStrategy

	// Splits are optional basis-point splits distributed at close. Max 8.
	Splits []Split

	// CloseDelay arms the idle-close watchdog; zero disables it.
	CloseDelay time.Duration

	// OpenTxSubmitter selects who broadcasts push-mode open transactions.
	// Default OpenTxSubmitterClient.
	OpenTxSubmitter OpenTxSubmitter

	// Signer is the merchant signer for the settle_and_seal + distribute
	// settlement transaction. It requires RPC to implement SettlementRPC so
	// close and idle-close settlement can recover from expired transactions.
	Signer solanatx.Signer

	// PaymentChannelPayerSigner completes the fee-payer signature when the
	// server broadcasts a client-built open (OpenTxSubmitterServer).
	PaymentChannelPayerSigner solanatx.Signer

	// Store is the pluggable channel store. It is required off localnet so
	// session state is not silently process-local in production. Localnet
	// defaults to an in-memory store for development.
	Store ChannelStore

	// AllowUnsafeEphemeralStoreOffLocalnet permits the built-in process-local
	// memory store outside localnet. Unsafe; intended only for explicit dev use.
	AllowUnsafeEphemeralStoreOffLocalnet bool

	// RPC is the optional RPC client used for on-chain checks and recentBlockhash
	// prefetch. It must implement SettlementRPC when Signer is set; without a
	// signer, nil skips every on-chain check and trusts payload claims as
	// provided.
	RPC solanatx.RPCClient
}

// Session is the server-side session method handler. Create with NewSession.
type Session struct {
	// core is the lower-level SessionServer dispatching open / voucher /
	// commit / topUp / close against the channel store.
	core *SessionServer

	// lifecycle is the idle-close watchdog; nil when CloseDelay is zero.
	lifecycle *SessionLifecycle

	// secretKey is the HMAC secret binding 402 challenges to this server.
	secretKey string

	// realm is the challenge realm advertised in 402 responses.
	realm string

	// cap is the maximum session cap offered in challenges (token base
	// units); per-challenge requested caps are clamped to it.
	cap uint64

	// currency is the challenge currency (symbol such as "USDC" or an SPL
	// mint address).
	currency string

	// recipient is the primary payment recipient pubkey (base58).
	recipient string

	// network is the Solana network ("mainnet", "devnet", "localnet").
	network string

	// openTxSubmitter selects whether the client or the server broadcasts
	// push-mode open transactions.
	openTxSubmitter OpenTxSubmitter

	// signer is the merchant signer for the close settlement transaction;
	// settlement only runs when both signer and rpc are configured.
	signer solanatx.Signer

	// payerSigner completes the fee-payer signature on server-broadcast
	// opens (OpenTxSubmitterServer).
	payerSigner solanatx.Signer

	// rpc is the optional RPC client for on-chain checks, the blockhash
	// prefetch, and settlement broadcasts; nil skips every on-chain check
	// and trusts payload claims as provided.
	rpc solanatx.RPCClient
}

func isNilOption(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

// NewSession creates the server-side session method.
func NewSession(options SessionOptions) (*Session, error) {
	if options.Cap == 0 {
		return nil, core.NewError(core.ErrCodeInvalidConfig, "cap must be positive")
	}
	if options.Recipient == "" {
		return nil, core.NewError(core.ErrCodeInvalidConfig, "recipient is required")
	}
	if _, err := solana.PublicKeyFromBase58(options.Recipient); err != nil {
		return nil, core.WrapError(core.ErrCodeInvalidConfig, "invalid recipient pubkey", err)
	}
	if len(options.Splits) > maxSplits {
		return nil, core.NewError(core.ErrCodeInvalidConfig,
			fmt.Sprintf("splits cannot exceed %d entries", maxSplits))
	}
	if options.SecretKey == "" {
		options.SecretKey = DetectSecretKey()
	}
	if options.SecretKey == "" {
		return nil, core.NewError(core.ErrCodeInvalidConfig, "missing secret key")
	}
	if options.Currency == "" {
		options.Currency = "USDC"
	}
	if options.Decimals == 0 {
		options.Decimals = 6
	}
	if options.Network == "" {
		options.Network = "mainnet"
	}
	if options.Realm == "" {
		options.Realm = DetectRealm(options.Recipient)
	}
	switch options.OpenTxSubmitter {
	case "":
		options.OpenTxSubmitter = OpenTxSubmitterClient
	case OpenTxSubmitterClient, OpenTxSubmitterServer:
	default:
		return nil, core.NewError(core.ErrCodeInvalidConfig,
			fmt.Sprintf("openTxSubmitter must be %q or %q, got %q",
				OpenTxSubmitterClient, OpenTxSubmitterServer, options.OpenTxSubmitter))
	}
	supportsPull := false
	for _, mode := range options.Modes {
		if mode == intents.SessionModePull {
			supportsPull = true
		}
	}
	if supportsPull && options.PullVoucherStrategy == nil {
		return nil, core.NewError(core.ErrCodeInvalidConfig,
			"pullVoucherStrategy is required when modes includes pull")
	}
	store := options.Store
	if store == nil {
		if options.Network != "localnet" {
			return nil, core.NewError(core.ErrCodeInvalidConfig,
				"session store is required off localnet; inject a durable shared ChannelStore")
		}
		store = NewMemoryChannelStore()
	}
	if options.Network != "localnet" && !options.AllowUnsafeEphemeralStoreOffLocalnet && !isDurableSharedSessionStore(store) {
		return nil, core.NewError(core.ErrCodeInvalidConfig,
			sessionStoreSafetyMessage(store))
	}
	signerConfigured := !isNilOption(options.Signer)
	rpcConfigured := !isNilOption(options.RPC)
	if options.Signer != nil && !signerConfigured {
		return nil, core.NewError(core.ErrCodeInvalidConfig, "signer must not be a typed nil")
	}
	if options.RPC != nil && !rpcConfigured {
		return nil, core.NewError(core.ErrCodeInvalidConfig, "RPC must not be a typed nil")
	}
	if signerConfigured && !rpcConfigured {
		return nil, core.NewError(core.ErrCodeInvalidConfig,
			"session settlement RPC is required when signer is configured")
	}
	if signerConfigured {
		_, ok := options.RPC.(SettlementRPC)
		if !ok {
			return nil, core.NewError(core.ErrCodeInvalidConfig,
				"session settlement RPC must implement GetBlockHeight")
		}
	}

	config := SessionConfig{
		Operator:                             options.Operator,
		Recipient:                            options.Recipient,
		Splits:                               options.Splits,
		MaxCap:                               options.Cap,
		Currency:                             options.Currency,
		Decimals:                             options.Decimals,
		Network:                              options.Network,
		ProgramID:                            options.ProgramID,
		MinVoucherDelta:                      options.MinVoucherDelta,
		Modes:                                options.Modes,
		PullVoucherStrategy:                  options.PullVoucherStrategy,
		AllowUnsafeEphemeralStoreOffLocalnet: options.AllowUnsafeEphemeralStoreOffLocalnet,
	}
	if options.RPC != nil {
		config.VerifyOpenTx = NewOpenTxVerifier(config, options.RPC)
		config.VerifyOpenStateTx = NewOpenStateTxVerifier(config, options.RPC)
	}
	config.VerifyTopUpStateTx = NewTopUpStateTxVerifier(config, options.RPC)
	session := &Session{
		core:            NewSessionServer(config, store),
		secretKey:       options.SecretKey,
		realm:           options.Realm,
		cap:             options.Cap,
		currency:        options.Currency,
		recipient:       options.Recipient,
		network:         options.Network,
		openTxSubmitter: options.OpenTxSubmitter,
		signer:          options.Signer,
		payerSigner:     options.PaymentChannelPayerSigner,
		rpc:             options.RPC,
	}
	if options.CloseDelay > 0 {
		session.lifecycle = NewSessionLifecycle(session.closeOnIdle, options.CloseDelay)
	}
	return session, nil
}

// Core returns the underlying SessionServer so hosts can reach the channel
// store and the lower-level lifecycle methods.
func (s *Session) Core() *SessionServer { return s.core }

// Shutdown cancels the idle-close watchdog timers. Hosts should call it when
// tearing the session method down.
func (s *Session) Shutdown() {
	if s.lifecycle != nil {
		s.lifecycle.Shutdown()
	}
}

// touch resets the idle-close timer for channelID when the watchdog is armed.
func (s *Session) touch(channelID string) {
	if s.lifecycle != nil {
		s.lifecycle.Touch(channelID)
	}
}

// closeOnIdle is the idle-close watchdog handler: always flip the channel to
// close-pending, then settle on-chain when both a merchant signer and an RPC
// client are configured. Errors have no synchronous caller to report to and
// are logged instead.
func (s *Session) closeOnIdle(channelID string) {
	if _, err := s.handleClose(context.Background(), &intents.ClosePayload{ChannelID: channelID}); err != nil {
		log.Printf("[solana-mpp] idle-close settle failed for %s: %v", channelID, err)
	}
}

// SessionChallengeOptions customize a single 402 session challenge.
type SessionChallengeOptions struct {
	// Cap is the requested session cap (base units, decimal string). Empty
	// uses the server maximum; larger requests are clamped to it.
	Cap string

	// Description is a human-readable challenge description.
	Description string

	// ExternalID is a merchant reference id echoed on the receipt.
	ExternalID string

	// Expires is the challenge expiry (RFC 3339). Default five minutes.
	Expires string
}

// Challenge builds the HMAC-bound 402 challenge embedding a SessionRequest.
//
// The requested cap is clamped to the server maximum, minVoucherDelta is
// included only when positive, modes are omitted when push-only,
// pullVoucherStrategy is included only when pull is offered, and a recent
// blockhash plus the current slot (the channel openSlot) are prefetched
// (non-fatally) when an RPC client is configured. Both come from the
// injected RPC client rather than a raw URL fetch so unit tests stay
// offline; clients never fetch the slot themselves.
func (s *Session) Challenge(ctx context.Context, options SessionChallengeOptions) (core.PaymentChallenge, error) {
	capValue := s.cap
	if options.Cap != "" {
		requested, err := parseSessionU64(options.Cap, "cap")
		if err != nil {
			return core.PaymentChallenge{}, core.WrapError(core.ErrCodeInvalidPayload, "invalid requested cap", err)
		}
		capValue = requested
	}
	request := s.core.BuildChallengeRequest(capValue)
	if options.Description != "" {
		description := options.Description
		request.Description = &description
	}
	if options.ExternalID != "" {
		externalID := options.ExternalID
		request.ExternalID = &externalID
	}
	if s.rpc != nil {
		// Non-fatal: the client fetches its own blockhash when absent, and an
		// omitted recentSlot fails the client's open derivation with a clear
		// error rather than failing the challenge.
		if out, err := s.rpc.GetLatestBlockhash(ctx, rpc.CommitmentConfirmed); err == nil && out != nil && out.Value != nil {
			blockhash := out.Value.Blockhash.String()
			request.RecentBlockhash = &blockhash
			// The blockhash response's context already carries the current
			// slot, so recentSlot needs no extra RPC round-trip. A zero slot
			// means the (test-fake) response omitted the context; skip it.
			if out.Context.Slot > 0 {
				recentSlot := intents.U64String(out.Context.Slot)
				request.RecentSlot = &recentSlot
			}
		}
	}
	requestValue, err := core.NewBase64URLJSONValue(request)
	if err != nil {
		return core.PaymentChallenge{}, err
	}
	expires := options.Expires
	if expires == "" {
		expires = core.Minutes(5)
	}
	return core.NewChallengeWithSecretFull(
		s.secretKey,
		s.realm,
		core.NewMethodName("solana"),
		core.NewIntentName("session"),
		requestValue,
		expires,
		"",
		options.Description,
		nil,
	), nil
}

// VerifyCredential verifies a session Authorization credential: Tier-1 HMAC
// and expiry, the Tier-2 pinned-field backstop, then dispatch on the payload
// action (open / voucher / commit / topUp / close).
func (s *Session) VerifyCredential(ctx context.Context, credential core.PaymentCredential) (core.Receipt, error) {
	challenge := core.PaymentChallenge{
		ID:      credential.Challenge.ID,
		Realm:   credential.Challenge.Realm,
		Method:  credential.Challenge.Method,
		Intent:  credential.Challenge.Intent,
		Request: credential.Challenge.Request,
		Expires: credential.Challenge.Expires,
		Digest:  credential.Challenge.Digest,
		Opaque:  credential.Challenge.Opaque,
	}
	if !challenge.Verify(s.secretKey) {
		return core.Receipt{}, core.NewError(core.ErrCodeChallengeMismatch, "challenge ID mismatch")
	}
	if challenge.IsExpired(time.Now()) {
		return core.Receipt{}, core.NewError(core.ErrCodeChallengeExpired,
			fmt.Sprintf("challenge expired at %s", challenge.Expires))
	}
	var request intents.SessionRequest
	if err := challenge.Request.Decode(&request); err != nil {
		return core.Receipt{}, err
	}
	if err := s.verifyPinnedSessionFields(credential, request); err != nil {
		return core.Receipt{}, err
	}
	var action intents.SessionAction
	if err := credential.PayloadAs(&action); err != nil {
		return core.Receipt{}, core.WrapError(core.ErrCodeInvalidPayload, "decode session action", err)
	}

	var reference string
	var err error
	switch {
	case action.Open != nil:
		// A signature-only push open has no transaction bytes to establish
		// the channel incarnation. It must echo the challenge's recentSlot;
		// accepting omission would let a confirmed signature for another PDA
		// incarnation be paired with this challenge.
		if action.Open.Mode == intents.SessionModePush && request.RecentSlot != nil &&
			action.Open.Transaction == nil && action.Open.ChannelID != nil {
			if action.Open.RecentSlot == nil {
				return core.Receipt{}, core.NewError(core.ErrCodeInvalidPayload,
					"signature-only push open requires recentSlot")
			}
		}
		if request.RecentSlot != nil && action.Open.RecentSlot != nil &&
			uint64(*request.RecentSlot) != *action.Open.RecentSlot {
			return core.Receipt{}, core.NewError(core.ErrCodeInvalidPayload,
				fmt.Sprintf("open payload recentSlot %d does not match the challenge recentSlot %d",
					*action.Open.RecentSlot, uint64(*request.RecentSlot)))
		}
		reference, err = s.handleOpen(ctx, action.Open, request.RecentSlot)
	case action.Voucher != nil:
		reference, err = s.handleVoucher(ctx, action.Voucher)
	case action.Commit != nil:
		reference, err = s.handleCommit(ctx, action.Commit)
	case action.TopUp != nil:
		reference, err = s.handleTopUp(ctx, action.TopUp)
	case action.Close != nil:
		reference, err = s.handleClose(ctx, action.Close)
	default:
		return core.Receipt{}, core.NewError(core.ErrCodeInvalidPayload, "unknown session action")
	}
	if err != nil {
		return core.Receipt{}, err
	}
	externalID := ""
	if request.ExternalID != nil {
		externalID = *request.ExternalID
	}
	return successReceipt(reference, credential.Challenge.ID, externalID), nil
}

// verifyPinnedSessionFields is the Tier-2 backstop for session credentials:
// after Tier-1 HMAC confirms the challenge was issued by this server, fields
// fixed at construction time are compared so a credential issued by a
// different method/intent/realm or for a different recipient/currency cannot
// reach the action handlers. Same rationale as the charge handler's
// verifyPinnedFields.
func (s *Session) verifyPinnedSessionFields(credential core.PaymentCredential, request intents.SessionRequest) error {
	const methodName = "solana"
	if string(credential.Challenge.Method) != methodName {
		return core.NewError(core.ErrCodeChallengeRouteMismatch,
			fmt.Sprintf("credential method %q does not match this server (expected %q)",
				credential.Challenge.Method, methodName))
	}
	if !credential.Challenge.Intent.IsSession() {
		return core.NewError(core.ErrCodeChallengeRouteMismatch,
			fmt.Sprintf("credential intent %q is not a session", credential.Challenge.Intent))
	}
	if credential.Challenge.Realm != s.realm {
		return core.NewError(core.ErrCodeChallengeRouteMismatch,
			fmt.Sprintf("credential realm %q does not match this server (expected %q)",
				credential.Challenge.Realm, s.realm))
	}
	if request.Currency != s.currency {
		return core.NewError(core.ErrCodeChallengeRouteMismatch,
			fmt.Sprintf("credential currency %q does not match this server (expected %q)",
				request.Currency, s.currency))
	}
	if request.Recipient != s.recipient {
		return core.NewError(core.ErrCodeRecipientMismatch,
			"credential recipient does not match this server")
	}
	return nil
}

// handleOpen processes an open action: resolve the channel facts from the
// payload (verifying or broadcasting the attached transaction when present),
// enforce the deposit invariants, and insert the channel state atomically and
// idempotently.
func (s *Session) handleOpen(ctx context.Context, payload *intents.OpenPayload, challengeRecentSlot *intents.U64String) (string, error) {
	mode := payload.Mode
	if !s.core.supportsMode(mode) {
		return "", fmt.Errorf("session mode %q is not supported by this challenge", mode)
	}
	if mode == intents.SessionModePull && s.core.config.PullVoucherStrategy == nil {
		return "", fmt.Errorf("pull-mode open requires a pullVoucherStrategy on the server config")
	}
	// Empty strings count as missing.
	hasTransaction := payload.Transaction != nil && *payload.Transaction != ""
	hasChannelID := payload.ChannelID != nil && *payload.ChannelID != ""
	if mode == intents.SessionModePush && !hasTransaction && !hasChannelID {
		return "", fmt.Errorf("open payload missing transaction or channelId")
	}

	var channelID string
	var deposit uint64
	signature := payload.Signature
	// Channel payer (the deposit funder / distribute refund destination, which
	// the program pins to channel.payer), captured from the verified open when
	// a transaction is present.
	var channelPayer string
	// Channel open_slot (a PDA seed), read from the verified open transaction
	// when one is present, else from the payload's recentSlot echo.
	openSlot := openSlotFromPayload(payload)
	var salt uint64
	var openSignature string
	var verifiedOpen VerifyOpenTxResult

	switch {
	case hasTransaction:
		// Payment-channel-backed open: push sessions and clientVoucher pull
		// sessions whose deposit lives in an on-chain payment channel both
		// attach the pre-signed open transaction.
		expected := VerifyOpenTxExpected{
			AuthorizedSigner: payload.AuthorizedSigner,
			Currency:         s.currency,
			MaxCap:           s.cap,
			Network:          s.network,
			Operator:         s.core.config.Operator,
			ProgramID:        s.core.config.ProgramID,
			Recipient:        s.recipient,
			Splits:           s.core.config.Splits,
			GracePeriod:      expectedSessionGracePeriod(s.core.config),
		}
		if challengeRecentSlot != nil {
			recentSlot := uint64(*challengeRecentSlot)
			expected.RecentSlot = &recentSlot
		}
		if s.openTxSubmitter == OpenTxSubmitterServer {
			if s.rpc == nil {
				return "", fmt.Errorf("openTxSubmitter=server requires an rpc client")
			}
			// Decode-only first so an idempotent replay of an
			// already-persisted open does not rebroadcast the transaction.
			preVerified, err := VerifyOpenTx(ctx, expected, payload, nil)
			if err != nil {
				return "", err
			}
			existing, err := s.core.store.GetChannel(ctx, preVerified.ChannelID)
			if err != nil {
				return "", err
			}
			if existing != nil {
				if existing.OpenSignature == "" {
					return "", fmt.Errorf("server-submitted open %s is missing its persisted broadcast signature", preVerified.ChannelID)
				}
				channelID = preVerified.ChannelID
				deposit = preVerified.Deposit
				channelPayer = preVerified.Payer
				openSlot = preVerified.OpenSlot
				salt = preVerified.Salt
				signature = existing.OpenSignature
				openSignature = existing.OpenSignature
				verifiedOpen = preVerified
			} else {
				submitted, err := SubmitOpenTx(ctx, expected, payload, s.payerSigner, s.rpc)
				if err != nil {
					return "", err
				}
				channelID = submitted.ChannelID
				deposit = submitted.Deposit
				channelPayer = submitted.Payer
				openSlot = submitted.OpenSlot
				salt = submitted.Salt
				signature = submitted.Signature
				openSignature = submitted.Signature
				verifiedOpen = submitted.VerifyOpenTxResult
			}
		} else {
			verified, err := VerifyOpenTx(ctx, expected, payload, s.rpc)
			if err != nil {
				return "", err
			}
			if err := validateAssertedOpenDeposit(payload, verified.Deposit); err != nil {
				return "", err
			}
			verifiedOpen = verified
			channelID = verified.ChannelID
			deposit = verified.Deposit
			channelPayer = verified.Payer
			openSlot = verified.OpenSlot
			salt = verified.Salt
		}
		if s.rpc == nil {
			if s.network != "localnet" {
				return "", fmt.Errorf("payment-channel open requires an rpc client to bind the on-chain channel off localnet")
			}
		} else {
			confirmedSlot, err := confirmedTransactionSlot(ctx, s.rpc, signature, "open")
			if err != nil {
				return "", err
			}
			channelPDA, err := solana.PublicKeyFromBase58(channelID)
			if err != nil {
				return "", fmt.Errorf("invalid channelId %q: %w", channelID, err)
			}
			bound, err := fetchAndBindChannelAccount(
				ctx,
				s.rpc,
				channelPDA,
				paycore.ResolveMint(s.currency, s.network),
				s.recipient,
				s.core.config.Operator,
				payload.AuthorizedSigner,
				expectedSessionGracePeriod(s.core.config),
				sessionDistributionHash(s.core.config.Splits),
				true,
				s.core.config.ProgramID,
				confirmedSlot,
			)
			if err != nil {
				return "", err
			}
			if err := validateBoundOpenChannel(bound, &verifiedOpen, s.cap); err != nil {
				return "", err
			}
			if err := validateAssertedOpenDeposit(payload, bound.Deposit); err != nil {
				return "", err
			}
			deposit = bound.Deposit
			channelPayer = bound.Payer
			openSlot = bound.OpenSlot
			salt = bound.Salt
		}
	case mode == intents.SessionModePush:
		// No transaction in the payload: with an RPC client, fetch and
		// validate the transaction named by the signature before reading the
		// channel account. Without one, localnet keeps the explicit
		// trust-as-provided test seam.
		channelID = *payload.ChannelID
		if s.rpc != nil {
			expected := VerifyOpenTxExpected{
				AuthorizedSigner: payload.AuthorizedSigner,
				Currency:         s.currency,
				MaxCap:           s.cap,
				Network:          s.network,
				Operator:         s.core.config.Operator,
				ProgramID:        s.core.config.ProgramID,
				Recipient:        s.recipient,
				Splits:           s.core.config.Splits,
				GracePeriod:      expectedSessionGracePeriod(s.core.config),
			}
			if challengeRecentSlot != nil {
				recentSlot := uint64(*challengeRecentSlot)
				expected.RecentSlot = &recentSlot
			}
			verified, confirmedSlot, err := verifySignatureOnlyOpen(ctx, expected, payload, s.rpc)
			if err != nil {
				return "", err
			}
			channelID = verified.ChannelID
			channelPDA, err := solana.PublicKeyFromBase58(verified.ChannelID)
			if err != nil {
				return "", fmt.Errorf("invalid verified channelId %q: %w", verified.ChannelID, err)
			}
			bound, err := fetchAndBindChannelAccount(
				ctx,
				s.rpc,
				channelPDA,
				paycore.ResolveMint(s.currency, s.network),
				s.recipient,
				s.core.config.Operator,
				payload.AuthorizedSigner,
				expectedSessionGracePeriod(s.core.config),
				sessionDistributionHash(s.core.config.Splits),
				true,
				s.core.config.ProgramID,
				confirmedSlot,
			)
			if err != nil {
				return "", err
			}
			if err := validateBoundOpenChannel(bound, &verified, s.cap); err != nil {
				return "", err
			}
			if err := validateAssertedOpenDeposit(payload, bound.Deposit); err != nil {
				return "", err
			}
			deposit = bound.Deposit
			channelPayer = bound.Payer
			openSlot = bound.OpenSlot
			salt = bound.Salt
		} else if s.network != "localnet" {
			return "", fmt.Errorf("payment-channel push open requires an rpc client to bind the on-chain channel off localnet")
		} else {
			var err error
			deposit, err = payload.DepositAmount()
			if err != nil {
				return "", err
			}
		}
	default:
		// Pull mode without a channel transaction: trust the
		// channelId/tokenAccount + approvedAmount. Keying order is channelId
		// first, then tokenAccount.
		//
		// The Go SDK has no multi-delegate program builders, so
		// operated-voucher opens do not submit a multi-delegate init
		// transaction here (the client cannot produce those transactions
		// either; see go/README.md scope notes).
		var err error
		channelID, err = payload.SessionID()
		if err != nil {
			return "", err
		}
		deposit, err = payload.DepositAmount()
		if err != nil {
			return "", err
		}
	}

	if deposit == 0 {
		return "", fmt.Errorf("deposit must be greater than zero")
	}
	if deposit > s.cap {
		return "", fmt.Errorf("deposit %d exceeds cap %d", deposit, s.cap)
	}

	// Prefer the payer read from the verified open transaction (account 0, what
	// the channel actually records) over the client-supplied payload fields.
	operator := operatorFromVerifiedOpen(channelPayer, payload.Owner, payload.Payer)
	fresh := ChannelState{
		ChannelID:        channelID,
		AuthorizedSigner: payload.AuthorizedSigner,
		Deposit:          deposit,
		OpenSlot:         openSlot,
		Salt:             salt,
		OpenSignature:    openSignature,
		Operator:         operator,
	}

	// The existence check lives inside the atomic mutator so a concurrent
	// open replay cannot race a fresh create. Replays must never reset the
	// voucher watermark.
	if _, err := s.core.store.UpdateChannel(ctx, channelID, func(current *ChannelState) (ChannelState, error) {
		if current != nil {
			if current.Sealed {
				return ChannelState{}, fmt.Errorf("channel %s is already sealed", channelID)
			}
			if current.AuthorizedSigner != payload.AuthorizedSigner {
				return ChannelState{}, fmt.Errorf(
					"open replay: authorizedSigner %s does not match existing channel %s",
					payload.AuthorizedSigner, channelID)
			}
			return *current, nil
		}
		return fresh, nil
	}); err != nil {
		return "", err
	}
	s.touch(channelID)

	if signature == "" {
		return channelID, nil
	}
	return signature, nil
}

// handleVoucher verifies a cumulative voucher and advances the watermark.
// The receipt reference is "<channelId>:<cumulative>".
func (s *Session) handleVoucher(ctx context.Context, payload *intents.VoucherPayload) (string, error) {
	channelID := payload.Voucher.Data.ChannelID
	cumulative, err := s.core.VerifyVoucher(ctx, payload)
	if err != nil {
		return "", err
	}
	s.touch(channelID)
	return fmt.Sprintf("%s:%d", channelID, cumulative), nil
}

// handleCommit commits a reserved metered delivery. The receipt reference is
// "<sessionId>:<deliveryId>:<cumulative>".
func (s *Session) handleCommit(ctx context.Context, payload *intents.CommitPayload) (string, error) {
	receipt, err := s.core.ProcessCommit(ctx, payload)
	if err != nil {
		return "", err
	}
	s.touch(receipt.SessionID)
	return fmt.Sprintf("%s:%s:%s", receipt.SessionID, receipt.DeliveryID, receipt.Cumulative), nil
}

// handleTopUp raises a channel's deposit after optional on-chain
// confirmation of the top-up signature. The receipt reference is the top-up
// transaction signature.
func (s *Session) handleTopUp(ctx context.Context, payload *intents.TopUpPayload) (string, error) {
	newDeposit, err := parseSessionU64(payload.NewDeposit, "newDeposit")
	if err != nil {
		return "", err
	}
	if newDeposit > s.cap {
		return "", fmt.Errorf("newDeposit %d exceeds cap %d", newDeposit, s.cap)
	}

	// Cheap store pre-checks before touching the network.
	existing, err := s.core.store.GetChannel(ctx, payload.ChannelID)
	if err != nil {
		return "", err
	}
	if existing == nil {
		return "", fmt.Errorf("channel %s not found", payload.ChannelID)
	}
	if existing.Sealed {
		return "", fmt.Errorf("channel %s is already sealed", payload.ChannelID)
	}
	if existing.CloseRequestedAt != nil {
		return "", fmt.Errorf("channel %s close is pending; no further top-ups accepted", payload.ChannelID)
	}
	if _, err := s.core.ProcessTopUp(ctx, payload); err != nil {
		return "", err
	}
	s.touch(payload.ChannelID)
	return payload.Signature, nil
}

// handleClose accepts the optional final voucher, flips close-pending
// atomically, and settles on-chain when both a merchant signer and an RPC
// client are configured. The receipt reference is the on-chain settle
// signature when one exists, else the channel id.
//
// Unlike SessionServer.ProcessClose, where a second close is always rejected,
// the close here is re-drivable while the channel remains unsealed. A retry
// either starts a fresh settlement or re-confirms the previously persisted
// broadcast signature, so an uncertain confirmation cannot strand the channel
// or cause a duplicate broadcast.
func (s *Session) handleClose(ctx context.Context, payload *intents.ClosePayload) (string, error) {
	channelID := payload.ChannelID
	now := uint64(time.Now().Unix())

	if _, err := s.core.store.UpdateChannel(ctx, channelID, func(current *ChannelState) (ChannelState, error) {
		if current == nil {
			return ChannelState{}, fmt.Errorf("channel %s not found", channelID)
		}
		if current.Sealed {
			return ChannelState{}, fmt.Errorf("channel %s is already sealed", channelID)
		}
		if current.CloseRequestedAt != nil {
			// Re-drivable close: leave state untouched and let settlement
			// either start or re-confirm its persisted signature.
			return *current, nil
		}

		next := *current
		closeRequestedAt := now
		if payload.Voucher != nil {
			voucher := *payload.Voucher
			// Idempotent replay of the current highest voucher (same
			// cumulative AND same signature) is accepted as-is.
			replay := current.HighestVoucherSignature != nil &&
				*current.HighestVoucherSignature == voucher.Signature &&
				voucher.Data.Cumulative == strconv.FormatUint(current.Cumulative, 10)
			if !replay {
				verdict := VerifyVoucherForChannel(VerifyVoucherArgs{
					State:                   *current,
					Signed:                  voucher,
					Deposit:                 current.Deposit,
					SettlementWindowSeconds: s.core.config.SettlementWindowSeconds,
				})
				switch verdict.Status {
				case VoucherVerifyRejected:
					// A non-replay final voucher at or below the watermark is
					// a hard error: the close must abort rather than silently
					// settle a stale amount.
					return ChannelState{}, fmt.Errorf("%s: %s", verdict.Reason, verdict.Detail)
				case VoucherVerifyAccepted:
					next.Cumulative = verdict.NewCumulative
					signature := verdict.NewSignature
					expiresAt := verdict.NewExpiresAt
					next.HighestVoucherSignature = &signature
					next.HighestVoucherExpiresAt = &expiresAt
				}
			} else {
				// Recheck expiry/window even on idempotent replay so the HTTP close
				// path doesn't record close-pending against a voucher that no longer
				// outlasts the settlement window (mirrors ProcessClose).
				if err := verifySessionVoucher(voucher, current.AuthorizedSigner, s.core.config.SettlementWindowSeconds); err != nil {
					return ChannelState{}, err
				}
			}
		}
		next.CloseRequestedAt = &closeRequestedAt
		return next, nil
	}); err != nil {
		return "", err
	}

	reference := channelID
	if s.signer != nil && s.rpc != nil {
		settleSignature, err := s.closeAndSettleChannel(ctx, channelID)
		if err != nil {
			return "", err
		}
		if settleSignature != "" {
			reference = settleSignature
		}
	}
	if s.lifecycle != nil {
		s.lifecycle.RemoveChannel(channelID)
	}
	return reference, nil
}

var (
	errSettlementChannelMissing = errors.New("settlement channel missing")
	errSettlementAlreadySealed  = errors.New("settlement already sealed")
	errSettlementAlreadyClaimed = errors.New("settlement already claimed")
)

const (
	settlementStateWriteTimeout = 5 * time.Second
	settlementClaimLease        = 30 * time.Second
)

type definiteSettlementFailure struct {
	detail any
}

type expiredSettlementOutbox struct {
	currentBlockHeight uint64
	lastValidHeight    uint64
}

func (e *expiredSettlementOutbox) Error() string {
	return fmt.Sprintf("settlement transaction expired at block height %d (current %d)", e.lastValidHeight, e.currentBlockHeight)
}

func (e *definiteSettlementFailure) Error() string {
	return fmt.Sprintf("settlement transaction failed on-chain: %v", e.detail)
}

func settlementStateContext(parent context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(parent), settlementStateWriteTimeout)
}

func newSettlementClaimOwner() (string, error) {
	var token [16]byte
	if _, err := rand.Read(token[:]); err != nil {
		return "", fmt.Errorf("generate settlement claim owner: %w", err)
	}
	return hex.EncodeToString(token[:]), nil
}

func waitForSettlementConfirmation(ctx context.Context, rpcClient SettlementRPC, signature solana.Signature, lastValidBlockHeight uint64) error {
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	for {
		out, err := rpcClient.GetSignatureStatuses(ctx, true, signature)
		notFound := err == nil && (out == nil || len(out.Value) == 0 || out.Value[0] == nil)
		if err == nil && out != nil && len(out.Value) > 0 && out.Value[0] != nil {
			status := out.Value[0]
			if status.Err != nil {
				return &definiteSettlementFailure{detail: status.Err}
			}
			if status.ConfirmationStatus == rpc.ConfirmationStatusConfirmed ||
				status.ConfirmationStatus == rpc.ConfirmationStatusFinalized || status.Confirmations == nil {
				return nil
			}
		}
		if notFound && lastValidBlockHeight != 0 {
			currentBlockHeight, heightErr := rpcClient.GetBlockHeight(ctx, rpc.CommitmentConfirmed)
			if heightErr == nil && currentBlockHeight > lastValidBlockHeight {
				return &expiredSettlementOutbox{
					currentBlockHeight: currentBlockHeight,
					lastValidHeight:    lastValidBlockHeight,
				}
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

// closeAndSettleChannel atomically claims a channel, builds settle_and_seal
// (+ the Ed25519 precompile when a voucher was accepted) + distribute,
// submits them as one merchant-signed transaction, waits for confirmation,
// and only then seals the channel with the settled signature. Definitive
// failures clear the attempt; uncertain outcomes preserve the outbox for
// exact-wire retry. Returns "" when the channel does not exist or another
// caller currently owns a fresh signature-less settlement claim.
func (s *Session) closeAndSettleChannel(ctx context.Context, channelID string) (string, error) {
	settlementRPC, ok := s.rpc.(SettlementRPC)
	if !ok {
		return "", core.NewError(core.ErrCodeInvalidConfig,
			"session settlement requires an RPC implementing GetBlockHeight")
	}
	claimOwner, err := newSettlementClaimOwner()
	if err != nil {
		return "", err
	}
	claimedAt := time.Now()
	var recordedSignature string
	state, err := s.core.store.UpdateChannel(ctx, channelID, func(current *ChannelState) (ChannelState, error) {
		if current == nil {
			return ChannelState{}, errSettlementChannelMissing
		}
		if current.Sealed {
			if current.SettledSignature != nil {
				recordedSignature = *current.SettledSignature
			}
			return ChannelState{}, errSettlementAlreadySealed
		}
		if current.Settling && current.SettledSignature == nil {
			claimExpiresAt := time.Unix(current.SettlementClaimedAt, 0).Add(settlementClaimLease)
			if current.SettlementClaimedAt != 0 && claimedAt.Before(claimExpiresAt) {
				return ChannelState{}, errSettlementAlreadyClaimed
			}
		}
		next := *current
		next.Settling = true
		next.SettlementClaimOwner = claimOwner
		next.SettlementClaimedAt = claimedAt.Unix()
		return next, nil
	})
	if err != nil {
		switch {
		case errors.Is(err, errSettlementChannelMissing), errors.Is(err, errSettlementAlreadyClaimed):
			return "", nil
		case errors.Is(err, errSettlementAlreadySealed):
			return recordedSignature, nil
		default:
			return "", err
		}
	}

	clearAttempt := func(settlementErr error, clearOutbox bool) (string, error) {
		// Definitive failures clear the owner-checked attempt under a detached,
		// bounded context. Uncertain failures do not call this helper: their
		// claim and exact signed wire remain durable for idempotent retry.
		writeCtx, cancel := settlementStateContext(ctx)
		defer cancel()
		_, releaseErr := s.core.store.UpdateChannel(writeCtx, channelID, func(current *ChannelState) (ChannelState, error) {
			if current == nil {
				return ChannelState{}, fmt.Errorf("channel %s disappeared while releasing settlement claim", channelID)
			}
			if current.Sealed || !current.Settling || current.SettlementClaimOwner != claimOwner {
				return *current, nil
			}
			next := *current
			next.Settling = false
			next.SettlementClaimOwner = ""
			next.SettlementClaimedAt = 0
			if clearOutbox {
				next.SettledSignature = nil
				next.SettlementWire = ""
				next.SettlementLastValidBlockHeight = 0
			}
			return next, nil
		})
		if releaseErr != nil {
			return "", errors.Join(settlementErr, fmt.Errorf("release settlement claim: %w", releaseErr))
		}
		return "", settlementErr
	}

	merchant := s.signer.PublicKey()
	var signature solana.Signature
	var settlementTx *solana.Transaction
	lastValidBlockHeight := state.SettlementLastValidBlockHeight
	if state.SettlementWire != "" && state.SettledSignature == nil {
		return clearAttempt(errors.New("stored settlement wire has no signature"), true)
	}
	if state.SettledSignature != nil {
		signature, err = solana.SignatureFromBase58(*state.SettledSignature)
		if err != nil {
			return clearAttempt(fmt.Errorf("invalid stored settlement signature %q: %w", *state.SettledSignature, err), true)
		}
		if state.SettlementWire != "" {
			settlementTx, err = solanatx.DecodeTransactionBase64(state.SettlementWire)
			if err != nil {
				return clearAttempt(fmt.Errorf("decode stored settlement wire: %w", err), true)
			}
			if len(settlementTx.Signatures) == 0 || settlementTx.Signatures[0] != signature {
				return clearAttempt(errors.New("stored settlement wire does not match its signature"), true)
			}
		}
	} else {
		// The distribute refund goes to the channel payer (the program enforces
		// payer == channel.payer), recorded as state.Operator at open. Never fall
		// back to the recipient: refunding the merchant would derive the wrong
		// refund token account and fail settlement on-chain — settlement errors
		// instead when the payer was never recorded.
		instructions, err := s.core.settlementInstructionsForState(state, channelID, merchant)
		if err != nil {
			return clearAttempt(err, true)
		}
		blockhash, err := settlementRPC.GetLatestBlockhash(ctx, rpc.CommitmentConfirmed)
		if err != nil {
			return clearAttempt(core.WrapError(core.ErrCodeRPC, "fetch settlement blockhash", err), true)
		}
		if blockhash == nil || blockhash.Value == nil {
			return clearAttempt(core.NewError(core.ErrCodeRPC, "fetch settlement blockhash: empty response"), true)
		}
		tx, err := solana.NewTransaction(instructions, blockhash.Value.Blockhash, solana.TransactionPayer(merchant))
		if err != nil {
			return clearAttempt(fmt.Errorf("build settlement transaction: %w", err), true)
		}
		if err := solanatx.SignTransaction(tx, s.signer); err != nil {
			return clearAttempt(fmt.Errorf("sign settlement transaction: %w", err), true)
		}
		if len(tx.Signatures) == 0 || tx.Signatures[0].IsZero() {
			return clearAttempt(errors.New("signed settlement transaction has no fee-payer signature"), true)
		}
		settlementTx = tx
		signature = tx.Signatures[0]
		settled := signature.String()
		wire, err := solanatx.EncodeTransactionBase64(tx)
		if err != nil {
			return clearAttempt(fmt.Errorf("encode signed settlement transaction: %w", err), true)
		}
		lastValidBlockHeight = blockhash.Value.LastValidBlockHeight
		writeCtx, cancel := settlementStateContext(ctx)
		stored, persistErr := s.core.store.UpdateChannel(writeCtx, channelID, func(current *ChannelState) (ChannelState, error) {
			if current == nil {
				return ChannelState{}, fmt.Errorf("channel %s disappeared before settlement broadcast", channelID)
			}
			if current.Sealed {
				return *current, nil
			}
			if !current.Settling || current.SettlementClaimOwner != claimOwner {
				return ChannelState{}, fmt.Errorf("channel %s lost settlement claim before broadcast", channelID)
			}
			if current.SettledSignature != nil && *current.SettledSignature != settled {
				return ChannelState{}, fmt.Errorf("channel %s already records settlement signature %s", channelID, *current.SettledSignature)
			}
			next := *current
			next.SettledSignature = &settled
			next.SettlementWire = wire
			next.SettlementLastValidBlockHeight = lastValidBlockHeight
			return next, nil
		})
		cancel()
		if persistErr != nil {
			// Nothing has been sent. Keep the durable claim so another instance
			// waits for lease expiry before rebuilding the transaction.
			return "", fmt.Errorf("persist settlement signature before broadcast: %w", persistErr)
		}
		if stored.Sealed {
			if stored.SettledSignature != nil {
				return *stored.SettledSignature, nil
			}
			return settled, nil
		}
	}

	var sendErr error
	if settlementTx != nil {
		var sentSignature solana.Signature
		sentSignature, sendErr = solanatx.SendTransaction(ctx, settlementRPC, settlementTx)
		if sendErr == nil && sentSignature != signature {
			sendErr = fmt.Errorf("broadcast settlement signature %s != signed signature %s", sentSignature, signature)
		}
	}

	if err := waitForSettlementConfirmation(ctx, settlementRPC, signature, lastValidBlockHeight); err != nil {
		var definite *definiteSettlementFailure
		if errors.As(err, &definite) {
			return clearAttempt(core.WrapError(core.ErrCodeRPC, "confirm settlement transaction", err), true)
		}
		var expired *expiredSettlementOutbox
		if errors.As(err, &expired) {
			return clearAttempt(core.WrapError(core.ErrCodeRPC, "confirm settlement transaction", err), true)
		}
		confirmationErr := core.WrapError(core.ErrCodeRPC, "confirm settlement transaction", err)
		if sendErr != nil {
			return "", errors.Join(core.WrapError(core.ErrCodeRPC, "send settlement transaction", sendErr), confirmationErr)
		}
		return "", confirmationErr
	}

	settled := signature.String()
	reconcileCtx, cancel := settlementStateContext(ctx)
	defer cancel()
	stored, err := s.core.store.UpdateChannel(reconcileCtx, channelID, func(current *ChannelState) (ChannelState, error) {
		if current == nil {
			return ChannelState{}, fmt.Errorf("channel %s disappeared during settle", channelID)
		}
		if current.Sealed {
			return *current, nil
		}
		if current.SettledSignature == nil || *current.SettledSignature != settled {
			return ChannelState{}, fmt.Errorf("channel %s settlement signature changed before seal", channelID)
		}
		next := *current
		next.Sealed = true
		next.SettledSignature = &settled
		next.SettlementWire = ""
		next.SettlementLastValidBlockHeight = 0
		next.Settling = false
		next.SettlementClaimOwner = ""
		next.SettlementClaimedAt = 0
		return next, nil
	})
	if err != nil {
		return "", fmt.Errorf("persist confirmed settlement: %w", err)
	}
	if stored.SettledSignature != nil {
		return *stored.SettledSignature, nil
	}
	return settled, nil
}

// parseSessionU64 parses a non-negative decimal string into a u64, naming
// the field in the error.
func parseSessionU64(value, name string) (uint64, error) {
	parsed, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%s is not an unsigned integer string: %s", name, value)
	}
	return parsed, nil
}
