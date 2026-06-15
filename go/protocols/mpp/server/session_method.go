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
	"fmt"
	"log"
	"strconv"
	"time"

	solana "github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/rpc"

	"github.com/solana-foundation/pay-kit/go/paycore/solanatx"
	core "github.com/solana-foundation/pay-kit/go/protocols/mpp/core"
	"github.com/solana-foundation/pay-kit/go/protocols/mpp/intents"
)

// OpenTxSubmitter selects who broadcasts a push-mode payment-channel open
// transaction.
type OpenTxSubmitter string

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

	// Signer is the merchant signer for the settle_and_finalize + distribute
	// settlement transaction. Settlement at close (and on idle close) only
	// runs when both Signer and RPC are configured.
	Signer solanatx.Signer

	// PaymentChannelPayerSigner completes the fee-payer signature when the
	// server broadcasts a client-built open (OpenTxSubmitterServer).
	PaymentChannelPayerSigner solanatx.Signer

	// Store is the pluggable channel store. Defaults to in-memory.
	Store ChannelStore

	// RPC is the optional RPC client used for on-chain checks, the
	// recentBlockhash prefetch, and settlement broadcasts. Nil skips every
	// on-chain check and trusts payload claims as provided.
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
		options.Realm = DetectRealm()
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
		store = NewMemoryChannelStore()
	}

	config := SessionConfig{
		Operator:            options.Operator,
		Recipient:           options.Recipient,
		Splits:              options.Splits,
		MaxCap:              options.Cap,
		Currency:            options.Currency,
		Decimals:            options.Decimals,
		Network:             options.Network,
		ProgramID:           options.ProgramID,
		MinVoucherDelta:     options.MinVoucherDelta,
		Modes:               options.Modes,
		PullVoucherStrategy: options.PullVoucherStrategy,
	}
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

// closeOnIdle is the idle-close watchdog handler: settle the channel
// on-chain when both a merchant signer and an RPC client are configured.
// Errors have no synchronous caller to report to and are logged instead.
func (s *Session) closeOnIdle(channelID string) {
	if s.signer == nil || s.rpc == nil {
		return
	}
	if _, err := s.closeAndSettleChannel(context.Background(), channelID); err != nil {
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
// blockhash is prefetched (non-fatally) when an RPC client is configured.
// The blockhash source is the injected RPC client rather than a raw URL
// fetch so unit tests stay offline.
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
		// Non-fatal: the client fetches its own blockhash when absent.
		if out, err := s.rpc.GetLatestBlockhash(ctx, rpc.CommitmentConfirmed); err == nil && out != nil && out.Value != nil {
			blockhash := out.Value.Blockhash.String()
			request.RecentBlockhash = &blockhash
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
		reference, err = s.handleOpen(ctx, action.Open)
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
func (s *Session) handleOpen(ctx context.Context, payload *intents.OpenPayload) (string, error) {
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
			ProgramID:        s.core.config.ProgramID,
			Recipient:        s.recipient,
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
				channelID = preVerified.ChannelID
				deposit = preVerified.Deposit
			} else {
				submitted, err := SubmitOpenTx(ctx, expected, payload, s.payerSigner, s.rpc)
				if err != nil {
					return "", err
				}
				channelID = submitted.ChannelID
				deposit = submitted.Deposit
				signature = submitted.Signature
			}
		} else {
			verified, err := VerifyOpenTx(ctx, expected, payload, s.rpc)
			if err != nil {
				return "", err
			}
			channelID = verified.ChannelID
			deposit = verified.Deposit
		}
	case mode == intents.SessionModePush:
		// No transaction in the payload: the client asserts a previously
		// broadcast open. With an RPC client the open signature is confirmed
		// on-chain before persisting; without one the channelId/deposit
		// fields are trusted as-is.
		channelID = *payload.ChannelID
		var err error
		deposit, err = payload.DepositAmount()
		if err != nil {
			return "", err
		}
		if s.rpc != nil {
			if err := confirmTransactionSignature(ctx, s.rpc, signature, "open"); err != nil {
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

	operator := payload.Owner
	if operator == nil {
		operator = payload.Payer
	}
	fresh := ChannelState{
		ChannelID:        channelID,
		AuthorizedSigner: payload.AuthorizedSigner,
		Deposit:          deposit,
		Operator:         operator,
	}

	// The existence check lives inside the atomic mutator so a concurrent
	// open replay cannot race a fresh create. Replays must never reset the
	// voucher watermark.
	if _, err := s.core.store.UpdateChannel(ctx, channelID, func(current *ChannelState) (ChannelState, error) {
		if current != nil {
			if current.Finalized {
				return ChannelState{}, fmt.Errorf("channel %s is already finalized", channelID)
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
	if existing.Finalized {
		return "", fmt.Errorf("channel %s is already finalized", payload.ChannelID)
	}
	if existing.CloseRequestedAt != nil {
		return "", fmt.Errorf("channel %s close is pending; no further top-ups accepted", payload.ChannelID)
	}
	if s.rpc != nil {
		if err := confirmTransactionSignature(ctx, s.rpc, payload.Signature, "topUp"); err != nil {
			return "", err
		}
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
// Unlike SessionServer.ProcessClose, where a second close is always
// rejected, the close here is re-drivable: when a prior close flipped the
// close-pending flag but settlement never recorded a signature, the retry
// proceeds so a transient settlement failure cannot strand the channel.
func (s *Session) handleClose(ctx context.Context, payload *intents.ClosePayload) (string, error) {
	channelID := payload.ChannelID
	now := uint64(time.Now().Unix())

	if _, err := s.core.store.UpdateChannel(ctx, channelID, func(current *ChannelState) (ChannelState, error) {
		if current == nil {
			return ChannelState{}, fmt.Errorf("channel %s not found", channelID)
		}
		if current.Finalized {
			return ChannelState{}, fmt.Errorf("channel %s is already finalized", channelID)
		}
		if current.CloseRequestedAt != nil {
			if current.SettledSignature == nil {
				// Re-drivable close: leave state untouched and let the
				// settlement retry proceed.
				return *current, nil
			}
			return ChannelState{}, fmt.Errorf("close already requested")
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
					State:   *current,
					Signed:  voucher,
					Deposit: current.Deposit,
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

// closeAndSettleChannel builds settle_and_finalize (+ the Ed25519 precompile
// when a voucher was accepted) + distribute for a channel that has flipped
// to close-pending, submits them as one merchant-signed transaction, and
// marks the channel finalized with the settled signature. Returns "" when
// the channel does not exist.
func (s *Session) closeAndSettleChannel(ctx context.Context, channelID string) (string, error) {
	state, err := s.core.store.GetChannel(ctx, channelID)
	if err != nil {
		return "", err
	}
	if state == nil {
		return "", nil
	}
	merchant := s.signer.PublicKey()
	// The recipient backstops the distribute payer for channels that never
	// recorded an operator.
	instructions, err := s.core.settlementInstructionsForState(*state, channelID, merchant, s.recipient)
	if err != nil {
		return "", err
	}
	blockhash, err := s.rpc.GetLatestBlockhash(ctx, rpc.CommitmentConfirmed)
	if err != nil {
		return "", core.WrapError(core.ErrCodeRPC, "fetch settlement blockhash", err)
	}
	if blockhash == nil || blockhash.Value == nil {
		return "", core.NewError(core.ErrCodeRPC, "fetch settlement blockhash: empty response")
	}
	tx, err := solana.NewTransaction(instructions, blockhash.Value.Blockhash, solana.TransactionPayer(merchant))
	if err != nil {
		return "", fmt.Errorf("build settlement transaction: %w", err)
	}
	if err := solanatx.SignTransaction(tx, s.signer); err != nil {
		return "", fmt.Errorf("sign settlement transaction: %w", err)
	}
	signature, err := solanatx.SendTransaction(ctx, s.rpc, tx)
	if err != nil {
		return "", core.WrapError(core.ErrCodeRPC, "send settlement transaction", err)
	}
	settled := signature.String()
	if _, err := s.core.store.UpdateChannel(ctx, channelID, func(current *ChannelState) (ChannelState, error) {
		if current == nil {
			return ChannelState{}, fmt.Errorf("channel %s disappeared during settle", channelID)
		}
		next := *current
		next.Finalized = true
		next.SettledSignature = &settled
		return next, nil
	}); err != nil {
		return "", err
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
