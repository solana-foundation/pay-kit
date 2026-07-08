// Client-side session intent implementation.
//
// ActiveSession tracks an open payment channel and signs cumulative vouchers
// for each metered API call. Vouchers are Ed25519-signed over the on-chain
// Borsh voucher layout used by the payment-channels program, so the same bytes
// the server verifies on the HTTP credential are the bytes the on-chain settle
// instruction consumes.
//
// Scope is client-only PUSH (payment-channel) plus pull/clientVoucher, both
// served by the challenge-driven openers in payment_channels.go: the client
// signs cumulative vouchers off-chain over a payment channel the operator
// settles. Pull/operatedVoucher (the multi-delegator program), the SPL
// approve-delegation builder for non-channel pull opens, and the server
// verification path are out of scope.
//
// The language SDKs produce byte-identical voucher signatures and credentials;
// the cross-language interop harness pins this behavior.
package client

import (
	"fmt"
	"strconv"

	solana "github.com/gagliardetto/solana-go"

	"github.com/solana-foundation/pay-kit/go/paycore/paymentchannels"
	"github.com/solana-foundation/pay-kit/go/paycore/solanatx"
	core "github.com/solana-foundation/pay-kit/go/protocols/mpp/core"
	"github.com/solana-foundation/pay-kit/go/protocols/mpp/intents"
)

// VoucherSigner signs the 50-byte voucher preimage with the ephemeral session
// key. It is the minimal Ed25519 message-signing surface shared with the
// charge client (solanatx.Signer satisfies it), so memory signers, hardware
// wallets, and cloud KMS backends all work unchanged.
type VoucherSigner = solanatx.Signer

// ActiveSession tracks the client-side state of an active payment session.
//
// It holds the session signing key and advances the cumulative watermark with
// each signed voucher. Vouchers are cumulative high-water marks: each one MUST
// strictly exceed the previous, and the signer's public key is the
// authorizedSigner passed to the server in the open action.
//
// ActiveSession is not safe for concurrent use; serialize access from one
// goroutine or guard it with a mutex.
type ActiveSession struct {
	// channelID is the on-chain channel PDA the vouchers settle against; its
	// raw 32 bytes follow the 2-byte magic prefix in the 50-byte voucher
	// preimage.
	channelID solana.PublicKey

	// cumulative is the watermark in token base units: the cumulative total
	// covered by the last recorded voucher, not a per-request delta.
	cumulative uint64

	// nonce counts recorded vouchers; it is carried in the voucher JSON for
	// server bookkeeping but is not part of the signed 50-byte preimage.
	nonce uint64

	// expiresAt is the voucher expiry as Unix epoch seconds, encoded
	// little-endian into the final 8 bytes of each voucher preimage.
	expiresAt int64

	// signer is the ephemeral session key (the channel authorizedSigner)
	// that Ed25519-signs voucher preimages.
	signer VoucherSigner
}

// NewActiveSession creates a session tracker for the channel obtained after
// opening, signing vouchers with signer until DefaultSessionExpiresAt.
func NewActiveSession(channelID solana.PublicKey, signer VoucherSigner) *ActiveSession {
	return NewActiveSessionAt(channelID, signer, intents.DefaultSessionExpiresAt)
}

// NewActiveSessionAt creates a session tracker with an explicit voucher expiry.
func NewActiveSessionAt(channelID solana.PublicKey, signer VoucherSigner, expiresAt int64) *ActiveSession {
	return &ActiveSession{
		channelID: channelID,
		expiresAt: expiresAt,
		signer:    signer,
	}
}

// NewActiveSessionWithWatermark creates a session tracker resumed at a known
// settled cumulative watermark, e.g. when re-attaching to a channel the server
// already holds vouchers for. Only the cumulative watermark is resumed; the
// nonce starts at zero.
func NewActiveSessionWithWatermark(channelID solana.PublicKey, signer VoucherSigner, cumulative uint64, expiresAt int64) *ActiveSession {
	session := NewActiveSessionAt(channelID, signer, expiresAt)
	session.cumulative = cumulative
	return session
}

// SetExpiresAt updates the expiry timestamp used for subsequent vouchers.
func (s *ActiveSession) SetExpiresAt(expiresAt int64) { s.expiresAt = expiresAt }

// Cumulative returns the current cumulative watermark (base units).
func (s *ActiveSession) Cumulative() uint64 { return s.cumulative }

// Nonce returns the current voucher nonce counter.
func (s *ActiveSession) Nonce() uint64 { return s.nonce }

// ExpiresAt returns the expiry timestamp applied to new vouchers.
func (s *ActiveSession) ExpiresAt() int64 { return s.expiresAt }

// ChannelID returns the on-chain channel address.
func (s *ActiveSession) ChannelID() solana.PublicKey { return s.channelID }

// ChannelIDString returns the channel address as base58.
func (s *ActiveSession) ChannelIDString() string { return s.channelID.String() }

// AuthorizedSigner returns the session signing key as base58, for the open
// action payload.
func (s *ActiveSession) AuthorizedSigner() string { return s.signer.PublicKey().String() }

// SignVoucher signs a voucher with an absolute cumulative amount and advances
// the local watermark. cumulative MUST strictly exceed the current watermark.
func (s *ActiveSession) SignVoucher(cumulative uint64) (intents.SignedVoucher, error) {
	voucher, err := s.PrepareVoucher(cumulative)
	if err != nil {
		return intents.SignedVoucher{}, err
	}
	if err := s.RecordVoucher(voucher); err != nil {
		return intents.SignedVoucher{}, err
	}
	return voucher, nil
}

// SignIncrement signs a voucher adding amount to the current cumulative.
func (s *ActiveSession) SignIncrement(amount uint64) (intents.SignedVoucher, error) {
	next, err := addCumulative(s.cumulative, amount)
	if err != nil {
		return intents.SignedVoucher{}, err
	}
	return s.SignVoucher(next)
}

// PrepareVoucher signs a voucher without advancing the local watermark.
//
// This keeps ack/commit transports safe to retry: a failed commit can be
// retried with the same cumulative amount without the local state drifting
// ahead of the server. cumulative MUST strictly exceed the current watermark.
func (s *ActiveSession) PrepareVoucher(cumulative uint64) (intents.SignedVoucher, error) {
	if cumulative <= s.cumulative {
		return intents.SignedVoucher{}, fmt.Errorf(
			"voucher cumulative %d must exceed current watermark %d", cumulative, s.cumulative)
	}

	nonce := s.nonce + 1
	data := intents.VoucherData{
		ChannelID:  s.ChannelIDString(),
		Cumulative: strconv.FormatUint(cumulative, 10),
		ExpiresAt:  s.expiresAt,
		Nonce:      &nonce,
	}

	preimage, err := paymentchannels.VoucherMessageBytes(s.channelID, cumulative, s.expiresAt)
	if err != nil {
		return intents.SignedVoucher{}, fmt.Errorf("voucher preimage: %w", err)
	}
	sig, err := s.signer.Sign(preimage)
	if err != nil {
		return intents.SignedVoucher{}, fmt.Errorf("sign voucher: %w", err)
	}

	return intents.SignedVoucher{Data: data, Signature: sig.String()}, nil
}

// PrepareIncrement signs a voucher adding amount to the current cumulative
// without advancing the watermark.
func (s *ActiveSession) PrepareIncrement(amount uint64) (intents.SignedVoucher, error) {
	next, err := addCumulative(s.cumulative, amount)
	if err != nil {
		return intents.SignedVoucher{}, err
	}
	return s.PrepareVoucher(next)
}

// RecordVoucher advances the local watermark to a prepared voucher the server
// has accepted. The voucher cumulative MUST strictly exceed the current
// watermark; the nonce advances to the larger of the current nonce and the
// voucher nonce (or +1 when the voucher omits a nonce).
func (s *ActiveSession) RecordVoucher(voucher intents.SignedVoucher) error {
	if voucher.Data.ChannelID != s.ChannelIDString() {
		return fmt.Errorf(
			"voucher channel %s does not match active session %s",
			voucher.Data.ChannelID, s.ChannelIDString())
	}
	cumulative, err := parseCumulative(voucher.Data.Cumulative)
	if err != nil {
		return err
	}
	if cumulative <= s.cumulative {
		return fmt.Errorf(
			"voucher cumulative %d must exceed current watermark %d", cumulative, s.cumulative)
	}
	s.cumulative = cumulative
	candidate := s.nonce + 1
	if voucher.Data.Nonce != nil && *voucher.Data.Nonce > candidate {
		candidate = *voucher.Data.Nonce
	}
	s.nonce = candidate
	return nil
}

// ReconcileSettled reconciles the local watermark to a server-settled
// cumulative, e.g. the Cumulative of a replayed commit receipt. It advances to
// settled when that is ahead of the current watermark and never regresses, so
// retrying a delivery the server already accepted (lost-response case) catches
// the client up without recording the freshly prepared higher voucher.
//
// When it advances, the request nonce also advances by one, mirroring the
// RecordVoucher accounting for the delivery the server settled, so the next
// prepared voucher does not reuse the already-settled nonce.
func (s *ActiveSession) ReconcileSettled(settled uint64) {
	if settled > s.cumulative {
		s.cumulative = settled
		s.nonce++
	}
}

// VoucherAction signs a fresh increment and wraps it as a voucher action.
func (s *ActiveSession) VoucherAction(amount uint64) (intents.SessionAction, error) {
	voucher, err := s.SignIncrement(amount)
	if err != nil {
		return intents.SessionAction{}, err
	}
	return intents.NewVoucherAction(intents.VoucherPayload{Voucher: voucher}), nil
}

// CloseAction builds a cooperative close action. When finalIncrement > 0 it
// signs one last voucher for the remaining balance before closing; otherwise
// the close carries no voucher.
func (s *ActiveSession) CloseAction(finalIncrement uint64) (intents.SessionAction, error) {
	payload := intents.ClosePayload{ChannelID: s.ChannelIDString()}
	if finalIncrement > 0 {
		voucher, err := s.SignIncrement(finalIncrement)
		if err != nil {
			return intents.SessionAction{}, err
		}
		payload.Voucher = &voucher
	}
	return intents.NewCloseAction(payload), nil
}

// OpenAction builds a push-mode open action. Call this after the on-chain open
// transaction has confirmed; the session channel ID MUST match the confirmed
// channel address.
func (s *ActiveSession) OpenAction(deposit uint64, openTxSignature string) intents.SessionAction {
	return intents.NewOpenAction(intents.OpenPayloadPush(
		s.ChannelIDString(),
		strconv.FormatUint(deposit, 10),
		s.AuthorizedSigner(),
		openTxSignature,
	))
}

// OpenPaymentChannelAction builds a payment-channel push open action carrying
// the full channel parameters.
func (s *ActiveSession) OpenPaymentChannelAction(
	deposit uint64,
	payer, payee, mint string,
	salt uint64,
	gracePeriod uint32,
	openSlot uint64,
	openTxSignature string,
) intents.SessionAction {
	return s.OpenPaymentChannelActionWithMode(
		intents.SessionModePush, deposit, payer, payee, mint, salt, gracePeriod, openSlot, openTxSignature)
}

// OpenPaymentChannelActionWithMode builds a payment-channel open action with an
// explicit submission mode (push, or pull when the operator broadcasts).
func (s *ActiveSession) OpenPaymentChannelActionWithMode(
	mode intents.SessionMode,
	deposit uint64,
	payer, payee, mint string,
	salt uint64,
	gracePeriod uint32,
	openSlot uint64,
	openTxSignature string,
) intents.SessionAction {
	return intents.NewOpenAction(intents.OpenPayloadPaymentChannelWithMode(
		mode,
		s.ChannelIDString(),
		strconv.FormatUint(deposit, 10),
		payer, payee, mint,
		salt, gracePeriod, openSlot,
		s.AuthorizedSigner(),
		openTxSignature,
	))
}

// OpenPullAction builds a pull-mode (SPL delegation) open action. The session
// channel ID is used as the token account, so callers should construct the
// ActiveSession with the delegated token account pubkey as the channel ID.
func (s *ActiveSession) OpenPullAction(approvedAmount uint64, owner, approveTxSignature string) intents.SessionAction {
	return intents.NewOpenAction(intents.OpenPayloadPull(
		s.ChannelIDString(),
		strconv.FormatUint(approvedAmount, 10),
		owner,
		s.AuthorizedSigner(),
		approveTxSignature,
	))
}

// TopUpAction builds a top-up action after a top-up transaction confirms.
func (s *ActiveSession) TopUpAction(newDeposit uint64, topupTxSignature string) intents.SessionAction {
	return intents.NewTopUpAction(intents.TopUpPayload{
		ChannelID:  s.ChannelIDString(),
		NewDeposit: strconv.FormatUint(newDeposit, 10),
		Signature:  topupTxSignature,
	})
}

// SerializeSessionCredential builds an Authorization header value for a session
// action, echoing the challenge and JCS-canonicalizing the credential. The
// result is "Payment <base64url(JCS(PaymentCredential))>", the same credential
// framing used for every payment authorization on the wire.
func SerializeSessionCredential(challenge core.PaymentChallenge, action intents.SessionAction) (string, error) {
	credential, err := core.NewPaymentCredential(challenge.ToEcho(), action)
	if err != nil {
		return "", err
	}
	return core.FormatAuthorization(credential)
}

// ParseSessionChallenge parses a WWW-Authenticate header value into the
// challenge and the decoded session request.
//
// It rejects non-session intents so callers do not accidentally treat a charge
// challenge as a session.
func ParseSessionChallenge(header string) (core.PaymentChallenge, intents.SessionRequest, error) {
	challenge, err := core.ParseWWWAuthenticate(header)
	if err != nil {
		return core.PaymentChallenge{}, intents.SessionRequest{}, err
	}
	if !challenge.Intent.IsSession() {
		return core.PaymentChallenge{}, intents.SessionRequest{}, fmt.Errorf(
			"challenge intent %q is not a session", challenge.Intent)
	}
	var request intents.SessionRequest
	if err := challenge.Request.Decode(&request); err != nil {
		return core.PaymentChallenge{}, intents.SessionRequest{}, fmt.Errorf("decode session request: %w", err)
	}
	return challenge, request, nil
}

// addCumulative adds amount to current, rejecting u64 overflow so a wrapped
// watermark can never be signed.
func addCumulative(current, amount uint64) (uint64, error) {
	next := current + amount
	if next < current {
		return 0, fmt.Errorf("voucher cumulative overflows u64: %d + %d", current, amount)
	}
	return next, nil
}

// parseCumulative parses a decimal voucher cumulative into base units.
func parseCumulative(raw string) (uint64, error) {
	value, err := strconv.ParseUint(raw, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid voucher cumulative %q", raw)
	}
	return value, nil
}
