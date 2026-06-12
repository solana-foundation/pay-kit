package intents

// Session intent request and voucher types.
//
// The session intent opens a payment channel between a client and server,
// allowing incremental payments via off-chain signed vouchers backed by the
// on-chain payment-channels program. The JSON wire format is identical across
// the language SDKs; the cross-language harness pins it.

import (
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/gagliardetto/solana-go"

	"github.com/solana-foundation/pay-kit/go/paycore/paymentchannels"
)

// DefaultSessionExpiresAt is the default session voucher/directive expiry:
// 2100-01-01T00:00:00Z.
//
// This stays below JavaScript's max safe integer so JSON intermediaries do not
// round it before the credential is decoded.
const DefaultSessionExpiresAt int64 = 4_102_444_800

// SessionMode is the on-chain funding mechanism for a session.
//
// Advertised by the server in SessionRequest.Modes; the client picks the mode
// it will use when sending its open action.
type SessionMode string

const (
	// SessionModePush is a payment channel backed by an on-chain escrow
	// deposit (client-funded).
	SessionModePush SessionMode = "push"

	// SessionModePull is an operator-assisted pull session. Voucher authority
	// is declared separately via SessionPullVoucherStrategy.
	SessionModePull SessionMode = "pull"
)

// SessionPullVoucherStrategy is the voucher authority used when
// SessionModePull is advertised.
type SessionPullVoucherStrategy string

const (
	// SessionPullVoucherStrategyClientVoucher means the client signs
	// cumulative vouchers.
	SessionPullVoucherStrategyClientVoucher SessionPullVoucherStrategy = "clientVoucher"

	// SessionPullVoucherStrategyOperatedVoucher means the operator signs
	// vouchers after metering/receipts.
	SessionPullVoucherStrategyOperatedVoucher SessionPullVoucherStrategy = "operatedVoucher"
)

// CommitStatus is the commit receipt status.
type CommitStatus string

const (
	// CommitStatusCommitted is the first successful commit for the delivery.
	CommitStatusCommitted CommitStatus = "committed"

	// CommitStatusReplayed is an idempotent replay of a previously accepted
	// commit.
	CommitStatusReplayed CommitStatus = "replayed"
)

// SessionRequest is the session intent request — the payload embedded in a 402
// challenge. Describes the channel parameters: cap, currency, splits, network,
// etc.
type SessionRequest struct {
	// Cap is the maximum total amount the client may spend in this session
	// (base units).
	Cap string `json:"cap"`

	// Currency/asset identifier (e.g., "USDC", mint address).
	Currency string `json:"currency"`

	// Decimals is the token decimals (default 6 for USDC-like tokens).
	Decimals *uint8 `json:"decimals,omitempty"`

	// Network is the Solana network: "mainnet", "devnet", "localnet".
	Network *string `json:"network,omitempty"`

	// Operator (server) public key (base58).
	Operator string `json:"operator"`

	// Recipient is the primary recipient for channel proceeds (base58).
	Recipient string `json:"recipient"`

	// Splits are optional fixed portions routed to specific recipients at
	// close. Omitted when empty.
	Splits []SessionSplit `json:"splits,omitempty"`

	// ProgramID is the channel program ID (base58). Defaults to the canonical
	// payment-channels program.
	ProgramID *string `json:"programId,omitempty"`

	// Description is a human-readable description.
	Description *string `json:"description,omitempty"`

	// ExternalID is a merchant reference ID.
	ExternalID *string `json:"externalId,omitempty"`

	// MinVoucherDelta is the minimum voucher increment (base units). Prevents
	// micro-increment spam.
	MinVoucherDelta *string `json:"minVoucherDelta,omitempty"`

	// Modes are the session modes supported by this server.
	//
	// Omitted/empty means only SessionModePush is supported. The client MUST
	// use one of the advertised modes in its open action.
	Modes []SessionMode `json:"modes,omitempty"`

	// PullVoucherStrategy is the voucher authority for pull-mode sessions.
	//
	// Required when Modes includes SessionModePull. Omitted when pull is not
	// supported.
	PullVoucherStrategy *SessionPullVoucherStrategy `json:"pullVoucherStrategy,omitempty"`

	// RecentBlockhash is a recent blockhash pre-fetched by the server
	// (base58). Included when the client needs to build server-broadcast
	// transactions without a second RPC round-trip.
	RecentBlockhash *string `json:"recentBlockhash,omitempty"`
}

// SessionSplit is a payment split committed at channel open; distributed to a
// specific recipient when the channel closes.
type SessionSplit struct {
	// Recipient address (base58).
	Recipient string `json:"recipient"`

	// BPS is the share in basis points.
	BPS uint16 `json:"bps"`
}

// ── Client actions ──

// sessionActionTag is the discriminator used by SessionAction's tagged-union
// serialization. The wire values are camelCase; note "topUp", not "topup".
type sessionActionTag string

const (
	sessionActionOpen    sessionActionTag = "open"
	sessionActionVoucher sessionActionTag = "voucher"
	sessionActionCommit  sessionActionTag = "commit"
	sessionActionTopUp   sessionActionTag = "topUp"
	sessionActionClose   sessionActionTag = "close"
)

// SessionAction is the action submitted by the client in an Authorization
// header.
//
// Serialized as a tagged object with
// "action": "open" | "voucher" | "commit" | "topUp" | "close",
// with the payload fields flattened alongside the discriminator. Exactly one of
// the payload pointers is non-nil for a valid action.
type SessionAction struct {
	// Open a new channel/delegation and start the session.
	Open *OpenPayload

	// Voucher submits a signed voucher authorizing payment for an API call.
	Voucher *VoucherPayload

	// Commit a metered delivery by attaching a signed voucher.
	Commit *CommitPayload

	// TopUp an existing channel's deposit.
	TopUp *TopUpPayload

	// Close requests cooperative close of the channel.
	Close *ClosePayload
}

// NewOpenAction wraps an OpenPayload as a SessionAction.
func NewOpenAction(payload OpenPayload) SessionAction {
	return SessionAction{Open: &payload}
}

// NewVoucherAction wraps a VoucherPayload as a SessionAction.
func NewVoucherAction(payload VoucherPayload) SessionAction {
	return SessionAction{Voucher: &payload}
}

// NewCommitAction wraps a CommitPayload as a SessionAction.
func NewCommitAction(payload CommitPayload) SessionAction {
	return SessionAction{Commit: &payload}
}

// NewTopUpAction wraps a TopUpPayload as a SessionAction.
func NewTopUpAction(payload TopUpPayload) SessionAction {
	return SessionAction{TopUp: &payload}
}

// NewCloseAction wraps a ClosePayload as a SessionAction.
func NewCloseAction(payload ClosePayload) SessionAction {
	return SessionAction{Close: &payload}
}

// MarshalJSON flattens the active payload alongside an "action" discriminator.
func (a SessionAction) MarshalJSON() ([]byte, error) {
	var tag sessionActionTag
	var payload any
	count := 0
	if a.Open != nil {
		tag, payload = sessionActionOpen, a.Open
		count++
	}
	if a.Voucher != nil {
		tag, payload = sessionActionVoucher, a.Voucher
		count++
	}
	if a.Commit != nil {
		tag, payload = sessionActionCommit, a.Commit
		count++
	}
	if a.TopUp != nil {
		tag, payload = sessionActionTopUp, a.TopUp
		count++
	}
	if a.Close != nil {
		tag, payload = sessionActionClose, a.Close
		count++
	}
	if count == 0 {
		return nil, fmt.Errorf("session action: no variant set")
	}
	if count > 1 {
		return nil, fmt.Errorf("session action: multiple variants set")
	}

	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal session action payload: %w", err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil, fmt.Errorf("flatten session action payload: %w", err)
	}
	tagRaw, err := json.Marshal(string(tag))
	if err != nil {
		return nil, fmt.Errorf("marshal session action tag: %w", err)
	}
	fields["action"] = tagRaw
	out, err := json.Marshal(fields)
	if err != nil {
		return nil, fmt.Errorf("marshal session action: %w", err)
	}
	return out, nil
}

// UnmarshalJSON reads the "action" discriminator and decodes the flattened
// payload into the matching variant.
func (a *SessionAction) UnmarshalJSON(data []byte) error {
	var probe struct {
		Action sessionActionTag `json:"action"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return fmt.Errorf("read session action tag: %w", err)
	}

	*a = SessionAction{}
	switch probe.Action {
	case sessionActionOpen:
		var p OpenPayload
		if err := json.Unmarshal(data, &p); err != nil {
			return fmt.Errorf("decode open action: %w", err)
		}
		a.Open = &p
	case sessionActionVoucher:
		var p VoucherPayload
		if err := json.Unmarshal(data, &p); err != nil {
			return fmt.Errorf("decode voucher action: %w", err)
		}
		a.Voucher = &p
	case sessionActionCommit:
		var p CommitPayload
		if err := json.Unmarshal(data, &p); err != nil {
			return fmt.Errorf("decode commit action: %w", err)
		}
		a.Commit = &p
	case sessionActionTopUp:
		var p TopUpPayload
		if err := json.Unmarshal(data, &p); err != nil {
			return fmt.Errorf("decode topUp action: %w", err)
		}
		a.TopUp = &p
	case sessionActionClose:
		var p ClosePayload
		if err := json.Unmarshal(data, &p); err != nil {
			return fmt.Errorf("decode close action: %w", err)
		}
		a.Close = &p
	case "":
		return fmt.Errorf("session action: missing action discriminator")
	default:
		return fmt.Errorf("session action: unknown action %q", probe.Action)
	}
	return nil
}

// OpenPayload is the payload for the open action.
//
// Use OpenPayloadPush, OpenPayloadPaymentChannel, or OpenPayloadPull to
// construct. Inspect Mode to distinguish variants on the server.
//
// Salt marshals as a decimal string (authorization headers are JSON
// canonicalized, and arbitrary uint64 values are not safe JSON numbers) and
// decodes from either a string or a JSON number.
type OpenPayload struct {
	// Mode is the session mode discriminant. Required (no default).
	Mode SessionMode `json:"mode"`

	// ── Push mode ──

	// ChannelID is the payment-channel address (base58). Required for push
	// mode.
	ChannelID *string `json:"channelId,omitempty"`

	// Deposit locked on-chain (base units). Required for push mode.
	Deposit *string `json:"deposit,omitempty"`

	// Payer is the client wallet that funds the payment channel.
	Payer *string `json:"payer,omitempty"`

	// Payee is the primary channel payee.
	Payee *string `json:"payee,omitempty"`

	// Mint is the SPL mint locked in the channel.
	Mint *string `json:"mint,omitempty"`

	// Salt used in the channel PDA seeds. Serialized as a decimal string.
	Salt *uint64 `json:"-"`

	// GracePeriod used by the on-chain close path.
	GracePeriod *uint32 `json:"gracePeriod,omitempty"`

	// Transaction is the signed payment-channel open transaction (base64),
	// when the client wants the server/operator to broadcast it.
	Transaction *string `json:"transaction,omitempty"`

	// ── Pull mode ──

	// TokenAccount is the SPL token account being delegated (base58). Required
	// for pull mode.
	TokenAccount *string `json:"tokenAccount,omitempty"`

	// ApprovedAmount is the amount approved for operator delegation (base
	// units). Required for pull mode.
	ApprovedAmount *string `json:"approvedAmount,omitempty"`

	// Owner is the client wallet pubkey (base58). Required for pull mode.
	Owner *string `json:"owner,omitempty"`

	// InitMultiDelegateTx is a pre-signed transaction (base64) that creates
	// the MultiDelegate PDA and an initial FixedDelegation.
	InitMultiDelegateTx *string `json:"initMultiDelegateTx,omitempty"`

	// UpdateDelegationTx is a pre-signed transaction (base64) that creates or
	// raises the FixedDelegation cap.
	UpdateDelegationTx *string `json:"updateDelegationTx,omitempty"`

	// ── Shared ──

	// AuthorizedSigner is the public key authorized to sign vouchers for this
	// session (base58). Usually an ephemeral key generated by the client.
	AuthorizedSigner string `json:"authorizedSigner"`

	// Signature is the transaction signature (base58) proving the on-chain
	// action.
	Signature string `json:"signature"`
}

// openPayloadJSON is the wire shape of OpenPayload with salt typed as
// json.RawMessage so it can be encoded as a string and decoded from
// string-or-number.
type openPayloadJSON struct {
	Mode                SessionMode     `json:"mode"`                          // funding mode discriminant ("push" or "pull")
	ChannelID           *string         `json:"channelId,omitempty"`           // payment-channel address (base58); push mode
	Deposit             *string         `json:"deposit,omitempty"`             // on-chain escrow deposit (base units); push mode
	Payer               *string         `json:"payer,omitempty"`               // funding client wallet (base58)
	Payee               *string         `json:"payee,omitempty"`               // primary channel payee (base58)
	Mint                *string         `json:"mint,omitempty"`                // SPL mint locked in the channel (base58)
	Salt                json.RawMessage `json:"salt,omitempty"`                // PDA-seed salt; encoded as decimal string, decoded string-or-number
	GracePeriod         *uint32         `json:"gracePeriod,omitempty"`         // on-chain close grace period
	Transaction         *string         `json:"transaction,omitempty"`         // signed channel-open tx (base64) for server broadcast
	TokenAccount        *string         `json:"tokenAccount,omitempty"`        // delegated SPL token account (base58); pull mode
	ApprovedAmount      *string         `json:"approvedAmount,omitempty"`      // operator delegation cap (base units); pull mode
	Owner               *string         `json:"owner,omitempty"`               // client wallet pubkey (base58); pull mode
	InitMultiDelegateTx *string         `json:"initMultiDelegateTx,omitempty"` // pre-signed MultiDelegate init tx (base64)
	UpdateDelegationTx  *string         `json:"updateDelegationTx,omitempty"`  // pre-signed delegation cap-update tx (base64)
	AuthorizedSigner    string          `json:"authorizedSigner"`              // voucher-signing session pubkey (base58)
	Signature           string          `json:"signature"`                     // on-chain proof tx signature (base58)
}

// MarshalJSON serializes Salt as a decimal string.
func (p OpenPayload) MarshalJSON() ([]byte, error) {
	wire := openPayloadJSON{
		Mode:                p.Mode,
		ChannelID:           p.ChannelID,
		Deposit:             p.Deposit,
		Payer:               p.Payer,
		Payee:               p.Payee,
		Mint:                p.Mint,
		GracePeriod:         p.GracePeriod,
		Transaction:         p.Transaction,
		TokenAccount:        p.TokenAccount,
		ApprovedAmount:      p.ApprovedAmount,
		Owner:               p.Owner,
		InitMultiDelegateTx: p.InitMultiDelegateTx,
		UpdateDelegationTx:  p.UpdateDelegationTx,
		AuthorizedSigner:    p.AuthorizedSigner,
		Signature:           p.Signature,
	}
	if p.Salt != nil {
		raw, err := json.Marshal(strconv.FormatUint(*p.Salt, 10))
		if err != nil {
			return nil, fmt.Errorf("marshal salt: %w", err)
		}
		wire.Salt = raw
	}
	out, err := json.Marshal(wire)
	if err != nil {
		return nil, fmt.Errorf("marshal open payload: %w", err)
	}
	return out, nil
}

// UnmarshalJSON decodes Salt from either a decimal string or a JSON number.
func (p *OpenPayload) UnmarshalJSON(data []byte) error {
	var wire openPayloadJSON
	if err := json.Unmarshal(data, &wire); err != nil {
		return fmt.Errorf("decode open payload: %w", err)
	}
	*p = OpenPayload{
		Mode:                wire.Mode,
		ChannelID:           wire.ChannelID,
		Deposit:             wire.Deposit,
		Payer:               wire.Payer,
		Payee:               wire.Payee,
		Mint:                wire.Mint,
		GracePeriod:         wire.GracePeriod,
		Transaction:         wire.Transaction,
		TokenAccount:        wire.TokenAccount,
		ApprovedAmount:      wire.ApprovedAmount,
		Owner:               wire.Owner,
		InitMultiDelegateTx: wire.InitMultiDelegateTx,
		UpdateDelegationTx:  wire.UpdateDelegationTx,
		AuthorizedSigner:    wire.AuthorizedSigner,
		Signature:           wire.Signature,
	}
	if p.Mode == "" {
		return fmt.Errorf("open payload: missing mode")
	}
	salt, err := parseOptionalSalt(wire.Salt)
	if err != nil {
		return err
	}
	p.Salt = salt
	return nil
}

// parseOptionalSalt parses a salt value that may be absent, null, a decimal
// string, or an unsigned 64-bit JSON number.
func parseOptionalSalt(raw json.RawMessage) (*uint64, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return nil, fmt.Errorf("decode salt: %w", err)
	}
	switch v := value.(type) {
	case string:
		parsed, err := strconv.ParseUint(v, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("salt must be a decimal string: %w", err)
		}
		return &parsed, nil
	case float64:
		// Standard json decoding yields float64 for numbers. Recover the
		// integer value from the raw bytes to avoid precision loss on large
		// u64 values.
		parsed, err := strconv.ParseUint(string(raw), 10, 64)
		if err != nil {
			return nil, fmt.Errorf("salt must be an unsigned 64-bit integer: %w", err)
		}
		return &parsed, nil
	default:
		return nil, fmt.Errorf("salt must be a decimal string or unsigned 64-bit integer")
	}
}

// OpenPayloadPush constructs a push payment-channel open payload.
func OpenPayloadPush(channelID, deposit, authorizedSigner, signature string) OpenPayload {
	return OpenPayload{
		Mode:             SessionModePush,
		ChannelID:        &channelID,
		Deposit:          &deposit,
		AuthorizedSigner: authorizedSigner,
		Signature:        signature,
	}
}

// OpenPayloadPaymentChannel constructs a payment-channel push open payload.
func OpenPayloadPaymentChannel(
	channelID, deposit, payer, payee, mint string,
	salt uint64,
	gracePeriod uint32,
	authorizedSigner, signature string,
) OpenPayload {
	return OpenPayloadPaymentChannelWithMode(
		SessionModePush,
		channelID, deposit, payer, payee, mint,
		salt, gracePeriod, authorizedSigner, signature,
	)
}

// OpenPayloadPaymentChannelWithMode constructs a payment-channel open payload
// with an explicit submission mode.
func OpenPayloadPaymentChannelWithMode(
	mode SessionMode,
	channelID, deposit, payer, payee, mint string,
	salt uint64,
	gracePeriod uint32,
	authorizedSigner, signature string,
) OpenPayload {
	return OpenPayload{
		Mode:             mode,
		ChannelID:        &channelID,
		Deposit:          &deposit,
		Payer:            &payer,
		Payee:            &payee,
		Mint:             &mint,
		Salt:             &salt,
		GracePeriod:      &gracePeriod,
		AuthorizedSigner: authorizedSigner,
		Signature:        signature,
	}
}

// OpenPayloadPull constructs a pull (SPL delegation) open payload.
func OpenPayloadPull(tokenAccount, approvedAmount, owner, authorizedSigner, signature string) OpenPayload {
	return OpenPayload{
		Mode:             SessionModePull,
		TokenAccount:     &tokenAccount,
		ApprovedAmount:   &approvedAmount,
		Owner:            &owner,
		AuthorizedSigner: authorizedSigner,
		Signature:        signature,
	}
}

// WithTransaction attaches a signed open transaction for operator/server
// broadcast.
func (p OpenPayload) WithTransaction(txBase64 string) OpenPayload {
	p.Transaction = &txBase64
	return p
}

// WithInitTx attaches a pre-signed InitMultiDelegate + CreateFixedDelegation
// transaction.
func (p OpenPayload) WithInitTx(txBase64 string) OpenPayload {
	p.InitMultiDelegateTx = &txBase64
	return p
}

// WithUpdateTx attaches a pre-signed CreateFixedDelegation (cap update)
// transaction.
func (p OpenPayload) WithUpdateTx(txBase64 string) OpenPayload {
	p.UpdateDelegationTx = &txBase64
	return p
}

// SessionID returns the session identifier used as the store key.
//
//   - Payment channel: ChannelID
//   - Operated-voucher pull: TokenAccount
func (p OpenPayload) SessionID() (string, error) {
	if p.ChannelID != nil {
		return *p.ChannelID, nil
	}
	switch p.Mode {
	case SessionModePush:
		return "", fmt.Errorf("push open missing channelId")
	case SessionModePull:
		if p.TokenAccount != nil {
			return *p.TokenAccount, nil
		}
		return "", fmt.Errorf("pull open missing channelId or tokenAccount")
	default:
		return "", fmt.Errorf("open payload: unknown mode %q", p.Mode)
	}
}

// DepositAmount returns the deposit / approved amount for this open (base
// units).
func (p OpenPayload) DepositAmount() (uint64, error) {
	var raw string
	switch {
	case p.Deposit != nil:
		raw = *p.Deposit
	case p.Mode == SessionModePush:
		return 0, fmt.Errorf("push open missing deposit")
	case p.Mode == SessionModePull:
		if p.ApprovedAmount == nil {
			return 0, fmt.Errorf("pull open missing deposit or approvedAmount")
		}
		raw = *p.ApprovedAmount
	default:
		return 0, fmt.Errorf("open payload: unknown mode %q", p.Mode)
	}
	value, err := strconv.ParseUint(raw, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid deposit amount: %s", raw)
	}
	return value, nil
}

// VoucherPayload is the payload for the voucher action (per-request
// micropayment).
type VoucherPayload struct {
	// Voucher is the signed voucher authorizing cumulative spend.
	Voucher SignedVoucher `json:"voucher"`
}

// MeteringDirective is the server-issued metering directive attached to a
// delivered message/response.
//
// Clients treat this like an offset in a message log: once the message has been
// processed successfully, ack/commit signs a voucher for Amount and sends a
// CommitPayload back to the server.
type MeteringDirective struct {
	// DeliveryID is the server-generated idempotency key for this delivery.
	DeliveryID string `json:"deliveryId"`

	// SessionID is the channel/session ID this delivery belongs to.
	SessionID string `json:"sessionId"`

	// Amount owed for this delivery in base units.
	Amount string `json:"amount"`

	// Currency/asset identifier (e.g., "USDC", mint address).
	Currency string `json:"currency"`

	// Sequence is the monotonic per-session delivery sequence.
	Sequence uint64 `json:"sequence"`

	// ExpiresAt is the Unix timestamp after which this directive should not be
	// committed.
	ExpiresAt int64 `json:"expiresAt"`

	// CommitURL is an optional commit endpoint hint for HTTP transports.
	CommitURL *string `json:"commitUrl,omitempty"`

	// Proof is optional server proof or opaque metadata for transport
	// integrations.
	Proof *string `json:"proof,omitempty"`
}

// AmountBaseUnits parses Amount as base units.
func (d MeteringDirective) AmountBaseUnits() (uint64, error) {
	value, err := strconv.ParseUint(d.Amount, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid metering amount: %s", d.Amount)
	}
	return value, nil
}

// MeteringUsage is the final usage reported by a streaming response.
//
// The amount MUST be less than or equal to the amount reserved by the original
// MeteringDirective.
type MeteringUsage struct {
	// DeliveryID is the delivery id from the original MeteringDirective.
	DeliveryID string `json:"deliveryId"`

	// Amount is the final amount owed for this stream in base units.
	Amount string `json:"amount"`
}

// AmountBaseUnits parses Amount as base units.
func (u MeteringUsage) AmountBaseUnits() (uint64, error) {
	value, err := strconv.ParseUint(u.Amount, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid metering usage amount: %s", u.Amount)
	}
	return value, nil
}

// MeteredEnvelope is a payload paired with the metering directive required to
// acknowledge it.
type MeteredEnvelope[T any] struct {
	// Payload is the delivered application message being charged for.
	Payload T `json:"payload"`

	// Metering is the server-issued directive the client commits (by
	// signing a voucher covering Metering.Amount) after processing Payload.
	Metering MeteringDirective `json:"metering"`
}

// CommitPayload is the payload for the commit action.
type CommitPayload struct {
	// DeliveryID from the original MeteringDirective.
	DeliveryID string `json:"deliveryId"`

	// Voucher is the signed voucher authorizing the delivery amount.
	Voucher SignedVoucher `json:"voucher"`
}

// CommitReceipt is the result returned after a delivery commit is accepted.
type CommitReceipt struct {
	// DeliveryID from the original MeteringDirective.
	DeliveryID string `json:"deliveryId"`

	// SessionID is the channel/session ID.
	SessionID string `json:"sessionId"`

	// Amount committed for this delivery in base units.
	Amount string `json:"amount"`

	// Cumulative is the new settled cumulative watermark in base units.
	Cumulative string `json:"cumulative"`

	// Status is the commit receipt status.
	Status CommitStatus `json:"status"`
}

// TopUpPayload is the payload for the topUp action.
type TopUpPayload struct {
	// ChannelID is the on-chain channel address (base58).
	ChannelID string `json:"channelId"`

	// NewDeposit is the new total deposit amount after the top-up (base
	// units).
	NewDeposit string `json:"newDeposit"`

	// Signature is the top-up transaction signature (base58).
	Signature string `json:"signature"`
}

// ClosePayload is the payload for the close action.
type ClosePayload struct {
	// ChannelID is the on-chain channel address (base58).
	ChannelID string `json:"channelId"`

	// Voucher is the final signed voucher for any remaining balance owed.
	Voucher *SignedVoucher `json:"voucher,omitempty"`
}

// ── Vouchers ──

// SignedVoucher is a signed voucher authorizing cumulative payment up to its
// cumulative amount.
//
// Vouchers are cumulative: the server always uses the latest valid voucher it
// has received. The client MUST increment the cumulative amount with each
// request.
type SignedVoucher struct {
	// Data is the voucher content.
	Data VoucherData `json:"data"`

	// Signature is the Ed25519 signature over the payment-channel Borsh
	// voucher bytes (base58).
	Signature string `json:"signature"`
}

// VoucherData is the canonical content of a voucher, signed by the client's
// session key.
//
// Serialized as the on-chain VoucherArgs layout before signing:
// channelId || cumulativeAmount(LE u64) || expiresAt(LE i64).
type VoucherData struct {
	// ChannelID is the channel/session ID this voucher is bound to (base58).
	//
	// For push sessions: the payment-channel address.
	// For pull sessions: the SPL token account address.
	ChannelID string `json:"channelId"`

	// Cumulative is the cumulative amount authorized (base units,
	// monotonically increasing). The wire field is "cumulativeAmount" with a
	// "cumulative" decode alias.
	Cumulative string `json:"cumulativeAmount"`

	// ExpiresAt is the Unix timestamp at which this voucher expires.
	ExpiresAt int64 `json:"expiresAt"`

	// Nonce is an optional client-side request counter. It is not included in
	// the on-chain voucher bytes.
	Nonce *uint64 `json:"nonce,omitempty"`
}

// voucherDataJSON is the wire shape of VoucherData with the "cumulative" decode
// alias handled explicitly.
type voucherDataJSON struct {
	ChannelID        string  `json:"channelId"`                  // channel/session ID the voucher is bound to (base58)
	CumulativeAmount *string `json:"cumulativeAmount,omitempty"` // canonical cumulative total authorized (base units)
	CumulativeAlias  *string `json:"cumulative,omitempty"`       // decode-only alias accepted for cumulativeAmount
	ExpiresAt        int64   `json:"expiresAt"`                  // voucher expiry, Unix epoch seconds
	Nonce            *uint64 `json:"nonce,omitempty"`            // optional client request counter; not signed on-chain
}

// UnmarshalJSON decodes VoucherData, accepting "cumulative" as an alias for
// "cumulativeAmount".
func (v *VoucherData) UnmarshalJSON(data []byte) error {
	var wire voucherDataJSON
	if err := json.Unmarshal(data, &wire); err != nil {
		return fmt.Errorf("decode voucher data: %w", err)
	}
	*v = VoucherData{
		ChannelID: wire.ChannelID,
		ExpiresAt: wire.ExpiresAt,
		Nonce:     wire.Nonce,
	}
	switch {
	case wire.CumulativeAmount != nil:
		v.Cumulative = *wire.CumulativeAmount
	case wire.CumulativeAlias != nil:
		v.Cumulative = *wire.CumulativeAlias
	default:
		// The cumulative amount is required on the wire, so a voucher without
		// "cumulativeAmount"/"cumulative" is malformed; reject it here rather
		// than leave Cumulative empty and fail with a cryptic parse error later
		// when the voucher is signed or recorded.
		return fmt.Errorf("voucher data missing cumulativeAmount")
	}
	return nil
}

// MessageBytes serializes the voucher to the payment-channels VoucherArgs bytes
// signed by Ed25519: channelId(32) || cumulativeAmount(LE u64) ||
// expiresAt(LE i64), for a total of exactly 48 bytes.
func (v VoucherData) MessageBytes() ([]byte, error) {
	channelID, err := solana.PublicKeyFromBase58(v.ChannelID)
	if err != nil {
		return nil, fmt.Errorf("invalid channelId %q: %w", v.ChannelID, err)
	}
	cumulative, err := strconv.ParseUint(v.Cumulative, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid voucher cumulative")
	}
	// Delegate to the canonical packer so the 48-byte layout has a single
	// source of truth.
	return paymentchannels.VoucherMessageBytes(channelID, cumulative, v.ExpiresAt)
}
