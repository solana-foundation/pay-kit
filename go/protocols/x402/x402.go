// Package x402 implements the x402 (exact scheme, Solana) adapter for
// the paykit umbrella. Issues challenges with a recent blockhash baked
// into `accepted.extra.recentBlockhash` (Ruby PR #142 caveat #5),
// runs base64 + signature validation on submitted credentials,
// partial-signs as the facilitator using the operator signer, and
// broadcasts via the configured RPC client. Delegated mode is gated
// off in v1; X402Config.FacilitatorURL must be empty.
package x402

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"time"

	bin "github.com/gagliardetto/binary"
	solana "github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/rpc"
	"github.com/solana-foundation/pay-kit/go/paycore"
	"github.com/solana-foundation/pay-kit/go/paykit"
)

const (
	paymentRequiredHeader = "payment-required"
	paymentResponseHeader = "payment-response"
	settlementHeader      = "x-payment-settlement-signature"
	x402Version           = 2

	// stablecoinDecimals is the mint decimal count advertised in the
	// challenge. Every stablecoin in the paycore table (USDC, USDT, USDG,
	// PYUSD, CASH) uses 6 decimals on Solana; revisit if a non-6 asset is
	// ever added (it would need a getMint lookup instead of a constant).
	stablecoinDecimals = 6

	// defaultDecimals is the transferChecked decimals the client assumes
	// when an offer omits both top-level and extra.decimals, matching the
	// Rust spine requirements.decimals.unwrap_or(6) (payment.rs:453).
	defaultDecimals = 6

	// defaultMaxTimeoutSeconds is the advertised credential lifetime the
	// challenge emits and the client assumes when an offer omits
	// maxTimeoutSeconds/maxAge, matching to_accepted_value's
	// max_age.unwrap_or(300) (types.rs:247).
	defaultMaxTimeoutSeconds = 300

	// solanaNetworkCAIP2 family identifiers mirror the Rust spine
	// (types.rs SOLANA_MAINNET/DEVNET/TESTNET, constants.rs SOLANA_NETWORK)
	// so cluster-slug offers normalize to the same CAIP-2 the client
	// compares preferences against.
	solanaNetworkCAIP2 = "solana"
	solanaMainnetCAIP2 = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"
	solanaDevnetCAIP2  = "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1"
	solanaTestnetCAIP2 = "solana:4uhcVJyU9pJkvQyS88uRDiswHXSCkY3z"
)

// rpcClient is the narrow Solana RPC surface the x402 settle path uses.
// Abstracted behind an interface so the broadcast + confirmation path
// is unit-testable with a fake (the concrete *rpc.Client satisfies it).
type rpcClient interface {
	SendEncodedTransactionWithOpts(ctx context.Context, b64 string, opts rpc.TransactionOpts) (solana.Signature, error)
	GetSignatureStatuses(ctx context.Context, searchHistory bool, sigs ...solana.Signature) (*rpc.GetSignatureStatusesResult, error)
	GetLatestBlockhash(ctx context.Context, commitment rpc.CommitmentType) (*rpc.GetLatestBlockhashResult, error)
}

// Adapter is the paykit.Adapter implementation for x402-exact.
type Adapter struct {
	cfg               paykit.Config
	signer            paykit.Signer // facilitator cosigner (X402.Signer override, else Operator.Signer)
	rpc               rpcClient
	replay            sync.Map // credential signature -> struct{}
	blockhashProvider func() (string, error)
}

// New builds an x402 adapter from the resolved config.
func New(cfg paykit.Config) (paykit.Adapter, error) {
	if cfg.X402.FacilitatorURL != "" {
		return nil, errors.New("protocols/x402: delegated mode (FacilitatorURL) not yet implemented; leave empty for self-hosted")
	}
	rpcURL := cfg.RPCURL
	if rpcURL == "" {
		rpcURL = cfg.Network.DefaultRPCURL()
	}
	// DESIGN rule 3: X402Config.Signer is the escape hatch; the
	// documented path is the operator signer.
	sgn := cfg.X402.Signer
	if sgn == nil {
		sgn = cfg.Operator.Signer
	}
	a := &Adapter{
		cfg:               cfg,
		signer:            sgn,
		rpc:               rpc.New(rpcURL),
		blockhashProvider: cfg.RecentBlockhashProvider,
	}
	return a, nil
}

func (a *Adapter) Protocol() paykit.Protocol { return paykit.X402 }

// AcceptsEntry is the typed JSON shape x402-exact emits into the 402
// body's `accepts[]` array.
//
// On parse the canonical-wire precedence from the Rust spine
// (rust/crates/x402/src/protocol/schemes/exact/types.rs Deserialize)
// is applied: top-level canonical fields win over their extra.*
// mirrors, `amount` falls back to `maxAmountRequired`, `payTo` to
// `recipient`, `asset` to `currency`, decimals defaults to 6, and
// tokenProgram defaults to the per-currency default. The raw bytes are
// captured so the client can echo the selected offer verbatim
// (to_accepted_value's value.clone()).
type AcceptsEntry struct {
	Protocol          string `json:"protocol"`
	Scheme            string `json:"scheme"`
	Network           string `json:"network"`
	Asset             string `json:"asset"`
	Amount            string `json:"amount"`
	MaxAmountRequired string `json:"maxAmountRequired"`
	PayTo             string `json:"payTo"`
	MaxTimeoutSeconds int    `json:"maxTimeoutSeconds"`
	Extra             Extra  `json:"extra"`

	// raw is the verbatim JSON object this entry was parsed from, used
	// to echo the selected offer back in the credential's `accepted`
	// field without dropping unknown keys. Empty for server-constructed
	// entries (which marshal from the typed fields).
	raw json.RawMessage
}

// Extra carries x402's optional metadata. RecentBlockhash is the
// Ruby PR #142 caveat #5 hook: stamp the server's recent blockhash
// so the pay-kit Rust client pins to it when building the tx
// against a surfpool / forked-mainnet ledger the public RPC has
// never seen.
//
// FeePayerSet records whether the wire carried an explicit boolean
// `feePayer` toggle so the client can honour an explicit `false`
// opt-out the way the Rust spine does (use_fee_payer =
// fee_payer.unwrap_or(false) && fee_payer_key.is_some()).
type Extra struct {
	FeePayer        bool   `json:"-"`
	FeePayerSet     bool   `json:"-"`
	FeePayerKey     string `json:"-"`
	Decimals        int    `json:"decimals"`
	DecimalsSet     bool   `json:"-"`
	TokenProgram    string `json:"tokenProgram"`
	Memo            string `json:"memo"`
	RecentBlockhash string `json:"recentBlockhash,omitempty"`
}

// rawAcceptsEntry is the literal JSON shape used for parsing, before the
// canonical-wire precedence rules collapse it into AcceptsEntry. Every
// canonical field exists both top-level and under extra so the
// top-level-first precedence can be applied.
type rawAcceptsEntry struct {
	Protocol          string    `json:"protocol"`
	Scheme            string    `json:"scheme"`
	Network           string    `json:"network"`
	Asset             string    `json:"asset"`
	Currency          string    `json:"currency"`
	Amount            string    `json:"amount"`
	MaxAmountRequired string    `json:"maxAmountRequired"`
	PayTo             string    `json:"payTo"`
	Recipient         string    `json:"recipient"`
	MaxTimeoutSeconds *int      `json:"maxTimeoutSeconds"`
	MaxAge            *int      `json:"maxAge"`
	Decimals          *int      `json:"decimals"`
	TokenProgram      string    `json:"tokenProgram"`
	RecentBlockhash   string    `json:"recentBlockhash"`
	FeePayer          *bool     `json:"feePayer"`
	FeePayerKey       string    `json:"feePayerKey"`
	Extra             *rawExtra `json:"extra"`
}

// rawExtra is the literal extra.* object. feePayer is decoded into a
// json.RawMessage because the Rust wire allows it to be either a boolean
// toggle (top-level) or a string key (extra.feePayer); here under extra
// it is the fee-payer key string.
type rawExtra struct {
	FeePayer        string `json:"feePayer"`
	Decimals        *int   `json:"decimals"`
	TokenProgram    string `json:"tokenProgram"`
	Memo            string `json:"memo"`
	RecentBlockhash string `json:"recentBlockhash"`
}

// UnmarshalJSON applies the Rust spine's canonical-wire precedence so a
// client parsing a server offer matches build_payment's view of it:
// top-level canonical fields win over extra.* mirrors, amount falls
// back to maxAmountRequired, payTo to recipient, asset to currency,
// decimals defaults to 6, and the fee-payer toggle honours an explicit
// boolean. The raw bytes are retained for verbatim accepted echo.
func (e *AcceptsEntry) UnmarshalJSON(data []byte) error {
	var r rawAcceptsEntry
	if err := json.Unmarshal(data, &r); err != nil {
		return err
	}
	if r.Extra == nil {
		r.Extra = &rawExtra{}
	}

	e.raw = append(json.RawMessage(nil), data...)
	e.Protocol = r.Protocol
	e.Scheme = r.Scheme
	e.Network = normalizeNetwork(r.Network)

	// asset := asset || currency (top-level currency, then offered asset).
	e.Asset = firstNonEmpty(r.Asset, r.Currency)
	// amount := amount || maxAmountRequired.
	e.Amount = firstNonEmpty(r.Amount, r.MaxAmountRequired)
	e.MaxAmountRequired = firstNonEmpty(r.MaxAmountRequired, r.Amount)
	// recipient := recipient || payTo. (Rust reads recipient first.)
	e.PayTo = firstNonEmpty(r.Recipient, r.PayTo)

	switch {
	case r.MaxTimeoutSeconds != nil:
		e.MaxTimeoutSeconds = *r.MaxTimeoutSeconds
	case r.MaxAge != nil:
		e.MaxTimeoutSeconds = *r.MaxAge
	default:
		e.MaxTimeoutSeconds = defaultMaxTimeoutSeconds
	}

	// Top-level field wins over extra.* mirror for each optional field.
	e.Extra.RecentBlockhash = firstNonEmpty(r.RecentBlockhash, r.Extra.RecentBlockhash)
	e.Extra.TokenProgram = firstNonEmpty(r.TokenProgram, r.Extra.TokenProgram)
	e.Extra.Memo = r.Extra.Memo

	// decimals: top-level then extra.decimals; default to 6 when absent.
	switch {
	case r.Decimals != nil:
		e.Extra.Decimals, e.Extra.DecimalsSet = *r.Decimals, true
	case r.Extra.Decimals != nil:
		e.Extra.Decimals, e.Extra.DecimalsSet = *r.Extra.Decimals, true
	default:
		e.Extra.Decimals, e.Extra.DecimalsSet = defaultDecimals, false
	}

	// fee_payer_key := feePayerKey (top-level) || extra.feePayer (string).
	e.Extra.FeePayerKey = firstNonEmpty(r.FeePayerKey, r.Extra.FeePayer)
	// fee_payer := bool feePayer, else true when a key is present.
	switch {
	case r.FeePayer != nil:
		e.Extra.FeePayer, e.Extra.FeePayerSet = *r.FeePayer, true
	case e.Extra.FeePayerKey != "":
		e.Extra.FeePayer, e.Extra.FeePayerSet = true, true
	default:
		e.Extra.FeePayer, e.Extra.FeePayerSet = false, false
	}
	return nil
}

// MarshalJSON keeps the server-emitted wire shape stable: the typed
// fields (protocol/scheme/network/asset/amount/maxAmountRequired/payTo/
// maxTimeoutSeconds/extra) with extra.feePayer rendered as the key
// string the client expects. When the entry was parsed from a server
// offer (raw is populated) the verbatim bytes are echoed instead so the
// credential's `accepted` field preserves unknown keys, matching the
// Rust to_accepted_value value.clone() path (types.rs:236-239).
func (e AcceptsEntry) MarshalJSON() ([]byte, error) {
	if len(e.raw) > 0 {
		return e.raw, nil
	}
	type wireExtra struct {
		FeePayer        string `json:"feePayer,omitempty"`
		Decimals        int    `json:"decimals"`
		TokenProgram    string `json:"tokenProgram"`
		Memo            string `json:"memo"`
		RecentBlockhash string `json:"recentBlockhash,omitempty"`
	}
	type wire struct {
		Protocol          string    `json:"protocol"`
		Scheme            string    `json:"scheme"`
		Network           string    `json:"network"`
		Asset             string    `json:"asset"`
		Amount            string    `json:"amount"`
		MaxAmountRequired string    `json:"maxAmountRequired"`
		PayTo             string    `json:"payTo"`
		MaxTimeoutSeconds int       `json:"maxTimeoutSeconds"`
		Extra             wireExtra `json:"extra"`
	}
	return json.Marshal(wire{
		Protocol:          e.Protocol,
		Scheme:            e.Scheme,
		Network:           e.Network,
		Asset:             e.Asset,
		Amount:            e.Amount,
		MaxAmountRequired: e.MaxAmountRequired,
		PayTo:             e.PayTo,
		MaxTimeoutSeconds: e.MaxTimeoutSeconds,
		Extra: wireExtra{
			FeePayer:        e.Extra.FeePayerKey,
			Decimals:        e.Extra.Decimals,
			TokenProgram:    e.Extra.TokenProgram,
			Memo:            e.Extra.Memo,
			RecentBlockhash: e.Extra.RecentBlockhash,
		},
	})
}

// RawAccepted returns the verbatim JSON the offer was parsed from, or
// nil for a server-constructed entry. The client echoes this in the
// credential's `accepted` field so unknown keys survive the round-trip.
func (e AcceptsEntry) RawAccepted() json.RawMessage { return e.raw }

// firstNonEmpty returns the first non-empty string argument.
func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

// normalizeNetwork maps cluster slugs and aliases to their canonical
// CAIP-2 identifier, mirroring the Rust normalize_network_identifier so
// a "mainnet"/"devnet"/"testnet" offer is comparable to a CAIP-2
// preference. CAIP-2 ids and unknown values pass through unchanged.
func normalizeNetwork(network string) string {
	switch network {
	case "":
		return ""
	case solanaNetworkCAIP2, "mainnet", "mainnet-beta":
		return solanaMainnetCAIP2
	case "solana-devnet", "devnet", "localnet":
		return solanaDevnetCAIP2
	case "solana-testnet", "testnet":
		return solanaTestnetCAIP2
	default:
		return network
	}
}

// AcceptsProtocol satisfies [paykit.AcceptsEntry].
func (e AcceptsEntry) AcceptsProtocol() paykit.Protocol { return paykit.X402 }

// Credential is the typed x402 credential the client posts in the
// payment-signature header (base64 of this JSON).
type Credential struct {
	X402Version int               `json:"x402Version"`
	Scheme      string            `json:"scheme"`
	Network     string            `json:"network"`
	Payload     CredentialPayload `json:"payload"`
	Accepted    *AcceptsEntry     `json:"accepted,omitempty"`
}

// CredentialPayload carries the protocol-specific bits the client
// hands the server for verification.
type CredentialPayload struct {
	Transaction string `json:"transaction"`
	Signature   string `json:"signature,omitempty"`
	ChallengeID string `json:"challengeId,omitempty"`
	Resource    string `json:"resource,omitempty"`
}

// SettlementResponse is the typed shape the adapter writes into the
// `payment-response` header (base64 of this JSON) after a successful
// settle.
type SettlementResponse struct {
	Success     bool   `json:"success"`
	Transaction string `json:"transaction"`
	Network     string `json:"network"`
	Payer       string `json:"payer"`
}

func (a *Adapter) AcceptsEntry(gate *paykit.Gate) paykit.AcceptsEntry {
	coin := a.settlementCoin(gate)
	mint := paycore.ResolveMint(coin, a.cfg.Network.MintsLabel())
	amount := a.totalUnits(gate, coin)
	payTo := a.payTo(gate)
	extra := Extra{
		FeePayer:     true,
		FeePayerSet:  true,
		FeePayerKey:  string(a.signer.Pubkey()),
		Decimals:     stablecoinDecimals,
		DecimalsSet:  true,
		TokenProgram: paycore.DefaultTokenProgramForCurrency(coin, a.cfg.Network.MintsLabel()),
		Memo:         gate.Desc,
	}
	if bh, err := a.recentBlockhash(); err == nil && bh != "" {
		extra.RecentBlockhash = bh
	}
	return AcceptsEntry{
		Protocol:          "x402",
		Scheme:            a.cfg.X402.Scheme,
		Network:           a.cfg.Network.CAIP2(),
		Asset:             mint,
		Amount:            amount,
		MaxAmountRequired: amount,
		PayTo:             string(payTo),
		MaxTimeoutSeconds: defaultMaxTimeoutSeconds,
		Extra:             extra,
	}
}

// ChallengeEnvelope is the typed shape of the payment-required
// header's base64-encoded JSON body.
type ChallengeEnvelope struct {
	X402Version int                   `json:"x402Version"`
	Resource    ResourceRef           `json:"resource"`
	Accepts     []paykit.AcceptsEntry `json:"accepts"`
}

// ResourceRef pins the protected resource the envelope advertises.
type ResourceRef struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

func (a *Adapter) ChallengeHeaders(gate *paykit.Gate) map[string]string {
	envelope := ChallengeEnvelope{
		X402Version: x402Version,
		Resource:    ResourceRef{Type: "http", URL: gate.Desc},
		Accepts:     []paykit.AcceptsEntry{a.AcceptsEntry(gate)},
	}
	raw, err := json.Marshal(envelope)
	if err != nil {
		return nil
	}
	return map[string]string{
		paymentRequiredHeader: base64.StdEncoding.EncodeToString(raw),
	}
}

func (a *Adapter) VerifyAndSettle(req *paykit.AdapterRequest) (*paykit.Payment, error) {
	ctx := context.Background()
	sig := req.PaymentSig
	if sig == "" {
		return nil, &paykit.PaymentError{Code: "payment_required", Err: paykit.ErrPaymentRequired, Gate: req.Gate}
	}
	credBytes, err := base64.StdEncoding.DecodeString(sig)
	if err != nil {
		return nil, &paykit.PaymentError{Code: "invalid_payload", Err: fmt.Errorf("base64 decode: %w", err), Gate: req.Gate}
	}
	var credential Credential
	if err := json.Unmarshal(credBytes, &credential); err != nil {
		return nil, &paykit.PaymentError{Code: "invalid_payload", Err: fmt.Errorf("decode credential: %w", err), Gate: req.Gate}
	}
	if credential.X402Version != x402Version {
		return nil, &paykit.PaymentError{Code: "version_mismatch", Err: fmt.Errorf("unsupported x402Version %d", credential.X402Version), Gate: req.Gate}
	}

	// Echoed-accepted binding: when the credential carries an `accepted`
	// object it is the requirements the client claims to be paying for.
	// Compare it against the ROUTE's requirements (never the other way),
	// so a credential that lies about its accepted offer is rejected
	// before any transaction processing or settlement. Targeted field
	// checks first, then a structural backstop over the canonical
	// accepted shape. Mirrors Rust verify_envelope_payload
	// (server/exact.rs:490-541).
	if credential.Accepted != nil {
		if err := a.verifyAcceptedBinding(req.Gate, credential.Accepted); err != nil {
			return nil, &paykit.PaymentError{Code: "charge_request_mismatch", Err: err, Gate: req.Gate}
		}
	}

	txBase64 := credential.Payload.Transaction
	if txBase64 == "" {
		return nil, &paykit.PaymentError{Code: "invalid_payload", Err: errors.New("missing transaction payload"), Gate: req.Gate}
	}
	rawTx, err := base64.StdEncoding.DecodeString(txBase64)
	if err != nil {
		return nil, &paykit.PaymentError{Code: "invalid_payload", Err: fmt.Errorf("transaction base64: %w", err), Gate: req.Gate}
	}
	tx, err := solana.TransactionFromDecoder(bin.NewBinDecoder(rawTx))
	if err != nil {
		return nil, &paykit.PaymentError{Code: "invalid_payload", Err: fmt.Errorf("transaction decode: %w", err), Gate: req.Gate}
	}
	if len(tx.Signatures) == 0 {
		return nil, &paykit.PaymentError{Code: "invalid_payload", Err: errors.New("transaction carries no signatures"), Gate: req.Gate}
	}

	// Structural verification BEFORE we cosign or broadcast: prove the
	// transaction actually pays the gate's recipient the expected
	// amount in the expected mint. Without this an attacker can unlock
	// the route with any broadcastable transaction. Mirrors the Rust /
	// PHP / Lua "exact" verifiers.
	reqs, err := a.transferRequirements(req.Gate)
	if err != nil {
		return nil, &paykit.PaymentError{Code: "invalid_gate", Err: err, Gate: req.Gate}
	}
	if err := verifyExactTransaction(tx, reqs); err != nil {
		// Surface the canonical invalid_exact_svm_payload_* reason from the
		// structural verifier rather than collapsing every failure to
		// charge_request_mismatch, matching the Rust verifier's specific
		// reasons (verify.rs:235-418).
		code := "charge_request_mismatch"
		var ve *verifyError
		if errors.As(err, &ve) {
			code = ve.Code
		}
		return nil, &paykit.PaymentError{Code: code, Err: err, Gate: req.Gate}
	}

	// Replay reservation, keyed on the client signature (slot 0). Rolled
	// back if the broadcast never lands so a transient RPC error does
	// not permanently burn the credential.
	replayKey := tx.Signatures[0].String()
	if _, loaded := a.replay.LoadOrStore(replayKey, struct{}{}); loaded {
		return nil, &paykit.PaymentError{Code: "signature_consumed", Err: errors.New("replay rejected"), Gate: req.Gate}
	}
	settled := false
	defer func() {
		if !settled {
			a.replay.Delete(replayKey)
		}
	}()

	wire, err := a.cosign(ctx, tx, rawTx)
	if err != nil {
		return nil, &paykit.PaymentError{Code: "invalid_payload", Err: err, Gate: req.Gate}
	}
	signature, err := a.rpc.SendEncodedTransactionWithOpts(ctx,
		base64.StdEncoding.EncodeToString(wire),
		rpc.TransactionOpts{
			Encoding:            solana.EncodingBase64,
			PreflightCommitment: rpc.CommitmentConfirmed,
		},
	)
	if err != nil {
		return nil, &paykit.PaymentError{Code: "send_failed", Err: err, Gate: req.Gate}
	}
	if err := a.awaitConfirmation(ctx, signature); err != nil {
		return nil, &paykit.PaymentError{Code: "settlement_failed", Err: err, Gate: req.Gate}
	}
	settled = true

	respEnvelope := SettlementResponse{
		Success:     true,
		Transaction: signature.String(),
		Network:     a.cfg.Network.CAIP2(),
	}
	respRaw, _ := json.Marshal(respEnvelope)
	headers := map[string]string{
		paymentResponseHeader: base64.StdEncoding.EncodeToString(respRaw),
		settlementHeader:      signature.String(),
	}
	return &paykit.Payment{
		Protocol:          paykit.X402,
		Gate:              req.Gate.Name,
		Transaction:       signature.String(),
		SettlementHeaders: headers,
		Raw:               sig,
	}, nil
}

// verifyAcceptedBinding rejects a credential whose echoed `accepted`
// offer does not match this route's advertised requirements. Targeted
// network/amount/recipient/currency checks give actionable errors; a
// canonical structural compare backstops drift on any remaining field.
// Mirrors Rust verify_envelope_payload (server/exact.rs:490-541).
func (a *Adapter) verifyAcceptedBinding(gate *paykit.Gate, accepted *AcceptsEntry) error {
	route := a.routeAccepts(gate)
	if accepted.Network != route.Network {
		return fmt.Errorf("network mismatch: expected %s, got %s", route.Network, accepted.Network)
	}
	if accepted.Amount != route.Amount {
		return fmt.Errorf("amount mismatch: expected %s, got %s", route.Amount, accepted.Amount)
	}
	if accepted.PayTo != route.PayTo {
		return errors.New("recipient mismatch: credential claims a different recipient")
	}
	if accepted.Asset != route.Asset {
		return fmt.Errorf("currency mismatch: expected %s, got %s", route.Asset, accepted.Asset)
	}
	// Structural backstop over the canonical typed shape. Compared via the
	// canonical marshal (not the verbatim raw) so a credential that
	// reorders keys or pins a divergent extra field (decimals,
	// tokenProgram, memo, fee payer, maxTimeoutSeconds) is still caught.
	acceptedJSON, err := canonicalAccepted(accepted)
	if err != nil {
		return err
	}
	routeJSON, err := canonicalAccepted(&route)
	if err != nil {
		return err
	}
	if !bytes.Equal(acceptedJSON, routeJSON) {
		return errors.New("credential's accepted requirements do not structurally match this route's expected requirements")
	}
	return nil
}

// routeAccepts builds the route's advertised accept entry without the
// RPC-backed recentBlockhash stamp, so the echoed-accepted comparison is
// deterministic and offline. recentBlockhash is a client-build hint, not
// part of the binding identity, so it is excluded from both sides.
func (a *Adapter) routeAccepts(gate *paykit.Gate) AcceptsEntry {
	coin := a.settlementCoin(gate)
	label := a.cfg.Network.MintsLabel()
	return AcceptsEntry{
		Protocol:          "x402",
		Scheme:            a.cfg.X402.Scheme,
		Network:           a.cfg.Network.CAIP2(),
		Asset:             paycore.ResolveMint(coin, label),
		Amount:            a.totalUnits(gate, coin),
		MaxAmountRequired: a.totalUnits(gate, coin),
		PayTo:             string(a.payTo(gate)),
		MaxTimeoutSeconds: defaultMaxTimeoutSeconds,
		Extra: Extra{
			FeePayer:     true,
			FeePayerSet:  true,
			FeePayerKey:  string(a.signer.Pubkey()),
			Decimals:     stablecoinDecimals,
			DecimalsSet:  true,
			TokenProgram: paycore.DefaultTokenProgramForCurrency(coin, label),
			Memo:         gate.Desc,
		},
	}
}

// canonicalAccepted serializes an accept entry through the typed wire
// shape (ignoring any verbatim raw bytes and the recentBlockhash hint)
// so two entries compare equal iff their binding-relevant fields match.
func canonicalAccepted(e *AcceptsEntry) ([]byte, error) {
	clone := *e
	clone.raw = nil
	clone.Extra.RecentBlockhash = ""
	return json.Marshal(clone)
}

// transferRequirements derives the structural-verification target from
// the gate + config: recipient, mint pubkey, token program, and the
// amount in base units.
func (a *Adapter) transferRequirements(gate *paykit.Gate) (transferRequirements, error) {
	coin := a.settlementCoin(gate)
	label := a.cfg.Network.MintsLabel()
	mintStr := paycore.ResolveMint(coin, label)
	mint, err := solana.PublicKeyFromBase58(mintStr)
	if err != nil {
		return transferRequirements{}, fmt.Errorf("resolve mint %q: %w", coin, err)
	}
	payToStr := string(a.payTo(gate))
	payTo, err := solana.PublicKeyFromBase58(payToStr)
	if err != nil {
		return transferRequirements{}, fmt.Errorf("recipient %q: %w", payToStr, err)
	}
	tokenProgram, err := solana.PublicKeyFromBase58(paycore.DefaultTokenProgramForCurrency(coin, label))
	if err != nil {
		return transferRequirements{}, fmt.Errorf("token program: %w", err)
	}
	feePayer, err := solana.PublicKeyFromBase58(string(a.signer.Pubkey()))
	if err != nil {
		return transferRequirements{}, fmt.Errorf("operator pubkey: %w", err)
	}
	amount, err := strconv.ParseUint(a.totalUnits(gate, coin), 10, 64)
	if err != nil {
		return transferRequirements{}, fmt.Errorf("amount: %w", err)
	}
	return transferRequirements{
		payTo:        payTo,
		mint:         mint,
		tokenProgram: tokenProgram,
		amount:       amount,
		feePayer:     feePayer,
		// extra.memo is advertised as the gate description. When set, the
		// spec requires the verifier to confirm exactly one Memo instruction
		// whose data equals it (payment-reference binding).
		expectedMemo: gate.Desc,
	}, nil
}

// cosign splices the operator's facilitator signature into the
// transaction's signature slot when the operator is the fee-payer (its
// pubkey appears in the static account list with an empty slot). It
// signs the EXACT original message bytes and overwrites only the 64
// signature bytes in the original wire, so the client's own signature
// stays valid over byte-identical message content (a re-marshal could
// reorder fields and invalidate it). When no cosign is needed the
// original bytes pass through untouched.
func (a *Adapter) cosign(ctx context.Context, tx *solana.Transaction, rawTx []byte) ([]byte, error) {
	operator, err := solana.PublicKeyFromBase58(string(a.signer.Pubkey()))
	if err != nil {
		return nil, fmt.Errorf("operator pubkey: %w", err)
	}
	cosignIdx := -1
	for i, key := range tx.Message.AccountKeys {
		if key.Equals(operator) && i < len(tx.Signatures) && tx.Signatures[i].IsZero() {
			cosignIdx = i
			break
		}
	}
	if cosignIdx < 0 {
		return rawTx, nil // operator not a missing signer; ship as-is.
	}
	msgBytes, err := tx.Message.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("marshal message: %w", err)
	}
	signature, err := a.signer.Sign(ctx, msgBytes)
	if err != nil {
		return nil, fmt.Errorf("operator sign: %w", err)
	}
	if len(signature) != 64 {
		return nil, fmt.Errorf("operator signature length %d, want 64", len(signature))
	}
	// Byte-preserving splice: the wire is
	//   [shortvec sigCount][64*sigCount signatures][message...]
	// The shortvec length prefix for sigCount (always < 128 here) is a
	// single byte, so signature i starts at 1 + i*64.
	offset := 1 + cosignIdx*64
	if offset+64 > len(rawTx) {
		return nil, errors.New("signature slot offset out of range")
	}
	wire := make([]byte, len(rawTx))
	copy(wire, rawTx)
	copy(wire[offset:offset+64], signature)
	return wire, nil
}

// awaitConfirmation polls getSignatureStatuses until the settlement
// signature reaches confirmed/finalized or the attempt budget runs
// out. Mirrors the MPP server's post-broadcast confirmation so x402
// does not return 200 before the transfer actually lands.
func (a *Adapter) awaitConfirmation(ctx context.Context, signature solana.Signature) error {
	const attempts = 40
	const delay = 250 * time.Millisecond
	for range attempts {
		statuses, err := a.rpc.GetSignatureStatuses(ctx, true, signature)
		if err == nil && statuses != nil && len(statuses.Value) > 0 {
			st := statuses.Value[0]
			if st != nil {
				if st.Err != nil {
					return fmt.Errorf("transaction %s failed: %v", signature, st.Err)
				}
				switch st.ConfirmationStatus {
				case rpc.ConfirmationStatusConfirmed, rpc.ConfirmationStatusFinalized:
					return nil
				}
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay):
		}
	}
	return fmt.Errorf("timed out confirming %s", signature)
}

func (a *Adapter) recentBlockhash() (string, error) {
	if a.blockhashProvider != nil {
		return a.blockhashProvider()
	}
	if a.rpc == nil {
		return "", errors.New("rpc client nil")
	}
	resp, err := a.rpc.GetLatestBlockhash(context.Background(), rpc.CommitmentConfirmed)
	if err != nil {
		return "", err
	}
	return resp.Value.Blockhash.String(), nil
}

func (a *Adapter) settlementCoin(gate *paykit.Gate) string {
	for _, s := range gate.Amount.Settlements() {
		return string(s)
	}
	for _, s := range a.cfg.Stablecoins {
		return string(s)
	}
	return "USDC"
}

func (a *Adapter) payTo(gate *paykit.Gate) paykit.Address {
	if gate.PayTo != "" {
		return gate.PayTo
	}
	return a.cfg.Operator.Recipient
}

func (a *Adapter) totalUnits(gate *paykit.Gate, _ string) string {
	scaled := gate.Total().Amount().Shift(int32(stablecoinDecimals))
	return scaled.Truncate(0).String()
}

func init() {
	paykit.RegisterAdapter(paykit.X402, New)
}
