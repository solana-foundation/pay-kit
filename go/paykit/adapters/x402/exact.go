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

	solana "github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/rpc"
	"github.com/solana-foundation/pay-kit/go/paycore"
	"github.com/solana-foundation/pay-kit/go/paycore/solanatx"
	"github.com/solana-foundation/pay-kit/go/paykit"
	core "github.com/solana-foundation/pay-kit/go/protocols/mpp/core"
	proto "github.com/solana-foundation/pay-kit/go/protocols/x402"
)

type Adapter struct {
	cfg               paykit.Config
	signer            paykit.Signer
	rpc               proto.RPCClient
	blockhashProvider func() (string, error)

	// ledgerOnce guards ledger, the consumed-signature ledger shared with
	// MPP charge. It is backed by cfg.MPP.Store when one is configured, so
	// a transaction settled through MPP on the same gate cannot be
	// presented again here, and by a process-local store otherwise.
	ledgerOnce    sync.Once
	ledger        paycore.ConsumedSignatures
	ledgerBacking paycore.ClaimStore
}

func New(cfg paykit.Config) (paykit.Adapter, error) {
	if cfg.X402.FacilitatorURL != "" {
		return nil, errors.New("protocols/x402: delegated mode (FacilitatorURL) not yet implemented; leave empty for self-hosted")
	}
	rpcURL := cfg.RPCURL
	if rpcURL == "" {
		rpcURL = cfg.Network.DefaultRPCURL()
	}
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

type AcceptsEntry struct {
	proto.AcceptsEntry
}

func (e AcceptsEntry) AcceptsProtocol() paykit.Protocol { return paykit.X402 }

func (a *Adapter) AcceptsEntry(gate *paykit.Gate) paykit.AcceptsEntry {
	coin := a.settlementCoin(gate)
	label := a.cfg.Network.MintsLabel()
	mint := paycore.ResolveMint(coin, label)
	amount := a.totalUnits(gate, coin)
	payTo := a.payTo(gate)
	extra := proto.Extra{
		FeePayer:     true,
		FeePayerSet:  true,
		FeePayerKey:  string(a.signer.Pubkey()),
		Decimals:     proto.StablecoinDecimals,
		DecimalsSet:  true,
		TokenProgram: paycore.DefaultTokenProgramForCurrency(coin, label),
		Memo:         gate.Desc,
	}
	if bh, err := a.recentBlockhash(); err == nil && bh != "" {
		extra.RecentBlockhash = bh
	}
	return AcceptsEntry{proto.AcceptsEntry{
		Protocol:          "x402",
		Scheme:            a.cfg.X402.Scheme,
		Network:           a.cfg.Network.CAIP2(),
		Asset:             mint,
		Amount:            amount,
		MaxAmountRequired: amount,
		PayTo:             string(payTo),
		MaxTimeoutSeconds: proto.DefaultMaxTimeoutSeconds,
		Extra:             extra,
	}}
}

func (a *Adapter) ChallengeHeaders(gate *paykit.Gate) map[string]string {
	entry := a.AcceptsEntry(gate)
	accepts := []paykit.AcceptsEntry{entry}
	envelope := map[string]interface{}{
		"x402Version": proto.X402Version,
		"resource":    map[string]string{"type": "http", "url": gate.Desc},
		"accepts":     accepts,
	}
	if ext := a.advertisedExtensions(); ext != nil {
		envelope["extensions"] = ext
	}
	raw, err := json.Marshal(envelope)
	if err != nil {
		return nil
	}
	return map[string]string{
		proto.PaymentRequiredHeader: base64.StdEncoding.EncodeToString(raw),
	}
}

func (a *Adapter) advertisedExtensions() json.RawMessage {
	if !a.cfg.X402.RequirePaymentIdentifier {
		return nil
	}
	required := true
	ext := proto.PaymentExtensions{
		PaymentIdentifier: &proto.PaymentIdentifierExtension{
			Info: proto.PaymentIdentifierInfo{Required: &required},
		},
	}
	raw, err := json.Marshal(ext)
	if err != nil {
		return nil
	}
	return raw
}

func (a *Adapter) VerifyAndSettle(req *paykit.AdapterRequest) (*paykit.Payment, error) {
	ctx := context.Background()
	sig := req.PaymentSig
	if sig == "" {
		sig = req.PaymentSigLegacy
	}
	if sig == "" {
		return nil, &paykit.PaymentError{Code: "payment_required", Err: paykit.ErrPaymentRequired, Gate: req.Gate}
	}
	reqs, err := a.transferRequirements(req.Gate)
	if err != nil {
		return nil, &paykit.PaymentError{Code: "invalid_gate", Err: err, Gate: req.Gate}
	}
	// Every pre-broadcast check (version, envelope binding, payment
	// identifier, structural transaction verification) runs in the shared
	// protocol verifier so this adapter and any other server cannot drift.
	verified, err := proto.VerifyPaymentHeader(sig, proto.ExactRoute{
		Network:                  a.cfg.Network.CAIP2(),
		Requirements:             reqs,
		RequirePaymentIdentifier: a.cfg.X402.RequirePaymentIdentifier,
	})
	if err != nil {
		code := "charge_request_mismatch"
		var ve *proto.VerifyError
		if errors.As(err, &ve) {
			code = ve.Code
		}
		return nil, &paykit.PaymentError{Code: code, Err: err, Gate: req.Gate}
	}
	credential, tx, rawTx := verified.Credential, verified.Transaction, verified.RawTransaction
	// This server's own offers carry extra fields (decimals, tokenProgram,
	// memo); a v2 echo must reproduce them exactly.
	if credential.X402Version == proto.X402Version {
		if err := a.verifyAcceptedBinding(req.Gate, credential.Accepted); err != nil {
			return nil, &paykit.PaymentError{Code: "charge_request_mismatch", Err: err, Gate: req.Gate}
		}
	}
	wire, err := a.cosign(ctx, tx, rawTx)
	if err != nil {
		return nil, &paykit.PaymentError{Code: "invalid_payload", Err: err, Gate: req.Gate}
	}
	replayKey, err := transactionReplayKey(wire)
	if err != nil {
		return nil, &paykit.PaymentError{Code: "invalid_payload", Err: err, Gate: req.Gate}
	}
	claimed, err := a.consumed().Claim(ctx, replayKey)
	if err != nil {
		return nil, &paykit.PaymentError{Code: "store_error", Err: fmt.Errorf("x402 replay store: %w", err), Gate: req.Gate}
	}
	var signature solana.Signature
	if claimed {
		signature, err = a.broadcast(ctx, req.Gate, wire, replayKey)
	} else {
		signature, err = a.reconcilePending(ctx, req.Gate, replayKey)
	}
	if err != nil {
		return nil, err
	}
	respEnvelope := proto.SettlementResponse{
		Success:     true,
		Transaction: signature.String(),
		Network:     a.cfg.Network.CAIP2(),
		Payer:       tx.Message.AccountKeys[0].String(),
	}
	respRaw, _ := json.Marshal(respEnvelope)
	headers := map[string]string{
		proto.SettlementHeader: signature.String(),
	}
	if credential.X402Version == proto.X402VersionLegacy {
		headers[proto.PaymentResponseHeaderLegacy] = base64.StdEncoding.EncodeToString(respRaw)
	} else {
		headers[proto.PaymentResponseHeader] = base64.StdEncoding.EncodeToString(respRaw)
	}
	return &paykit.Payment{
		Protocol:          paykit.X402,
		Gate:              req.Gate.Name,
		Transaction:       signature.String(),
		SettlementHeaders: headers,
		Raw:               sig,
	}, nil
}

// A settlement whose transaction may have left the server but whose outcome
// is unknown (an ambiguous sendTransaction error, a confirmation timeout) is
// recorded as pending under its signature. The consumed-signature claim is
// kept, so the payer is told to retry the same payment rather than pay a
// replacement while the original can still land; the retry reconciles the
// record against the chain and is granted once.
const (
	pendingSettlementPrefix  = "x402-exact:pending:"
	resolvedSettlementPrefix = "x402-exact:pending-resolved:"
)

type pendingSettlement struct {
	Gate string `json:"gate"`
}

// Confirmation polling budget; tests shorten it.
var (
	confirmAttempts = 40
	confirmDelay    = 250 * time.Millisecond
)

// errUnconfirmed is a confirmation poll that ended without a status: the
// transaction may still land.
var errUnconfirmed = errors.New("transaction not confirmed yet")

func settlementInProgress(gate *paykit.Gate, signature string, cause error) *paykit.PaymentError {
	return &paykit.PaymentError{
		Code: paykit.CodeSettlementInProgress,
		Err:  fmt.Errorf("settlement of transaction %s is in progress; retry the same payment, do not pay again: %w", signature, cause),
		Gate: gate,
	}
}

// broadcast sends the claimed transaction and confirms it. The claim is
// released only when the transaction provably moved nothing: the node's
// preflight refused it (so no node was handed it), or it landed and failed.
// Any other outcome keeps the claim and answers settlement_in_progress.
//
// The pending record a retry reconciles is written with the claim, before
// anything is sent: written afterwards, a store failure would leave a claim
// with no record, and the retry would refuse a payment that may have landed
// as consumed forever. Every grant, inline or reconciled, takes the same
// single-winner token, so a concurrent retry cannot grant it a second time.
func (a *Adapter) broadcast(ctx context.Context, gate *paykit.Gate, wire []byte, replayKey string) (solana.Signature, error) {
	store := a.ledgerStore()
	pendingKey := pendingSettlementPrefix + replayKey
	detached := context.WithoutCancel(ctx)
	unsent := func() {
		_ = store.Delete(detached, pendingKey)
		_ = a.consumed().Release(detached, replayKey)
	}
	if _, err := store.PutIfAbsent(ctx, pendingKey, pendingSettlement{Gate: gate.Name}); err != nil {
		unsent()
		return solana.Signature{}, &paykit.PaymentError{Code: "store_error", Err: fmt.Errorf("x402 replay store: %w", err), Gate: gate}
	}
	signature, err := a.rpc.SendEncodedTransactionWithOpts(ctx,
		base64.StdEncoding.EncodeToString(wire),
		rpc.TransactionOpts{
			Encoding:            solana.EncodingBase64,
			PreflightCommitment: rpc.CommitmentConfirmed,
		},
	)
	if err != nil {
		if solanatx.IsPreflightRejection(err) {
			unsent()
			return solana.Signature{}, &paykit.PaymentError{Code: "send_failed", Err: err, Gate: gate}
		}
		// A lost response, a timeout, a 5xx from a proxy that already
		// forwarded it: the transaction may still land.
		return solana.Signature{}, settlementInProgress(gate, replayKey, err)
	}
	if err := a.awaitConfirmation(ctx, signature); err != nil {
		if errors.Is(err, errUnconfirmed) || ctx.Err() != nil {
			return solana.Signature{}, settlementInProgress(gate, replayKey, err)
		}
		unsent()
		return solana.Signature{}, &paykit.PaymentError{Code: "settlement_failed", Err: err, Gate: gate}
	}
	return signature, a.grant(ctx, gate, replayKey)
}

// grant takes the payment's single-winner token and drops its pending
// record. A false means another presentation already granted it.
func (a *Adapter) grant(ctx context.Context, gate *paykit.Gate, replayKey string) error {
	store := a.ledgerStore()
	granted, err := store.PutIfAbsent(ctx, resolvedSettlementPrefix+replayKey, true)
	if err != nil {
		return &paykit.PaymentError{Code: "store_error", Err: fmt.Errorf("x402 replay store: %w", err), Gate: gate}
	}
	if !granted {
		return &paykit.PaymentError{Code: "signature_consumed", Err: errors.New("replay rejected"), Gate: gate}
	}
	_ = store.Delete(context.WithoutCancel(ctx), pendingSettlementPrefix+replayKey)
	return nil
}

// reconcilePending resolves a presentation whose signature is already
// claimed. Without a pending record for this gate the signature was settled
// before, so it is a replay. With one, only an explicit on-chain outcome
// resolves it: a missing status is never proof of non-execution, so it
// stays in progress.
func (a *Adapter) reconcilePending(ctx context.Context, gate *paykit.Gate, replayKey string) (solana.Signature, error) {
	consumed := &paykit.PaymentError{Code: "signature_consumed", Err: errors.New("replay rejected"), Gate: gate}
	store := a.ledgerStore()
	raw, ok, err := store.Get(ctx, pendingSettlementPrefix+replayKey)
	if err != nil {
		return solana.Signature{}, &paykit.PaymentError{Code: "store_error", Err: fmt.Errorf("x402 replay store: %w", err), Gate: gate}
	}
	if !ok {
		return solana.Signature{}, consumed
	}
	var record pendingSettlement
	if err := json.Unmarshal(raw, &record); err != nil || record.Gate != gate.Name {
		return solana.Signature{}, consumed
	}
	signature, err := solana.SignatureFromBase58(replayKey)
	if err != nil {
		return solana.Signature{}, consumed
	}
	out, err := a.rpc.GetSignatureStatuses(ctx, true, signature)
	if err != nil {
		return solana.Signature{}, settlementInProgress(gate, replayKey, err)
	}
	if out == nil || len(out.Value) == 0 || out.Value[0] == nil {
		return solana.Signature{}, settlementInProgress(gate, replayKey, errUnconfirmed)
	}
	status := out.Value[0]
	if status.Err != nil {
		_ = store.Delete(context.WithoutCancel(ctx), pendingSettlementPrefix+replayKey)
		return solana.Signature{}, &paykit.PaymentError{Code: "settlement_failed",
			Err: fmt.Errorf("transaction %s landed on-chain but failed: %v", replayKey, status.Err), Gate: gate}
	}
	if status.ConfirmationStatus != rpc.ConfirmationStatusConfirmed &&
		status.ConfirmationStatus != rpc.ConfirmationStatusFinalized {
		return solana.Signature{}, settlementInProgress(gate, replayKey, errUnconfirmed)
	}
	// Grant the landed payment exactly once across concurrent retries.
	if err := a.grant(ctx, gate, replayKey); err != nil {
		return solana.Signature{}, err
	}
	return signature, nil
}

// transactionReplayKey is the signature that identifies the fully signed
// (co-signed) wire transaction on-chain: its first signature. MPP charge
// claims the same signature, so the shared ledger catches a transaction
// presented through both protocols. It is derived through
// solanatx.VerifiedSignature, so a key is only ever produced for a
// transaction whose every signature verifies against its message: a forged
// signature is refused before anything is claimed or sent.
func transactionReplayKey(wire []byte) (string, error) {
	tx, err := solanatx.DecodeTransaction(wire)
	if err != nil {
		return "", fmt.Errorf("transaction decode: %w", err)
	}
	signature, err := solanatx.VerifiedSignature(tx)
	if err != nil {
		return "", err
	}
	return signature.String(), nil
}

// consumed is the consumed-signature ledger shared with MPP charge.
func (a *Adapter) consumed() paycore.ConsumedSignatures {
	a.initLedger()
	return a.ledger
}

// ledgerStore is the store behind [Adapter.consumed], which also holds the
// pending-settlement records.
func (a *Adapter) ledgerStore() paycore.ClaimStore {
	a.initLedger()
	return a.ledgerBacking
}

func (a *Adapter) initLedger() {
	a.ledgerOnce.Do(func() {
		var store paycore.ClaimStore = core.NewMemoryStore()
		if a.cfg.MPP.Store != nil {
			store = a.cfg.MPP.Store
		}
		a.ledgerBacking = store
		a.ledger = paycore.NewConsumedSignatures(store)
	})
}

func (a *Adapter) verifyAcceptedBinding(gate *paykit.Gate, accepted *proto.AcceptsEntry) error {
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

func (a *Adapter) routeAccepts(gate *paykit.Gate) proto.AcceptsEntry {
	coin := a.settlementCoin(gate)
	label := a.cfg.Network.MintsLabel()
	return proto.AcceptsEntry{
		Protocol:          "x402",
		Scheme:            a.cfg.X402.Scheme,
		Network:           a.cfg.Network.CAIP2(),
		Asset:             paycore.ResolveMint(coin, label),
		Amount:            a.totalUnits(gate, coin),
		MaxAmountRequired: a.totalUnits(gate, coin),
		PayTo:             string(a.payTo(gate)),
		MaxTimeoutSeconds: proto.DefaultMaxTimeoutSeconds,
		Extra: proto.Extra{
			FeePayer:     true,
			FeePayerSet:  true,
			FeePayerKey:  string(a.signer.Pubkey()),
			Decimals:     proto.StablecoinDecimals,
			DecimalsSet:  true,
			TokenProgram: paycore.DefaultTokenProgramForCurrency(coin, label),
			Memo:         gate.Desc,
		},
	}
}

func canonicalAccepted(e *proto.AcceptsEntry) ([]byte, error) {
	clone := *e
	clone.ClearRaw()
	clone.Extra.RecentBlockhash = ""
	return json.Marshal(clone)
}

func (a *Adapter) transferRequirements(gate *paykit.Gate) (proto.TransferRequirements, error) {
	coin := a.settlementCoin(gate)
	label := a.cfg.Network.MintsLabel()
	mintStr := paycore.ResolveMint(coin, label)
	mint, err := solana.PublicKeyFromBase58(mintStr)
	if err != nil {
		return proto.TransferRequirements{}, fmt.Errorf("resolve mint %q: %w", coin, err)
	}
	payToStr := string(a.payTo(gate))
	payTo, err := solana.PublicKeyFromBase58(payToStr)
	if err != nil {
		return proto.TransferRequirements{}, fmt.Errorf("recipient %q: %w", payToStr, err)
	}
	tokenProgram, err := solana.PublicKeyFromBase58(paycore.DefaultTokenProgramForCurrency(coin, label))
	if err != nil {
		return proto.TransferRequirements{}, fmt.Errorf("token program: %w", err)
	}
	feePayer, err := solana.PublicKeyFromBase58(string(a.signer.Pubkey()))
	if err != nil {
		return proto.TransferRequirements{}, fmt.Errorf("operator pubkey: %w", err)
	}
	amount, err := strconv.ParseUint(a.totalUnits(gate, coin), 10, 64)
	if err != nil {
		return proto.TransferRequirements{}, fmt.Errorf("amount: %w", err)
	}
	return proto.TransferRequirements{
		PayTo:        payTo,
		Mint:         mint,
		TokenProgram: tokenProgram,
		Amount:       amount,
		FeePayer:     feePayer,
		ExpectedMemo: gate.Desc,
	}, nil
}

func (a *Adapter) cosign(ctx context.Context, tx *solana.Transaction, rawTx []byte) ([]byte, error) {
	operator, err := solana.PublicKeyFromBase58(string(a.signer.Pubkey()))
	if err != nil {
		return nil, fmt.Errorf("operator pubkey: %w", err)
	}
	// The operator slot is always (re)signed: whatever the client put there
	// is overwritten, so a client-filled slot can never name the payment.
	cosignIdx := -1
	for i, key := range tx.Message.AccountKeys {
		if key.Equals(operator) && i < int(tx.Message.Header.NumRequiredSignatures) && i < len(tx.Signatures) {
			cosignIdx = i
			break
		}
	}
	if cosignIdx < 0 {
		return rawTx, nil
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
	offset := 1 + cosignIdx*64
	if offset+64 > len(rawTx) {
		return nil, errors.New("signature slot offset out of range")
	}
	wire := make([]byte, len(rawTx))
	copy(wire, rawTx)
	copy(wire[offset:offset+64], signature)
	return wire, nil
}

func (a *Adapter) awaitConfirmation(ctx context.Context, signature solana.Signature) error {
	attempts, delay := confirmAttempts, confirmDelay
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
	return fmt.Errorf("timed out confirming %s: %w", signature, errUnconfirmed)
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
	scaled := gate.Total().Amount().Shift(int32(proto.StablecoinDecimals))
	return scaled.Truncate(0).String()
}

func normalizeNetwork(network string) string {
	switch network {
	case "":
		return ""
	case "solana", "mainnet", "mainnet-beta":
		return "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"
	case "solana-devnet", "devnet", "localnet":
		return "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1"
	case "solana-testnet", "testnet":
		return "solana:4uhcVJyU9pJkvQyS88uRDiswHXSCkY3z"
	default:
		return network
	}
}

func init() {
	paykit.RegisterAdapter(paykit.X402, New)
}
