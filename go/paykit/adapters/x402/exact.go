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
	mppcore "github.com/solana-foundation/pay-kit/go/protocols/mpp/core"
	proto "github.com/solana-foundation/pay-kit/go/protocols/x402"
)

// consumedPrefix namespaces the replay markers this adapter writes into the
// shared store so they never collide with other schemes' keys. Mirrors the
// MPP charge server's consumed-signature namespace.
const consumedPrefix = "x402-exact:consumed:"

type Adapter struct {
	cfg               paykit.Config
	signer            paykit.Signer
	rpc               proto.RPCClient
	replay            mppcore.Store
	replayOnce        sync.Once
	blockhashProvider func() (string, error)
	// confirmAttempts and confirmDelay bound the settlement confirmation
	// poll. Zero values fall back to the package defaults; tests set them
	// small to exercise the confirmation-timeout path deterministically.
	confirmAttempts int
	confirmDelay    time.Duration
}

// replayStore returns the adapter's consumed-signature store, lazily
// defaulting to a process-local in-memory store when the adapter was built
// without one (New always injects one; a bare literal, e.g. in tests, may
// not). Cached so repeated settlements share the same replay set.
func (a *Adapter) replayStore() mppcore.Store {
	a.replayOnce.Do(func() {
		if a.replay == nil {
			a.replay = mppcore.NewMemoryStore()
		}
	})
	return a.replay
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
	store := cfg.X402.ReplayStore
	if store == nil {
		store = mppcore.NewMemoryStore()
	}
	a := &Adapter{
		cfg:               cfg,
		signer:            sgn,
		rpc:               rpc.New(rpcURL),
		replay:            store,
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
	credBytes, err := base64.StdEncoding.DecodeString(sig)
	if err != nil {
		return nil, &paykit.PaymentError{Code: "invalid_payload", Err: fmt.Errorf("base64 decode: %w", err), Gate: req.Gate}
	}
	var credential proto.Credential
	if err := json.Unmarshal(credBytes, &credential); err != nil {
		return nil, &paykit.PaymentError{Code: "invalid_payload", Err: fmt.Errorf("decode credential: %w", err), Gate: req.Gate}
	}
	switch credential.X402Version {
	case proto.X402VersionLegacy:
		if err := a.verifyLegacyBinding(req.Gate, &credential); err != nil {
			return nil, &paykit.PaymentError{Code: "charge_request_mismatch", Err: err, Gate: req.Gate}
		}
	case proto.X402Version:
		if credential.Accepted != nil {
			if err := a.verifyAcceptedBinding(req.Gate, credential.Accepted); err != nil {
				return nil, &paykit.PaymentError{Code: "charge_request_mismatch", Err: err, Gate: req.Gate}
			}
		}
	default:
		return nil, &paykit.PaymentError{Code: "version_mismatch", Err: fmt.Errorf("unsupported x402 version %d", credential.X402Version), Gate: req.Gate}
	}
	if a.cfg.X402.RequirePaymentIdentifier {
		id := credential.Extensions.PaymentIdentifierID()
		if id == "" {
			return nil, &paykit.PaymentError{
				Code: "payment_identifier_required",
				Err:  errors.New("payment-identifier required but credential echoed no id"),
				Gate: req.Gate,
			}
		}
		if !proto.IsValidPaymentIdentifierID(id) {
			return nil, &paykit.PaymentError{
				Code: "payment_identifier_required",
				Err:  fmt.Errorf("payment-identifier id is invalid: %q does not match ^[A-Za-z0-9_-]{16,128}$", id),
				Gate: req.Gate,
			}
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
	reqs, err := a.transferRequirements(req.Gate)
	if err != nil {
		return nil, &paykit.PaymentError{Code: "invalid_gate", Err: err, Gate: req.Gate}
	}
	if err := proto.VerifyExactTransaction(tx, reqs); err != nil {
		code := "charge_request_mismatch"
		var ve *proto.VerifyError
		if errors.As(err, &ve) {
			code = ve.Code
		}
		return nil, &paykit.PaymentError{Code: code, Err: err, Gate: req.Gate}
	}
	replayKey, err := transactionReplayKey(tx)
	if err != nil {
		return nil, &paykit.PaymentError{Code: "invalid_payload", Err: err, Gate: req.Gate}
	}
	// Reserve the credential before broadcast so a concurrent duplicate is
	// rejected during the verify + cosign window. The reservation is released
	// ONLY on a definitive pre-broadcast failure (cosign error, send error) —
	// cases where the transaction provably never reached the chain. Once the
	// broadcast succeeds the marker becomes permanent and is never deleted on
	// a confirmation timeout, because the transaction may still land on-chain;
	// deleting it would reopen a double-serve window on this replica (and, with
	// a shared store, across replicas) while the original settlement lands.
	// Mirrors the MPP charge server's consumed-signature invariant
	// (protocols/mpp/server/server.go: cleanupConsumed pinned to false right
	// after SendTransaction succeeds, never released on a confirmation timeout).
	consumedKey := consumedPrefix + replayKey
	store := a.replayStore()
	inserted, err := store.PutIfAbsent(ctx, consumedKey, true)
	if err != nil {
		return nil, &paykit.PaymentError{Code: "signature_consumed", Err: err, Gate: req.Gate}
	}
	if !inserted {
		return nil, &paykit.PaymentError{Code: "signature_consumed", Err: errors.New("replay rejected"), Gate: req.Gate}
	}
	cleanupConsumed := true
	defer func() {
		if cleanupConsumed {
			// Detach cancellation but keep values so the rollback still runs
			// when the caller's context is already canceled.
			_ = store.Delete(context.WithoutCancel(ctx), consumedKey)
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
	// The RPC accepted the broadcast. From here the transaction may land even
	// if confirmation polling times out, so pin the replay marker now: a
	// confirmation/verify timeout must not delete it and reopen the credential
	// for a second submission while the original lands and double-pays.
	cleanupConsumed = false
	if err := a.awaitConfirmation(ctx, signature); err != nil {
		return nil, &paykit.PaymentError{Code: "settlement_failed", Err: err, Gate: req.Gate}
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

func transactionReplayKey(tx *solana.Transaction) (string, error) {
	for _, sig := range tx.Signatures {
		if !sig.IsZero() {
			return sig.String(), nil
		}
	}
	return "", errors.New("transaction carries no non-zero signer signature")
}

func (a *Adapter) verifyLegacyBinding(gate *paykit.Gate, credential *proto.Credential) error {
	if credential.Scheme != proto.ExactScheme {
		return fmt.Errorf("scheme mismatch: expected %s, got %q", proto.ExactScheme, credential.Scheme)
	}
	route := a.routeAccepts(gate)
	got := normalizeNetwork(credential.Network)
	if got != route.Network {
		return fmt.Errorf("network mismatch: expected %s, got %s", route.Network, credential.Network)
	}
	return nil
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
	cosignIdx := -1
	for i, key := range tx.Message.AccountKeys {
		if key.Equals(operator) && i < len(tx.Signatures) && tx.Signatures[i].IsZero() {
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
	attempts := a.confirmAttempts
	if attempts <= 0 {
		attempts = 40
	}
	delay := a.confirmDelay
	if delay <= 0 {
		delay = 250 * time.Millisecond
	}
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
