package x402

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"sync"
	"time"

	bin "github.com/gagliardetto/binary"
	"github.com/solana-foundation/pay-kit/go/paycore"
	"github.com/solana-foundation/pay-kit/go/paykit"
	mppcore "github.com/solana-foundation/pay-kit/go/protocols/mpp/core"
	proto "github.com/solana-foundation/pay-kit/go/protocols/x402"
	solana "github.com/solana-foundation/solana-go/v2"
	"github.com/solana-foundation/solana-go/v2/rpc"
	"github.com/solana-foundation/solana-go/v2/rpc/jsonrpc"
)

// consumedPrefix namespaces the replay markers this adapter writes into the
// shared store so they never collide with other schemes' keys. Mirrors the
// MPP charge server's consumed-signature namespace.
const consumedPrefix = "x402-svm-exact:consumed:"

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
	allowUnsafeMemoryStore := os.Getenv("PAY_KIT_ALLOW_INMEMORY_REPLAY_STORE") == "1"
	if cfg.Network == paykit.SolanaMainnet && allowUnsafeMemoryStore {
		return nil, errors.New("protocols/x402: PAY_KIT_ALLOW_INMEMORY_REPLAY_STORE is forbidden on mainnet; inject a durable shared replay store")
	}
	store := cfg.X402.ReplayStore
	if store == nil {
		if cfg.Network == paykit.SolanaMainnet {
			return nil, errors.New("protocols/x402: mainnet exact settlement requires X402.ReplayStore with durable shared replay capability")
		}
		if cfg.Network != paykit.SolanaLocalnet && !allowUnsafeMemoryStore {
			return nil, errors.New("protocols/x402: non-localnet exact settlement requires X402.ReplayStore with durable shared replay capability; inject a shared atomic store or set PAY_KIT_ALLOW_INMEMORY_REPLAY_STORE=1 to acknowledge process-local replay protection")
		}
		store = mppcore.NewMemoryStore()
	} else if cfg.Network != paykit.SolanaLocalnet && !allowUnsafeMemoryStore {
		capability, ok := store.(paykit.ReplayStoreCapability)
		if !ok || !capability.ProvidesDurableSharedReplayProtection() {
			if cfg.Network == paykit.SolanaMainnet {
				return nil, errors.New("protocols/x402: mainnet X402.ReplayStore must implement ReplayStoreCapability and report durable shared replay protection")
			}
			return nil, errors.New("protocols/x402: non-localnet X402.ReplayStore must implement ReplayStoreCapability and report durable shared replay protection; set PAY_KIT_ALLOW_INMEMORY_REPLAY_STORE=1 only for an explicit process-local override")
		}
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

func (a *Adapter) AcceptsEntry(gate *paykit.Gate) (paykit.AcceptsEntry, error) {
	coin := a.settlementCoin(gate)
	label := a.cfg.Network.MintsLabel()
	mint := paycore.ResolveMint(coin, label)
	amount, err := a.totalUnits(gate, coin)
	if err != nil {
		return nil, err
	}
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
	// recentBlockhash is best-effort: a stale/absent blockhash still
	// yields a payable challenge, so a lookup error is intentionally
	// non-fatal here rather than propagated.
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
	}}, nil
}

func (a *Adapter) ChallengeHeaders(gate *paykit.Gate) (map[string]string, error) {
	entry, err := a.AcceptsEntry(gate)
	if err != nil {
		return nil, err
	}
	accepts := []paykit.AcceptsEntry{entry}
	envelope := map[string]any{
		"x402Version": proto.X402Version,
		"resource":    map[string]string{"type": "http", "url": gate.Desc},
		"accepts":     accepts,
	}
	if ext := a.advertisedExtensions(); ext != nil {
		envelope["extensions"] = ext
	}
	raw, err := json.Marshal(envelope)
	if err != nil {
		return nil, fmt.Errorf("protocols/x402: marshal payment-required envelope: %w", err)
	}
	return map[string]string{
		proto.PaymentRequiredHeader: base64.StdEncoding.EncodeToString(raw),
	}, nil
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
	gate := *req.Gate
	if req.Path != "" {
		gate.Desc = req.Path
	}
	req.Gate = &gate
	if _, err := a.totalUnits(req.Gate, a.settlementCoin(req.Gate)); err != nil {
		return nil, &paykit.PaymentError{Code: "invalid_gate", Err: err, Gate: req.Gate}
	}
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
	if err := a.rejectManagedSourceOwner(ctx, tx, reqs.ManagedSigners); err != nil {
		code := "source_owner_check_failed"
		var managedOwner *managedSourceOwnerError
		if errors.As(err, &managedOwner) {
			code = "invalid_exact_svm_payload_transaction_fee_payer_transferring_funds"
		}
		return nil, &paykit.PaymentError{Code: code, Err: err, Gate: req.Gate}
	}
	replayKey, err := transactionReplayKey(tx)
	if err != nil {
		return nil, &paykit.PaymentError{Code: "invalid_payload", Err: err, Gate: req.Gate}
	}
	// Reserve the credential before broadcast so a concurrent duplicate is
	// rejected during the verify + cosign window. The reservation is released
	// ONLY on a definitive pre-broadcast failure (cosign error, send error),
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
		// A store I/O failure (e.g. a shared Redis outage) is NOT a replay: the
		// credential's consumption state is simply unknown. Surface a distinct
		// code so operators debugging an outage don't see honest clients told
		// their credential was already spent (which could cause a client to
		// discard a valid, unsettled credential). "signature_consumed" is
		// reserved for the provably-already-reserved (!inserted) branch below.
		return nil, &paykit.PaymentError{Code: "replay_store_error", Err: err, Gate: req.Gate}
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
		// A transport timeout or generic RPC error does not prove the node
		// rejected the transaction before broadcast: it may have accepted the
		// bytes and lost the response. Keep the reservation on every ambiguous
		// send failure. Solana's explicit simulation failure (-32002) is the one
		// definitive preflight rejection and is safe to release for a corrected
		// retry.
		if !definitivePreflightFailure(err) {
			cleanupConsumed = false
		}
		return nil, &paykit.PaymentError{Code: "send_failed", Err: err, Gate: req.Gate}
	}
	// The RPC accepted the broadcast. From here the transaction may land even
	// if confirmation polling times out, so pin the replay marker now: a
	// confirmation/verify timeout must not delete it and reopen the credential
	// for a second submission while the original lands and double-pays.
	cleanupConsumed = false
	if err := a.awaitConfirmation(ctx, signature); err != nil {
		// Release only when this transaction's exact recent blockhash is
		// finalized-invalid and its signature is absent from full history.
		if a.settlementNotLanded(ctx, signature, tx.Message.RecentBlockhash) {
			_ = store.Delete(context.WithoutCancel(ctx), consumedKey)
		}
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

func definitivePreflightFailure(err error) bool {
	var rpcErr *jsonrpc.RPCError
	return errors.As(err, &rpcErr) && rpcErr.Code == -32002
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
	route, err := a.routeAccepts(gate)
	if err != nil {
		return err
	}
	got := normalizeNetwork(credential.Network)
	if got != route.Network {
		return fmt.Errorf("network mismatch: expected %s, got %s", route.Network, credential.Network)
	}
	return nil
}

func (a *Adapter) verifyAcceptedBinding(gate *paykit.Gate, accepted *proto.AcceptsEntry) error {
	route, err := a.routeAccepts(gate)
	if err != nil {
		return err
	}
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

func (a *Adapter) routeAccepts(gate *paykit.Gate) (proto.AcceptsEntry, error) {
	coin := a.settlementCoin(gate)
	label := a.cfg.Network.MintsLabel()
	amount, err := a.totalUnits(gate, coin)
	if err != nil {
		return proto.AcceptsEntry{}, err
	}
	return proto.AcceptsEntry{
		Protocol:          "x402",
		Scheme:            a.cfg.X402.Scheme,
		Network:           a.cfg.Network.CAIP2(),
		Asset:             paycore.ResolveMint(coin, label),
		Amount:            amount,
		MaxAmountRequired: amount,
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
	}, nil
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
	amountText, err := a.totalUnits(gate, coin)
	if err != nil {
		return proto.TransferRequirements{}, fmt.Errorf("amount: %w", err)
	}
	amount, err := strconv.ParseUint(amountText, 10, 64)
	if err != nil {
		return proto.TransferRequirements{}, fmt.Errorf("amount: %w", err)
	}
	return proto.TransferRequirements{
		PayTo:        payTo,
		Mint:         mint,
		TokenProgram: tokenProgram,
		Amount:       amount,
		ManagedSigners: []solana.PublicKey{
			feePayer,
		},
		ExpectedMemo: gate.Desc,
	}, nil
}

func (a *Adapter) cosign(ctx context.Context, tx *solana.Transaction, rawTx []byte) ([]byte, error) {
	if tx == nil {
		return nil, errors.New("transaction is nil")
	}
	operator, err := solana.PublicKeyFromBase58(string(a.signer.Pubkey()))
	if err != nil {
		return nil, fmt.Errorf("operator pubkey: %w", err)
	}
	// The operator co-signs ONLY the fee-payer slot, which on Solana is always
	// account key index 0. Pinning to slot 0 (rather than scanning for the
	// operator key anywhere in the account list) closes the operator-signs-
	// attacker-instruction path: a crafted transaction could place a different
	// signer at index 0 and the operator's key at some later signer index, and
	// a scan would then spend the operator's signature on a slot it never
	// intended to authorize while leaving the real fee payer unsigned. Mirrors
	// the Rust/TS index-0 pin.
	signers := tx.Message.Signers()
	requiredSigners := int(tx.Message.Header.NumRequiredSignatures)
	if requiredSigners == 0 || len(signers) != requiredSigners || len(tx.Signatures) != requiredSigners {
		return nil, fmt.Errorf("invalid signer vector: message requires %d signatures, transaction carries %d", requiredSigners, len(tx.Signatures))
	}
	// Solana debits the fee payer, so the first required signer must be
	// writable. A message marking every required signer read-only is invalid;
	// refuse to sign it instead of producing an operator signature for a
	// transaction that cannot be a valid fee-paying transaction.
	if int(tx.Message.Header.NumReadonlySignedAccounts) >= requiredSigners {
		return nil, errors.New("invalid fee payer: first required signer is read-only")
	}
	if !signers[0].Equals(operator) {
		// The operator is not this transaction's fee payer, so it has nothing to
		// co-sign. Return the wire unchanged rather than signing an off-slot key.
		return rawTx, nil
	}
	if !tx.Signatures[0].IsZero() {
		// Slot 0 is either absent or already filled (the operator or client
		// already signed): nothing to do.
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
	tx.Signatures[0] = solana.SignatureFromBytes(signature)
	wire, err := tx.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("marshal cosigned transaction: %w", err)
	}
	return wire, nil
}

// rejectManagedSourceOwner closes the delegate path that structural account
// indexes cannot see: a non-managed delegate may transfer from a token account
// whose stored owner is a managed signer.
type managedSourceOwnerError struct {
	owner solana.PublicKey
}

func (e *managedSourceOwnerError) Error() string {
	return fmt.Sprintf("transfer source token account is owned by managed signer %s", e.owner)
}

func (a *Adapter) rejectManagedSourceOwner(ctx context.Context, tx *solana.Transaction, managed []solana.PublicKey) error {
	if len(tx.Message.Instructions) < 3 {
		return errors.New("missing transferChecked instruction")
	}
	ix := tx.Message.Instructions[2]
	if len(ix.Accounts) < 1 || int(ix.ProgramIDIndex) >= len(tx.Message.AccountKeys) || int(ix.Accounts[0]) >= len(tx.Message.AccountKeys) {
		return errors.New("invalid transferChecked source indexes")
	}
	program := tx.Message.AccountKeys[ix.ProgramIDIndex]
	source := tx.Message.AccountKeys[ix.Accounts[0]]
	reader, ok := a.rpc.(interface {
		GetAccountInfoWithOpts(context.Context, solana.PublicKey, *rpc.GetAccountInfoOpts) (*rpc.GetAccountInfoResult, error)
	})
	if !ok {
		return errors.New("RPC client cannot inspect the transfer source account")
	}
	info, err := reader.GetAccountInfoWithOpts(ctx, source, &rpc.GetAccountInfoOpts{
		Commitment: rpc.CommitmentConfirmed,
		Encoding:   solana.EncodingBase64,
	})
	if err != nil {
		return fmt.Errorf("fetch transfer source account: %w", err)
	}
	if info == nil || info.Value == nil || info.Value.Data == nil {
		return errors.New("transfer source account is missing")
	}
	if !info.Value.Owner.Equals(program) {
		return fmt.Errorf("transfer source account owner program %s != %s", info.Value.Owner, program)
	}
	data := info.Value.Data.GetBinary()
	if len(data) < 64 {
		return fmt.Errorf("transfer source token account data is too short: %d", len(data))
	}
	owner := solana.PublicKeyFromBytes(data[32:64])
	for _, signer := range managed {
		if owner.Equals(signer) {
			return &managedSourceOwnerError{owner: signer}
		}
	}
	return nil
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

type blockhashValidator interface {
	IsBlockhashValid(context.Context, solana.Hash, rpc.CommitmentType) (*rpc.IsValidBlockhashResult, error)
}

// settlementNotLanded releases only with evidence tied to the transaction's
// signed blockhash. A fresh GetLatestBlockhash response cannot establish this
// transaction's expiry and must never be used as a substitute.
func (a *Adapter) settlementNotLanded(ctx context.Context, signature solana.Signature, blockhash solana.Hash) bool {
	validator, ok := a.rpc.(blockhashValidator)
	if !ok {
		return false
	}
	validity, err := validator.IsBlockhashValid(ctx, blockhash, rpc.CommitmentFinalized)
	if err != nil || validity == nil || validity.Value {
		return false
	}
	statuses, err := a.rpc.GetSignatureStatuses(ctx, true, signature)
	return err == nil && statuses != nil && len(statuses.Value) > 0 && statuses.Value[0] == nil
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

func (a *Adapter) totalUnits(gate *paykit.Gate, _ string) (string, error) {
	total := gate.Total().Amount()
	scaled := total.Shift(int32(proto.StablecoinDecimals))
	units := scaled.Truncate(0)
	if total.IsPositive() && units.IsZero() {
		return "", fmt.Errorf("price %s resolves below one base unit", total)
	}
	if !scaled.Equal(units) {
		return "", fmt.Errorf("price %s is not representable in base units", total)
	}
	return units.String(), nil
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
