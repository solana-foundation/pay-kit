package x402

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"

	solana "github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/rpc"
	"github.com/solana-foundation/pay-kit/go/paycore"
	"github.com/solana-foundation/pay-kit/go/paycore/signer"
	"github.com/solana-foundation/pay-kit/go/paycore/solanatx"
	"github.com/solana-foundation/pay-kit/go/paykit"
	mppcore "github.com/solana-foundation/pay-kit/go/protocols/mpp/core"
	proto "github.com/solana-foundation/pay-kit/go/protocols/x402"
)

// pendingRPC is a broadcast test double whose send always succeeds but whose
// confirmation status never advances past pending, so awaitConfirmation runs
// out its poll budget and returns a timeout. This models the "landed but
// unconfirmed" window: the RPC accepted the broadcast (the transaction may
// still land on-chain) yet the server never observes a confirmed status.
type pendingRPC struct {
	sig   solana.Signature
	sends int
}

func (p *pendingRPC) SendEncodedTransactionWithOpts(_ context.Context, _ string, _ rpc.TransactionOpts) (solana.Signature, error) {
	p.sends++
	return p.sig, nil
}

func (p *pendingRPC) GetSignatureStatuses(_ context.Context, _ bool, _ ...solana.Signature) (*rpc.GetSignatureStatusesResult, error) {
	// Empty confirmation status with no error: neither confirmed nor
	// finalized, so awaitConfirmation keeps polling until the budget is
	// exhausted.
	st := &rpc.SignatureStatusesResult{}
	return &rpc.GetSignatureStatusesResult{Value: []*rpc.SignatureStatusesResult{st}}, nil
}

func (p *pendingRPC) GetLatestBlockhash(_ context.Context, _ rpc.CommitmentType) (*rpc.GetLatestBlockhashResult, error) {
	return &rpc.GetLatestBlockhashResult{Value: &rpc.LatestBlockhashResult{}}, nil
}

// exactCredential builds a structurally valid x402 exact transaction that pays
// the given operator, and returns the base64 credential a client would submit.
func exactCredential(t *testing.T, op paykit.Signer) string {
	t.Helper()
	opPub := solana.MustPublicKeyFromBase58(string(op.Pubkey()))
	mint := solana.MustPublicKeyFromBase58(paycore.USDCMainnetMint)
	tokenProgram := solana.MustPublicKeyFromBase58(paycore.TokenProgram)
	authority := solana.NewWallet().PublicKey()
	source := solana.NewWallet().PublicKey()
	dest, err := solanatx.FindAssociatedTokenAddressWithProgram(opPub, mint, tokenProgram)
	if err != nil {
		t.Fatal(err)
	}
	computeBudget := solana.MustPublicKeyFromBase58(proto.ComputeBudgetProgram)
	keys := solana.PublicKeySlice{opPub, source, mint, dest, authority, computeBudget, tokenProgram}
	const amount = uint64(1000)
	priceData := make([]byte, 9)
	priceData[0] = 3
	binaryPutUint64(priceData[1:], 1000)
	transferData := make([]byte, 10)
	transferData[0] = 12
	binaryPutUint64(transferData[1:9], amount)
	transferData[9] = 6
	tx := &solana.Transaction{
		Message: solana.Message{
			AccountKeys: keys,
			Instructions: []solana.CompiledInstruction{
				{ProgramIDIndex: 5, Data: []byte{2, 0, 0, 0, 0}},
				{ProgramIDIndex: 5, Data: priceData},
				{ProgramIDIndex: 6, Accounts: []uint16{1, 2, 3, 4}, Data: transferData},
			},
		},
		Signatures: []solana.Signature{{}, solana.MustSignatureFromBase58(sampleClientSig)},
	}
	wire, err := tx.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	cred := proto.Credential{X402Version: proto.X402Version, Payload: proto.CredentialPayload{Transaction: base64.StdEncoding.EncodeToString(wire)}}
	credJSON, err := json.Marshal(cred)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(credJSON)
}

func binaryPutUint64(b []byte, v uint64) {
	for i := 0; i < 8; i++ {
		b[i] = byte(v >> (8 * uint(i)))
	}
}

func opConfig(op paykit.Signer, store mppcore.Store) paykit.Config {
	return paykit.Config{
		Network:     paykit.SolanaLocalnet,
		Stablecoins: []paykit.Stablecoin{paykit.USDC},
		Operator:    paykit.Operator{Signer: op, Recipient: op.Pubkey()},
		X402:        paykit.X402Config{Scheme: "exact", ReplayStore: store},
	}
}

// TestConfirmationTimeoutKeepsReplayMarker is the double-pay-protection
// regression: after a
// successful broadcast the confirmation poll times out (the transaction may
// have landed), so the credential MUST stay consumed. A retry with the same
// credential must be rejected as signature_consumed rather than re-broadcast.
//
// Before the fix the deferred rollback deleted the marker whenever settlement
// did not complete, including on a confirmation timeout, reopening a
// double-serve window; this test drives exactly that path.
func TestConfirmationTimeoutKeepsReplayMarker(t *testing.T) {
	op := signer.Generate()
	fake := &pendingRPC{sig: solana.MustSignatureFromBase58(sampleSig)}
	a := &Adapter{
		cfg:               opConfig(op, nil),
		signer:            op,
		rpc:               fake,
		blockhashProvider: func() (string, error) { return "BH", nil },
		confirmAttempts:   2,
		confirmDelay:      time.Millisecond,
	}
	cred := exactCredential(t, op)

	// First submission: send succeeds, confirmation never lands -> timeout.
	_, err := a.VerifyAndSettle(&paykit.AdapterRequest{Gate: &paykit.Gate{Amount: paykit.MustParseUSD("0.001")}, PaymentSig: cred})
	var perr *paykit.PaymentError
	if !errorsAs(err, &perr) || perr.Code != "settlement_failed" {
		t.Fatalf("first submission: expected settlement_failed on confirmation timeout, got %v", err)
	}
	if fake.sends != 1 {
		t.Fatalf("expected exactly one broadcast on the first submission, got %d", fake.sends)
	}

	// Retry with the same credential: the marker must still be held, so the
	// adapter rejects the replay instead of broadcasting a second time.
	_, err = a.VerifyAndSettle(&paykit.AdapterRequest{Gate: &paykit.Gate{Amount: paykit.MustParseUSD("0.001")}, PaymentSig: cred})
	if !errorsAs(err, &perr) || perr.Code != "signature_consumed" {
		t.Fatalf("retry after timeout: expected signature_consumed, got %v", err)
	}
	if fake.sends != 1 {
		t.Fatalf("replay must not reach broadcast; expected 1 total send, got %d", fake.sends)
	}
}

// notLandedRPC models the definitive post-timeout not-landed check. Broadcast
// always succeeds; confirmation polling never advances (so awaitConfirmation
// runs out its budget); the final searchTransactionHistory status lookup is
// scripted per field so a test can drive either the provably-not-landed release
// path or one of the keep-the-marker (ambiguous) branches.
type notLandedRPC struct {
	sig solana.Signature
	// statusErr, when set, makes the final status lookup fail (indeterminate:
	// we cannot prove the tx did not land, so the marker must be KEPT).
	statusErr error
	// found, when true, returns a landed on-chain status for the signature (the
	// marker must be KEPT because the tx occupied its slot).
	found bool
	// lastValidBlockHeight is echoed from GetLatestBlockhash so the adapter can
	// capture the blockhash validity window at broadcast time.
	lastValidBlockHeight uint64
	// currentHeight is returned by GetBlockHeight: when it is past
	// lastValidBlockHeight the blockhash is provably expired.
	currentHeight uint64
	// heightErr, when set, makes GetBlockHeight fail so expiry cannot be proven
	// (the marker must be KEPT).
	heightErr error
	sends     int
	// statusCalls counts confirmation-status lookups; the final definitive
	// check is the last one.
	statusCalls int
}

func (n *notLandedRPC) SendEncodedTransactionWithOpts(_ context.Context, _ string, _ rpc.TransactionOpts) (solana.Signature, error) {
	n.sends++
	return n.sig, nil
}

func (n *notLandedRPC) GetSignatureStatuses(_ context.Context, _ bool, _ ...solana.Signature) (*rpc.GetSignatureStatusesResult, error) {
	n.statusCalls++
	if n.statusErr != nil {
		return nil, n.statusErr
	}
	if n.found {
		st := &rpc.SignatureStatusesResult{ConfirmationStatus: rpc.ConfirmationStatusFinalized}
		return &rpc.GetSignatureStatusesResult{Value: []*rpc.SignatureStatusesResult{st}}, nil
	}
	// Signature not found: the per-signature entry is nil (JSON null) while the
	// outer Value slice is non-nil. This is how a node reports "unknown
	// transaction" for a searched-but-absent signature.
	return &rpc.GetSignatureStatusesResult{Value: []*rpc.SignatureStatusesResult{nil}}, nil
}

func (n *notLandedRPC) GetLatestBlockhash(_ context.Context, _ rpc.CommitmentType) (*rpc.GetLatestBlockhashResult, error) {
	return &rpc.GetLatestBlockhashResult{Value: &rpc.LatestBlockhashResult{LastValidBlockHeight: n.lastValidBlockHeight}}, nil
}

func (n *notLandedRPC) GetBlockHeight(_ context.Context, _ rpc.CommitmentType) (uint64, error) {
	if n.heightErr != nil {
		return 0, n.heightErr
	}
	return n.currentHeight, nil
}

// TestSettlementReleasesReservationWhenProvablyNotLanded is the not-landed
// release regression:
// after a successful broadcast the confirmation poll times out, then the
// definitive searchTransactionHistory status lookup reports the signature is
// absent AND the blockhash is provably expired (current height past
// lastValidBlockHeight). Because the transaction can never land, the credential
// must be released so an honest client can rebuild/resubmit.
//
// Before the fix Go pins the marker permanently on ANY confirmation timeout, so
// the retry is rejected as signature_consumed and never re-broadcasts.
func TestSettlementReleasesReservationWhenProvablyNotLanded(t *testing.T) {
	op := signer.Generate()
	fake := &notLandedRPC{
		sig:                  solana.MustSignatureFromBase58(sampleSig),
		lastValidBlockHeight: 100,
		currentHeight:        101, // past lastValidBlockHeight: blockhash expired.
	}
	a := &Adapter{
		cfg:               opConfig(op, nil),
		signer:            op,
		rpc:               fake,
		blockhashProvider: func() (string, error) { return "BH", nil },
		confirmAttempts:   2,
		confirmDelay:      time.Millisecond,
	}
	cred := exactCredential(t, op)

	_, err := a.VerifyAndSettle(&paykit.AdapterRequest{Gate: &paykit.Gate{Amount: paykit.MustParseUSD("0.001")}, PaymentSig: cred})
	var perr *paykit.PaymentError
	if !errors.As(err, &perr) || perr.Code != "settlement_failed" {
		t.Fatalf("first submission: expected settlement_failed on not-landed timeout, got %v", err)
	}
	if fake.sends != 1 {
		t.Fatalf("expected exactly one broadcast on the first submission, got %d", fake.sends)
	}

	// The credential was provably never landed, so the reservation was
	// released: a retry re-broadcasts instead of tripping signature_consumed.
	_, err = a.VerifyAndSettle(&paykit.AdapterRequest{Gate: &paykit.Gate{Amount: paykit.MustParseUSD("0.001")}, PaymentSig: cred})
	if !errors.As(err, &perr) || perr.Code != "settlement_failed" {
		t.Fatalf("retry after not-landed release: expected re-broadcast then settlement_failed, got %v", err)
	}
	if fake.sends != 2 {
		t.Fatalf("released credential must re-broadcast; expected 2 total sends, got %d", fake.sends)
	}
}

// TestSettlementKeepsReservationWhenBlockhashStillValid is the not-landed
// companion:
// the definitive lookup reports the signature absent, but the blockhash has NOT
// expired (current height still within lastValidBlockHeight), so the tx may
// still land. The marker MUST be kept (fail-closed) and a retry is rejected.
func TestSettlementKeepsReservationWhenBlockhashStillValid(t *testing.T) {
	op := signer.Generate()
	fake := &notLandedRPC{
		sig:                  solana.MustSignatureFromBase58(sampleSig),
		lastValidBlockHeight: 100,
		currentHeight:        100, // not past lastValidBlockHeight: still valid.
	}
	a := &Adapter{
		cfg:               opConfig(op, nil),
		signer:            op,
		rpc:               fake,
		blockhashProvider: func() (string, error) { return "BH", nil },
		confirmAttempts:   2,
		confirmDelay:      time.Millisecond,
	}
	cred := exactCredential(t, op)

	_, err := a.VerifyAndSettle(&paykit.AdapterRequest{Gate: &paykit.Gate{Amount: paykit.MustParseUSD("0.001")}, PaymentSig: cred})
	var perr *paykit.PaymentError
	if !errors.As(err, &perr) || perr.Code != "settlement_failed" {
		t.Fatalf("expected settlement_failed, got %v", err)
	}
	_, err = a.VerifyAndSettle(&paykit.AdapterRequest{Gate: &paykit.Gate{Amount: paykit.MustParseUSD("0.001")}, PaymentSig: cred})
	if !errors.As(err, &perr) || perr.Code != "signature_consumed" {
		t.Fatalf("blockhash still valid: retry must be rejected as signature_consumed, got %v", err)
	}
	if fake.sends != 1 {
		t.Fatalf("marker must be kept; expected 1 total send, got %d", fake.sends)
	}
}

// TestSettlementKeepsReservationWhenStatusLookupErrors is the not-landed
// companion:
// the definitive status lookup itself fails (indeterminate). We cannot prove
// the tx did not land, so the marker MUST be kept.
func TestSettlementKeepsReservationWhenStatusLookupErrors(t *testing.T) {
	op := signer.Generate()
	fake := &notLandedRPC{
		sig:                  solana.MustSignatureFromBase58(sampleSig),
		statusErr:            errors.New("rpc unavailable"),
		lastValidBlockHeight: 100,
		currentHeight:        101,
	}
	a := &Adapter{
		cfg:               opConfig(op, nil),
		signer:            op,
		rpc:               fake,
		blockhashProvider: func() (string, error) { return "BH", nil },
		confirmAttempts:   2,
		confirmDelay:      time.Millisecond,
	}
	cred := exactCredential(t, op)

	if _, err := a.VerifyAndSettle(&paykit.AdapterRequest{Gate: &paykit.Gate{Amount: paykit.MustParseUSD("0.001")}, PaymentSig: cred}); err == nil {
		t.Fatal("expected settlement_failed on the first submission")
	}
	_, err := a.VerifyAndSettle(&paykit.AdapterRequest{Gate: &paykit.Gate{Amount: paykit.MustParseUSD("0.001")}, PaymentSig: cred})
	var perr *paykit.PaymentError
	if !errors.As(err, &perr) || perr.Code != "signature_consumed" {
		t.Fatalf("indeterminate status: retry must be rejected as signature_consumed, got %v", err)
	}
}

// TestReplayStoreErrorReportsDistinctCode is the store-outage-code regression: a ReplayStore
// I/O failure on PutIfAbsent (e.g. a shared Redis outage) must be reported with
// a distinct code, not the client-facing signature_consumed replay rejection.
//
// Before the fix the store-error branch surfaced code "signature_consumed",
// telling honest clients their credential was already spent during an outage.
func TestReplayStoreErrorReportsDistinctCode(t *testing.T) {
	op := signer.Generate()
	fake := &fakeRPC{sig: solana.MustSignatureFromBase58(sampleSig), confirm: rpc.ConfirmationStatusConfirmed}
	a := &Adapter{
		cfg:               opConfig(op, &errStore{err: errors.New("redis down")}),
		signer:            op,
		rpc:               fake,
		replay:            &errStore{err: errors.New("redis down")},
		blockhashProvider: func() (string, error) { return "BH", nil },
	}
	cred := exactCredential(t, op)

	_, err := a.VerifyAndSettle(&paykit.AdapterRequest{Gate: &paykit.Gate{Amount: paykit.MustParseUSD("0.001")}, PaymentSig: cred})
	var perr *paykit.PaymentError
	if !errors.As(err, &perr) {
		t.Fatalf("expected a PaymentError on a store outage, got %v", err)
	}
	if perr.Code != "replay_store_error" {
		t.Fatalf("store outage must surface replay_store_error, got %q", perr.Code)
	}
}

// TestSettlementNotLandedBranches exercises the remaining guard branches of the
// evidence-based release decision directly, pinning each fail-closed exit.
func TestSettlementNotLandedBranches(t *testing.T) {
	op := signer.Generate()
	sig := solana.MustSignatureFromBase58(sampleSig)

	// No validity window: cannot prove expiry, keep the marker.
	a := &Adapter{cfg: opConfig(op, nil), signer: op, rpc: &notLandedRPC{currentHeight: 999}}
	if a.settlementNotLanded(context.Background(), sig, 0) {
		t.Fatal("zero lastValidBlockHeight must never release")
	}

	// RPC without block-height support (fakeRPC does not implement blockHeighter):
	// expiry cannot be proven, keep the marker.
	a.rpc = &fakeRPC{}
	if a.settlementNotLanded(context.Background(), sig, 100) {
		t.Fatal("an RPC without GetBlockHeight must never release")
	}

	// Signature found (landed): keep the marker even though a window exists.
	a.rpc = &notLandedRPC{found: true, lastValidBlockHeight: 100, currentHeight: 200}
	if a.settlementNotLanded(context.Background(), sig, 100) {
		t.Fatal("a landed signature must never release")
	}

	// Provably absent + expired: release.
	a.rpc = &notLandedRPC{lastValidBlockHeight: 100, currentHeight: 101}
	if !a.settlementNotLanded(context.Background(), sig, 100) {
		t.Fatal("provably absent + expired blockhash must release")
	}

	// Block-height lookup fails: expiry unprovable, keep the marker.
	a.rpc = &notLandedRPC{lastValidBlockHeight: 100, heightErr: errors.New("rpc down")}
	if a.settlementNotLanded(context.Background(), sig, 100) {
		t.Fatal("a failed block-height lookup must never release")
	}
}

// TestSettlementValidityHeight covers the validity-window capture helper,
// including the fail-closed zero returns.
func TestSettlementValidityHeight(t *testing.T) {
	op := signer.Generate()

	// Nil RPC: zero window (disables release).
	a := &Adapter{cfg: opConfig(op, nil), signer: op}
	if h := a.settlementValidityHeight(context.Background()); h != 0 {
		t.Fatalf("nil rpc must yield 0, got %d", h)
	}

	// Healthy RPC echoes lastValidBlockHeight.
	a.rpc = &notLandedRPC{lastValidBlockHeight: 4242}
	if h := a.settlementValidityHeight(context.Background()); h != 4242 {
		t.Fatalf("expected 4242, got %d", h)
	}
}

// errStore is a ReplayStore whose PutIfAbsent always fails, modelling a
// shared-store outage.
type errStore struct{ err error }

func (e *errStore) Get(context.Context, string) (json.RawMessage, bool, error) {
	return nil, false, e.err
}
func (e *errStore) Put(context.Context, string, any) error { return e.err }
func (e *errStore) Delete(context.Context, string) error   { return nil }
func (e *errStore) PutIfAbsent(context.Context, string, any) (bool, error) {
	return false, e.err
}

// TestSharedReplayStoreRejectsCrossReplica is the cross-replica-replay
// regression: two adapter
// instances built over one injected shared store behave like two replicas
// behind a load balancer. When the first replica consumes a signature the
// second replica must reject the same credential as signature_consumed.
//
// Before the fix the consumed-signature set was a per-Adapter sync.Map with no
// injection point, so replicas could not share it and each would settle the
// same credential once.
func TestSharedReplayStoreRejectsCrossReplica(t *testing.T) {
	op := signer.Generate()
	shared := mppcore.NewMemoryStore()

	newReplica := func() *Adapter {
		built, err := New(opConfig(op, shared))
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		a, ok := built.(*Adapter)
		if !ok {
			t.Fatalf("New returned %T, want *Adapter", built)
		}
		a.rpc = &fakeRPC{sig: solana.MustSignatureFromBase58(sampleSig), confirm: rpc.ConfirmationStatusFinalized}
		a.blockhashProvider = func() (string, error) { return "BH", nil }
		return a
	}

	replicaA := newReplica()
	replicaB := newReplica()
	cred := exactCredential(t, op)

	if _, err := replicaA.VerifyAndSettle(&paykit.AdapterRequest{Gate: &paykit.Gate{Amount: paykit.MustParseUSD("0.001")}, PaymentSig: cred}); err != nil {
		t.Fatalf("replica A settle: %v", err)
	}
	_, err := replicaB.VerifyAndSettle(&paykit.AdapterRequest{Gate: &paykit.Gate{Amount: paykit.MustParseUSD("0.001")}, PaymentSig: cred})
	var perr *paykit.PaymentError
	if !errorsAs(err, &perr) || perr.Code != "signature_consumed" {
		t.Fatalf("replica B: expected signature_consumed via the shared store, got %v", err)
	}
}

// TestPreBroadcastFailureReleasesReplayMarker is the paired positive: a
// definitive pre-broadcast failure (the RPC rejects the send, so nothing was
// broadcast) must release the reservation so an honest retry can proceed.
func TestPreBroadcastFailureReleasesReplayMarker(t *testing.T) {
	op := signer.Generate()
	fake := &fakeRPC{sendErr: context.DeadlineExceeded}
	a := &Adapter{
		cfg:               opConfig(op, nil),
		signer:            op,
		rpc:               fake,
		blockhashProvider: func() (string, error) { return "BH", nil },
	}
	cred := exactCredential(t, op)

	if _, err := a.VerifyAndSettle(&paykit.AdapterRequest{Gate: &paykit.Gate{Amount: paykit.MustParseUSD("0.001")}, PaymentSig: cred}); err == nil {
		t.Fatal("expected send_failed on the first submission")
	}
	// The send never reached the chain, so the marker was released: a retry
	// with a healthy RPC settles instead of tripping signature_consumed.
	fake.sendErr = nil
	fake.sig = solana.MustSignatureFromBase58(sampleSig)
	fake.confirm = rpc.ConfirmationStatusConfirmed
	if _, err := a.VerifyAndSettle(&paykit.AdapterRequest{Gate: &paykit.Gate{Amount: paykit.MustParseUSD("0.001")}, PaymentSig: cred}); err != nil {
		t.Fatalf("retry after a pre-broadcast failure should settle, got %v", err)
	}
}
