package x402

import (
	"context"
	"encoding/base64"
	"encoding/json"
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

// TestConfirmationTimeoutKeepsReplayMarker is the M-2 regression: after a
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

// TestSharedReplayStoreRejectsCrossReplica is the M-3 regression: two adapter
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
