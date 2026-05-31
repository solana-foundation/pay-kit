package client

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	solana "github.com/gagliardetto/solana-go"
	"github.com/solana-foundation/pay-kit/go/internal/testutil"
	"github.com/solana-foundation/pay-kit/go/paycore"
	"github.com/solana-foundation/pay-kit/go/paycore/solanatx"
	x402 "github.com/solana-foundation/pay-kit/go/protocols/x402"
)

const (
	mainnetCAIP2 = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"
	devnetCAIP2  = "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1"
)

// blockhash returns a valid base58 32-byte string (a pubkey doubles as one)
// so BuildPaymentHeader never needs an RPC round trip in tests.
func blockhash() string { return testutil.NewPrivateKey().PublicKey().String() }

func entry(asset, amount, network string) x402.AcceptsEntry {
	return x402.AcceptsEntry{
		Protocol: "x402",
		Scheme:   "exact",
		Network:  network,
		Asset:    asset,
		Amount:   amount,
		PayTo:    testutil.NewPrivateKey().PublicKey().String(),
		Extra: x402.Extra{
			FeePayer:        true,
			FeePayerSet:     true,
			FeePayerKey:     testutil.NewPrivateKey().PublicKey().String(),
			Decimals:        6,
			DecimalsSet:     true,
			TokenProgram:    solana.TokenProgramID.String(),
			Memo:            "test",
			RecentBlockhash: blockhash(),
		},
	}
}

func TestSelectEntryCheapest(t *testing.T) {
	usdc := testutil.NewPrivateKey().PublicKey().String()
	usdt := testutil.NewPrivateKey().PublicKey().String()
	accepts := []x402.AcceptsEntry{
		entry(usdc, "500000", mainnetCAIP2),
		entry(usdt, "100000", mainnetCAIP2),
	}
	got := selectEntry(accepts, ChallengeSelection{})
	if got == nil || got.Amount != "100000" {
		t.Fatalf("cheapest: got %+v", got)
	}
}

func TestSelectEntryCurrencyPriority(t *testing.T) {
	usdc := testutil.NewPrivateKey().PublicKey().String()
	usdt := testutil.NewPrivateKey().PublicKey().String()
	accepts := []x402.AcceptsEntry{
		entry(usdc, "500000", mainnetCAIP2),
		entry(usdt, "100000", mainnetCAIP2),
	}
	// Prefer the usdc mint even though usdt is cheaper.
	got := selectEntry(accepts, ChallengeSelection{Currencies: []string{usdc}})
	if got == nil || got.Asset != usdc {
		t.Fatalf("currency priority: got %+v", got)
	}
	// No matching currency -> no fallback.
	if got := selectEntry(accepts, ChallengeSelection{Currencies: []string{"NOPE"}}); got != nil {
		t.Fatalf("expected nil for unmatched currency, got %+v", got)
	}
}

func TestSelectEntryNetworkFilter(t *testing.T) {
	a := testutil.NewPrivateKey().PublicKey().String()
	accepts := []x402.AcceptsEntry{
		entry(a, "100000", devnetCAIP2),
		entry(a, "500000", mainnetCAIP2),
	}
	got := selectEntry(accepts, ChallengeSelection{Network: mainnetCAIP2})
	if got == nil || got.Network != mainnetCAIP2 {
		t.Fatalf("network filter: got %+v", got)
	}
}

func TestSelectEntryIgnoresNonX402AndNonSolana(t *testing.T) {
	mpp := entry(testutil.NewPrivateKey().PublicKey().String(), "1", mainnetCAIP2)
	mpp.Protocol = "mpp"
	evm := entry(testutil.NewPrivateKey().PublicKey().String(), "1", "eip155:1")
	if got := selectEntry([]x402.AcceptsEntry{mpp, evm}, ChallengeSelection{}); got != nil {
		t.Fatalf("expected nil, got %+v", got)
	}
}

func TestParseChallengeFromHeaderAndBody(t *testing.T) {
	e := entry(testutil.NewPrivateKey().PublicKey().String(), "100000", mainnetCAIP2)
	raw, _ := json.Marshal(challengeEnvelope{X402Version: 2, Accepts: []x402.AcceptsEntry{e}})

	h := http.Header{}
	h.Set(paymentRequiredHeader, base64.StdEncoding.EncodeToString(raw))
	if got, ok := ParseChallenge(h, nil, ChallengeSelection{}); !ok || got.Amount != "100000" {
		t.Fatalf("header parse: ok=%v got=%+v", ok, got)
	}

	// Body (x402-express) fallback when the header is absent.
	if got, ok := ParseChallenge(http.Header{}, raw, ChallengeSelection{}); !ok || got.Amount != "100000" {
		t.Fatalf("body parse: ok=%v got=%+v", ok, got)
	}

	if _, ok := ParseChallenge(http.Header{}, nil, ChallengeSelection{}); ok {
		t.Fatal("expected no challenge")
	}
}

func TestBuildPaymentHeaderSPL(t *testing.T) {
	signer := testutil.NewPrivateKey()
	e := entry(testutil.NewPrivateKey().PublicKey().String(), "100000", mainnetCAIP2)

	header, err := BuildPaymentHeader(context.Background(), signer, testutil.NewFakeRPC(), &e)
	if err != nil {
		t.Fatal(err)
	}
	tx := decodeCredentialTx(t, header)

	// compute limit, compute price, transferChecked, memo.
	if len(tx.Message.Instructions) != 4 {
		t.Fatalf("instruction count: got %d want 4", len(tx.Message.Instructions))
	}
	// Fee payer (account 0) is the server's advertised fee payer, left
	// unsigned for the server to cosign.
	feePayer := solana.MustPublicKeyFromBase58(e.Extra.FeePayerKey)
	if !tx.Message.AccountKeys[0].Equals(feePayer) {
		t.Errorf("fee payer: got %s want %s", tx.Message.AccountKeys[0], feePayer)
	}
	if len(tx.Signatures) != 2 {
		t.Fatalf("signatures: got %d want 2", len(tx.Signatures))
	}
	if !tx.Signatures[0].IsZero() {
		t.Error("server fee-payer slot should be unsigned")
	}
}

func TestBuildPaymentHeaderSOL(t *testing.T) {
	signer := testutil.NewPrivateKey()
	e := entry("", "1000000", mainnetCAIP2) // empty Asset => native SOL
	e.Extra.FeePayer = false                // self-paid
	e.Extra.FeePayerKey = ""

	header, err := BuildPaymentHeader(context.Background(), signer, testutil.NewFakeRPC(), &e)
	if err != nil {
		t.Fatal(err)
	}
	tx := decodeCredentialTx(t, header)
	// compute limit, compute price, system transfer, memo.
	if len(tx.Message.Instructions) != 4 {
		t.Fatalf("instruction count: got %d want 4", len(tx.Message.Instructions))
	}
	if !tx.Message.AccountKeys[0].Equals(signer.PublicKey()) {
		t.Error("self-paid fee payer should be the signer")
	}
}

func TestBuildPaymentHeaderNilEntry(t *testing.T) {
	if _, err := BuildPaymentHeader(context.Background(), testutil.NewPrivateKey(), testutil.NewFakeRPC(), nil); err == nil {
		t.Fatal("expected error for nil entry")
	}
}

func TestCurrencyMatches(t *testing.T) {
	mint := testutil.NewPrivateKey().PublicKey().String()
	if !currencyMatches(mint, mint) {
		t.Error("direct mint match failed")
	}
	if currencyMatches(mint, "USDC") {
		t.Error("random mint should not match USDC symbol")
	}
}

func TestPaymentTransportSettles402(t *testing.T) {
	signer := testutil.NewPrivateKey()
	e := entry(testutil.NewPrivateKey().PublicKey().String(), "100000", mainnetCAIP2)
	challenge, _ := json.Marshal(challengeEnvelope{X402Version: 2, Accepts: []x402.AcceptsEntry{e}})

	var sawCredential string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if cred := r.Header.Get(paymentSignatureHeader); cred != "" {
			sawCredential = cred
			_, _ = io.WriteString(w, `{"ok":true}`)
			return
		}
		w.Header().Set(paymentRequiredHeader, base64.StdEncoding.EncodeToString(challenge))
		w.WriteHeader(http.StatusPaymentRequired)
	}))
	defer srv.Close()

	httpClient := NewClient(signer, testutil.NewFakeRPC())
	resp, err := httpClient.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d want 200", resp.StatusCode)
	}
	if sawCredential == "" {
		t.Fatal("server never received a Payment-Signature")
	}
	// The credential the server saw decodes to a valid signed tx.
	tx := decodeCredentialTx(t, sawCredential)
	if len(tx.Message.Instructions) != 4 {
		t.Errorf("settled tx instruction count: got %d", len(tx.Message.Instructions))
	}
}

func TestPaymentTransportPassesThroughNon402(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	defer srv.Close()
	resp, err := NewClient(testutil.NewPrivateKey(), testutil.NewFakeRPC()).Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d", resp.StatusCode)
	}
}

func TestPaymentTransportLeavesUnknown402(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusPaymentRequired) // no payment-required header
	}))
	defer srv.Close()
	resp, err := NewClient(testutil.NewPrivateKey(), testutil.NewFakeRPC()).Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusPaymentRequired {
		t.Fatalf("expected the original 402 to pass through, got %d", resp.StatusCode)
	}
}

func decodeCredentialTx(t *testing.T, header string) *solana.Transaction {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(header)
	if err != nil {
		t.Fatal(err)
	}
	var cred x402.Credential
	if err := json.Unmarshal(raw, &cred); err != nil {
		t.Fatal(err)
	}
	if cred.X402Version != 2 {
		t.Errorf("x402Version: got %d", cred.X402Version)
	}
	if !strings.EqualFold(cred.Scheme, "exact") {
		t.Errorf("scheme: got %q", cred.Scheme)
	}
	tx, err := solanatx.DecodeTransactionBase64(cred.Payload.Transaction)
	if err != nil {
		t.Fatal(err)
	}
	return tx
}

func TestBuildTransactionErrorPaths(t *testing.T) {
	signer := testutil.NewPrivateKey()
	rpc := testutil.NewFakeRPC()
	ctx := context.Background()
	mint := testutil.NewPrivateKey().PublicKey().String()

	cases := map[string]func(e *x402.AcceptsEntry){
		"bad amount":        func(e *x402.AcceptsEntry) { e.Amount = "notanumber" },
		"bad recipient":     func(e *x402.AcceptsEntry) { e.PayTo = "!!!" },
		"bad mint":          func(e *x402.AcceptsEntry) { e.Asset = "!!!" },
		"bad token program": func(e *x402.AcceptsEntry) { e.Extra.TokenProgram = "!!!" },
		"bad fee payer":     func(e *x402.AcceptsEntry) { e.Extra.FeePayerKey = "!!!" },
	}
	for name, mutate := range cases {
		e := entry(mint, "100000", mainnetCAIP2)
		mutate(&e)
		if _, err := BuildPaymentHeader(ctx, signer, rpc, &e); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestBuildPaymentHeaderFetchesBlockhashFromRPC(t *testing.T) {
	signer := testutil.NewPrivateKey()
	e := entry(testutil.NewPrivateKey().PublicKey().String(), "100000", mainnetCAIP2)
	e.Extra.RecentBlockhash = "" // force the RPC GetLatestBlockhash path
	if _, err := BuildPaymentHeader(context.Background(), signer, testutil.NewFakeRPC(), &e); err != nil {
		t.Fatalf("expected RPC blockhash fallback to succeed: %v", err)
	}
}

func TestCurrencyMatchesSymbol(t *testing.T) {
	usdc := paycore.ResolveMint("USDC", "mainnet-beta")
	if !currencyMatches(usdc, "USDC") {
		t.Error("USDC symbol should resolve to its mainnet mint")
	}
}

func TestPaymentTransportSettlesPOSTWithBody(t *testing.T) {
	signer := testutil.NewPrivateKey()
	e := entry(testutil.NewPrivateKey().PublicKey().String(), "100000", mainnetCAIP2)
	challenge, _ := json.Marshal(challengeEnvelope{X402Version: 2, Accepts: []x402.AcceptsEntry{e}})
	var gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(paymentSignatureHeader) != "" {
			b, _ := io.ReadAll(r.Body)
			gotBody = string(b)
			_, _ = io.WriteString(w, "ok")
			return
		}
		w.Header().Set(paymentRequiredHeader, base64.StdEncoding.EncodeToString(challenge))
		w.WriteHeader(http.StatusPaymentRequired)
	}))
	defer srv.Close()

	resp, err := NewClient(signer, testutil.NewFakeRPC()).Post(srv.URL, "text/plain", strings.NewReader("payload"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if gotBody != "payload" {
		t.Errorf("request body not replayed on retry: got %q", gotBody)
	}
}

func TestParseChallengeInvalidJSON(t *testing.T) {
	if _, ok := ParseChallenge(http.Header{}, []byte("{not json"), ChallengeSelection{}); ok {
		t.Error("garbage body should not yield a challenge")
	}
	h := http.Header{}
	h.Set(paymentRequiredHeader, base64.StdEncoding.EncodeToString([]byte("{not json")))
	if _, ok := ParseChallenge(h, nil, ChallengeSelection{}); ok {
		t.Error("garbage header should not yield a challenge")
	}
}

// memoData returns the data of the single Memo Program instruction in the
// transaction, failing the test if there is not exactly one.
func memoData(t *testing.T, tx *solana.Transaction) string {
	t.Helper()
	memoProgram := solana.MustPublicKeyFromBase58(paycore.MemoProgram)
	var found []string
	for _, ix := range tx.Message.Instructions {
		idx := int(ix.ProgramIDIndex)
		if idx < 0 || idx >= len(tx.Message.AccountKeys) {
			t.Fatalf("instruction program index %d out of range", idx)
		}
		if tx.Message.AccountKeys[idx].Equals(memoProgram) {
			found = append(found, string(ix.Data))
		}
	}
	if len(found) != 1 {
		t.Fatalf("expected exactly one memo instruction, found %d", len(found))
	}
	return found[0]
}

// TestBuildPaymentHeaderAppendsNonceMemoWhenNoExtraMemo proves the client
// always appends a Memo instruction even when the offer carries no
// extra.memo, using a random >=16-byte hex nonce. This guarantees uniqueness
// of otherwise-identical payments. Regression for Decision 2.
func TestBuildPaymentHeaderAppendsNonceMemoWhenNoExtraMemo(t *testing.T) {
	signer := testutil.NewPrivateKey()
	e := entry(testutil.NewPrivateKey().PublicKey().String(), "100000", mainnetCAIP2)
	e.Extra.Memo = "" // no seller-pinned memo

	header, err := BuildPaymentHeader(context.Background(), signer, testutil.NewFakeRPC(), &e)
	if err != nil {
		t.Fatal(err)
	}
	tx := decodeCredentialTx(t, header)
	// compute limit, compute price, transferChecked, nonce memo.
	if len(tx.Message.Instructions) != 4 {
		t.Fatalf("instruction count: got %d want 4", len(tx.Message.Instructions))
	}
	memo := memoData(t, tx)
	raw, err := hex.DecodeString(memo)
	if err != nil {
		t.Fatalf("nonce memo %q is not hex-encoded: %v", memo, err)
	}
	if len(raw) < 16 {
		t.Fatalf("nonce memo decodes to %d bytes, want >= 16", len(raw))
	}
}

// TestBuildPaymentHeaderNonceMemoIsUnique proves two payments built from the
// same offer carry distinct nonce memos so the transactions are unique.
func TestBuildPaymentHeaderNonceMemoIsUnique(t *testing.T) {
	signer := testutil.NewPrivateKey()
	e := entry(testutil.NewPrivateKey().PublicKey().String(), "100000", mainnetCAIP2)
	e.Extra.Memo = ""

	build := func() string {
		header, err := BuildPaymentHeader(context.Background(), signer, testutil.NewFakeRPC(), &e)
		if err != nil {
			t.Fatal(err)
		}
		return memoData(t, decodeCredentialTx(t, header))
	}
	if a, b := build(), build(); a == b {
		t.Fatalf("two payments produced identical nonce memos %q", a)
	}
}

// TestBuildPaymentHeaderUsesExtraMemoWhenPresent proves the seller-pinned
// extra.memo wins over a generated nonce.
func TestBuildPaymentHeaderUsesExtraMemoWhenPresent(t *testing.T) {
	signer := testutil.NewPrivateKey()
	e := entry(testutil.NewPrivateKey().PublicKey().String(), "100000", mainnetCAIP2)
	e.Extra.Memo = "pi_invoice_42"

	header, err := BuildPaymentHeader(context.Background(), signer, testutil.NewFakeRPC(), &e)
	if err != nil {
		t.Fatal(err)
	}
	if got := memoData(t, decodeCredentialTx(t, header)); got != "pi_invoice_42" {
		t.Fatalf("memo: got %q want %q", got, "pi_invoice_42")
	}
}

// TestNonceSourceIsInjectable proves the nonce source can be overridden so
// deterministic/golden-vector tests get a fixed nonce.
func TestNonceSourceIsInjectable(t *testing.T) {
	signer := testutil.NewPrivateKey()
	e := entry(testutil.NewPrivateKey().PublicKey().String(), "100000", mainnetCAIP2)
	e.Extra.Memo = ""

	fixed := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	orig := nonceSource
	nonceSource = func() ([]byte, error) { return fixed, nil }
	defer func() { nonceSource = orig }()

	header, err := BuildPaymentHeader(context.Background(), signer, testutil.NewFakeRPC(), &e)
	if err != nil {
		t.Fatal(err)
	}
	if got := memoData(t, decodeCredentialTx(t, header)); got != hex.EncodeToString(fixed) {
		t.Fatalf("memo: got %q want %q", got, hex.EncodeToString(fixed))
	}
}

func TestCheapestSkipsUnparseableAmount(t *testing.T) {
	mint := testutil.NewPrivateKey().PublicKey().String()
	junk := entry(mint, "notanumber", mainnetCAIP2)
	good := entry(mint, "42", mainnetCAIP2)
	got := selectEntry([]x402.AcceptsEntry{junk, good}, ChallengeSelection{})
	if got == nil || got.Amount != "42" {
		t.Fatalf("cheapest should skip the unparseable amount, got %+v", got)
	}
}

func TestPaymentTransportUsesExplicitBase(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	defer srv.Close()
	tr := &PaymentTransport{Base: http.DefaultTransport, Signer: testutil.NewPrivateKey(), RPC: testutil.NewFakeRPC()}
	resp, err := (&http.Client{Transport: tr}).Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d", resp.StatusCode)
	}
}

func TestPaymentTransportReturnsBuildError(t *testing.T) {
	bad := entry("!!!notamint", "100000", mainnetCAIP2) // unbuildable offer
	challenge, _ := json.Marshal(challengeEnvelope{X402Version: 2, Accepts: []x402.AcceptsEntry{bad}})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set(paymentRequiredHeader, base64.StdEncoding.EncodeToString(challenge))
		w.WriteHeader(http.StatusPaymentRequired)
	}))
	defer srv.Close()
	if _, err := NewClient(testutil.NewPrivateKey(), testutil.NewFakeRPC()).Get(srv.URL); err == nil {
		t.Error("expected the transport to surface the build error for an unbuildable offer")
	}
}

// TestBuildTransactionNonceSourceError proves that a failing nonce source
// propagates as an error from buildTransaction (the branch at client.go:276).
func TestBuildTransactionNonceSourceError(t *testing.T) {
	signer := testutil.NewPrivateKey()
	e := entry(testutil.NewPrivateKey().PublicKey().String(), "100000", mainnetCAIP2)
	e.Extra.Memo = "" // force the nonce-source path

	orig := nonceSource
	nonceSource = func() ([]byte, error) { return nil, fmt.Errorf("entropy exhausted") }
	defer func() { nonceSource = orig }()

	_, err := BuildPaymentHeader(context.Background(), signer, testutil.NewFakeRPC(), &e)
	if err == nil {
		t.Fatal("expected error when nonce source fails")
	}
	if !strings.Contains(err.Error(), "generate memo nonce") {
		t.Fatalf("unexpected error: %v", err)
	}
}
