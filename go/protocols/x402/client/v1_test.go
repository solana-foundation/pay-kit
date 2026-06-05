package client

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/solana-foundation/pay-kit/go/internal/testutil"
	x402 "github.com/solana-foundation/pay-kit/go/protocols/x402"
)

// decodeV1Credential decodes a legacy X-PAYMENT header into the typed
// credential so the v1 wire shape can be asserted: x402Version=1, top-level
// scheme + plain network slug, NO accepted object.
func decodeV1Credential(t *testing.T, header string) x402.Credential {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(header)
	if err != nil {
		t.Fatalf("base64 decode: %v", err)
	}
	var cred x402.Credential
	if err := json.Unmarshal(raw, &cred); err != nil {
		t.Fatalf("unmarshal credential: %v", err)
	}
	return cred
}

func TestV1NetworkForEntry(t *testing.T) {
	cases := []struct {
		network string
		want    string
	}{
		{"devnet", legacyNetworkDevnet},
		{"solana-devnet", legacyNetworkDevnet},
		{"localnet", legacyNetworkDevnet},
		{devnetCAIP2, legacyNetworkDevnet},
		{mainnetCAIP2, legacyNetworkMainnet},
		{"mainnet-beta", legacyNetworkMainnet},
		{"solana:4uhcVJyU9pJkvQyS88uRDiswHXSCkY3z", legacyNetworkMainnet}, // testnet collapses to "solana"
		{"", legacyNetworkMainnet},
	}
	for _, c := range cases {
		e := entry(testutil.NewPrivateKey().PublicKey().String(), "1", c.network)
		if got := v1NetworkForEntry(&e); got != c.want {
			t.Errorf("v1NetworkForEntry(%q): got %q want %q", c.network, got, c.want)
		}
	}
}

func TestBuildPaymentHeaderV1Devnet(t *testing.T) {
	signer := testutil.NewPrivateKey()
	e := entry(testutil.NewPrivateKey().PublicKey().String(), "1000", devnetCAIP2)

	header, err := BuildPaymentHeaderV1(context.Background(), signer, testutil.NewFakeRPC(), &e)
	if err != nil {
		t.Fatal(err)
	}
	cred := decodeV1Credential(t, header)
	if cred.X402Version != x402VersionLegacy {
		t.Errorf("x402Version: got %d want %d", cred.X402Version, x402VersionLegacy)
	}
	if cred.Scheme != exactScheme {
		t.Errorf("scheme: got %q want %q", cred.Scheme, exactScheme)
	}
	if cred.Network != legacyNetworkDevnet {
		t.Errorf("network: got %q want %q (plain slug, not CAIP-2)", cred.Network, legacyNetworkDevnet)
	}
	if cred.Accepted != nil {
		t.Error("v1 envelope must not carry an accepted object")
	}
	if cred.Payload.Transaction == "" {
		t.Error("v1 envelope missing transaction payload")
	}
}

func TestBuildPaymentHeaderV1MainnetNetworkName(t *testing.T) {
	signer := testutil.NewPrivateKey()
	e := entry(testutil.NewPrivateKey().PublicKey().String(), "10000", mainnetCAIP2)

	header, err := BuildPaymentHeaderV1(context.Background(), signer, testutil.NewFakeRPC(), &e)
	if err != nil {
		t.Fatal(err)
	}
	cred := decodeV1Credential(t, header)
	if cred.Network != legacyNetworkMainnet {
		t.Errorf("network: got %q want %q", cred.Network, legacyNetworkMainnet)
	}
}

func TestBuildPaymentHeaderV1NilEntry(t *testing.T) {
	if _, err := BuildPaymentHeaderV1(context.Background(), testutil.NewPrivateKey(), testutil.NewFakeRPC(), nil); err == nil {
		t.Fatal("expected error for nil entry")
	}
}

func TestBuildPaymentHeaderV1BuildError(t *testing.T) {
	signer := testutil.NewPrivateKey()
	// A non-base58 recipient makes buildTransaction fail, so the v1
	// producer must surface that error rather than emit a header.
	e := entry(testutil.NewPrivateKey().PublicKey().String(), "1000", devnetCAIP2)
	e.PayTo = "not-a-valid-base58-key"
	if _, err := BuildPaymentHeaderV1(context.Background(), signer, testutil.NewFakeRPC(), &e); err == nil {
		t.Fatal("expected build error for invalid recipient")
	}
}

func TestParseChallengeVersionedV1Header(t *testing.T) {
	e := entry(testutil.NewPrivateKey().PublicKey().String(), "1000", devnetCAIP2)
	// A v1 challenge advertised in the legacy X-PAYMENT-REQUIRED header,
	// carried as plain (un-base64'd) JSON, mirroring the rust dual-read.
	body, _ := json.Marshal(challengeEnvelope{X402Version: x402VersionLegacy, Accepts: []x402.AcceptsEntry{e}})
	h := http.Header{}
	h.Set(paymentRequiredHeaderLegacy, string(body))

	got, version, ok := ParseChallengeVersioned(h, nil, ChallengeSelection{})
	if !ok {
		t.Fatal("expected to parse a v1 challenge from the legacy header")
	}
	if version != x402VersionLegacy {
		t.Errorf("version: got %d want %d", version, x402VersionLegacy)
	}
	if got == nil || got.Amount != "1000" {
		t.Errorf("selected entry: got %+v", got)
	}
}

func TestParseChallengeVersionedV1Body(t *testing.T) {
	e := entry(testutil.NewPrivateKey().PublicKey().String(), "1000", devnetCAIP2)
	body, _ := json.Marshal(challengeEnvelope{X402Version: x402VersionLegacy, Accepts: []x402.AcceptsEntry{e}})

	_, version, ok := ParseChallengeVersioned(http.Header{}, body, ChallengeSelection{})
	if !ok {
		t.Fatal("expected to parse a v1 challenge from the 402 body")
	}
	if version != x402VersionLegacy {
		t.Errorf("version: got %d want %d", version, x402VersionLegacy)
	}
}

func TestParseChallengeVersionedV2HeaderWins(t *testing.T) {
	e := entry(testutil.NewPrivateKey().PublicKey().String(), "1000", devnetCAIP2)
	v2, _ := json.Marshal(challengeEnvelope{X402Version: x402Version, Accepts: []x402.AcceptsEntry{e}})
	v1, _ := json.Marshal(challengeEnvelope{X402Version: x402VersionLegacy, Accepts: []x402.AcceptsEntry{e}})
	h := http.Header{}
	// Both headers present: the canonical v2 header takes precedence.
	h.Set(paymentRequiredHeader, base64.StdEncoding.EncodeToString(v2))
	h.Set(paymentRequiredHeaderLegacy, string(v1))

	_, version, ok := ParseChallengeVersioned(h, nil, ChallengeSelection{})
	if !ok {
		t.Fatal("expected a challenge")
	}
	if version != x402Version {
		t.Errorf("version: got %d want %d (v2 header must win)", version, x402Version)
	}
}

func TestParseChallengeVersionedDefaultsToV2(t *testing.T) {
	e := entry(testutil.NewPrivateKey().PublicKey().String(), "1000", mainnetCAIP2)
	// Envelope without an explicit x402Version: defaults to the canonical
	// version so the transport stays a v2 producer.
	body, _ := json.Marshal(struct {
		Accepts []x402.AcceptsEntry `json:"accepts"`
	}{Accepts: []x402.AcceptsEntry{e}})

	_, version, ok := ParseChallengeVersioned(http.Header{}, body, ChallengeSelection{})
	if !ok {
		t.Fatal("expected a challenge")
	}
	if version != x402Version {
		t.Errorf("version: got %d want %d", version, x402Version)
	}
}

// TestPaymentTransportSettlesV1Challenge proves the dual-read transport
// emits the legacy X-PAYMENT producer (not Payment-Signature) when the
// server's challenge declared v1.
func TestPaymentTransportSettlesV1Challenge(t *testing.T) {
	signer := testutil.NewPrivateKey()
	e := entry(testutil.NewPrivateKey().PublicKey().String(), "100000", devnetCAIP2)
	challenge, _ := json.Marshal(challengeEnvelope{X402Version: x402VersionLegacy, Accepts: []x402.AcceptsEntry{e}})

	var sawV1, sawV2 string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if cred := r.Header.Get(paymentHeaderLegacy); cred != "" {
			sawV1 = cred
			_, _ = io.WriteString(w, `{"ok":true}`)
			return
		}
		if cred := r.Header.Get(paymentSignatureHeader); cred != "" {
			sawV2 = cred
			_, _ = io.WriteString(w, `{"ok":true}`)
			return
		}
		// Advertise the v1 challenge as a 402 JSON body.
		w.WriteHeader(http.StatusPaymentRequired)
		_, _ = w.Write(challenge)
	}))
	defer srv.Close()

	resp, err := NewClient(signer, testutil.NewFakeRPC()).Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d want 200", resp.StatusCode)
	}
	if sawV1 == "" {
		t.Fatal("server never received an X-PAYMENT credential")
	}
	if sawV2 != "" {
		t.Fatal("a v1 challenge must not produce a Payment-Signature credential")
	}
	cred := decodeV1Credential(t, sawV1)
	if cred.X402Version != x402VersionLegacy || cred.Scheme != exactScheme || cred.Network != legacyNetworkDevnet {
		t.Errorf("v1 credential shape wrong: %+v", cred)
	}
}
