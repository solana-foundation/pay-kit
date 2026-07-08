package x402

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	solana "github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/rpc"
	"github.com/solana-foundation/pay-kit/go/paycore/signer"
	"github.com/solana-foundation/pay-kit/go/paykit"
	proto "github.com/solana-foundation/pay-kit/go/protocols/x402"
)

// Plain legacy SVM network slugs used to construct v1 credentials in these
// tests. The server normalizes them via normalizeNetwork before the gate.
const (
	legacyNetworkMainnet = "solana"
	legacyNetworkDevnet  = "solana-devnet"
)

// v1Credential re-wraps the transaction from a settle fixture into a legacy
// v1 envelope (x402Version=1, top-level scheme + plain network slug, no
// accepted object), returning the base64 X-PAYMENT header value.
func v1Credential(t *testing.T, v2Sig, network string) string {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(v2Sig)
	if err != nil {
		t.Fatal(err)
	}
	var v2 proto.Credential
	if err := json.Unmarshal(raw, &v2); err != nil {
		t.Fatal(err)
	}
	v1 := proto.Credential{
		X402Version: proto.X402VersionLegacy,
		Scheme:      proto.ExactScheme,
		Network:     network,
		Payload:     v2.Payload,
	}
	out, err := json.Marshal(v1)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(out)
}

// TestVerifyAndSettleV1HappyPath proves the server dual-accepts a legacy v1
// envelope posted in the X-PAYMENT header (PaymentSigLegacy), settles it,
// and echoes the settlement on the legacy X-PAYMENT-RESPONSE header.
func TestVerifyAndSettleV1HappyPath(t *testing.T) {
	fake := &fakeRPC{sig: solana.MustSignatureFromBase58(sampleSig), confirm: rpc.ConfirmationStatusConfirmed}
	a, gate, v2Sig := settleFixture(t, fake)
	// Localnet normalizes to the devnet CAIP-2, so the plain "solana-devnet"
	// slug matches the route network.
	v1Sig := v1Credential(t, v2Sig, legacyNetworkDevnet)

	pmt, err := a.VerifyAndSettle(&paykit.AdapterRequest{Gate: gate, PaymentSigLegacy: v1Sig})
	if err != nil {
		t.Fatalf("expected v1 settle to succeed, got %v", err)
	}
	if pmt.SettlementHeaders[proto.PaymentResponseHeaderLegacy] == "" {
		t.Error("v1 settle must emit the legacy x-payment-response header")
	}
	if pmt.SettlementHeaders[proto.PaymentResponseHeader] != "" {
		t.Error("v1 settle must not emit the canonical payment-response header")
	}
	if pmt.SettlementHeaders[proto.SettlementHeader] != sampleSig {
		t.Error("settlement signature header missing")
	}
	// The decoded v1 settlement body carries success + payer + network.
	body, err := base64.StdEncoding.DecodeString(pmt.SettlementHeaders[proto.PaymentResponseHeaderLegacy])
	if err != nil {
		t.Fatal(err)
	}
	var resp proto.SettlementResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatal(err)
	}
	if !resp.Success || resp.Payer == "" {
		t.Errorf("v1 settlement response: %+v", resp)
	}
}

// TestVerifyAndSettleV1PrefersV2Header proves that when both credentials are
// present the canonical Payment-Signature wins (the legacy header is only a
// fallback), matching the rust dual-read precedence.
func TestVerifyAndSettleV1PrefersV2Header(t *testing.T) {
	fake := &fakeRPC{sig: solana.MustSignatureFromBase58(sampleSig), confirm: rpc.ConfirmationStatusConfirmed}
	a, gate, v2Sig := settleFixture(t, fake)
	// A deliberately broken legacy credential: if the server fell back to
	// it instead of preferring the v2 header, the settle would fail.
	pmt, err := a.VerifyAndSettle(&paykit.AdapterRequest{
		Gate:             gate,
		PaymentSig:       v2Sig,
		PaymentSigLegacy: "not-base64-and-would-fail",
	})
	if err != nil {
		t.Fatalf("expected v2 header to win and settle, got %v", err)
	}
	if pmt.SettlementHeaders[proto.PaymentResponseHeader] == "" {
		t.Error("v2 settle must emit the canonical payment-response header")
	}
}

func TestVerifyAndSettleV1RejectsWrongScheme(t *testing.T) {
	fake := &fakeRPC{sig: solana.MustSignatureFromBase58(sampleSig), confirm: rpc.ConfirmationStatusConfirmed}
	a, gate, v2Sig := settleFixture(t, fake)

	raw, _ := base64.StdEncoding.DecodeString(v2Sig)
	var v2 proto.Credential
	_ = json.Unmarshal(raw, &v2)
	bad := proto.Credential{X402Version: proto.X402VersionLegacy, Scheme: "not-exact", Network: legacyNetworkDevnet, Payload: v2.Payload}
	badJSON, _ := json.Marshal(bad)

	_, err := a.VerifyAndSettle(&paykit.AdapterRequest{
		Gate:             gate,
		PaymentSigLegacy: base64.StdEncoding.EncodeToString(badJSON),
	})
	if err == nil {
		t.Fatal("expected scheme mismatch rejection")
	}
	var perr *paykit.PaymentError
	if !errorsAs(err, &perr) || perr.Code != "charge_request_mismatch" {
		t.Errorf("expected charge_request_mismatch, got %v", err)
	}
}

func TestVerifyAndSettleV1RejectsWrongNetwork(t *testing.T) {
	fake := &fakeRPC{sig: solana.MustSignatureFromBase58(sampleSig), confirm: rpc.ConfirmationStatusConfirmed}
	a, gate, v2Sig := settleFixture(t, fake)
	// "solana" normalizes to mainnet; the route is localnet (devnet).
	v1Sig := v1Credential(t, v2Sig, legacyNetworkMainnet)

	_, err := a.VerifyAndSettle(&paykit.AdapterRequest{Gate: gate, PaymentSigLegacy: v1Sig})
	if err == nil {
		t.Fatal("expected network mismatch rejection")
	}
	var perr *paykit.PaymentError
	if !errorsAs(err, &perr) || perr.Code != "charge_request_mismatch" {
		t.Errorf("expected charge_request_mismatch, got %v", err)
	}
}

func TestVerifyAndSettleStillRejectsUnknownVersion(t *testing.T) {
	a, err := New(cfgLocal())
	if err != nil {
		t.Fatal(err)
	}
	// A v1-shaped envelope (top-level scheme/network) carrying an unknown
	// version must still be rejected: dual-accept does not widen the gate.
	bad := proto.Credential{X402Version: 9, Scheme: proto.ExactScheme, Network: legacyNetworkDevnet}
	badJSON, _ := json.Marshal(bad)
	g := paykit.Gate{Amount: paykit.MustParseUSD("0.10")}
	_, err = a.VerifyAndSettle(&paykit.AdapterRequest{
		Gate:             &g,
		PaymentSigLegacy: base64.StdEncoding.EncodeToString(badJSON),
	})
	if err == nil {
		t.Fatal("expected version_mismatch for unknown version")
	}
	var perr *paykit.PaymentError
	if !errorsAs(err, &perr) || perr.Code != "version_mismatch" {
		t.Errorf("expected version_mismatch, got %v", err)
	}
}

func TestVerifyLegacyBindingDirect(t *testing.T) {
	a, err := New(cfgLocal())
	if err != nil {
		t.Fatal(err)
	}
	adapter := a.(*Adapter)
	g := &paykit.Gate{Amount: paykit.MustParseUSD("0.10")}

	if err := adapter.verifyLegacyBinding(g, &proto.Credential{Scheme: proto.ExactScheme, Network: legacyNetworkDevnet}); err != nil {
		t.Errorf("devnet slug against localnet route should bind: %v", err)
	}
	if err := adapter.verifyLegacyBinding(g, &proto.Credential{Scheme: "bad", Network: legacyNetworkDevnet}); err == nil {
		t.Error("non-exact scheme must be rejected")
	}
	if err := adapter.verifyLegacyBinding(g, &proto.Credential{Scheme: proto.ExactScheme, Network: legacyNetworkMainnet}); err == nil {
		t.Error("mainnet slug against devnet route must be rejected")
	}
}

// cfgLocal builds a localnet adapter config for the envelope-level v1 tests
// that never reach broadcast.
func cfgLocal() paykit.Config {
	return paykit.Config{
		Network: paykit.SolanaLocalnet,
		Accept:  []paykit.Protocol{paykit.X402},
		Operator: paykit.Operator{
			Signer:    signer.Demo(),
			Recipient: signer.Demo().Pubkey(),
		},
		X402:                    paykit.X402Config{Scheme: "exact"},
		RecentBlockhashProvider: func() (string, error) { return "BLOCKHASH-STUB-111111111111111111111111111", nil },
		RecentSlotProvider:      func() (uint64, error) { return 55_555, nil },
	}
}
