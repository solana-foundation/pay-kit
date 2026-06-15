package x402

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/solana-foundation/pay-kit/go/paycore/signer"
	"github.com/solana-foundation/pay-kit/go/paykit"
)

// Finding #11: the server enforces the credential's echoed `accepted`
// offer against the route's requirements before settlement, matching
// Rust verify_envelope_payload (server/exact.rs:490-541). A credential
// that lies about its accepted amount/recipient/network/currency is
// rejected. Before the fix the server ignored credential.Accepted, so a
// lying offer reached the structural/broadcast path.
func bindingAdapter(t *testing.T) *Adapter {
	t.Helper()
	op := signer.Generate()
	return &Adapter{
		cfg: paykit.Config{
			Network:     paykit.SolanaMainnet,
			Stablecoins: []paykit.Stablecoin{paykit.USDC},
			Operator:    paykit.Operator{Signer: op, Recipient: op.Pubkey()},
			X402:        paykit.X402Config{Scheme: "exact"},
		},
		signer:            op,
		blockhashProvider: func() (string, error) { return "BH", nil },
	}
}

func encodeCredential(t *testing.T, cred Credential) string {
	t.Helper()
	raw, err := json.Marshal(cred)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(raw)
}

func TestVerifyRejectsLyingAcceptedAmount(t *testing.T) {
	a := bindingAdapter(t)
	gate := paykit.Gate{Amount: paykit.MustParseUSD("0.10")}

	// Build the route's honest accepted view, then tamper the amount.
	route := a.routeAccepts(&gate)
	tampered := route
	tampered.Amount = "999999999"
	tampered.MaxAmountRequired = "999999999"

	cred := Credential{
		X402Version: x402Version,
		Payload:     CredentialPayload{Transaction: base64.StdEncoding.EncodeToString([]byte("ignored"))},
		Accepted:    &tampered,
	}
	_, err := a.VerifyAndSettle(&paykit.AdapterRequest{Gate: &gate, PaymentSig: encodeCredential(t, cred)})
	var perr *paykit.PaymentError
	if !errorsAs(err, &perr) || perr.Code != "charge_request_mismatch" {
		t.Fatalf("expected charge_request_mismatch for lying amount, got %v", err)
	}
}

func TestVerifyRejectsLyingAcceptedRecipient(t *testing.T) {
	a := bindingAdapter(t)
	gate := paykit.Gate{Amount: paykit.MustParseUSD("0.10")}

	route := a.routeAccepts(&gate)
	tampered := route
	tampered.PayTo = string(signer.Generate().Pubkey())

	cred := Credential{
		X402Version: x402Version,
		Payload:     CredentialPayload{Transaction: base64.StdEncoding.EncodeToString([]byte("ignored"))},
		Accepted:    &tampered,
	}
	_, err := a.VerifyAndSettle(&paykit.AdapterRequest{Gate: &gate, PaymentSig: encodeCredential(t, cred)})
	var perr *paykit.PaymentError
	if !errorsAs(err, &perr) || perr.Code != "charge_request_mismatch" {
		t.Fatalf("expected charge_request_mismatch for lying recipient, got %v", err)
	}
}

func TestVerifyAcceptsHonestAcceptedThenProceeds(t *testing.T) {
	a := bindingAdapter(t)
	gate := paykit.Gate{Amount: paykit.MustParseUSD("0.10")}

	// Honest accepted echo: binding passes, so the flow proceeds past the
	// binding gate and fails later on the bogus transaction payload (not
	// on charge_request_mismatch from the binding check).
	honest := a.routeAccepts(&gate)
	cred := Credential{
		X402Version: x402Version,
		Payload:     CredentialPayload{Transaction: base64.StdEncoding.EncodeToString([]byte("not-a-tx"))},
		Accepted:    &honest,
	}
	_, err := a.VerifyAndSettle(&paykit.AdapterRequest{Gate: &gate, PaymentSig: encodeCredential(t, cred)})
	var perr *paykit.PaymentError
	if !errorsAs(err, &perr) {
		t.Fatalf("expected a PaymentError, got %v", err)
	}
	if perr.Code == "charge_request_mismatch" {
		t.Fatalf("honest accepted should pass the binding gate, got %v", err)
	}
}
