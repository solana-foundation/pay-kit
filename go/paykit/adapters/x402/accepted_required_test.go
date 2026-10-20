package x402

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	solana "github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/rpc"

	"github.com/solana-foundation/pay-kit/go/paykit"
)

// x402 v2 makes PaymentPayload.accepted required. A v2 credential without
// it used to skip the route binding and settle; it is now refused before
// any broadcast. The positive control is the same credential with its
// accepted echo intact.
func TestVerifyAndSettleRejectsV2CredentialWithoutAccepted(t *testing.T) {
	fake := &fakeRPC{sig: solana.MustSignatureFromBase58(sampleSig), confirm: rpc.ConfirmationStatusConfirmed}
	a, gate, sig := settleFixture(t, fake)

	raw, err := base64.StdEncoding.DecodeString(sig)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	delete(m, "accepted")
	stripped, _ := json.Marshal(m)

	_, err = a.VerifyAndSettle(&paykit.AdapterRequest{Gate: gate, PaymentSig: base64.StdEncoding.EncodeToString(stripped)})
	var perr *paykit.PaymentError
	if !errorsAs(err, &perr) || perr.Code != "invalid_payload" {
		t.Fatalf("expected invalid_payload for a v2 credential without accepted, got %v", err)
	}
	if fake.sends != 0 {
		t.Fatal("credential without accepted reached broadcast")
	}
	if _, err := a.VerifyAndSettle(&paykit.AdapterRequest{Gate: gate, PaymentSig: sig}); err != nil {
		t.Fatalf("control credential with accepted: %v", err)
	}
}
