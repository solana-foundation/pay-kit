package client

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/solana-foundation/pay-kit/go/internal/testutil"
	"github.com/solana-foundation/pay-kit/go/protocols/x402"
)

func TestEchoAndAppendExtensions(t *testing.T) {
	t.Run("nil when server advertised none", func(t *testing.T) {
		got, err := echoAndAppendExtensions(nil)
		if err != nil {
			t.Fatal(err)
		}
		if got != nil {
			t.Fatalf("got %+v, want nil", got)
		}
	})

	t.Run("generates a valid id when required and none supplied", func(t *testing.T) {
		advertised := json.RawMessage(`{"payment-identifier":{"info":{"required":true}}}`)
		got, err := echoAndAppendExtensions(advertised)
		if err != nil {
			t.Fatal(err)
		}
		id := got.PaymentIdentifierID()
		if !x402.IsValidPaymentIdentifierID(id) {
			t.Fatalf("generated id %q violates spec pattern", id)
		}
		if !got.RequiresPaymentIdentifier() {
			t.Fatal("server required flag dropped")
		}
	})

	t.Run("preserves a client-supplied id without regenerating", func(t *testing.T) {
		advertised := json.RawMessage(`{"payment-identifier":{"info":{"required":true,"id":"pay_clientsupplied01"}}}`)
		got, err := echoAndAppendExtensions(advertised)
		if err != nil {
			t.Fatal(err)
		}
		if got.PaymentIdentifierID() != "pay_clientsupplied01" {
			t.Fatalf("id = %q, want preserved", got.PaymentIdentifierID())
		}
	})

	t.Run("nil when echoed object is empty", func(t *testing.T) {
		got, err := echoAndAppendExtensions(json.RawMessage(`{}`))
		if err != nil {
			t.Fatal(err)
		}
		if got != nil {
			t.Fatalf("got %+v, want nil for empty extensions", got)
		}
	})

	t.Run("error on malformed inbound", func(t *testing.T) {
		if _, err := echoAndAppendExtensions(json.RawMessage(`{`)); err == nil {
			t.Fatal("expected error")
		}
	})
}

// credentialExtensions decodes the base64 PAYMENT-SIGNATURE header and
// returns the raw extensions object carried on the credential (nil when
// the credential omitted it).
func credentialExtensions(t *testing.T, header string) json.RawMessage {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(header)
	if err != nil {
		t.Fatalf("decode header: %v", err)
	}
	var cred struct {
		Extensions json.RawMessage `json:"extensions"`
	}
	if err := json.Unmarshal(raw, &cred); err != nil {
		t.Fatalf("unmarshal credential: %v", err)
	}
	return cred.Extensions
}

func TestBuildPaymentHeaderWithExtensions(t *testing.T) {
	t.Run("echoes a required payment-identifier with a generated id", func(t *testing.T) {
		signer := testutil.NewPrivateKey()
		e := entry(testutil.NewPrivateKey().PublicKey().String(), "100000", mainnetCAIP2)
		advertised := json.RawMessage(`{"payment-identifier":{"info":{"required":true}}}`)

		header, err := BuildPaymentHeaderWithExtensions(context.Background(), signer, testutil.NewFakeRPC(), &e, advertised)
		if err != nil {
			t.Fatal(err)
		}
		extRaw := credentialExtensions(t, header)
		if len(extRaw) == 0 {
			t.Fatal("credential omitted extensions")
		}
		var ext x402.PaymentExtensions
		if err := json.Unmarshal(extRaw, &ext); err != nil {
			t.Fatalf("unmarshal extensions: %v", err)
		}
		if !x402.IsValidPaymentIdentifierID(ext.PaymentIdentifierID()) {
			t.Fatalf("echoed id %q invalid", ext.PaymentIdentifierID())
		}
	})

	t.Run("omits extensions when server advertised none", func(t *testing.T) {
		signer := testutil.NewPrivateKey()
		e := entry(testutil.NewPrivateKey().PublicKey().String(), "100000", mainnetCAIP2)

		header, err := BuildPaymentHeaderWithExtensions(context.Background(), signer, testutil.NewFakeRPC(), &e, nil)
		if err != nil {
			t.Fatal(err)
		}
		if extRaw := credentialExtensions(t, header); len(extRaw) != 0 && string(extRaw) != "null" {
			t.Fatalf("expected omitted extensions, got %s", extRaw)
		}
	})

	t.Run("nil entry errors", func(t *testing.T) {
		signer := testutil.NewPrivateKey()
		if _, err := BuildPaymentHeaderWithExtensions(context.Background(), signer, testutil.NewFakeRPC(), nil, nil); err == nil {
			t.Fatal("expected error for nil entry")
		}
	})

	t.Run("malformed advertised extensions error", func(t *testing.T) {
		signer := testutil.NewPrivateKey()
		e := entry(testutil.NewPrivateKey().PublicKey().String(), "100000", mainnetCAIP2)
		if _, err := BuildPaymentHeaderWithExtensions(context.Background(), signer, testutil.NewFakeRPC(), &e, json.RawMessage(`{`)); err == nil {
			t.Fatal("expected error for malformed extensions")
		}
	})
}
