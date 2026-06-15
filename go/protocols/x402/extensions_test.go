package x402

import (
	"encoding/json"
	"testing"

	"github.com/solana-foundation/pay-kit/go/paykit"
)

func boolPtr(b bool) *bool { return &b }

func TestAdvertisedExtensions(t *testing.T) {
	t.Run("nil when payment-identifier not required", func(t *testing.T) {
		a := &Adapter{cfg: paykit.Config{X402: paykit.X402Config{RequirePaymentIdentifier: false}}}
		if raw := a.advertisedExtensions(); raw != nil {
			t.Fatalf("expected nil advertisement, got %s", raw)
		}
	})
	t.Run("advertises required payment-identifier", func(t *testing.T) {
		a := &Adapter{cfg: paykit.Config{X402: paykit.X402Config{RequirePaymentIdentifier: true}}}
		raw := a.advertisedExtensions()
		if len(raw) == 0 {
			t.Fatal("expected an advertisement")
		}
		var ext PaymentExtensions
		if err := json.Unmarshal(raw, &ext); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if !ext.RequiresPaymentIdentifier() {
			t.Fatalf("advertisement does not mark required: %s", raw)
		}
		// No id advertised by the server (client fills it).
		if ext.PaymentIdentifierID() != "" {
			t.Fatalf("server must not advertise an id: %s", raw)
		}
	})
}

func TestRawAccepted(t *testing.T) {
	// A server-constructed entry has no verbatim source JSON.
	if raw := (AcceptsEntry{}).RawAccepted(); raw != nil {
		t.Fatalf("expected nil raw for constructed entry, got %s", raw)
	}
}

func TestVerifyError(t *testing.T) {
	withMsg := verifyFail("invalid_exact_svm_payload_compute_limit", "compute unit limit exceeds cap")
	if got := withMsg.Error(); got != "x402: compute unit limit exceeds cap" {
		t.Fatalf("with message = %q", got)
	}
	codeOnly := &verifyError{Code: "charge_request_mismatch"}
	if got := codeOnly.Error(); got != "x402: charge_request_mismatch" {
		t.Fatalf("code-only = %q", got)
	}
}

func TestPaymentExtensionsMarshalJSON(t *testing.T) {
	t.Run("payment-identifier under kebab key", func(t *testing.T) {
		ext := PaymentExtensions{
			PaymentIdentifier: &PaymentIdentifierExtension{
				Info: PaymentIdentifierInfo{Required: boolPtr(true)},
			},
		}
		raw, err := json.Marshal(ext)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		var back map[string]json.RawMessage
		if err := json.Unmarshal(raw, &back); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if _, ok := back[PaymentIdentifierKey]; !ok {
			t.Fatalf("expected kebab key %q, got %s", PaymentIdentifierKey, raw)
		}
		if _, ok := back["paymentIdentifier"]; ok {
			t.Fatalf("camelCase key must not appear: %s", raw)
		}
		// required-only serializes with no id key (skip_serializing_if None).
		if got := string(back[PaymentIdentifierKey]); got != `{"info":{"required":true}}` {
			t.Fatalf("required-only shape = %s", got)
		}
	})

	t.Run("unknown extensions preserved verbatim", func(t *testing.T) {
		ext := PaymentExtensions{
			Other: map[string]json.RawMessage{
				"future-extension": json.RawMessage(`{"hello":"world"}`),
			},
		}
		raw, err := json.Marshal(ext)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		var back map[string]json.RawMessage
		if err := json.Unmarshal(raw, &back); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if string(back["future-extension"]) != `{"hello":"world"}` {
			t.Fatalf("unknown extension not preserved: %s", raw)
		}
	})
}

func TestPaymentExtensionsUnmarshalJSON(t *testing.T) {
	in := json.RawMessage(`{"payment-identifier":{"info":{"required":true,"id":"pay_0123456789abcdef"}},"future-extension":{"x":1}}`)
	var ext PaymentExtensions
	if err := json.Unmarshal(in, &ext); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if ext.PaymentIdentifier == nil {
		t.Fatal("payment-identifier not split out")
	}
	if ext.PaymentIdentifier.Info.Id != "pay_0123456789abcdef" {
		t.Fatalf("id = %q", ext.PaymentIdentifier.Info.Id)
	}
	if got := string(ext.Other["future-extension"]); got != `{"x":1}` {
		t.Fatalf("unknown extension verbatim = %s", got)
	}
	if _, ok := ext.Other[PaymentIdentifierKey]; ok {
		t.Fatal("payment-identifier leaked into Other")
	}

	t.Run("malformed object errors", func(t *testing.T) {
		var bad PaymentExtensions
		if err := json.Unmarshal([]byte(`not-an-object`), &bad); err == nil {
			t.Fatal("expected error for non-object")
		}
	})

	t.Run("malformed payment-identifier errors", func(t *testing.T) {
		var bad PaymentExtensions
		if err := json.Unmarshal([]byte(`{"payment-identifier":[]}`), &bad); err == nil {
			t.Fatal("expected error for non-object payment-identifier")
		}
	})
}

func TestPaymentExtensionsIsEmpty(t *testing.T) {
	var nilExt *PaymentExtensions
	if !nilExt.IsEmpty() {
		t.Fatal("nil must be empty")
	}
	if !(&PaymentExtensions{}).IsEmpty() {
		t.Fatal("zero value must be empty")
	}
	if (&PaymentExtensions{PaymentIdentifier: &PaymentIdentifierExtension{}}).IsEmpty() {
		t.Fatal("with payment-identifier must not be empty")
	}
	if (&PaymentExtensions{Other: map[string]json.RawMessage{"k": json.RawMessage("1")}}).IsEmpty() {
		t.Fatal("with unknown extension must not be empty")
	}
}

func TestRequiresPaymentIdentifier(t *testing.T) {
	cases := []struct {
		name string
		ext  *PaymentExtensions
		want bool
	}{
		{"nil", nil, false},
		{"no payment-identifier", &PaymentExtensions{}, false},
		{"required nil", &PaymentExtensions{PaymentIdentifier: &PaymentIdentifierExtension{}}, false},
		{"required false", &PaymentExtensions{PaymentIdentifier: &PaymentIdentifierExtension{Info: PaymentIdentifierInfo{Required: boolPtr(false)}}}, false},
		{"required true", &PaymentExtensions{PaymentIdentifier: &PaymentIdentifierExtension{Info: PaymentIdentifierInfo{Required: boolPtr(true)}}}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.ext.RequiresPaymentIdentifier(); got != c.want {
				t.Fatalf("got %v want %v", got, c.want)
			}
		})
	}
}

func TestPaymentIdentifierID(t *testing.T) {
	var nilExt *PaymentExtensions
	if nilExt.PaymentIdentifierID() != "" {
		t.Fatal("nil id must be empty")
	}
	if (&PaymentExtensions{}).PaymentIdentifierID() != "" {
		t.Fatal("absent id must be empty")
	}
	ext := &PaymentExtensions{PaymentIdentifier: &PaymentIdentifierExtension{Info: PaymentIdentifierInfo{Id: "pay_0123456789abcdef"}}}
	if ext.PaymentIdentifierID() != "pay_0123456789abcdef" {
		t.Fatalf("id = %q", ext.PaymentIdentifierID())
	}
}

func TestWithPaymentIdentifierID(t *testing.T) {
	t.Run("creates entry when server advertised none", func(t *testing.T) {
		ext := &PaymentExtensions{}
		ext.WithPaymentIdentifierID("pay_0123456789abcdef")
		if ext.PaymentIdentifierID() != "pay_0123456789abcdef" {
			t.Fatalf("id = %q", ext.PaymentIdentifierID())
		}
	})
	t.Run("preserves server required when filling id", func(t *testing.T) {
		ext := &PaymentExtensions{PaymentIdentifier: &PaymentIdentifierExtension{Info: PaymentIdentifierInfo{Required: boolPtr(true)}}}
		ext.WithPaymentIdentifierID("pay_0123456789abcdef")
		if !ext.RequiresPaymentIdentifier() {
			t.Fatal("required flag dropped")
		}
		if ext.PaymentIdentifierID() != "pay_0123456789abcdef" {
			t.Fatalf("id = %q", ext.PaymentIdentifierID())
		}
	})
}

func TestKeys(t *testing.T) {
	var nilExt *PaymentExtensions
	if nilExt.Keys() != nil {
		t.Fatal("nil keys must be nil")
	}
	ext := &PaymentExtensions{
		PaymentIdentifier: &PaymentIdentifierExtension{},
		Other: map[string]json.RawMessage{
			"zeta-extension": json.RawMessage("1"),
			"alpha-ext":      json.RawMessage("2"),
		},
	}
	keys := ext.Keys()
	want := []string{"alpha-ext", PaymentIdentifierKey, "zeta-extension"}
	if len(keys) != len(want) {
		t.Fatalf("keys = %v", keys)
	}
	for i := range want {
		if keys[i] != want[i] {
			t.Fatalf("keys = %v want sorted %v", keys, want)
		}
	}
}

func TestEchoExtensions(t *testing.T) {
	t.Run("nil when none advertised", func(t *testing.T) {
		for _, in := range []json.RawMessage{nil, json.RawMessage(""), json.RawMessage("null")} {
			got, err := EchoExtensions(in)
			if err != nil {
				t.Fatalf("echo(%q): %v", in, err)
			}
			if got != nil {
				t.Fatalf("echo(%q) = %+v, want nil", in, got)
			}
		}
	})
	t.Run("preserves unknown verbatim and surfaces payment-identifier", func(t *testing.T) {
		in := json.RawMessage(`{"payment-identifier":{"info":{"required":true}},"future-extension":{"keep":true}}`)
		got, err := EchoExtensions(in)
		if err != nil {
			t.Fatalf("echo: %v", err)
		}
		if !got.RequiresPaymentIdentifier() {
			t.Fatal("required not echoed")
		}
		if string(got.Other["future-extension"]) != `{"keep":true}` {
			t.Fatalf("unknown extension dropped: %+v", got.Other)
		}
	})
	t.Run("error on malformed inbound", func(t *testing.T) {
		if _, err := EchoExtensions(json.RawMessage(`{`)); err == nil {
			t.Fatal("expected error")
		}
	})
}

func TestIsValidPaymentIdentifierID(t *testing.T) {
	cases := []struct {
		id   string
		want bool
	}{
		{"pay_0123456789abcdef", true},
		{"0123456789abcdef", true}, // exactly 16
		{"short_id", false},        // < 16
		{"pay_with space", false},  // illegal char
		{"pay_with.dot", false},    // illegal char
		{"", false},                // empty
	}
	for _, c := range cases {
		if got := IsValidPaymentIdentifierID(c.id); got != c.want {
			t.Fatalf("IsValidPaymentIdentifierID(%q) = %v want %v", c.id, got, c.want)
		}
	}
	// 128 chars is the max bound; 129 must be rejected.
	long := make([]byte, 129)
	for i := range long {
		long[i] = 'a'
	}
	if IsValidPaymentIdentifierID(string(long[:128])) != true {
		t.Fatal("128-char id must be valid")
	}
	if IsValidPaymentIdentifierID(string(long)) != false {
		t.Fatal("129-char id must be invalid")
	}
}

func TestGeneratePaymentIdentifierID(t *testing.T) {
	id := GeneratePaymentIdentifierID()
	if len(id) != 36 { // "pay_" + 32 hex
		t.Fatalf("len = %d (%q)", len(id), id)
	}
	if id[:4] != "pay_" {
		t.Fatalf("missing pay_ prefix: %q", id)
	}
	if !IsValidPaymentIdentifierID(id) {
		t.Fatalf("generated id violates spec pattern: %q", id)
	}
	// Distinct across calls (idempotency keys must be unique per request).
	seen := map[string]bool{}
	for i := 0; i < 64; i++ {
		g := GeneratePaymentIdentifierID()
		if seen[g] {
			t.Fatalf("collision: %q", g)
		}
		seen[g] = true
	}
}
