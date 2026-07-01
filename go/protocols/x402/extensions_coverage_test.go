package x402

import (
	"encoding/json"
	"testing"
)

func TestPaymentExtensionsIsEmpty(t *testing.T) {
	var p *PaymentExtensions
	if !p.IsEmpty() {
		t.Fatal("nil should be empty")
	}
	p = &PaymentExtensions{}
	if !p.IsEmpty() {
		t.Fatal("zero value should be empty")
	}
	p.PaymentIdentifier = &PaymentIdentifierExtension{}
	if p.IsEmpty() {
		t.Fatal("with identifier should not be empty")
	}
}

func TestPaymentExtensionsRequiresPaymentIdentifier(t *testing.T) {
	var p *PaymentExtensions
	if p.RequiresPaymentIdentifier() {
		t.Fatal("nil should not require")
	}
	p = &PaymentExtensions{}
	if p.RequiresPaymentIdentifier() {
		t.Fatal("empty should not require")
	}
	p.PaymentIdentifier = &PaymentIdentifierExtension{}
	if p.RequiresPaymentIdentifier() {
		t.Fatal("identifier without required should not require")
	}
	req := true
	p.PaymentIdentifier.Info.Required = &req
	if !p.RequiresPaymentIdentifier() {
		t.Fatal("should require when required=true")
	}
	req = false
	if p.RequiresPaymentIdentifier() {
		t.Fatal("should not require when required=false")
	}
}

func TestPaymentExtensionsPaymentIdentifierID(t *testing.T) {
	var p *PaymentExtensions
	if p.PaymentIdentifierID() != "" {
		t.Fatal("nil should return empty")
	}
	p = &PaymentExtensions{}
	if p.PaymentIdentifierID() != "" {
		t.Fatal("empty should return empty")
	}
	p.PaymentIdentifier = &PaymentIdentifierExtension{Info: PaymentIdentifierInfo{Id: "pay_test1234567890"}}
	if p.PaymentIdentifierID() != "pay_test1234567890" {
		t.Fatalf("got %q", p.PaymentIdentifierID())
	}
}

func TestPaymentExtensionsWithPaymentIdentifierID(t *testing.T) {
	p := &PaymentExtensions{}
	p.WithPaymentIdentifierID("pay_test1234567890")
	if p.PaymentIdentifier == nil {
		t.Fatal("should create identifier")
	}
	if p.PaymentIdentifier.Info.Id != "pay_test1234567890" {
		t.Fatalf("id = %q", p.PaymentIdentifier.Info.Id)
	}
	// Overwrite existing.
	p.WithPaymentIdentifierID("pay_updated1234567890")
	if p.PaymentIdentifier.Info.Id != "pay_updated1234567890" {
		t.Fatalf("id = %q", p.PaymentIdentifier.Info.Id)
	}
}

func TestPaymentExtensionsKeys(t *testing.T) {
	var p *PaymentExtensions
	if p.Keys() != nil {
		t.Fatal("nil should return nil")
	}
	p = &PaymentExtensions{Other: map[string]json.RawMessage{"custom": json.RawMessage(`1`)}}
	keys := p.Keys()
	if len(keys) != 1 || keys[0] != "custom" {
		t.Fatalf("keys = %v", keys)
	}
	p.PaymentIdentifier = &PaymentIdentifierExtension{}
	keys = p.Keys()
	if len(keys) != 2 || keys[0] != "custom" || keys[1] != PaymentIdentifierKey {
		t.Fatalf("keys = %v", keys)
	}
}

func TestPaymentExtensionsMarshalUnmarshalRoundTrip(t *testing.T) {
	req := true
	ext := PaymentExtensions{
		PaymentIdentifier: &PaymentIdentifierExtension{
			Info: PaymentIdentifierInfo{Required: &req, Id: "pay_test1234567890"},
		},
		Other: map[string]json.RawMessage{"custom": json.RawMessage(`"value"`)},
	}
	data, err := ext.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}
	var got PaymentExtensions
	if err := got.UnmarshalJSON(data); err != nil {
		t.Fatalf("UnmarshalJSON: %v", err)
	}
	if got.PaymentIdentifier == nil {
		t.Fatal("payment-identifier not unmarshalled")
	}
	if got.PaymentIdentifier.Info.Id != "pay_test1234567890" {
		t.Fatalf("id = %q", got.PaymentIdentifier.Info.Id)
	}
	if len(got.Other) != 1 || string(got.Other["custom"]) != `"value"` {
		t.Fatalf("other = %v", got.Other)
	}
}

func TestPaymentExtensionsUnmarshalNoIdentifier(t *testing.T) {
	data := json.RawMessage(`{"custom":"value"}`)
	var ext PaymentExtensions
	if err := ext.UnmarshalJSON(data); err != nil {
		t.Fatalf("UnmarshalJSON: %v", err)
	}
	if ext.PaymentIdentifier != nil {
		t.Fatal("expected nil identifier")
	}
	if len(ext.Other) != 1 {
		t.Fatalf("expected 1 other, got %d", len(ext.Other))
	}
}

func TestPaymentExtensionsUnmarshalEmpty(t *testing.T) {
	var ext PaymentExtensions
	if err := ext.UnmarshalJSON(json.RawMessage(`{}`)); err != nil {
		t.Fatalf("UnmarshalJSON: %v", err)
	}
	if ext.PaymentIdentifier != nil {
		t.Fatal("expected nil identifier")
	}
	if ext.Other != nil {
		t.Fatal("expected nil other")
	}
}

func TestEchoExtensionsNil(t *testing.T) {
	ext, err := EchoExtensions(nil)
	if err != nil {
		t.Fatalf("EchoExtensions(nil): %v", err)
	}
	if ext != nil {
		t.Fatal("expected nil")
	}
	ext, err = EchoExtensions(json.RawMessage("null"))
	if err != nil {
		t.Fatalf("EchoExtensions(null): %v", err)
	}
	if ext != nil {
		t.Fatal("expected nil")
	}
}

func TestEchoExtensionsRoundTrip(t *testing.T) {
	in := json.RawMessage(`{"payment-identifier":{"info":{"required":true}},"custom":"value"}`)
	ext, err := EchoExtensions(in)
	if err != nil {
		t.Fatalf("EchoExtensions: %v", err)
	}
	if ext == nil {
		t.Fatal("expected non-nil")
	}
	if ext.PaymentIdentifier == nil || !*ext.PaymentIdentifier.Info.Required {
		t.Fatal("expected payment-identifier with required")
	}
	if string(ext.Other["custom"]) != `"value"` {
		t.Fatalf("custom = %s", ext.Other["custom"])
	}
}

func TestIsValidPaymentIdentifierID(t *testing.T) {
	if !IsValidPaymentIdentifierID("pay_test1234567890") {
		t.Fatal("pay_test1234567890 should be valid (18 chars)")
	}
	if IsValidPaymentIdentifierID("short") {
		t.Fatal("too short should be invalid")
	}
	if IsValidPaymentIdentifierID("") {
		t.Fatal("empty should be invalid")
	}
}

func TestGeneratePaymentIdentifierID(t *testing.T) {
	id := GeneratePaymentIdentifierID()
	if len(id) < 16 {
		t.Fatalf("id too short: %q", id)
	}
	if !IsValidPaymentIdentifierID(id) {
		t.Fatalf("generated id %q is invalid", id)
	}
	if id[:4] != "pay_" {
		t.Fatalf("id %q does not start with pay_", id)
	}
}

func TestPaymentExtensionsMarshalJSONNoIdentifier(t *testing.T) {
	ext := PaymentExtensions{Other: map[string]json.RawMessage{"foo": json.RawMessage(`"bar"`)}}
	data, err := ext.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if string(raw["foo"]) != `"bar"` {
		t.Fatalf("foo = %s", raw["foo"])
	}
	if _, ok := raw[PaymentIdentifierKey]; ok {
		t.Fatal("should not have payment-identifier key")
	}
}
