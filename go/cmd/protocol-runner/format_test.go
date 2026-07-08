package main

// Round-trip coverage for the format verbs (challenge.format,
// credential.format, receipt.format) and their parse counterparts, including
// opaque blobs, credential payloads, and the malformed-input failure paths.

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/solana-foundation/pay-kit/go/protocols/mpp/wire"
)

func TestDispatchChallengeFormatParseRoundtrip(t *testing.T) {
	format := dispatch(req(t, "challenge.format", map[string]any{
		"id":          "ch_roundtrip",
		"realm":       "api.example.com",
		"method":      "solana",
		"intent":      "session",
		"request":     map[string]any{"cap": "1000000", "currency": "USDC"},
		"expires":     "2030-01-01T00:00:00Z",
		"description": "Metered stream",
		"digest":      "sha256=abc",
		"opaque":      map[string]any{"hint": "value"},
	}))
	if !format.Success {
		t.Fatalf("challenge.format failed: %s", format.Error)
	}
	header := format.Result.(headerInput).Header
	if !strings.HasPrefix(header, "Payment ") {
		t.Fatalf("formatted header = %q", header)
	}

	parse := dispatch(req(t, "challenge.parse", map[string]string{"header": header}))
	if !parse.Success {
		t.Fatalf("challenge.parse failed: %s", parse.Error)
	}
	obj := parse.Result.(challengeObject)
	if obj.ID != "ch_roundtrip" || obj.Intent != "session" || obj.Description != "Metered stream" {
		t.Fatalf("round-tripped challenge = %+v", obj)
	}
	request, okType := obj.Request.(map[string]any)
	if !okType || request["cap"] != "1000000" {
		t.Fatalf("round-tripped request = %#v", obj.Request)
	}
	opaque, okType := obj.Opaque.(map[string]any)
	if !okType || opaque["hint"] != "value" {
		t.Fatalf("round-tripped opaque = %#v", obj.Opaque)
	}
}

func TestDispatchChallengeFormatMalformedInput(t *testing.T) {
	resp := dispatch(request{Op: "challenge.format", Input: json.RawMessage(`"not-an-object"`)})
	if resp.Success || resp.ErrorType != "format_error" {
		t.Fatalf("malformed challenge.format = %+v", resp)
	}
}

func TestDispatchCredentialFormatParseRoundtrip(t *testing.T) {
	format := dispatch(req(t, "credential.format", map[string]any{
		"challenge": map[string]any{
			"id":      "ch_cred",
			"realm":   "api.example.com",
			"method":  "solana",
			"intent":  "session",
			"request": map[string]any{"cap": "1000"},
			"expires": "2030-01-01T00:00:00Z",
			"opaque":  map[string]any{"k": "v"},
		},
		"source":  "wallet",
		"payload": map[string]any{"action": "close", "channelId": "abc"},
	}))
	if !format.Success {
		t.Fatalf("credential.format failed: %s", format.Error)
	}
	header := format.Result.(headerInput).Header

	parse := dispatch(req(t, "credential.parse", map[string]string{"header": header}))
	if !parse.Success {
		t.Fatalf("credential.parse failed: %s", parse.Error)
	}
	credential := parse.Result.(wire.PaymentCredential)
	if credential.Challenge.ID != "ch_cred" || credential.Source != "wallet" {
		t.Fatalf("round-tripped credential = %+v", credential)
	}
	if credential.Payload == nil || !strings.Contains(string(*credential.Payload), `"close"`) {
		t.Fatalf("round-tripped payload = %v", credential.Payload)
	}
}

func TestDispatchCredentialFormatAndParseMalformedInput(t *testing.T) {
	format := dispatch(request{Op: "credential.format", Input: json.RawMessage(`"nope"`)})
	if format.Success || format.ErrorType != "format_error" {
		t.Fatalf("malformed credential.format = %+v", format)
	}
	parse := dispatch(req(t, "credential.parse", map[string]string{"header": "Payment !!!"}))
	if parse.Success || parse.ErrorType != "parse_error" {
		t.Fatalf("malformed credential.parse = %+v", parse)
	}
}

func TestDispatchReceiptFormatParseRoundtrip(t *testing.T) {
	format := dispatch(req(t, "receipt.format", map[string]any{
		"status":    "success",
		"method":    "solana",
		"timestamp": "2030-01-01T00:00:00Z",
		"reference": "5sig",
	}))
	if !format.Success {
		t.Fatalf("receipt.format failed: %s", format.Error)
	}
	header := format.Result.(headerInput).Header

	parse := dispatch(req(t, "receipt.parse", map[string]string{"header": header}))
	if !parse.Success {
		t.Fatalf("receipt.parse failed: %s", parse.Error)
	}
	receipt := parse.Result.(wire.Receipt)
	if receipt.Status != wire.ReceiptStatusSuccess || receipt.Reference != "5sig" {
		t.Fatalf("round-tripped receipt = %+v", receipt)
	}
}

func TestDispatchReceiptMalformedInput(t *testing.T) {
	format := dispatch(request{Op: "receipt.format", Input: json.RawMessage(`"nope"`)})
	if format.Success || format.ErrorType != "format_error" {
		t.Fatalf("malformed receipt.format = %+v", format)
	}
	parse := dispatch(req(t, "receipt.parse", map[string]string{"header": "!!!"}))
	if parse.Success || parse.ErrorType != "parse_error" {
		t.Fatalf("malformed receipt.parse = %+v", parse)
	}
}

func TestDispatchHeaderInputDecodeFailures(t *testing.T) {
	for _, op := range []string{"challenge.parse", "credential.parse", "receipt.parse", "base64url.encode", "base64url.decode"} {
		resp := dispatch(request{Op: op, Input: json.RawMessage(`5`)})
		if resp.Success {
			t.Fatalf("%s accepted a malformed input", op)
		}
	}
}
