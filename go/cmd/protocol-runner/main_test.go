package main

import (
	"encoding/json"
	"testing"
)

// req builds an adapter-ABI request from an op and an input value.
func req(t *testing.T, op string, input interface{}) request {
	t.Helper()
	raw, err := json.Marshal(input)
	if err != nil {
		t.Fatalf("marshal input: %v", err)
	}
	return request{Op: op, Input: raw}
}

func TestDispatchBase64URLRoundtrip(t *testing.T) {
	enc := dispatch(req(t, "base64url.encode", map[string]string{"text": "Hello, World!"}))
	if !enc.Success {
		t.Fatalf("encode failed: %s", enc.Error)
	}
	encText := enc.Result.(textInput).Text
	if encText != "SGVsbG8sIFdvcmxkIQ" {
		t.Fatalf("encode mismatch: got %q", encText)
	}
	dec := dispatch(req(t, "base64url.decode", map[string]string{"text": encText}))
	if !dec.Success {
		t.Fatalf("decode failed: %s", dec.Error)
	}
	if got := dec.Result.(textInput).Text; got != "Hello, World!" {
		t.Fatalf("decode mismatch: got %q", got)
	}
}

func TestDispatchChallengeID(t *testing.T) {
	resp := dispatch(req(t, "challenge.id", map[string]interface{}{
		"secretKey": "test-vector-secret",
		"realm":     "api.example.com",
		"method":    "tempo",
		"intent":    "charge",
		"request":   map[string]string{"amount": "1000000"},
	}))
	if !resp.Success {
		t.Fatalf("challenge.id failed: %s", resp.Error)
	}
	out, _ := json.Marshal(resp.Result)
	const want = `{"id":"X6v1eo7fJ76gAxqY0xN9Jd__4lUyDDYmriryOM-5FO4"}`
	if string(out) != want {
		t.Fatalf("challenge.id mismatch: got %s want %s", out, want)
	}
}

func TestDispatchChallengeParseRoundtrip(t *testing.T) {
	wire := `Payment id="ch_abc123", realm="api.example.com", method="tempo", intent="charge", ` +
		`request="eyJhbW91bnQiOiIxMDAwMDAwIn0"`
	parse := dispatch(req(t, "challenge.parse", map[string]string{"header": wire}))
	if !parse.Success {
		t.Fatalf("challenge.parse failed: %s", parse.Error)
	}
	obj := parse.Result.(challengeObject)
	if obj.ID != "ch_abc123" || obj.Method != "tempo" || obj.Intent != "charge" {
		t.Fatalf("parsed challenge fields mismatch: %+v", obj)
	}
	if reqMap, okType := obj.Request.(map[string]interface{}); !okType || reqMap["amount"] != "1000000" {
		t.Fatalf("parsed request not decoded to object: %#v", obj.Request)
	}
}

func TestDispatchUnknownOperationIsUnsupported(t *testing.T) {
	resp := dispatch(request{Op: "subscription.format", Input: json.RawMessage(`{}`)})
	if resp.Success {
		t.Fatal("expected failure for unknown op")
	}
	if resp.ErrorType != "unsupported_operation" {
		t.Fatalf("want error_type=unsupported_operation got %q", resp.ErrorType)
	}
}

func TestDispatchInvalidBase64URLDecodeIsEncodingError(t *testing.T) {
	resp := dispatch(req(t, "base64url.decode", map[string]string{"text": "!!!not base64!!!"}))
	if resp.Success {
		t.Fatal("expected decode failure for invalid input")
	}
	if resp.ErrorType != "encoding_error" {
		t.Fatalf("want error_type=encoding_error got %q", resp.ErrorType)
	}
}
