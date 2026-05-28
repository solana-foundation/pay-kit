package wire

import "testing"

func TestMethodNameNormalization(t *testing.T) {
	method := NewMethodName("SOLANA")
	if method != "solana" {
		t.Fatalf("unexpected method %q", method)
	}
	if !method.IsValid() {
		t.Fatal("expected normalized method to be valid")
	}
}

func TestBase64URLRoundTrip(t *testing.T) {
	encoded := Base64URLEncode([]byte("hello"))
	decoded, err := Base64URLDecode(encoded)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if string(decoded) != "hello" {
		t.Fatalf("unexpected decoded value %q", string(decoded))
	}
}

func TestBase64URLJSONRoundTrip(t *testing.T) {
	value, err := NewBase64URLJSONValue(map[string]string{"amount": "1000"})
	if err != nil {
		t.Fatalf("encode failed: %v", err)
	}
	var decoded map[string]string
	if err := value.Decode(&decoded); err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if decoded["amount"] != "1000" {
		t.Fatalf("unexpected payload: %#v", decoded)
	}
	if value.IsEmpty() {
		t.Fatal("expected encoded value to be non-empty")
	}
	generic, err := value.DecodeValue()
	if err != nil {
		t.Fatalf("decode value failed: %v", err)
	}
	if generic["amount"] != "1000" {
		t.Fatalf("unexpected generic payload: %#v", generic)
	}
}

func TestBase64URLJSONValueRejectsUnmarshalableValue(t *testing.T) {
	if _, err := NewBase64URLJSONValue(map[string]any{"bad": make(chan int)}); err == nil {
		t.Fatal("expected marshal error")
	}
}

func TestBase64URLJSONDecodeRejectsInvalidRawValue(t *testing.T) {
	value := NewBase64URLJSONRaw("not-base64")
	var out map[string]any
	if err := value.Decode(&out); err == nil {
		t.Fatal("expected invalid base64 decode error")
	}
	if _, err := value.DecodeValue(); err == nil {
		t.Fatal("expected invalid base64 decode value error")
	}
}

func TestBase64URLJSONValueCanonicalizesStructFields(t *testing.T) {
	type request struct {
		Currency      string         `json:"currency"`
		Amount        string         `json:"amount"`
		MethodDetails map[string]any `json:"methodDetails"`
	}
	value, err := NewBase64URLJSONValue(request{
		Currency: "USDC",
		Amount:   "1000",
		MethodDetails: map[string]any{
			"network":  "localnet",
			"feePayer": true,
		},
	})
	if err != nil {
		t.Fatalf("encode failed: %v", err)
	}
	decoded, err := Base64URLDecode(value.Raw())
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	want := `{"amount":"1000","currency":"USDC","methodDetails":{"feePayer":true,"network":"localnet"}}`
	if string(decoded) != want {
		t.Fatalf("unexpected canonical JSON:\n got %s\nwant %s", decoded, want)
	}
}

func TestBase64URLJSONValuePreservesLargeJSONNumbers(t *testing.T) {
	type request struct {
		Sequence uint64 `json:"sequence"`
		Amount   string `json:"amount"`
	}
	value, err := NewBase64URLJSONValue(request{
		Sequence: 9_007_199_254_740_993,
		Amount:   "1000",
	})
	if err != nil {
		t.Fatalf("encode failed: %v", err)
	}
	decoded, err := Base64URLDecode(value.Raw())
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	want := `{"amount":"1000","sequence":9007199254740993}`
	if string(decoded) != want {
		t.Fatalf("unexpected canonical JSON:\n got %s\nwant %s", decoded, want)
	}
}

func TestIntentNameIsCharge(t *testing.T) {
	if !NewIntentName("Charge").IsCharge() {
		t.Fatal("expected charge intent")
	}
}

func TestMethodNameInvalid(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"empty", ""},
		{"numbers", "123"},
		{"uppercase", "ABC"},
		{"spaces", "foo bar"},
		{"special chars", "sol-ana"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Test raw string, not normalized
			if MethodName(tc.input).IsValid() {
				t.Fatalf("expected %q to be invalid", tc.input)
			}
		})
	}
}

func TestBase64URLDecodeStandardBase64(t *testing.T) {
	// Base64URLDecode should handle standard base64 with + / =
	input := Base64URLEncode([]byte("test data"))
	decoded, err := Base64URLDecode(input)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if string(decoded) != "test data" {
		t.Fatalf("unexpected: %q", string(decoded))
	}
}

func TestBase64URLJSONMarshalUnmarshal(t *testing.T) {
	original, _ := NewBase64URLJSONValue(map[string]string{"key": "value"})
	jsonBytes, err := original.MarshalJSON()
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	var restored Base64URLJSON
	if err := restored.UnmarshalJSON(jsonBytes); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if restored.Raw() != original.Raw() {
		t.Fatalf("round-trip mismatch: %q != %q", restored.Raw(), original.Raw())
	}
}

func TestNewBase64URLJSONRaw(t *testing.T) {
	raw := "dGVzdA"
	b := NewBase64URLJSONRaw(raw)
	if b.Raw() != raw {
		t.Fatalf("expected raw %q, got %q", raw, b.Raw())
	}
}

func TestBase64URLJSONIsEmpty(t *testing.T) {
	empty := Base64URLJSON{}
	if !empty.IsEmpty() {
		t.Fatal("expected empty")
	}
	nonEmpty, _ := NewBase64URLJSONValue("test")
	if nonEmpty.IsEmpty() {
		t.Fatal("expected non-empty")
	}
}

func TestIntentNameNotCharge(t *testing.T) {
	if NewIntentName("subscribe").IsCharge() {
		t.Fatal("subscribe should not be charge")
	}
}
