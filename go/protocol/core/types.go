package core

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strings"
)

// MethodName identifies a payment method.
type MethodName string

// NewMethodName normalizes method names to lowercase.
func NewMethodName(name string) MethodName { return MethodName(strings.ToLower(name)) }

// IsValid returns true when the method is lowercase ASCII letters.
func (m MethodName) IsValid() bool {
	if m == "" {
		return false
	}
	for _, ch := range m {
		if ch < 'a' || ch > 'z' {
			return false
		}
	}
	return true
}

// IntentName identifies a payment intent.
type IntentName string

// NewIntentName normalizes intent names to lowercase.
func NewIntentName(name string) IntentName { return IntentName(strings.ToLower(name)) }

// IsCharge returns whether the intent is the charge intent.
func (i IntentName) IsCharge() bool { return strings.EqualFold(string(i), "charge") }

// Base64URLJSON preserves a base64url-encoded JSON blob.
type Base64URLJSON struct {
	raw string
}

// NewBase64URLJSONRaw creates a value from a raw base64url string.
func NewBase64URLJSONRaw(raw string) Base64URLJSON { return Base64URLJSON{raw: raw} }

// NewBase64URLJSONValue encodes a value as canonical JSON and base64url.
func NewBase64URLJSONValue(value any) (Base64URLJSON, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return Base64URLJSON{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var canonicalValue any
	if err := decoder.Decode(&canonicalValue); err != nil {
		return Base64URLJSON{}, err
	}
	canonicalRaw, err := json.Marshal(canonicalValue)
	if err != nil {
		return Base64URLJSON{}, err
	}
	return Base64URLJSON{raw: Base64URLEncode(canonicalRaw)}, nil
}

// Raw returns the raw base64url value.
func (b Base64URLJSON) Raw() string { return b.raw }

// IsEmpty returns whether the raw value is empty.
func (b Base64URLJSON) IsEmpty() bool { return b.raw == "" }

// Decode decodes the JSON into out.
func (b Base64URLJSON) Decode(out any) error {
	payload, err := Base64URLDecode(b.raw)
	if err != nil {
		return err
	}
	return json.Unmarshal(payload, out)
}

// DecodeValue decodes the JSON into a generic map.
func (b Base64URLJSON) DecodeValue() (map[string]any, error) {
	var out map[string]any
	if err := b.Decode(&out); err != nil {
		return nil, err
	}
	return out, nil
}

// MarshalJSON emits the embedded base64url-encoded JSON string so the
// outer document keeps the canonical wire form.
func (b Base64URLJSON) MarshalJSON() ([]byte, error) {
	return json.Marshal(b.raw)
}

// UnmarshalJSON reads a base64url-encoded JSON string into the value.
func (b *Base64URLJSON) UnmarshalJSON(data []byte) error {
	return json.Unmarshal(data, &b.raw)
}

// Base64URLEncode encodes bytes with URL-safe base64 and no padding.
func Base64URLEncode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

// Base64URLDecode decodes both URL-safe and standard base64 with or without padding.
func Base64URLDecode(input string) ([]byte, error) {
	normalized := strings.NewReplacer("+", "-", "/", "_", "=", "").Replace(input)
	return base64.RawURLEncoding.DecodeString(normalized)
}

// ReceiptStatus is the status of a payment receipt.
type ReceiptStatus string

const (
	// ReceiptStatusSuccess indicates a completed payment.
	ReceiptStatusSuccess ReceiptStatus = "success"
)
