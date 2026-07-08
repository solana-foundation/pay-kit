package wire

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"sort"
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

// IsSession returns whether the intent is the session intent.
func (i IntentName) IsSession() bool { return strings.EqualFold(string(i), "session") }

// Base64URLJSON preserves a base64url-encoded JSON blob.
type Base64URLJSON struct {
	// raw is the base64url-encoded JSON kept verbatim as it appeared on
	// the wire (never re-encoded), so the HMAC challenge ID computed over
	// it stays byte-stable; "" means the value is absent.
	raw string
}

// NewBase64URLJSONRaw creates a value from a raw base64url string.
func NewBase64URLJSONRaw(raw string) Base64URLJSON { return Base64URLJSON{raw: raw} }

// NewBase64URLJSONValue encodes a value as RFC 8785 canonical JSON and
// base64url. The canonical form sorts object keys lexicographically, emits no
// insignificant whitespace, and — critically — does NOT escape the
// HTML-sensitive characters < > & that Go's encoding/json escapes by default.
// This matches the canonical mpp-tools golden so the HMAC challenge-ID derived
// from the encoded request is byte-identical across SDKs.
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
	canonicalRaw, err := canonicalJSON(canonicalValue)
	if err != nil {
		return Base64URLJSON{}, err
	}
	return Base64URLJSON{raw: Base64URLEncode(canonicalRaw)}, nil
}

// canonicalJSON serializes a generic JSON value following RFC 8785 (JSON
// Canonicalization Scheme): object members sorted by key, arrays in order, no
// insignificant whitespace, and no HTML escaping of < > & (json.Marshal escapes
// these by default; SetEscapeHTML(false) disables that).
func canonicalJSON(value any) ([]byte, error) {
	var buf bytes.Buffer
	if err := writeCanonical(&buf, value); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func writeCanonical(buf *bytes.Buffer, value any) error {
	switch v := value.(type) {
	case map[string]any:
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeCanonicalScalar(buf, k); err != nil {
				return err
			}
			buf.WriteByte(':')
			if err := writeCanonical(buf, v[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
		return nil
	case []any:
		buf.WriteByte('[')
		for i, item := range v {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeCanonical(buf, item); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
		return nil
	default:
		return writeCanonicalScalar(buf, value)
	}
}

// writeCanonicalScalar writes a scalar (string, json.Number, bool, nil) without
// HTML escaping, matching RFC 8785 string serialization.
func writeCanonicalScalar(buf *bytes.Buffer, value any) error {
	enc := json.NewEncoder(buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(value); err != nil {
		return err
	}
	// json.Encoder appends a trailing newline; drop it.
	if buf.Len() > 0 && buf.Bytes()[buf.Len()-1] == '\n' {
		buf.Truncate(buf.Len() - 1)
	}
	return nil
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
