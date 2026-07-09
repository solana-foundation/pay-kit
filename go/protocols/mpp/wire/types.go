package wire

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
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
	if err := validateJSONSurrogateEscapes(raw); err != nil {
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
// Canonicalization Scheme): object keys sorted by UTF-16 code unit, arrays in
// order, no insignificant whitespace, strings escaped per JCS (raw UTF-8 for
// everything above U+001F, including U+2028/U+2029 which encoding/json escapes
// unconditionally), and numbers normalized through the ES6 Number::toString
// algorithm. The < > & characters are NOT escaped. This matches the shared
// cross-SDK JCS reference (harness/src/conformance/jcs.ts) so the HMAC
// challenge-ID derived from an encoded request is byte-identical across SDKs.
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
		// RFC 8785 orders object keys by UTF-16 code unit, not Unicode code
		// point: an astral character (surrogate pair, leading unit >= 0xD800)
		// sorts before a BMP character above 0xD800 such as U+FB03. Go's byte
		// order sorts by code point, so compare UTF-16 units explicitly.
		sort.Slice(keys, func(i, j int) bool {
			return compareUTF16(keys[i], keys[j]) < 0
		})
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			writeCanonicalString(buf, k)
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
	case string:
		writeCanonicalString(buf, v)
		return nil
	case json.Number:
		return writeCanonicalNumber(buf, v)
	case bool:
		if v {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
		return nil
	case nil:
		buf.WriteString("null")
		return nil
	default:
		// Residual scalar types (e.g. a raw float64/int when a caller bypasses
		// the UseNumber decode). Fall back to the standard encoder with HTML
		// escaping disabled, matching the RFC 8785 punctuation rules.
		return writeCanonicalScalar(buf, value)
	}
}

const hexDigits = "0123456789abcdef"

// compareUTF16 orders two strings by their UTF-16 code units, the ordering RFC
// 8785 mandates for object keys. Go strings are UTF-8, so both operands are
// re-encoded to UTF-16 before the lexicographic comparison. It returns a
// negative, zero, or positive value like the sort comparators.
func compareUTF16(a, b string) int {
	au := utf16.Encode([]rune(a))
	bu := utf16.Encode([]rune(b))
	n := min(len(bu), len(au))
	for i := range n {
		if au[i] != bu[i] {
			if au[i] < bu[i] {
				return -1
			}
			return 1
		}
	}
	return len(au) - len(bu)
}

// writeCanonicalString serializes a JSON string per RFC 8785: two-character
// escapes for the named control characters, \u00XX for the remaining ASCII
// controls, \\ and \" for backslash and quote, and every other rune (including
// U+2028 LINE SEPARATOR and U+2029 PARAGRAPH SEPARATOR, which encoding/json
// escapes unconditionally) emitted as raw UTF-8.
func writeCanonicalString(buf *bytes.Buffer, s string) {
	buf.WriteByte('"')
	for _, r := range s {
		switch r {
		case '\\':
			buf.WriteString(`\\`)
		case '"':
			buf.WriteString(`\"`)
		case '\b':
			buf.WriteString(`\b`)
		case '\t':
			buf.WriteString(`\t`)
		case '\n':
			buf.WriteString(`\n`)
		case '\f':
			buf.WriteString(`\f`)
		case '\r':
			buf.WriteString(`\r`)
		default:
			if r < 0x20 {
				buf.WriteString(`\u00`)
				buf.WriteByte(hexDigits[(r>>4)&0xf])
				buf.WriteByte(hexDigits[r&0xf])
			} else {
				buf.WriteRune(r)
			}
		}
	}
	buf.WriteByte('"')
}

// writeCanonicalNumber serializes a JSON number per RFC 8785. Every number is
// first interpreted as an IEEE-754 binary64 value, then rendered with the ES6
// Number::toString algorithm. This deliberately rounds literals such as
// 9007199254740993 to 9007199254740992 and collapses both -0 and -0.0 to 0.
func writeCanonicalNumber(buf *bytes.Buffer, n json.Number) error {
	s := n.String()
	f, err := n.Float64()
	if err != nil {
		return fmt.Errorf("canonical json: normalize number %q: %w", s, err)
	}
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return fmt.Errorf("canonical json: number %q is not finite", s)
	}
	buf.WriteString(formatES6Number(f))
	return nil
}

// validateJSONSurrogateEscapes rejects unpaired UTF-16 surrogate escapes in a
// raw JSON document before encoding/json substitutes U+FFFD during decoding.
// It deliberately leaves all other JSON validation to encoding/json.
func validateJSONSurrogateEscapes(raw []byte) error {
	inString := false
	for i := 0; i < len(raw); {
		if !inString {
			if raw[i] == '"' {
				inString = true
			}
			i++
			continue
		}

		switch raw[i] {
		case '"':
			inString = false
			i++
		case '\\':
			if i+1 >= len(raw) || raw[i+1] != 'u' {
				i += 2
				continue
			}
			unit, ok := jsonEscapeUTF16Unit(raw, i+2)
			if !ok {
				i += 2
				continue
			}
			switch {
			case unit >= 0xd800 && unit <= 0xdbff:
				if i+7 >= len(raw) || raw[i+6] != '\\' || raw[i+7] != 'u' {
					return fmt.Errorf("canonical json: unpaired surrogate escape")
				}
				low, ok := jsonEscapeUTF16Unit(raw, i+8)
				if !ok || low < 0xdc00 || low > 0xdfff {
					return fmt.Errorf("canonical json: unpaired surrogate escape")
				}
				i += 12
			case unit >= 0xdc00 && unit <= 0xdfff:
				return fmt.Errorf("canonical json: unpaired surrogate escape")
			default:
				i += 6
			}
		default:
			i++
		}
	}
	return nil
}

func jsonEscapeUTF16Unit(raw []byte, start int) (uint16, bool) {
	if start+4 > len(raw) {
		return 0, false
	}
	var unit uint16
	for _, b := range raw[start : start+4] {
		var digit byte
		switch {
		case b >= '0' && b <= '9':
			digit = b - '0'
		case b >= 'a' && b <= 'f':
			digit = b - 'a' + 10
		case b >= 'A' && b <= 'F':
			digit = b - 'A' + 10
		default:
			return 0, false
		}
		unit = unit<<4 | uint16(digit)
	}
	return unit, true
}

// formatES6Number renders a finite float64 the way ECMAScript's
// Number::toString (and thus RFC 8785) does: fixed-point notation between 1e-6
// and 1e21, exponential notation outside that band with a sign and no leading
// zero in the exponent, and "0" for both 0 and -0.
func formatES6Number(f float64) string {
	if f == 0 {
		return "0"
	}
	sign := ""
	if f < 0 {
		f = -f
		sign = "-"
	}
	format := byte('e')
	if f >= 1e-6 && f < 1e21 {
		format = 'f'
	}
	out := strconv.FormatFloat(f, format, -1, 64)
	if e := strings.IndexByte(out, 'e'); e >= 0 {
		// Go emits "1e+09"/"1e-09"; ES6 wants "1e+9"/"1e-9": strip the leading
		// zeros from the exponent while keeping its sign.
		mantissa := out[:e]
		expSign := out[e+1]
		expDigits := strings.TrimLeft(out[e+2:], "0")
		if expDigits == "" {
			expDigits = "0"
		}
		out = mantissa + "e" + string(expSign) + expDigits
	}
	return sign + out
}

// writeCanonicalScalar writes a residual scalar (a raw numeric type reaching
// the canonicalizer without a UseNumber decode) without HTML escaping,
// matching RFC 8785 punctuation. String, json.Number, bool, and nil are
// handled by writeCanonical directly and never reach here.
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
