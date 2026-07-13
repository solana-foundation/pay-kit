package wire

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// TestCompareUTF16Ordering pins the RFC 8785 UTF-16 code-unit ordering,
// including the astral case where the ordering diverges from Unicode
// code-point (Go byte) ordering: U+1F600 (grinning face) encodes to the
// surrogate pair D83D DE00, whose leading unit D83D sorts *before* the BMP
// unit FB03 (U+FB03 ligature ffi), even though its code point (0x1F600) is
// numerically larger.
func TestCompareUTF16Ordering(t *testing.T) {
	tests := []struct {
		name string
		a, b string
		want int // sign of the result
	}{
		{"ascii less", "a", "z", -1},
		{"ascii greater", "z", "a", 1},
		{"equal", "a", "a", 0},
		{"prefix shorter first", "a", "ab", -1},
		{"prefix longer first", "ab", "a", 1},
		{"astral before FB03", "\U0001F600", "ﬃ", -1},
		{"FB03 after astral", "ﬃ", "\U0001F600", 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := compareUTF16(tc.a, tc.b)
			if sign(got) != tc.want {
				t.Fatalf("compareUTF16(%q,%q)=%d, want sign %d", tc.a, tc.b, got, tc.want)
			}
		})
	}
}

func sign(n int) int {
	switch {
	case n < 0:
		return -1
	case n > 0:
		return 1
	default:
		return 0
	}
}

// TestCanonicalKeyOrderingUTF16 exercises full-pipeline key ordering: the
// astral key U+1F600 must sort before U+FB03 by UTF-16 unit, which is the
// opposite of Go's default code-point byte order.
func TestCanonicalKeyOrderingUTF16(t *testing.T) {
	value := map[string]any{
		"z":          1,
		"a":          2,
		"\U0001F600": 3, // astral, UTF-16 lead unit D83D
		"ﬃ":          4, // BMP unit FB03
	}
	encoded, err := NewBase64URLJSONValue(value)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	decoded, err := Base64URLDecode(encoded.Raw())
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	want := "{\"a\":2,\"z\":1,\"\U0001F600\":3,\"ﬃ\":4}"
	if string(decoded) != want {
		t.Fatalf("canonical key order mismatch:\n got %s\nwant %s", decoded, want)
	}
}

// TestCanonicalStringRawSeparators verifies that U+2028 LINE SEPARATOR and
// U+2029 PARAGRAPH SEPARATOR are emitted as raw UTF-8 (RFC 8785), not the
// six-character   /   escapes that encoding/json emits
// unconditionally.
func TestCanonicalStringRawSeparators(t *testing.T) {
	input := "a b c"
	encoded, err := NewBase64URLJSONValue(map[string]any{"k": input})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	decoded, err := Base64URLDecode(encoded.Raw())
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	got := string(decoded)
	// The literal six-character escapes must be absent.
	if strings.Contains(got, "\\u2028") || strings.Contains(got, "\\u2029") {
		t.Fatalf("separators must not be escaped, got %q", got)
	}
	// The raw code points must be present.
	if !strings.Contains(got, " ") || !strings.Contains(got, " ") {
		t.Fatalf("expected raw separators in output, got %q", got)
	}
	if want := "{\"k\":\"" + input + "\"}"; got != want {
		t.Fatalf("unexpected canonical form:\n got %q\nwant %q", got, want)
	}
}

// TestWriteCanonicalStringEscapes pins each escape branch of
// writeCanonicalString: the five named control escapes, the \u00XX path for
// the remaining C0 controls (exercising both hex nibbles including the 'f'
// letter digit), backslash and quote, and -- critically for JCS -- that the
// HTML-sensitive < > & characters and astral runes are emitted verbatim.
func TestWriteCanonicalStringEscapes(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"backslash", "\\", `"\\"`},
		{"quote", "\"", `"\""`},
		{"backspace", "\b", `"\b"`},
		{"tab", "\t", `"\t"`},
		{"newline", "\n", `"\n"`},
		{"formfeed", "\f", `"\f"`},
		{"carriage return", "\r", `"\r"`},
		{"null control", "\x00", "\"\\u0000\""},
		{"vertical tab control", "\v", "\"\\u000b\""},
		{"unit separator control", "\x1f", "\"\\u001f\""},
		{"html chars not escaped", "a<b>&c", `"a<b>&c"`},
		{"astral raw", "\U0001F600", "\"\U0001F600\""},
		{"del is raw", "\x7f", "\"\x7f\""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			writeCanonicalString(&buf, tc.in)
			if buf.String() != tc.want {
				t.Fatalf("writeCanonicalString(%q)=%q, want %q", tc.in, buf.String(), tc.want)
			}
		})
	}
}

// TestWriteCanonicalNumberNormalization pins the IEEE-754 / ES6
// Number::toString normalization RFC 8785 requires for every JSON number.
func TestWriteCanonicalNumberNormalization(t *testing.T) {
	tests := []struct {
		name string
		in   json.Number
		want string
	}{
		{"trailing zero fraction", "1.0", "1"},
		{"uppercase exponent", "1E2", "100"},
		{"padded fraction", "100.00", "100"},
		{"trim to one decimal", "1.50", "1.5"},
		{"negative zero fraction", "-0.0", "0"},
		{"negative zero integer", "-0", "0"},
		{"needs positive exponent", "1e21", "1e+21"},
		{"needs negative exponent", "1e-7", "1e-7"},
		{"large integer rounds to IEEE-754", "9007199254740993", "9007199254740992"},
		{"plain integer verbatim", "42", "42"},
		{"negative fraction", "-12.50", "-12.5"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := writeCanonicalNumber(&buf, tc.in); err != nil {
				t.Fatalf("writeCanonicalNumber(%q): %v", tc.in, err)
			}
			if buf.String() != tc.want {
				t.Fatalf("writeCanonicalNumber(%q)=%s, want %s", tc.in, buf.String(), tc.want)
			}
		})
	}
}

// TestWriteCanonicalNumberError covers malformed, non-finite, and out-of-range
// values that cannot appear in a JCS document.
func TestWriteCanonicalNumberError(t *testing.T) {
	for _, input := range []json.Number{"1.2.3", "NaN", "Infinity", "1e400"} {
		var buf bytes.Buffer
		if err := writeCanonicalNumber(&buf, input); err == nil {
			t.Fatalf("expected %q to fail", input)
		}
	}
}

func TestNewBase64URLJSONValueValidatesRawSurrogateEscapes(t *testing.T) {
	for _, input := range []json.RawMessage{
		json.RawMessage(`{"k":"\uD800"}`),
		json.RawMessage(`{"\uDE00":"ok"}`),
	} {
		if _, err := NewBase64URLJSONValue(input); err == nil {
			t.Fatalf("expected %s to reject an unpaired surrogate", input)
		}
	}

	encoded, err := NewBase64URLJSONValue(json.RawMessage(`{"k":"\uD83D\uDE00"}`))
	if err != nil {
		t.Fatalf("valid surrogate pair: %v", err)
	}
	decoded, err := Base64URLDecode(encoded.Raw())
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got, want := string(decoded), `{"k":"😀"}`; got != want {
		t.Fatalf("canonical JSON = %q, want %q", got, want)
	}
}

// TestFormatES6Number pins the ES6 float rendering directly, covering the
// zero, negative-sign, fixed-point, and exponential (both signs, with the
// leading-zero exponent trim) branches.
func TestFormatES6Number(t *testing.T) {
	tests := []struct {
		in   float64
		want string
	}{
		{0, "0"},
		{1, "1"},
		{100, "100"},
		{1.5, "1.5"},
		{-12.5, "-12.5"},
		{1e21, "1e+21"},
		{1e-7, "1e-7"},
		{1e-6, "0.000001"},
	}
	for _, tc := range tests {
		got := formatES6Number(tc.in)
		if got != tc.want {
			t.Fatalf("formatES6Number(%v)=%s, want %s", tc.in, got, tc.want)
		}
	}
	// Negative zero must collapse to "0" (exercises the f==0 branch on a
	// negative zero); constructed at runtime to avoid a const-folded literal.
	negZero := -1.0 * 0.0
	if got := formatES6Number(negZero); got != "0" {
		t.Fatalf("formatES6Number(-0)=%s, want 0", got)
	}
}

// TestCanonicalScalarResidual drives the writeCanonical default branch, where
// a raw numeric scalar (not a json.Number) reaches the canonicalizer and is
// emitted through the standard encoder with HTML escaping disabled.
func TestCanonicalScalarResidual(t *testing.T) {
	got, err := canonicalJSON(3.5)
	if err != nil {
		t.Fatalf("canonicalJSON(float64): %v", err)
	}
	if string(got) != "3.5" {
		t.Fatalf("canonicalJSON(3.5)=%s, want 3.5", got)
	}
	got, err = canonicalJSON(42)
	if err != nil {
		t.Fatalf("canonicalJSON(int): %v", err)
	}
	if string(got) != "42" {
		t.Fatalf("canonicalJSON(42)=%s, want 42", got)
	}
}

// TestCanonicalScalarError covers the residual-scalar error path (and its
// propagation through canonicalJSON): an unencodable value reaching the
// default branch returns the encoder error.
func TestCanonicalScalarError(t *testing.T) {
	if _, err := canonicalJSON(make(chan int)); err == nil {
		t.Fatal("expected error for unencodable residual scalar")
	}
}
