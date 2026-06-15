package wire

import "testing"

// TestNewBase64URLJSONValueNestedCanonicalization exercises the recursive
// array and nested-object branches of writeCanonical, plus number/bool/null
// scalar serialization, through the public canonicalizing constructor.
func TestNewBase64URLJSONValueNestedCanonicalization(t *testing.T) {
	value := map[string]any{
		"b": []any{
			map[string]any{"y": 2, "x": 1},
			"two",
			true,
			nil,
		},
		"a": 3.5,
	}
	encoded, err := NewBase64URLJSONValue(value)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	decoded, err := Base64URLDecode(encoded.Raw())
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	// Keys must be sorted at every level: top-level a before b, and the nested
	// object x before y.
	got := string(decoded)
	want := `{"a":3.5,"b":[{"x":1,"y":2},"two",true,null]}`
	if got != want {
		t.Fatalf("canonical mismatch:\n got: %s\nwant: %s", got, want)
	}
}

// TestNewBase64URLJSONValueEmptyArray covers the array branch with no elements.
func TestNewBase64URLJSONValueEmptyArray(t *testing.T) {
	encoded, err := NewBase64URLJSONValue(map[string]any{"items": []any{}})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	decoded, _ := Base64URLDecode(encoded.Raw())
	if string(decoded) != `{"items":[]}` {
		t.Fatalf("unexpected canonical form: %s", decoded)
	}
}
