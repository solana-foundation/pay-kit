package x402

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"regexp"
	"sort"
)

// x402 v2 extensions (mirrors rust
// rust/crates/x402/src/protocol/schemes/exact/types.rs PaymentExtensions
// et al.). The `extensions` object rides on BOTH the inbound
// PAYMENT-REQUIRED challenge and the outbound PAYMENT-SIGNATURE
// credential. The client echoes the inbound object back, fills required
// client-side fields (payment-identifier.info.id), preserves unknown
// extensions verbatim (forward-compat echo-and-append, coinbase x402 v2
// §5.1.2), and omits the object entirely when the server advertised none.

// PaymentIdentifierKey is the spec JSON key for the payment-identifier
// extension (rust #[serde(rename = "payment-identifier")]).
const PaymentIdentifierKey = "payment-identifier"

// paymentIdentifierIDPattern is the spec id constraint
// ^[A-Za-z0-9_-]{16,128}$ (rust types.rs:488).
var paymentIdentifierIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{16,128}$`)

// PaymentIdentifierInfo carries the client/server fields of the
// payment-identifier extension. camelCase wire (rust types.rs:483-493).
type PaymentIdentifierInfo struct {
	// Required is the server-side flag: when true and Id is missing the
	// server returns 400 (rust types.rs:484-487).
	Required *bool `json:"required,omitempty"`
	// Id is the client-side idempotency key. Must match
	// ^[A-Za-z0-9_-]{16,128}$. Canonical Solana uses a pay_ prefix.
	Id string `json:"id,omitempty"`
}

// PaymentIdentifierExtension is the payment-identifier extension. The
// client echoes it into the outbound PAYMENT-SIGNATURE with info.id
// populated (rust types.rs:500-507).
type PaymentIdentifierExtension struct {
	Info PaymentIdentifierInfo `json:"info"`
	// Schema is the JSON Schema published by the server. Echoed verbatim
	// per x402 v2 §5.1.2 (rust types.rs:505-506).
	Schema json.RawMessage `json:"schema,omitempty"`
}

// PaymentExtensions is the typed view over the v2 `extensions` object.
// The payment-identifier extension is fielded out directly; unknown
// extensions flow through Other verbatim so the echo-and-append rule
// (§5.1.2) does not drop forward-compatible payloads. Mirrors rust
// PaymentExtensions { payment_identifier, #[serde(flatten)] other }
// (types.rs:513-528).
type PaymentExtensions struct {
	// PaymentIdentifier is the payment-identifier idempotency extension.
	PaymentIdentifier *PaymentIdentifierExtension
	// Other holds extensions this SDK does not type natively, captured
	// during echo and re-emitted verbatim (rust #[serde(flatten)] other).
	Other map[string]json.RawMessage
}

// MarshalJSON renders the payment-identifier extension under its kebab-case
// key alongside any verbatim unknown extensions, mirroring rust's rename +
// flatten. Go has no native serde flatten, so the two are merged by hand.
func (p PaymentExtensions) MarshalJSON() ([]byte, error) {
	out := make(map[string]json.RawMessage, len(p.Other)+1)
	for k, v := range p.Other {
		out[k] = v
	}
	if p.PaymentIdentifier != nil {
		raw, err := json.Marshal(p.PaymentIdentifier)
		if err != nil {
			return nil, err
		}
		out[PaymentIdentifierKey] = raw
	}
	return json.Marshal(out)
}

// UnmarshalJSON splits the payment-identifier extension out of the object
// and captures every other key verbatim into Other, mirroring rust's
// rename + flatten (echo-and-append: unknown extensions survive byte-equal).
func (p *PaymentExtensions) UnmarshalJSON(data []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	p.PaymentIdentifier = nil
	p.Other = nil
	for k, v := range raw {
		if k == PaymentIdentifierKey {
			var ext PaymentIdentifierExtension
			if err := json.Unmarshal(v, &ext); err != nil {
				return err
			}
			p.PaymentIdentifier = &ext
			continue
		}
		if p.Other == nil {
			p.Other = make(map[string]json.RawMessage)
		}
		p.Other[k] = append(json.RawMessage(nil), v...)
	}
	return nil
}

// IsEmpty reports whether no fields are populated. Callers use it to avoid
// emitting an empty `extensions: {}` object on outbound envelopes (rust
// PaymentExtensions::is_empty, types.rs:533-535).
func (p *PaymentExtensions) IsEmpty() bool {
	if p == nil {
		return true
	}
	return p.PaymentIdentifier == nil && len(p.Other) == 0
}

// RequiresPaymentIdentifier reports whether
// payment-identifier.info.required == true (rust
// requires_payment_identifier, types.rs:538-543).
func (p *PaymentExtensions) RequiresPaymentIdentifier() bool {
	if p == nil || p.PaymentIdentifier == nil {
		return false
	}
	return p.PaymentIdentifier.Info.Required != nil && *p.PaymentIdentifier.Info.Required
}

// PaymentIdentifierID returns the echoed client-side id, or "" when absent.
func (p *PaymentExtensions) PaymentIdentifierID() string {
	if p == nil || p.PaymentIdentifier == nil {
		return ""
	}
	return p.PaymentIdentifier.Info.Id
}

// WithPaymentIdentifierID sets (or overwrites) the client-side
// payment-identifier.info.id, creating the extension entry if the server
// did not advertise one, preserving server-side info (required) and schema
// verbatim (rust with_payment_identifier_id, types.rs:548-553).
func (p *PaymentExtensions) WithPaymentIdentifierID(id string) {
	if p.PaymentIdentifier == nil {
		p.PaymentIdentifier = &PaymentIdentifierExtension{}
	}
	p.PaymentIdentifier.Info.Id = id
}

// Keys returns the sorted top-level extension keys present on the object
// (the payment-identifier key plus any verbatim unknown keys). Used by the
// conformance oracle to assert the echo-and-append key set.
func (p *PaymentExtensions) Keys() []string {
	if p == nil {
		return nil
	}
	keys := make([]string, 0, len(p.Other)+1)
	if p.PaymentIdentifier != nil {
		keys = append(keys, PaymentIdentifierKey)
	}
	for k := range p.Other {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// EchoExtensions deep-copies the inbound extensions blob so unknown keys
// round-trip verbatim, mirroring rust PaymentExtensions::echoing
// (types.rs:559-565). Returns nil when the server advertised no extensions
// (so the outbound omits the object). The inbound is provided as the raw
// JSON object carried on the PAYMENT-REQUIRED challenge.
func EchoExtensions(inbound json.RawMessage) (*PaymentExtensions, error) {
	if len(inbound) == 0 || string(inbound) == "null" {
		return nil, nil
	}
	var ext PaymentExtensions
	if err := json.Unmarshal(inbound, &ext); err != nil {
		return nil, err
	}
	return &ext, nil
}

// IsValidPaymentIdentifierID reports whether id matches the spec pattern
// ^[A-Za-z0-9_-]{16,128}$ (rust types.rs:488).
func IsValidPaymentIdentifierID(id string) bool {
	return paymentIdentifierIDPattern.MatchString(id)
}

// GeneratePaymentIdentifierID generates a fresh pay_-prefixed idempotency
// id (32 lowercase hex chars after the prefix; 36 total), satisfying the
// spec pattern ^[A-Za-z0-9_-]{16,128}$ and the canonical Solana
// ^pay_[a-zA-Z0-9_-]{10,120}$ shape (rust generate_payment_identifier_id,
// types.rs:575-585). Callers MUST reuse the same id across retries of the
// same logical request so the server can return a cached 200 instead of
// charging twice.
func GeneratePaymentIdentifierID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("x402: getrandom CSPRNG failure: " + err.Error())
	}
	return "pay_" + hex.EncodeToString(b[:])
}
