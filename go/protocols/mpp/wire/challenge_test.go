package wire

import (
	"encoding/json"
	"os"
	"testing"
	"time"
)

func TestChallengeVerify(t *testing.T) {
	request, err := NewBase64URLJSONValue(map[string]string{"amount": "1000"})
	if err != nil {
		t.Fatalf("request encode failed: %v", err)
	}
	challenge := NewChallengeWithSecret("secret", "realm", NewMethodName("solana"), NewIntentName("charge"), request)
	if !challenge.Verify("secret") {
		t.Fatal("expected challenge verification to succeed")
	}
	if challenge.Verify("wrong") {
		t.Fatal("expected challenge verification to fail with wrong key")
	}
}

func TestChallengeIsExpired(t *testing.T) {
	request, _ := NewBase64URLJSONValue(map[string]string{"amount": "1000"})
	challenge := NewChallengeWithSecretFull("secret", "realm", NewMethodName("solana"), NewIntentName("charge"), request, "2020-01-01T00:00:00Z", "", "", nil)
	if !challenge.IsExpired(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)) {
		t.Fatal("expected challenge to be expired")
	}
}

func TestPaymentCredentialPayloadAs(t *testing.T) {
	request, _ := NewBase64URLJSONValue(map[string]string{"amount": "1000"})
	challenge := NewChallengeWithSecret("secret", "realm", NewMethodName("solana"), NewIntentName("charge"), request)
	credential, err := NewPaymentCredential(challenge.ToEcho(), map[string]string{"type": "transaction"})
	if err != nil {
		t.Fatalf("credential failed: %v", err)
	}
	var payload map[string]string
	if err := credential.PayloadAs(&payload); err != nil {
		t.Fatalf("payload decode failed: %v", err)
	}
	if payload["type"] != "transaction" {
		t.Fatalf("unexpected payload %#v", payload)
	}
}

func TestIsExpiredEmptyString(t *testing.T) {
	request, _ := NewBase64URLJSONValue(map[string]string{"amount": "1"})
	challenge := NewChallengeWithSecretFull("s", "r", NewMethodName("solana"), NewIntentName("charge"), request, "", "", "", nil)
	if challenge.IsExpired(time.Now()) {
		t.Fatal("empty expires should not be expired")
	}
}

func TestIsExpiredInvalidTimestamp(t *testing.T) {
	request, _ := NewBase64URLJSONValue(map[string]string{"amount": "1"})
	challenge := NewChallengeWithSecretFull("s", "r", NewMethodName("solana"), NewIntentName("charge"), request, "not-a-date", "", "", nil)
	if !challenge.IsExpired(time.Now()) {
		t.Fatal("invalid timestamp should be treated as expired")
	}
}

func TestIsExpiredFutureTimestamp(t *testing.T) {
	request, _ := NewBase64URLJSONValue(map[string]string{"amount": "1"})
	future := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	challenge := NewChallengeWithSecretFull("s", "r", NewMethodName("solana"), NewIntentName("charge"), request, future, "", "", nil)
	if challenge.IsExpired(time.Now()) {
		t.Fatal("future timestamp should not be expired")
	}
}

func TestIsExpiredPastTimestamp(t *testing.T) {
	request, _ := NewBase64URLJSONValue(map[string]string{"amount": "1"})
	past := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	challenge := NewChallengeWithSecretFull("s", "r", NewMethodName("solana"), NewIntentName("charge"), request, past, "", "", nil)
	if !challenge.IsExpired(time.Now()) {
		t.Fatal("past timestamp should be expired")
	}
}

func TestPayloadAsNilPayload(t *testing.T) {
	credential := PaymentCredential{Payload: nil}
	var out map[string]string
	if err := credential.PayloadAs(&out); err != nil {
		t.Fatalf("nil payload should not error: %v", err)
	}
	if out != nil {
		t.Fatalf("expected nil output, got %v", out)
	}
}

func TestComputeChallengeIDDeterministic(t *testing.T) {
	id1 := ComputeChallengeID("secret", "realm", "solana", "charge", "req", "exp", "digest", "opaque")
	id2 := ComputeChallengeID("secret", "realm", "solana", "charge", "req", "exp", "digest", "opaque")
	if id1 != id2 {
		t.Fatalf("challenge ID not deterministic: %q != %q", id1, id2)
	}
	id3 := ComputeChallengeID("different", "realm", "solana", "charge", "req", "exp", "digest", "opaque")
	if id1 == id3 {
		t.Fatal("different secret should produce different ID")
	}
}

func TestVerifyWithWrongSecretKey(t *testing.T) {
	request, _ := NewBase64URLJSONValue(map[string]string{"amount": "1"})
	challenge := NewChallengeWithSecret("correct-secret", "realm", NewMethodName("solana"), NewIntentName("charge"), request)
	if challenge.Verify("wrong-secret") {
		t.Fatal("verify with wrong secret should fail")
	}
	if !challenge.Verify("correct-secret") {
		t.Fatal("verify with correct secret should pass")
	}
}

func TestNewChallengeWithSecretFullAllFields(t *testing.T) {
	request, _ := NewBase64URLJSONValue(map[string]string{"amount": "1"})
	opaque, _ := NewBase64URLJSONValue(map[string]string{"session": "abc"})
	challenge := NewChallengeWithSecretFull("secret", "realm", NewMethodName("solana"), NewIntentName("charge"), request, "2030-01-01T00:00:00Z", "sha256=abc", "buy coffee", &opaque)
	if challenge.Realm != "realm" {
		t.Fatalf("unexpected realm: %q", challenge.Realm)
	}
	if challenge.Expires != "2030-01-01T00:00:00Z" {
		t.Fatalf("unexpected expires: %q", challenge.Expires)
	}
	if challenge.Digest != "sha256=abc" {
		t.Fatalf("unexpected digest: %q", challenge.Digest)
	}
	if challenge.Description != "buy coffee" {
		t.Fatalf("unexpected description: %q", challenge.Description)
	}
	if challenge.Opaque == nil || challenge.Opaque.Raw() != opaque.Raw() {
		t.Fatal("unexpected opaque")
	}
	if challenge.ID == "" {
		t.Fatal("expected non-empty ID")
	}
	if !challenge.Verify("secret") {
		t.Fatal("challenge should verify with correct secret")
	}
}

func TestToEchoPreservesFields(t *testing.T) {
	request, _ := NewBase64URLJSONValue(map[string]string{"amount": "1"})
	opaque, _ := NewBase64URLJSONValue(map[string]string{"k": "v"})
	challenge := NewChallengeWithSecretFull("secret", "realm", NewMethodName("solana"), NewIntentName("charge"), request, "2030-01-01T00:00:00Z", "sha256=abc", "desc", &opaque)
	echo := challenge.ToEcho()
	if echo.ID != challenge.ID || echo.Realm != challenge.Realm || echo.Expires != challenge.Expires {
		t.Fatal("echo did not preserve basic fields")
	}
	if echo.Digest != challenge.Digest {
		t.Fatal("echo did not preserve digest")
	}
	if echo.Opaque == nil || echo.Opaque.Raw() != challenge.Opaque.Raw() {
		t.Fatal("echo did not preserve opaque")
	}
}

func TestNewPaymentCredentialRejectsUnmarshalablePayload(t *testing.T) {
	request, _ := NewBase64URLJSONValue(map[string]string{"amount": "1000"})
	challenge := NewChallengeWithSecret("secret", "realm", NewMethodName("solana"), NewIntentName("charge"), request)
	if _, err := NewPaymentCredential(challenge.ToEcho(), map[string]any{"bad": make(chan int)}); err == nil {
		t.Fatal("expected marshal error")
	}
}

// ── Cross-SDK RFC 3339 conformance corpus (issue #111) ──
//
// Vectors live in `harness/vectors/mpp-protocol/expires-rfc3339-corpus.json`
// under the `expires.parse` operation. Every SDK asserts the same ACCEPT /
// REJECT verdict against the same vectors, so a divergence between two SDKs
// shows up as a failing test in exactly one of them rather than as silence.
//
// Only the `applies_to == "date-time"` slice is run here. The corpus also
// carries `full-date` and `full-time` scenarios, which answer a different
// question than an `expires` field asks — `1963-06-19` is a valid RFC 3339
// `full-date` and no `date-time` parser should accept it. Filtering is on the
// first-class `applies_to` field, never on a name prefix or a description
// string.
//
// The verdict is read out of this package's own `PaymentChallenge.IsExpired`,
// not out of a bare `time.Parse`. `IsExpired` fails closed — it returns true
// both for "parsed, and in the past" and for "did not parse" — but `now` is a
// parameter, so passing a reference instant before every year the corpus can
// express (0000..9999) makes every parse success sort strictly after `now`.
// IsExpired then returns false for a parse success and true for a parse
// failure, and the verdict comes from the shipped function.

const conformanceCorpusPath = "../../../../harness/vectors/mpp-protocol/expires-rfc3339-corpus.json"

// rfc3339ConformanceReference is far enough in the past that every instant the
// corpus can express sorts after it, so IsExpired's time comparison never fires
// on a parse success and only the parse outcome is observed.
var rfc3339ConformanceReference = time.Date(-9999, time.January, 1, 0, 0, 0, 0, time.UTC)

type rfc3339Scenario struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	AppliesTo   string          `json:"applies_to"`
	Input       string          `json:"input"`
	Tests       json.RawMessage `json:"tests"`
}

type rfc3339Corpus struct {
	Scenarios []rfc3339Scenario `json:"scenarios"`
}

// wantsAccept reports whether the scenario's `tests.parse` encodes ACCEPT.
// `true` is ACCEPT; an object carrying `success: false` is REJECT. Mirrors the
// encoding used by the other vector files in the same directory.
func (s rfc3339Scenario) wantsAccept(t *testing.T) bool {
	t.Helper()
	var probe struct {
		Parse json.RawMessage `json:"parse"`
	}
	if err := json.Unmarshal(s.Tests, &probe); err != nil {
		t.Fatalf("%s: tests block did not decode: %v", s.Name, err)
	}
	var accepted bool
	if err := json.Unmarshal(probe.Parse, &accepted); err == nil {
		return accepted
	}
	var rejection struct {
		Success bool `json:"success"`
	}
	if err := json.Unmarshal(probe.Parse, &rejection); err != nil {
		t.Fatalf("%s: tests.parse was neither a bool nor an object: %v", s.Name, err)
	}
	return rejection.Success
}

func loadRFC3339DateTimeVectors(t *testing.T) []rfc3339Scenario {
	t.Helper()
	raw, err := os.ReadFile(conformanceCorpusPath)
	if err != nil {
		t.Fatalf("conformance corpus unreadable at %s: %v", conformanceCorpusPath, err)
	}
	var corpus rfc3339Corpus
	if err := json.Unmarshal(raw, &corpus); err != nil {
		t.Fatalf("conformance corpus did not decode: %v", err)
	}
	var dateTime []rfc3339Scenario
	for _, scenario := range corpus.Scenarios {
		if scenario.AppliesTo == "date-time" {
			dateTime = append(dateTime, scenario)
		}
	}
	if len(dateTime) == 0 {
		t.Fatal("conformance corpus admitted zero date-time scenarios")
	}
	return dateTime
}

func TestRFC3339ConformanceCorpus(t *testing.T) {
	t.Parallel()
	for _, scenario := range loadRFC3339DateTimeVectors(t) {
		t.Run(scenario.Name, func(t *testing.T) {
			t.Parallel()
			challenge := PaymentChallenge{Expires: scenario.Input}
			accepted := !challenge.IsExpired(rfc3339ConformanceReference)
			want := scenario.wantsAccept(t)
			if accepted != want {
				t.Fatalf("%s (%s): input %q — corpus expects %s, IsExpired reports %s",
					scenario.Name, scenario.Description, scenario.Input,
					conformanceVerdictName(want), conformanceVerdictName(accepted))
			}
		})
	}
}

func conformanceVerdictName(accepted bool) string {
	if accepted {
		return "ACCEPT"
	}
	return "REJECT"
}
