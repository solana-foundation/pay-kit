// Package core implements the wire-level primitives shared by every MPP
// intent: PaymentChallenge, PaymentCredential, Receipt, the
// MethodName/IntentName newtypes, the Base64URLJSON helper, RFC 8785
// canonical-JSON encoding, HMAC challenge-ID computation, and the
// WWW-Authenticate / Authorization / Payment-Receipt header
// parser/formatter pair. The wire format mirrors
// rust/src/protocol/core/{challenge,headers,types}.rs so the
// cross-language harness exercises byte-identical output.
package wire

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// time.Parse alone is looser than RFC 3339 §5.6 (comma secfrac, offsets past
// 23:59) and stricter (no leap second); the grammar gate closes that gap.
var rfc3339DateTime = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:(\d{2})(?:\.\d+)?(?:[Zz]|[+-](\d{2}):(\d{2}))$`)

// PaymentChallenge is sent by a server via WWW-Authenticate.
type PaymentChallenge struct {
	ID          string         `json:"id"`
	Realm       string         `json:"realm"`
	Method      MethodName     `json:"method"`
	Intent      IntentName     `json:"intent"`
	Request     Base64URLJSON  `json:"request"`
	Expires     string         `json:"expires,omitempty"`
	Description string         `json:"description,omitempty"`
	Digest      string         `json:"digest,omitempty"`
	Opaque      *Base64URLJSON `json:"opaque,omitempty"`
}

// ChallengeEcho is echoed inside a credential.
type ChallengeEcho struct {
	ID      string         `json:"id"`
	Realm   string         `json:"realm"`
	Method  MethodName     `json:"method"`
	Intent  IntentName     `json:"intent"`
	Request Base64URLJSON  `json:"request"`
	Expires string         `json:"expires,omitempty"`
	Digest  string         `json:"digest,omitempty"`
	Opaque  *Base64URLJSON `json:"opaque,omitempty"`
}

// PaymentCredential is sent by a client in Authorization.
type PaymentCredential struct {
	Challenge ChallengeEcho    `json:"challenge"`
	Source    string           `json:"source,omitempty"`
	Payload   *json.RawMessage `json:"payload,omitempty"`
}

// Receipt is returned by a server in Payment-Receipt.
type Receipt struct {
	Status      ReceiptStatus `json:"status"`
	Method      MethodName    `json:"method"`
	Timestamp   string        `json:"timestamp"`
	Reference   string        `json:"reference"`
	ChallengeID string        `json:"challengeId,omitempty"`
	ExternalID  string        `json:"externalId,omitempty"`
}

// NewChallengeWithSecret creates an HMAC-bound challenge.
func NewChallengeWithSecret(secretKey, realm string, method MethodName, intent IntentName, request Base64URLJSON) PaymentChallenge {
	return NewChallengeWithSecretFull(secretKey, realm, method, intent, request, "", "", "", nil)
}

// NewChallengeWithSecretFull creates an HMAC-bound challenge with optional fields.
func NewChallengeWithSecretFull(
	secretKey, realm string,
	method MethodName,
	intent IntentName,
	request Base64URLJSON,
	expires, digest, description string,
	opaque *Base64URLJSON,
) PaymentChallenge {
	return PaymentChallenge{
		ID:          ComputeChallengeID(secretKey, realm, string(method), string(intent), request.Raw(), expires, digest, opaqueRaw(opaque)),
		Realm:       realm,
		Method:      method,
		Intent:      intent,
		Request:     request,
		Expires:     expires,
		Description: description,
		Digest:      digest,
		Opaque:      opaque,
	}
}

// ToEcho converts a challenge into the echoed credential form.
func (c PaymentChallenge) ToEcho() ChallengeEcho {
	return ChallengeEcho{
		ID:      c.ID,
		Realm:   c.Realm,
		Method:  c.Method,
		Intent:  c.Intent,
		Request: c.Request,
		Expires: c.Expires,
		Digest:  c.Digest,
		Opaque:  c.Opaque,
	}
}

// Verify checks that the challenge ID was issued by the server secret.
func (c PaymentChallenge) Verify(secretKey string) bool {
	expected := ComputeChallengeID(secretKey, c.Realm, string(c.Method), string(c.Intent), c.Request.Raw(), c.Expires, c.Digest, opaqueRaw(c.Opaque))
	return subtle.ConstantTimeCompare([]byte(c.ID), []byte(expected)) == 1
}

// IsExpired returns true when the challenge expiration is in the past or invalid.
func (c PaymentChallenge) IsExpired(now time.Time) bool {
	if strings.TrimSpace(c.Expires) == "" {
		return false
	}
	expiresAt, err := parseRFC3339(c.Expires)
	if err != nil {
		return true
	}
	return !expiresAt.After(now.UTC())
}

// parseRFC3339 matches the TypeScript and Python SDKs: a leap second is
// accepted only where it ends a UTC month (§5.7) and clamps to the last
// instant of :59, so every SDK reads the same expiry off the same wire.
func parseRFC3339(value string) (time.Time, error) {
	m := rfc3339DateTime.FindStringSubmatch(value)
	if m == nil {
		return time.Time{}, fmt.Errorf("not an RFC 3339 date-time: %q", value)
	}
	if m[2] > "23" || m[3] > "59" {
		return time.Time{}, fmt.Errorf("offset out of range: %q", value)
	}
	leapSecond := m[1] == "60"
	if leapSecond {
		value = value[:17] + "59" + value[19:]
	}
	parsed, err := time.Parse(time.RFC3339, strings.ToUpper(value))
	if err != nil {
		return time.Time{}, err
	}
	if leapSecond {
		utc := parsed.UTC()
		if utc.Hour() != 23 || utc.Minute() != 59 || utc.AddDate(0, 0, 1).Month() == utc.Month() {
			return time.Time{}, fmt.Errorf("leap second not at a UTC month end: %q", value)
		}
		parsed = parsed.Truncate(time.Second).Add(time.Second - time.Nanosecond)
	}
	return parsed, nil
}

// NewPaymentCredential creates a typed credential payload.
func NewPaymentCredential(challenge ChallengeEcho, payload any) (PaymentCredential, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return PaymentCredential{}, err
	}
	msg := json.RawMessage(raw)
	return PaymentCredential{Challenge: challenge, Payload: &msg}, nil
}

// PayloadAs decodes the payload into out.
func (c PaymentCredential) PayloadAs(out any) error {
	if c.Payload == nil {
		return nil
	}
	return json.Unmarshal(*c.Payload, out)
}

// ComputeChallengeID computes the HMAC-SHA256 challenge identifier.
func ComputeChallengeID(secretKey, realm, method, intent, request, expires, digest, opaque string) string {
	mac := hmac.New(sha256.New, []byte(secretKey))
	_, _ = mac.Write([]byte(strings.Join([]string{
		realm,
		method,
		intent,
		request,
		expires,
		digest,
		opaque,
	}, "|")))
	return Base64URLEncode(mac.Sum(nil))
}

func opaqueRaw(value *Base64URLJSON) string {
	if value == nil {
		return ""
	}
	return value.Raw()
}
