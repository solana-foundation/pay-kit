// Package wire implements the wire-level primitives shared by every MPP
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
	"strings"
	"time"
)

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

// NewChallengeWithSecret creates an HMAC-bound challenge. The required fields
// are positional; optional fields (expires, digest, description, opaque) are
// supplied via ChallengeOption values so the three same-typed optional strings
// cannot be transposed silently at a call site.
func NewChallengeWithSecret(
	secretKey, realm string,
	method MethodName,
	intent IntentName,
	request Base64URLJSON,
	opts ...ChallengeOption,
) PaymentChallenge {
	var cfg challengeOptions
	for _, opt := range opts {
		opt(&cfg)
	}
	return PaymentChallenge{
		ID:          ComputeChallengeID(secretKey, realm, string(method), string(intent), request.Raw(), cfg.expires, cfg.digest, opaqueRaw(cfg.opaque)),
		Realm:       realm,
		Method:      method,
		Intent:      intent,
		Request:     request,
		Expires:     cfg.expires,
		Description: cfg.description,
		Digest:      cfg.digest,
		Opaque:      cfg.opaque,
	}
}

// challengeOptions accumulates the optional challenge fields set by
// ChallengeOption values.
type challengeOptions struct {
	expires     string
	digest      string
	description string
	opaque      *Base64URLJSON
}

// ChallengeOption sets an optional field on a challenge built by
// NewChallengeWithSecret. Each option names the field it sets, which prevents
// the expires/digest/description strings from being passed in the wrong order.
type ChallengeOption func(*challengeOptions)

// WithExpires sets the challenge expiry (RFC 3339). Empty leaves it unset.
func WithExpires(expires string) ChallengeOption {
	return func(o *challengeOptions) { o.expires = expires }
}

// WithDigest sets the request-body digest bound into the challenge ID.
func WithDigest(digest string) ChallengeOption {
	return func(o *challengeOptions) { o.digest = digest }
}

// WithDescription sets the human-readable challenge description.
func WithDescription(description string) ChallengeOption {
	return func(o *challengeOptions) { o.description = description }
}

// WithOpaque sets the opaque server state echoed back in the credential.
func WithOpaque(opaque *Base64URLJSON) ChallengeOption {
	return func(o *challengeOptions) { o.opaque = opaque }
}

// NewChallengeWithSecretFull creates an HMAC-bound challenge with every
// optional field supplied positionally.
//
// The expires, digest, and description arguments are three adjacent strings
// that compile in any order, so a transposition silently changes the
// HMAC-bound challenge ID. Prefer NewChallengeWithSecret with the WithExpires /
// WithDigest / WithDescription / WithOpaque options; this wrapper is retained
// so existing callers keep working.
func NewChallengeWithSecretFull(
	secretKey, realm string,
	method MethodName,
	intent IntentName,
	request Base64URLJSON,
	expires, digest, description string,
	opaque *Base64URLJSON,
) PaymentChallenge {
	return NewChallengeWithSecret(
		secretKey, realm, method, intent, request,
		WithExpires(expires),
		WithDigest(digest),
		WithDescription(description),
		WithOpaque(opaque),
	)
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
	expiresAt, err := time.Parse(time.RFC3339, c.Expires)
	if err != nil {
		return true
	}
	return !expiresAt.After(now.UTC())
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
