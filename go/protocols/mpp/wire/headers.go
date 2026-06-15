package wire

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Header names and scheme tokens for the HTTP Payment Authentication
// scheme. Names are lowercase to match Go's canonical http.Header keys.
const (
	WWWAuthenticateHeader = "www-authenticate"
	AuthorizationHeader   = "authorization"
	PaymentReceiptHeader  = "payment-receipt"
	PaymentScheme         = "Payment"
	maxTokenLen           = 16 * 1024
)

// ParseWWWAuthenticate parses a Payment challenge header.
func ParseWWWAuthenticate(header string) (PaymentChallenge, error) {
	rest, ok := stripPaymentScheme(header)
	if !ok {
		return PaymentChallenge{}, fmt.Errorf("expected %q scheme", PaymentScheme)
	}
	params, err := parseAuthParams(strings.TrimSpace(rest))
	if err != nil {
		return PaymentChallenge{}, err
	}
	requestRaw, ok := params["request"]
	if !ok || requestRaw == "" {
		return PaymentChallenge{}, fmt.Errorf("missing %q field", "request")
	}
	// Cap the base64url request param before decoding/JSON-parsing it, matching
	// the credential (ParseAuthorization) and receipt (ParseReceipt) parsers.
	// request is the only challenge field that drives O(n) decode + JSON-parse
	// work; an oversized value would otherwise do unbounded work here.
	if len(requestRaw) > maxTokenLen {
		return PaymentChallenge{}, fmt.Errorf("request field exceeds maximum length of %d bytes", maxTokenLen)
	}
	requestBytes, err := Base64URLDecode(requestRaw)
	if err != nil {
		return PaymentChallenge{}, fmt.Errorf("invalid request field: %w", err)
	}
	var requestValue any
	if err := json.Unmarshal(requestBytes, &requestValue); err != nil {
		return PaymentChallenge{}, fmt.Errorf("invalid JSON in request field: %w", err)
	}
	method := NewMethodName(params["method"])
	if !method.IsValid() {
		return PaymentChallenge{}, fmt.Errorf("invalid method: %q", params["method"])
	}
	challenge := PaymentChallenge{
		ID:          params["id"],
		Realm:       params["realm"],
		Method:      method,
		Intent:      NewIntentName(params["intent"]),
		Request:     NewBase64URLJSONRaw(requestRaw),
		Expires:     params["expires"],
		Description: params["description"],
		Digest:      params["digest"],
	}
	if opaque, ok := params["opaque"]; ok {
		value := NewBase64URLJSONRaw(opaque)
		challenge.Opaque = &value
	}
	if challenge.ID == "" || challenge.Realm == "" || challenge.Intent == "" {
		return PaymentChallenge{}, fmt.Errorf("missing required challenge fields")
	}
	return challenge, nil
}

// ParseWWWAuthenticateAll parses successfully decoded Payment challenges from
// WWW-Authenticate header values, including merged values that also contain
// non-Payment schemes.
func ParseWWWAuthenticateAll(headers []string) []PaymentChallenge {
	challenges := make([]PaymentChallenge, 0, len(headers))
	for _, header := range headers {
		for _, value := range splitPaymentChallengeValues(header) {
			challenge, err := ParseWWWAuthenticate(value)
			if err == nil {
				challenges = append(challenges, challenge)
			}
		}
	}
	return challenges
}

// FormatWWWAuthenticate formats a challenge into a header value.
func FormatWWWAuthenticate(challenge PaymentChallenge) (string, error) {
	parts := []string{
		fmt.Sprintf(`id="%s"`, escapeQuotedValue(challenge.ID)),
		fmt.Sprintf(`realm="%s"`, escapeQuotedValue(challenge.Realm)),
		fmt.Sprintf(`method="%s"`, escapeQuotedValue(string(challenge.Method))),
		fmt.Sprintf(`intent="%s"`, escapeQuotedValue(string(challenge.Intent))),
		fmt.Sprintf(`request="%s"`, escapeQuotedValue(challenge.Request.Raw())),
	}
	// Canonical mpp-tools field order: description, then digest, then expires.
	// The description round-trips as a top-level header param so a parsed
	// challenge re-serializes byte-identically to the canonical golden wire.
	if challenge.Description != "" {
		parts = append(parts, fmt.Sprintf(`description="%s"`, escapeQuotedValue(challenge.Description)))
	}
	if challenge.Digest != "" {
		parts = append(parts, fmt.Sprintf(`digest="%s"`, escapeQuotedValue(challenge.Digest)))
	}
	if challenge.Expires != "" {
		parts = append(parts, fmt.Sprintf(`expires="%s"`, escapeQuotedValue(challenge.Expires)))
	}
	if challenge.Opaque != nil {
		parts = append(parts, fmt.Sprintf(`opaque="%s"`, escapeQuotedValue(challenge.Opaque.Raw())))
	}
	return PaymentScheme + " " + strings.Join(parts, ", "), nil
}

// ParseAuthorization parses a credential header.
func ParseAuthorization(header string) (PaymentCredential, error) {
	token, ok := ExtractPaymentScheme(header)
	if !ok {
		return PaymentCredential{}, fmt.Errorf("expected %q scheme", PaymentScheme)
	}
	token = strings.TrimSpace(strings.TrimPrefix(token, PaymentScheme))
	if len(token) > maxTokenLen {
		return PaymentCredential{}, fmt.Errorf("token exceeds maximum length of %d bytes", maxTokenLen)
	}
	payload, err := Base64URLDecode(strings.TrimSpace(token))
	if err != nil {
		return PaymentCredential{}, err
	}
	var credential PaymentCredential
	if err := json.Unmarshal(payload, &credential); err != nil {
		return PaymentCredential{}, fmt.Errorf("invalid credential JSON: %w", err)
	}
	// The canonical wire requires an embedded challenge that carries an id.
	// json.Unmarshal silently zero-fills missing fields, so validate the
	// decoded shape against the raw object to reject credentials whose
	// challenge is absent or whose challenge has no id.
	var probe struct {
		Challenge *struct {
			ID string `json:"id"`
		} `json:"challenge"`
	}
	if err := json.Unmarshal(payload, &probe); err != nil {
		return PaymentCredential{}, fmt.Errorf("invalid credential JSON: %w", err)
	}
	if probe.Challenge == nil {
		return PaymentCredential{}, fmt.Errorf("missing %q field", "challenge")
	}
	if probe.Challenge.ID == "" {
		return PaymentCredential{}, fmt.Errorf("missing %q field", "challenge.id")
	}
	return credential, nil
}

// FormatAuthorization formats a credential as a header value.
func FormatAuthorization(credential PaymentCredential) (string, error) {
	payload, err := json.Marshal(credential)
	if err != nil {
		return "", err
	}
	return PaymentScheme + " " + Base64URLEncode(payload), nil
}

// ParseReceipt parses a payment receipt header.
func ParseReceipt(header string) (Receipt, error) {
	if len(header) > maxTokenLen {
		return Receipt{}, fmt.Errorf("receipt exceeds maximum length of %d bytes", maxTokenLen)
	}
	payload, err := Base64URLDecode(strings.TrimSpace(header))
	if err != nil {
		return Receipt{}, err
	}
	var receipt Receipt
	if err := json.Unmarshal(payload, &receipt); err != nil {
		return Receipt{}, fmt.Errorf("invalid receipt JSON: %w", err)
	}
	// The canonical wire requires status, method, reference, and an
	// ISO-8601 timestamp. json.Unmarshal zero-fills missing fields, so
	// reject any receipt that omits a required field or carries a
	// non-ISO-8601 timestamp.
	if receipt.Status == "" {
		return Receipt{}, fmt.Errorf("missing %q field", "status")
	}
	if receipt.Method == "" {
		return Receipt{}, fmt.Errorf("missing %q field", "method")
	}
	if receipt.Reference == "" {
		return Receipt{}, fmt.Errorf("missing %q field", "reference")
	}
	if receipt.Timestamp == "" {
		return Receipt{}, fmt.Errorf("missing %q field", "timestamp")
	}
	if !isISO8601(receipt.Timestamp) {
		return Receipt{}, fmt.Errorf("invalid timestamp: %q is not ISO-8601", receipt.Timestamp)
	}
	return receipt, nil
}

// isISO8601 reports whether s parses as an RFC 3339 / ISO-8601 timestamp.
func isISO8601(s string) bool {
	if _, err := time.Parse(time.RFC3339, s); err == nil {
		return true
	}
	_, err := time.Parse(time.RFC3339Nano, s)
	return err == nil
}

// FormatReceipt formats a receipt as a header value.
func FormatReceipt(receipt Receipt) (string, error) {
	payload, err := json.Marshal(receipt)
	if err != nil {
		return "", err
	}
	return Base64URLEncode(payload), nil
}

// ExtractPaymentScheme returns the Payment scheme section when present.
func ExtractPaymentScheme(header string) (string, bool) {
	for _, part := range strings.Split(header, ",") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(strings.ToLower(part), strings.ToLower(PaymentScheme)+" ") {
			return part, true
		}
	}
	return "", false
}

func splitPaymentChallengeValues(header string) []string {
	starts := []int{}
	inQuote := false
	escaped := false
	for i := 0; i < len(header); i++ {
		if inQuote {
			if escaped {
				escaped = false
				continue
			}
			switch header[i] {
			case '\\':
				escaped = true
			case '"':
				inQuote = false
			}
			continue
		}
		if header[i] == '"' {
			inQuote = true
			continue
		}
		if isPaymentSchemeStart(header, i) {
			starts = append(starts, i)
			i += len(PaymentScheme) - 1
		}
	}

	values := make([]string, 0, len(starts))
	for i, start := range starts {
		end := len(header)
		if i+1 < len(starts) {
			end = starts[i+1]
		} else if next := nextAuthSchemeStart(header, start+len(PaymentScheme)); next != -1 {
			end = next
		}
		value := strings.TrimSpace(strings.TrimRight(strings.TrimSpace(header[start:end]), ","))
		if value != "" {
			values = append(values, value)
		}
	}
	return values
}

func nextAuthSchemeStart(header string, index int) int {
	inQuote := false
	escaped := false
	for i := index; i < len(header); i++ {
		if inQuote {
			if escaped {
				escaped = false
				continue
			}
			switch header[i] {
			case '\\':
				escaped = true
			case '"':
				inQuote = false
			}
			continue
		}
		if header[i] == '"' {
			inQuote = true
			continue
		}
		if header[i] != ',' {
			continue
		}
		next := i + 1
		for next < len(header) && (header[next] == ' ' || header[next] == '\t') {
			next++
		}
		if isAuthSchemeStart(header, next) {
			return next
		}
	}
	return -1
}

func isAuthSchemeStart(header string, index int) bool {
	if index >= len(header) {
		return false
	}
	tokenEnd := index
	for tokenEnd < len(header) {
		ch := header[tokenEnd]
		if ch == ' ' || ch == '\t' || ch == ',' || ch == '=' {
			break
		}
		tokenEnd++
	}
	if tokenEnd == index || tokenEnd >= len(header) {
		return false
	}
	return header[tokenEnd] == ' ' || header[tokenEnd] == '\t'
}

func isPaymentSchemeStart(header string, index int) bool {
	end := index + len(PaymentScheme)
	if end >= len(header) {
		return false
	}
	if !strings.EqualFold(header[index:end], PaymentScheme) {
		return false
	}
	if header[end] != ' ' && header[end] != '\t' {
		return false
	}

	previous := index
	for previous > 0 && (header[previous-1] == ' ' || header[previous-1] == '\t') {
		previous--
	}
	return previous == 0 || header[previous-1] == ','
}

func stripPaymentScheme(header string) (string, bool) {
	header = strings.TrimSpace(header)
	if len(header) < len(PaymentScheme) {
		return "", false
	}
	if !strings.EqualFold(header[:len(PaymentScheme)], PaymentScheme) {
		return "", false
	}
	return strings.TrimSpace(header[len(PaymentScheme):]), true
}

func escapeQuotedValue(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, `"`, `\"`)
	value = strings.ReplaceAll(value, "\r", "")
	value = strings.ReplaceAll(value, "\n", "")
	return value
}

// parseAuthParams permissively parses comma/whitespace-separated `key="value"`
// (or `key=token`) auth params. It mirrors the canonical mpp-tools parser: a
// quoted value terminates at the first unescaped closing quote, and any token
// that is not a well-formed `key=` pair is silently skipped (it does not abort
// the whole parse). This lets unescaped quotes inside a description value
// truncate at the quote boundary with the remaining text ignored, instead of
// failing the parse.
func parseAuthParams(input string) (map[string]string, error) {
	params := map[string]string{}
	chars := []rune(input)
	i := 0
	n := len(chars)
	for i < n {
		// Skip leading separators (whitespace and commas).
		for i < n && (isSpaceRune(chars[i]) || chars[i] == ',') {
			i++
		}
		if i >= n {
			break
		}
		// Read the key token up to '=' or whitespace.
		keyStart := i
		for i < n && chars[i] != '=' && !isSpaceRune(chars[i]) {
			i++
		}
		if i >= n || chars[i] != '=' {
			// Not a key=value token; skip the stray token and continue.
			for i < n && !isSpaceRune(chars[i]) && chars[i] != ',' {
				i++
			}
			continue
		}
		key := string(chars[keyStart:i])
		i++ // consume '='
		if i >= n {
			break
		}
		var value string
		if chars[i] == '"' {
			i++ // consume opening quote
			var builder strings.Builder
			for i < n && chars[i] != '"' {
				if chars[i] == '\\' && i+1 < n {
					i++
					builder.WriteRune(chars[i])
				} else {
					builder.WriteRune(chars[i])
				}
				i++
			}
			if i < n {
				i++ // consume closing quote
			}
			value = builder.String()
		} else {
			valueStart := i
			for i < n && !isSpaceRune(chars[i]) && chars[i] != ',' {
				i++
			}
			value = string(chars[valueStart:i])
		}
		if _, exists := params[key]; exists {
			return nil, fmt.Errorf("duplicate parameter: %s", key)
		}
		params[key] = value
	}
	return params, nil
}

func isSpaceRune(r rune) bool {
	return r == ' ' || r == '\t' || r == '\r' || r == '\n'
}

// SortedHeaderParams is a test helper for deterministic comparisons.
func SortedHeaderParams(params map[string]string) []string {
	keys := make([]string, 0, len(params))
	for key := range params {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]string, 0, len(keys))
	for _, key := range keys {
		out = append(out, key+"="+params[key])
	}
	return out
}
