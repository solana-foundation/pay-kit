package core

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
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
	if challenge.Expires != "" {
		parts = append(parts, fmt.Sprintf(`expires="%s"`, escapeQuotedValue(challenge.Expires)))
	}
	// description is already encoded inside the request payload —
	// don't duplicate it as a top-level header param (non-ASCII descriptions
	// would make the header value invalid).
	if challenge.Digest != "" {
		parts = append(parts, fmt.Sprintf(`digest="%s"`, escapeQuotedValue(challenge.Digest)))
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
	return receipt, nil
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

func parseAuthParams(input string) (map[string]string, error) {
	params := map[string]string{}
	for len(strings.TrimSpace(input)) > 0 {
		input = strings.TrimLeft(input, " \t,")
		if input == "" {
			break
		}
		eq := strings.IndexByte(input, '=')
		if eq <= 0 {
			return nil, fmt.Errorf("invalid auth parameter")
		}
		key := strings.TrimSpace(input[:eq])
		input = input[eq+1:]
		var value string
		if strings.HasPrefix(input, `"`) {
			input = input[1:]
			var builder strings.Builder
			escaped := false
			consumed := -1
			for i, ch := range input {
				if escaped {
					builder.WriteRune(ch)
					escaped = false
					continue
				}
				if ch == '\\' {
					escaped = true
					continue
				}
				if ch == '"' {
					value = builder.String()
					consumed = i + 1
					break
				}
				builder.WriteRune(ch)
			}
			if consumed == -1 {
				return nil, fmt.Errorf("unterminated quoted value")
			}
			input = input[consumed:]
		} else {
			next := strings.IndexByte(input, ',')
			if next == -1 {
				value = strings.TrimSpace(input)
				input = ""
			} else {
				value = strings.TrimSpace(input[:next])
				input = input[next+1:]
			}
		}
		if _, exists := params[key]; exists {
			return nil, fmt.Errorf("duplicate parameter: %s", key)
		}
		params[key] = value
	}
	return params, nil
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
