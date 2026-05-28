package server

import (
	_ "embed" // required by go:embed directives below
	"encoding/json"
	"fmt"
	gohtml "html"
	"math"
	"net/http"
	"strconv"
	"strings"

	"github.com/solana-foundation/pay-kit/go/paycore"
	core "github.com/solana-foundation/pay-kit/go/protocols/mpp/core"
	"github.com/solana-foundation/pay-kit/go/protocols/mpp/intents"
)

//go:embed html/template.gen.html
var htmlTemplate string

//go:embed html/service-worker.gen.js
var serviceWorkerJS string

const serviceWorkerParam = "__mpp_worker"

// HTMLEnabled reports whether HTML payment links are enabled.
func (m *Mpp) HTMLEnabled() bool {
	return m.html
}

// RPCURL returns the resolved Solana RPC endpoint URL.
func (m *Mpp) RPCURL() string {
	return m.rpcURL
}

// ChallengeToHTML renders a self-contained HTML payment page for the given challenge.
// The page uses the mppx-generated template with placeholder replacements for
// {{AMOUNT}}, {{DESCRIPTION}}, {{EXPIRES}}, and {{DATA_JSON}}.
func (m *Mpp) ChallengeToHTML(challenge core.PaymentChallenge) (string, error) {
	challengeJSON, err := json.Marshal(challenge)
	if err != nil {
		return "", fmt.Errorf("marshal challenge: %w", err)
	}

	// Decode the request field to extract amount/currency for display.
	var request intents.ChargeRequest
	if err := challenge.Request.Decode(&request); err != nil {
		return "", fmt.Errorf("decode challenge request: %w", err)
	}

	// Format the amount for display.
	amountDisplay := formatAmountDisplay(request.Amount, request.Currency, m.decimals)

	// Build description HTML.
	descriptionHTML := ""
	if challenge.Description != "" {
		descriptionHTML = fmt.Sprintf(
			`<p class="mppx-summary-description">%s</p>`,
			escapeHTML(challenge.Description),
		)
	}

	// Build expires HTML.
	expiresHTML := ""
	if challenge.Expires != "" {
		escaped := escapeHTML(challenge.Expires)
		expiresHTML = fmt.Sprintf(
			`<p class="mppx-summary-expires">Expires at <time datetime="%s" id="_exp">%s</time></p><script>document.getElementById('_exp').textContent=new Date('%s').toLocaleString()</script>`,
			escaped, escaped, escaped,
		)
	}

	// Build embedded data JSON (challenge stays as original base64url string
	// to preserve HMAC integrity).
	embeddedData := map[string]any{
		"challenge": json.RawMessage(challengeJSON),
		"network":   m.network,
		"rpcUrl":    m.rpcURL,
	}
	embeddedDataJSON, err := json.Marshal(embeddedData)
	if err != nil {
		return "", fmt.Errorf("marshal embedded data: %w", err)
	}
	// Escape < to prevent </script> injection in JSON inside <script> tag.
	dataJSON := strings.ReplaceAll(string(embeddedDataJSON), "<", `\u003c`)

	// Simple placeholder replacement on the mppx-generated template.
	result := htmlTemplate
	result = strings.Replace(result, "{{AMOUNT}}", escapeHTML(amountDisplay), 1)
	result = strings.Replace(result, "{{DESCRIPTION}}", descriptionHTML, 1)
	result = strings.Replace(result, "{{EXPIRES}}", expiresHTML, 1)
	result = strings.Replace(result, "{{DATA_JSON}}", dataJSON, 1)

	return result, nil
}

// formatAmountDisplay converts raw base-unit amount + currency into a
// human-readable display string (e.g. "$1.00", "0.5 SOL").
func formatAmountDisplay(amountRaw, currency string, decimals uint8) string {
	d := int(decimals)
	if strings.EqualFold(currency, "sol") {
		d = 9
	}

	raw, err := strconv.ParseFloat(amountRaw, 64)
	if err != nil {
		raw = 0
	}
	amountF := raw / math.Pow10(d)

	displayAmount := strconv.FormatFloat(amountF, 'f', -1, 64)
	if amountF != math.Floor(amountF) {
		displayAmount = strconv.FormatFloat(amountF, 'f', 2, 64)
	}

	switch {
	case paycore.StablecoinSymbol(currency) != "":
		return "$" + displayAmount
	case strings.EqualFold(currency, "sol"):
		return displayAmount + " SOL"
	default:
		label := currency
		if len(label) > 6 {
			label = label[:6]
		}
		return displayAmount + " " + label
	}
}

// escapeHTML escapes a string to prevent XSS when interpolating into HTML.
func escapeHTML(s string) string {
	return gohtml.EscapeString(s)
}

// ServiceWorkerJS returns the embedded service worker JavaScript content.
func ServiceWorkerJS() string {
	return serviceWorkerJS
}

// AcceptsHTML reports whether the request's Accept header includes "text/html".
func AcceptsHTML(r *http.Request) bool {
	return strings.Contains(r.Header.Get("Accept"), "text/html")
}

// IsServiceWorkerRequest reports whether the request URL contains the
// service worker query parameter (__mpp_worker).
func IsServiceWorkerRequest(r *http.Request) bool {
	return r.URL.Query().Has(serviceWorkerParam)
}
