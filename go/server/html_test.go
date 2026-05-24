package server

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func newHTMLTestMpp(t *testing.T) *Mpp {
	t.Helper()
	handler, err := New(Config{
		Recipient: "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY",
		SecretKey: "test-secret-key-that-is-long-enough-for-hmac-sha256-operations",
		Network:   "devnet",
		HTML:      true,
	})
	if err != nil {
		t.Fatalf("new mpp failed: %v", err)
	}
	return handler
}

func TestAcceptsHTML(t *testing.T) {
	tests := []struct {
		name   string
		accept string
		want   bool
	}{
		{"text/html", "text/html", true},
		{"text/html with charset", "text/html; charset=utf-8", true},
		{"mixed with html first", "text/html, application/json", true},
		{"mixed with json first", "application/json, text/html", true},
		{"application/json only", "application/json", false},
		{"empty", "", false},
		{"wildcard", "*/*", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &http.Request{Header: http.Header{}}
			if tt.accept != "" {
				r.Header.Set("Accept", tt.accept)
			}
			if got := AcceptsHTML(r); got != tt.want {
				t.Fatalf("AcceptsHTML(%q) = %v, want %v", tt.accept, got, tt.want)
			}
		})
	}
}

func TestIsServiceWorkerRequest(t *testing.T) {
	tests := []struct {
		name   string
		rawURL string
		want   bool
	}{
		{"with param", "http://example.com/?__mpp_worker", true},
		{"with param and value", "http://example.com/?__mpp_worker=1", true},
		{"without param", "http://example.com/", false},
		{"other param only", "http://example.com/?foo=bar", false},
		{"mixed params", "http://example.com/?foo=bar&__mpp_worker", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, err := url.Parse(tt.rawURL)
			if err != nil {
				t.Fatalf("parse url: %v", err)
			}
			r := &http.Request{URL: u}
			if got := IsServiceWorkerRequest(r); got != tt.want {
				t.Fatalf("IsServiceWorkerRequest(%q) = %v, want %v", tt.rawURL, got, tt.want)
			}
		})
	}
}

func TestServiceWorkerJS(t *testing.T) {
	js := ServiceWorkerJS()
	if js == "" {
		t.Fatal("ServiceWorkerJS() returned empty string")
	}
}

func TestChallengeToHTML(t *testing.T) {
	handler := newHTMLTestMpp(t)
	challenge, err := handler.ChargeWithOptions(context.Background(), "1.00", ChargeOptions{
		Description: "Test payment",
	})
	if err != nil {
		t.Fatalf("charge failed: %v", err)
	}

	html, err := handler.ChallengeToHTML(challenge)
	if err != nil {
		t.Fatalf("ChallengeToHTML failed: %v", err)
	}

	checks := []struct {
		name   string
		substr string
	}{
		{"doctype", "<!doctype html>"},
		{"data element", `id="__MPP_DATA__"`},
		{"root div", `id="root"`},
		{"challenge ID", challenge.ID},
		{"script tag", "<script"},
	}
	for _, c := range checks {
		t.Run(c.name, func(t *testing.T) {
			if !strings.Contains(html, c.substr) {
				t.Fatalf("expected HTML to contain %q", c.substr)
			}
		})
	}
}

func TestHTMLEnabled(t *testing.T) {
	enabled := newHTMLTestMpp(t)
	if !enabled.HTMLEnabled() {
		t.Fatal("expected HTMLEnabled() = true when Config.HTML is true")
	}

	disabled, err := New(Config{
		Recipient: "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY",
		SecretKey: "test-secret-key-that-is-long-enough-for-hmac-sha256-operations",
		Network:   "devnet",
		HTML:      false,
	})
	if err != nil {
		t.Fatalf("new mpp failed: %v", err)
	}
	if disabled.HTMLEnabled() {
		t.Fatal("expected HTMLEnabled() = false when Config.HTML is false")
	}
}

func TestChallengeToHTMLNetwork(t *testing.T) {
	handler := newHTMLTestMpp(t)
	challenge, err := handler.Charge(context.Background(), "1.00")
	if err != nil {
		t.Fatalf("charge failed: %v", err)
	}

	html, err := handler.ChallengeToHTML(challenge)
	if err != nil {
		t.Fatalf("ChallengeToHTML failed: %v", err)
	}

	if !strings.Contains(html, `"network":"devnet"`) {
		t.Fatal("expected embedded JSON to contain network field")
	}
}

func TestChallengeToHTMLEscapesDescription(t *testing.T) {
	handler := newHTMLTestMpp(t)
	challenge, err := handler.ChargeWithOptions(context.Background(), "1.00", ChargeOptions{
		Description: `<script>alert(1)</script>`,
	})
	if err != nil {
		t.Fatalf("charge failed: %v", err)
	}

	html, err := handler.ChallengeToHTML(challenge)
	if err != nil {
		t.Fatalf("ChallengeToHTML failed: %v", err)
	}

	if strings.Contains(html, `<script>alert(1)</script>`) {
		t.Fatal("expected description to be HTML-escaped, but found raw <script> tag")
	}
	if !strings.Contains(html, `&lt;script&gt;alert(1)&lt;/script&gt;`) {
		t.Fatal("expected HTML-escaped description in output")
	}
}

func TestFormatAmountDisplay(t *testing.T) {
	tests := []struct {
		name     string
		amount   string
		currency string
		decimals uint8
		want     string
	}{
		{"usdc whole", "1000000", "USDC", 6, "$1"},
		{"usdc fractional", "1230000", "USDC", 6, "$1.23"},
		{"sol uses lamports", "500000000", "sol", 6, "0.50 SOL"},
		{"invalid amount", "not-a-number", "USDC", 6, "$0"},
		{"custom currency truncated", "123456", "LONGTOKENMINT", 6, "0.12 LONGTO"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := formatAmountDisplay(tt.amount, tt.currency, tt.decimals); got != tt.want {
				t.Fatalf("formatAmountDisplay() = %q, want %q", got, tt.want)
			}
		})
	}
}
