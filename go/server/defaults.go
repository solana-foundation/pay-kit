// Package server implements the Solana MPP server-side charge handler.
// It generates HMAC-signed challenges, verifies client credentials in
// pull (server-broadcasts) and push (client-broadcasts) modes, enforces
// the Tier-2 pinned-field backstop and per-route expected-charge checks,
// and renders the payment-link HTML page. The wire format and validation
// order mirror the Rust reference (rust/src/server/charge.rs) so the
// cross-language interop harness exercises identical behavior.
package server

import "os"

// DetectRealm checks environment variables for a suitable realm value.
// It iterates through common platform-specific variables before falling
// back to the default realm.
func DetectRealm() string {
	for _, key := range []string{
		"MPP_REALM", "FLY_APP_NAME", "HEROKU_APP_NAME",
		"RAILWAY_SERVICE_NAME", "RENDER_SERVICE_NAME",
		"K_SERVICE", "HOSTNAME",
	} {
		if v := os.Getenv(key); v != "" {
			return v
		}
	}
	return defaultRealm
}

// DetectSecretKey reads the MPP_SECRET_KEY environment variable.
func DetectSecretKey() string {
	return os.Getenv(secretKeyEnvVar)
}
