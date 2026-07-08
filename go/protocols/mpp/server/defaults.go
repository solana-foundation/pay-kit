// Package server implements the Solana MPP server-side charge handler.
// It generates HMAC-signed challenges, verifies client credentials in
// pull (server-broadcasts) and push (client-broadcasts) modes, enforces
// the Tier-2 pinned-field backstop and per-route expected-charge checks,
// and renders the payment-link HTML page. The wire format and validation
// order mirror the Rust reference (rust/src/server/charge.rs) so the
// cross-language harness exercises identical behavior.
package server

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"os"
)

// DetectRealm checks environment variables for a suitable realm value.
// It iterates through common platform-specific variables before falling
// back to a realm derived from the recipient pubkey. The recipient is
// unique per merchant, so two servers that share MPP_SECRET_KEY but pay
// different recipients get different realms (and therefore different HMAC
// challenge IDs), which closes the cross-service replay window that a fixed
// shared default realm would open. Mirrors the Rust reference
// derive_default_realm.
func DetectRealm(recipient string) string {
	for _, key := range []string{
		"MPP_REALM", "FLY_APP_NAME", "HEROKU_APP_NAME",
		"RAILWAY_SERVICE_NAME", "RENDER_SERVICE_NAME",
		"K_SERVICE", "HOSTNAME",
	} {
		if v := os.Getenv(key); v != "" {
			return v
		}
	}
	return deriveDefaultRealm(recipient)
}

// deriveDefaultRealm hashes the recipient with SHA-256, takes the first 4
// bytes as a big-endian u32 mod 10^8, and formats it as "App Id - #<digits>".
// Deterministic (restart-safe) and human-friendly. Mirrors the Rust
// reference derive_default_realm.
func deriveDefaultRealm(recipient string) string {
	sum := sha256.Sum256([]byte(recipient))
	n := binary.BigEndian.Uint32(sum[:4]) % 100_000_000
	return fmt.Sprintf("App Id - #%d", n)
}

// DetectSecretKey reads the MPP_SECRET_KEY environment variable.
func DetectSecretKey() string {
	return os.Getenv(secretKeyEnvVar)
}
