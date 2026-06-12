package paycore

import "strings"

// SolanaNetwork is the canonical Solana cluster slug carried by method
// details and used by the client-side challenge selectors. The zero
// value means "unspecified" (selectors treat it as no filter).
type SolanaNetwork string

// Canonical cluster slugs. The wire format writes these exact strings.
const (
	// NetworkMainnet is the Solana mainnet cluster.
	NetworkMainnet SolanaNetwork = "mainnet"
	// NetworkDevnet is the Solana devnet cluster.
	NetworkDevnet SolanaNetwork = "devnet"
	// NetworkTestnet is the Solana testnet cluster.
	NetworkTestnet SolanaNetwork = "testnet"
	// NetworkLocalnet is a local or hosted Surfpool test validator.
	NetworkLocalnet SolanaNetwork = "localnet"
)

// ParseSolanaNetwork folds cluster aliases onto the canonical slug:
// the legacy "mainnet-beta" spelling (any case) becomes
// [NetworkMainnet]; every other value passes through unchanged so
// unknown slugs keep their server-provided spelling.
func ParseSolanaNetwork(network string) SolanaNetwork {
	lower := strings.ToLower(network)
	if lower == "mainnet" || lower == "mainnet-beta" {
		return NetworkMainnet
	}
	return SolanaNetwork(network)
}

// String returns the canonical slug.
func (n SolanaNetwork) String() string { return string(n) }
