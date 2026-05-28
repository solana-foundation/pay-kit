package paykit

import "context"

// Signer is the Ed25519 signer interface every signer backend
// implements. Local signers (signer.Demo, .FromFile, ...) ignore
// the context; remote enclave signers (paykit/kms.GCP, ...) honor it
// for network I/O timeouts + cancellation.
type Signer interface {
	// Pubkey returns the base58 Solana pubkey.
	Pubkey() Address
	// Sign produces an Ed25519 signature over the message bytes.
	Sign(ctx context.Context, message []byte) ([]byte, error)
	// IsDemo reports whether this is the package-shipped demo
	// keypair. paykit.New refuses to boot on solana_mainnet when this
	// returns true.
	IsDemo() bool
	// SecretKey returns the 64-byte secret-key blob if the backend
	// stores it locally, or nil for remote backends. Used by the x402
	// adapter to partial-sign settlement transactions; remote backends
	// instead override the adapter's signer via X402Config.Scheme path.
	SecretKey() []byte
}
