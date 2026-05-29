package paykit

import "context"

// Signer is the Ed25519 signer interface every signer backend
// implements. Local signers (signer.Demo, signer.FromFile, ...) ignore
// the context; remote enclave (KMS) signers honor it
// for network I/O timeouts and cancellation.
//
// The interface deliberately never exposes the raw secret key: both the
// x402 facilitator cosign and the MPP fee-payer cosign go through
// Sign, so a KMS- or HSM-backed signer that can never export its key
// still satisfies the contract. This diverges from the original
// DESIGN.md sketch (which had a FeePayer() bool method on Signer);
// fee-payer policy lives on Operator, not the key source.
type Signer interface {
	// Pubkey returns the base58 Solana pubkey.
	Pubkey() Address
	// Sign produces a 64-byte Ed25519 signature over the message bytes.
	Sign(ctx context.Context, message []byte) ([]byte, error)
	// IsDemo reports whether this is the package-shipped demo keypair.
	// paykit.New refuses to boot on solana_mainnet when this returns
	// true.
	IsDemo() bool
}
