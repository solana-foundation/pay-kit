//! Solana-flavored signature scheme for AP2 mandates.
//!
//! The AP2 spec is signature-agnostic — it just says "user-signed". For
//! Solana we pick **Ed25519 over RFC 8785 canonical JSON**, matching
//! what `solana-mpp` already uses for credential signing. This means a
//! signer for a pay-kit MPP charge is also a valid AP2 mandate signer
//! against the same pubkey, and verification can reuse the same JCS
//! canonicalizer dependency.
//!
//! Encoding: signatures and pubkeys are base58 strings on the wire, the
//! same convention as Solana addresses everywhere else in pay-kit.
//!
//! Eventually the AP2 wire format will need a `signatureScheme` field
//! so a single Cart Mandate can carry both an EIP-712 signature (for
//! EVM clients) and an Ed25519 signature (for Solana clients). For now
//! we ship Ed25519 only and document it in `docs/SPEC.md`.

use serde::{Deserialize, Serialize};

use crate::error::Ap2Error;

pub use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

/// Canonicalize a serializable value into the byte string we sign.
///
/// Uses RFC 8785 (JSON Canonicalization Scheme) — same canonicalizer as
/// `solana-mpp`, so MPP credentials and AP2 mandates produce identical
/// canonical bytes for identical JSON shapes. Required so two different
/// implementations (Rust ↔ Python, server ↔ client) compute the same
/// signature input from the same logical mandate.
pub fn canonicalize<T: Serialize>(value: &T) -> Result<Vec<u8>, Ap2Error> {
    serde_json_canonicalizer::to_vec(value)
        .map_err(|e| Ap2Error::Malformed(format!("canonical JSON encoding failed: {e}")))
}

/// A signature bound to a specific message. We store the raw 64-byte
/// Ed25519 signature in the struct and the base58-encoded form on the
/// wire, again matching pay-kit's Solana conventions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedBytes {
    /// Base58-encoded Ed25519 signature.
    pub signature: String,

    /// Base58-encoded Ed25519 verifying key (the signer's Solana pubkey).
    pub signer_pubkey: String,
}

impl SignedBytes {
    /// Verify the signature against the canonical-JSON encoding of `value`.
    /// Returns `Ok(())` on a valid signature, `Err(SignatureInvalid)` otherwise.
    pub fn verify<T: Serialize>(&self, value: &T, what: &'static str) -> Result<(), Ap2Error> {
        let bytes = canonicalize(value)?;
        let pubkey_bytes = bs58::decode(&self.signer_pubkey)
            .into_vec()
            .map_err(|_| Ap2Error::SignatureInvalid { what })?;
        let pubkey_array: [u8; 32] = pubkey_bytes
            .as_slice()
            .try_into()
            .map_err(|_| Ap2Error::SignatureInvalid { what })?;
        let verifying = VerifyingKey::from_bytes(&pubkey_array)
            .map_err(|_| Ap2Error::SignatureInvalid { what })?;

        let sig_bytes = bs58::decode(&self.signature)
            .into_vec()
            .map_err(|_| Ap2Error::SignatureInvalid { what })?;
        let sig_array: [u8; 64] = sig_bytes
            .as_slice()
            .try_into()
            .map_err(|_| Ap2Error::SignatureInvalid { what })?;
        let signature = Signature::from_bytes(&sig_array);

        verifying
            .verify(&bytes, &signature)
            .map_err(|_| Ap2Error::SignatureInvalid { what })
    }
}

/// Convenience wrapper around an Ed25519 signing key for tests and
/// in-process signers. Production code should plug in a hardware-backed
/// `Signer` (Ledger, Trezor, KMS) that produces a `SignedBytes` value
/// over the same canonical bytes.
pub struct Ed25519Signer {
    key: SigningKey,
}

impl Ed25519Signer {
    /// Construct from a 32-byte seed.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self { key: SigningKey::from_bytes(seed) }
    }

    /// Generate a fresh keypair (uses `OsRng`).
    pub fn generate() -> Self {
        use rand_core::OsRng;
        Self { key: SigningKey::generate(&mut OsRng) }
    }

    /// The signer's base58-encoded Solana pubkey.
    pub fn pubkey(&self) -> String {
        bs58::encode(self.key.verifying_key().to_bytes()).into_string()
    }

    /// Sign the canonical-JSON encoding of `value`. Returns the same
    /// `SignedBytes` envelope a remote signer would produce.
    pub fn sign<T: Serialize>(&self, value: &T) -> Result<SignedBytes, Ap2Error> {
        let bytes = canonicalize(value)?;
        let signature = self.key.sign(&bytes);
        Ok(SignedBytes {
            signature: bs58::encode(signature.to_bytes()).into_string(),
            signer_pubkey: self.pubkey(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Serialize;

    #[derive(Debug, Clone, Serialize)]
    struct Fixture {
        a: u32,
        b: String,
    }

    #[test]
    fn round_trip_sign_and_verify() {
        let signer = Ed25519Signer::from_seed(&[7; 32]);
        let value = Fixture { a: 42, b: "hello".into() };
        let signed = signer.sign(&value).unwrap();

        signed.verify(&value, "fixture").expect("valid sig must verify");
    }

    #[test]
    fn tampering_invalidates_signature() {
        let signer = Ed25519Signer::from_seed(&[7; 32]);
        let value = Fixture { a: 42, b: "hello".into() };
        let signed = signer.sign(&value).unwrap();

        let tampered = Fixture { a: 99, b: "hello".into() };
        assert!(signed.verify(&tampered, "fixture").is_err());
    }

    #[test]
    fn canonical_json_is_field_order_independent() {
        #[derive(Serialize)]
        struct A {
            x: u32,
            y: u32,
        }
        #[derive(Serialize)]
        struct B {
            y: u32,
            x: u32,
        }

        let bytes_a = canonicalize(&A { x: 1, y: 2 }).unwrap();
        let bytes_b = canonicalize(&B { y: 2, x: 1 }).unwrap();
        assert_eq!(bytes_a, bytes_b, "JCS sorts keys; field order in the Rust struct must not matter");
    }
}
