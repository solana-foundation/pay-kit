//! Agent Payments Protocol (AP2) helpers for Solana.
//!
//! AP2 is Google's protocol for attaching a cryptographically-signed,
//! user-authorized audit trail to a payment that moves over some other
//! rail (cards, stablecoins, …). It defines three "Mandates":
//!
//! - [`IntentMandate`] — the user delegates spending authority to an agent.
//! - [`CartMandate`] — the merchant proposes a specific cart at a specific
//!   price, signed against the user's intent.
//! - [`PaymentMandate`] — the user approves the cart and attaches a
//!   payment proof to it.
//!
//! This crate is **rail-agnostic at the AP2 layer** but **Solana-only at
//! the payment layer**: every mandate carries a [`PaymentMethod`] that
//! resolves to either an x402 [`PaymentRequirements`] block or an MPP
//! [`ChargeRequest`] block. Verification chains the three mandates, then
//! delegates to the existing pay-kit x402 / MPP server verifiers.
//!
//! # Scope
//!
//! Phase 1 of the AP2 design (mandate types + signature + replay store +
//! payment-method bridge to x402 / MPP). Later phases will add the A2A
//! envelope (`x402.payment.*` metadata on A2A Tasks/Messages) and an
//! `Ap2Server` orchestrator that wraps `x402::Server::Exact` and
//! `mpp::Server::Charge`.
//!
//! # Compatibility with upstream a2a-x402
//!
//! The `PaymentMethod::X402` variant matches `supported_methods:
//! "https://www.x402.org/"` from `google-agentic-commerce/a2a-x402`
//! v0.2.
//!
//! The `PaymentMethod::Mpp` variant is a **pay-kit extension**. It uses
//! `supported_methods: "https://paymentauth.org/mpp"` and embeds an MPP
//! [`ChargeRequest`] where the x402 variant embeds a `PaymentRequirements`.
//! Upstream a2a-x402 currently only specifies the x402 variant; we'd file
//! a spec PR to standardize the MPP URI before declaring wire-portable
//! interop with non-pay-kit AP2 clients.
//!
//! [`PaymentRequirements`]: solana_x402::exact::PaymentRequirements
//! [`ChargeRequest`]: solana_mpp::ChargeRequest

pub mod error;
pub mod mandate;
pub mod method;
pub mod signature;
pub mod verify;

pub use error::Ap2Error;
pub use mandate::{
    Cart, CartItem, CartMandate, IntentConstraints, IntentMandate, MandateId, PaymentMandate,
};
pub use method::{
    MPP_METHOD_URI, PaymentMethod, PaymentMethodId, PaymentPayload, X402_METHOD_URI,
};
pub use signature::{Ed25519Signer, SignedBytes, canonicalize};
pub use verify::{InMemoryMandateReplayStore, MandateReplayError, MandateReplayStore, MandateVerifier};

/// Version of the AP2 wire format this crate targets. Tracks
/// `google-agentic-commerce/a2a-x402` v0.2; pinned at the crate level
/// so consumers can branch on it as the spec churns.
pub const AP2_WIRE_VERSION: &str = "0.2";
