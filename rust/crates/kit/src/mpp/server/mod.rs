//! Server-side MPP support.
//!
//! The server module is split by intent:
//! - [`charge`] handles one-shot Solana charge challenges and verification.
//! - [`session`] handles session challenges, vouchers, and channel lifecycle.
//! - [`html`] renders browser payment-link responses.

pub mod authenticate;
pub mod charge;
pub mod html;
pub mod session;
pub mod subscription;

#[cfg(feature = "axum")]
pub mod axum;

#[cfg(feature = "confidential")]
pub mod confidential;

#[cfg(feature = "worker")]
pub mod confidential_worker;

pub use authenticate::{
    AuthenticateConfig, AuthenticateServer, VerifyError as AuthenticateVerifyError,
};
pub use charge::{check_network_blockhash, ChargeOptions, Config, Mpp, VerificationError};
pub use subscription::{SubscriptionConfig, SubscriptionServer};

#[cfg(feature = "worker")]
pub use confidential::ConfidentialSweepReport;

#[cfg(feature = "worker")]
pub use confidential_worker::{
    spawn as spawn_confidential_worker, ConfidentialHandle, ConfidentialWorkerConfig,
};
