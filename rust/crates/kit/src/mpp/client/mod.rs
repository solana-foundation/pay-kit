//! Client-side implementations for the charge, session, and subscription intents.

pub mod authenticate;
mod charge;
#[cfg(feature = "confidential")]
pub(crate) mod confidential;
#[cfg(feature = "confidential")]
pub use confidential::{build_confidential_transfer_bundle, ConfidentialTransferParams};
pub mod http_stream;
pub mod session;
pub mod session_consumer;
pub mod subscription;

pub use authenticate::{
    build_credential as build_authenticate_credential,
    build_credential_header as build_authenticate_credential_header,
};
pub use charge::*;
pub use http_stream::*;
pub use session::{
    build_open_payment_channel_transaction, create_payment_channel_session_opener,
    derive_payment_channel_open, BuildOpenPaymentChannelTransactionParams,
    DerivePaymentChannelOpenParams, PaymentChannelOpen, PaymentChannelOpenOptions,
    PaymentChannelSessionOpen, PaymentChannelSessionOpenOptions, DEFAULT_GRACE_PERIOD_SECONDS,
};
pub use session_consumer::*;
pub use subscription::{
    build_subscription_activation_transaction,
    build_subscription_activation_transaction_with_options, BuildSubscriptionActivationOptions,
    SubscriptionMethodDetails,
};
