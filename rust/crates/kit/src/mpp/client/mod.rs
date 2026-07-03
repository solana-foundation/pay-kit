//! Client-side implementations for the charge, session, and subscription intents.

pub mod authenticate;
mod charge;
#[cfg(feature = "confidential")]
pub(crate) mod confidential;
#[cfg(feature = "confidential")]
pub use confidential::{build_confidential_transfer_bundle, ConfidentialTransferParams};
// The streaming consumer polls `reqwest::Response::chunk()` and hands out
// `Send` futures; on wasm reqwest's response bodies are neither. Making this
// work there needs a `?Send`/bytes_stream refactor — native-only until then.
#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
pub mod http_stream;
pub mod session;
pub mod session_consumer;
// Subscription activation is an RPC round-trip (fetch delegation accounts,
// send-and-confirm), so it has no offline variant and stays native-only.
#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
pub mod subscription;

pub use authenticate::{
    build_credential as build_authenticate_credential,
    build_credential_header as build_authenticate_credential_header,
};
pub use charge::*;
#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
pub use http_stream::*;
// The payment-channel session opener now lives in `session`; re-export the
// same symbols here to preserve the historical `mpp::client::*` paths.
pub use session::{
    build_open_payment_channel_transaction, create_payment_channel_session_opener,
    create_server_opened_payment_channel_session_opener, derive_payment_channel_open,
    BuildOpenPaymentChannelTransactionParams, DerivePaymentChannelOpenParams, PaymentChannelOpen,
    PaymentChannelOpenOptions, PaymentChannelSessionOpen, PaymentChannelSessionOpenOptions,
    ServerOpenedPaymentChannelSessionOpenOptions, DEFAULT_GRACE_PERIOD_SECONDS,
    PENDING_SERVER_SIGNATURE,
};
pub use session_consumer::*;
#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
pub use subscription::{
    build_subscription_activation_transaction,
    build_subscription_activation_transaction_with_options, BuildSubscriptionActivationOptions,
    SubscriptionMethodDetails,
};
