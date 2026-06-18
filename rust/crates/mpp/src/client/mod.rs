//! Client-side implementations for the charge, session, and subscription intents.

pub mod authenticate;
mod charge;
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
pub use subscription::{
    build_subscription_activation_transaction,
    build_subscription_activation_transaction_with_options, BuildSubscriptionActivationOptions,
    SubscriptionMethodDetails,
};
