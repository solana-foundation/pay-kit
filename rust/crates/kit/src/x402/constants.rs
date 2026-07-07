//! x402 protocol constants shared across schemes.

/// Network identifier used by older Solana x402 integrations.
pub const SOLANA_NETWORK: &str = "solana";

/// Canonical JSON field name for the x402 protocol version.
pub const X402_VERSION_FIELD: &str = "x402Version";

/// Legacy x402 protocol version.
pub const X402_VERSION_V1: u64 = 1;

/// Canonical x402 protocol version used by current payments.
pub const X402_VERSION_V2: u64 = 2;

/// Legacy v1 client payment header.
pub const X402_V1_PAYMENT_HEADER: &str = "X-PAYMENT";

/// Legacy v1 payment-required header.
pub const X402_V1_PAYMENT_REQUIRED_HEADER: &str = "X-PAYMENT-REQUIRED";

/// Legacy v1 settlement response header.
pub const X402_V1_PAYMENT_RESPONSE_HEADER: &str = "X-PAYMENT-RESPONSE";

/// v2 client payment header.
pub const X402_V2_PAYMENT_HEADER: &str = "PAYMENT-SIGNATURE";

/// v2 payment-required header.
pub const X402_V2_PAYMENT_REQUIRED_HEADER: &str = "PAYMENT-REQUIRED";

/// v2 settlement response header.
pub const X402_V2_PAYMENT_RESPONSE_HEADER: &str = "PAYMENT-RESPONSE";

/// Canonical sign-in extension key.
pub const SIGN_IN_WITH_X: &str = "sign-in-with-x";

/// Header carrying a signed sign-in-with-x payload.
pub const SIGN_IN_WITH_X_HEADER: &str = "SIGN-IN-WITH-X";

/// Header carrying x402 payment requirements from server to client.
pub const PAYMENT_REQUIRED_HEADER: &str = X402_V2_PAYMENT_REQUIRED_HEADER;

/// Header carrying an x402 payment proof from client to server.
pub const PAYMENT_SIGNATURE_HEADER: &str = X402_V2_PAYMENT_HEADER;

/// Header carrying an x402 payment result from server to client.
pub const PAYMENT_RESPONSE_HEADER: &str = X402_V2_PAYMENT_RESPONSE_HEADER;
