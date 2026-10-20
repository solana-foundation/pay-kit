/// Errors produced by the Solana x402 SDK.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("RPC error: {0}")]
    Rpc(String),

    #[error("Transaction not found or not yet confirmed")]
    TransactionNotFound,

    #[error("Transaction failed on-chain: {0}")]
    TransactionFailed(String),

    #[error("No matching transfer instruction found")]
    NoTransferInstruction,

    #[error("Amount mismatch: expected {expected}, got {actual}")]
    AmountMismatch { expected: String, actual: String },

    #[error("Recipient mismatch: expected {expected}, got {actual}")]
    RecipientMismatch { expected: String, actual: String },

    #[error("Token mint mismatch: expected {expected}, got {actual}")]
    MintMismatch { expected: String, actual: String },

    #[error("Destination ATA does not belong to expected recipient")]
    AtaMismatch,

    #[error(
        "Signed against {received} but the server expects {expected}. \
         Switch your client RPC to {expected} and re-sign."
    )]
    WrongNetwork { expected: String, received: String },

    #[error("Transaction signature already consumed")]
    SignatureConsumed,

    #[error("Simulation failed: {0}")]
    SimulationFailed(String),

    #[error("Missing transaction data in payment payload")]
    MissingTransaction,

    #[error("Missing signature in payment payload")]
    MissingSignature,

    #[error("Invalid payload type: {0}")]
    InvalidPayloadType(String),

    #[error("HTTP error: {0}")]
    Http(String),

    #[error("Invalid 402 response: {0}")]
    InvalidPaymentRequired(String),

    #[error("Payment header missing from 402 response")]
    MissingPaymentHeader,

    /// The route requires the `payment-identifier` extension and the
    /// credential carried no id, or carried one that violates the format.
    /// The extension spec answers this with HTTP 400 (see [`Error::http_status`]).
    #[error("payment-identifier required: {0}")]
    PaymentIdentifierRequired(String),

    /// A v2 credential's `accepted` requirements match none of the options
    /// the route offers (for example a credential issued for another route
    /// or price). The payment is for something this route does not sell.
    #[error("Credential's accepted does not match any offered payment option")]
    AcceptedMismatch,

    #[error("{0}")]
    Other(String),
}

impl Error {
    /// HTTP status a resource server answers with when payment verification
    /// fails with this error: 400 for a missing or malformed required
    /// `payment-identifier` (per the extension spec), 402 otherwise.
    pub fn http_status(&self) -> u16 {
        match self {
            Error::PaymentIdentifierRequired(_) => 400,
            _ => 402,
        }
    }
}

impl From<crate::core::Error> for Error {
    fn from(err: crate::core::Error) -> Self {
        match err {
            crate::core::Error::Serialization(msg) => Error::Other(msg),
            crate::core::Error::Other(msg) => Error::Other(msg),
        }
    }
}
