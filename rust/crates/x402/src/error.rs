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

    #[error("{0}")]
    Other(String),
}
