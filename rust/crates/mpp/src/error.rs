/// Errors produced by the Solana MPP SDK.
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

    #[error("Transaction signature already consumed")]
    SignatureConsumed,

    #[error("Simulation failed: {0}")]
    SimulationFailed(String),

    #[error("Missing transaction data in credential payload")]
    MissingTransaction,

    #[error("Missing signature in credential payload")]
    MissingSignature,

    #[error("Invalid payload type: {0}")]
    InvalidPayloadType(String),

    #[error("Splits consume the entire amount")]
    SplitsExceedAmount,

    #[error("Splits exceed maximum of 8 entries")]
    TooManySplits,

    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),

    #[error("Challenge expired at {0}")]
    ChallengeExpired(String),

    #[error("Challenge ID mismatch — not issued by this server")]
    ChallengeMismatch,

    #[error("{0}")]
    Other(String),
}

/// Result type alias.
pub type Result<T> = std::result::Result<T, Error>;
