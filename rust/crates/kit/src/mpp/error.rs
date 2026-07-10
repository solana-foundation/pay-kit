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

    #[error(
        "Splits exceed maximum of {} entries",
        crate::mpp::protocol::solana::MAX_SPLITS
    )]
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

impl From<crate::core::Error> for Error {
    fn from(err: crate::core::Error) -> Self {
        match err {
            crate::core::Error::Serialization(msg) => Error::Other(msg),
            crate::core::Error::Other(msg) => Error::Other(msg),
        }
    }
}

/// Result type alias.
pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_core_serialization_maps_to_other() {
        let core = crate::core::Error::Serialization("bad borsh".to_string());
        let err: Error = core.into();
        match err {
            Error::Other(msg) => assert_eq!(msg, "bad borsh"),
            other => panic!("expected Other, got {other:?}"),
        }
    }

    #[test]
    fn from_core_other_maps_to_other() {
        let core = crate::core::Error::Other("boom".to_string());
        let err: Error = core.into();
        match err {
            Error::Other(msg) => assert_eq!(msg, "boom"),
            other => panic!("expected Other, got {other:?}"),
        }
    }

    #[test]
    fn display_messages_render_fields() {
        assert_eq!(
            Error::AmountMismatch {
                expected: "10".to_string(),
                actual: "9".to_string(),
            }
            .to_string(),
            "Amount mismatch: expected 10, got 9"
        );
        assert_eq!(
            Error::RecipientMismatch {
                expected: "AAA".to_string(),
                actual: "BBB".to_string(),
            }
            .to_string(),
            "Recipient mismatch: expected AAA, got BBB"
        );
        assert_eq!(
            Error::MintMismatch {
                expected: "USDC".to_string(),
                actual: "USDT".to_string(),
            }
            .to_string(),
            "Token mint mismatch: expected USDC, got USDT"
        );
    }

    #[test]
    fn display_simple_variants() {
        assert_eq!(Error::Rpc("down".into()).to_string(), "RPC error: down");
        assert_eq!(
            Error::TransactionNotFound.to_string(),
            "Transaction not found or not yet confirmed"
        );
        assert_eq!(
            Error::TransactionFailed("boom".into()).to_string(),
            "Transaction failed on-chain: boom"
        );
        assert_eq!(
            Error::NoTransferInstruction.to_string(),
            "No matching transfer instruction found"
        );
        assert_eq!(
            Error::AtaMismatch.to_string(),
            "Destination ATA does not belong to expected recipient"
        );
        assert_eq!(
            Error::SignatureConsumed.to_string(),
            "Transaction signature already consumed"
        );
        assert_eq!(
            Error::SimulationFailed("nope".into()).to_string(),
            "Simulation failed: nope"
        );
        assert_eq!(
            Error::MissingTransaction.to_string(),
            "Missing transaction data in credential payload"
        );
        assert_eq!(
            Error::MissingSignature.to_string(),
            "Missing signature in credential payload"
        );
        assert_eq!(
            Error::InvalidPayloadType("weird".into()).to_string(),
            "Invalid payload type: weird"
        );
        assert_eq!(
            Error::SplitsExceedAmount.to_string(),
            "Splits consume the entire amount"
        );
        assert_eq!(
            Error::InvalidConfig("bad".into()).to_string(),
            "Invalid configuration: bad"
        );
        assert_eq!(
            Error::ChallengeExpired("2020-01-01T00:00:00Z".into()).to_string(),
            "Challenge expired at 2020-01-01T00:00:00Z"
        );
        assert_eq!(
            Error::ChallengeMismatch.to_string(),
            "Challenge ID mismatch — not issued by this server"
        );
        assert_eq!(Error::Other("plain".into()).to_string(), "plain");
    }

    #[test]
    fn too_many_splits_display_mentions_max() {
        let msg = Error::TooManySplits.to_string();
        assert!(msg.contains("Splits exceed maximum of"), "got: {msg}");
        assert!(
            msg.contains(&crate::mpp::protocol::solana::MAX_SPLITS.to_string()),
            "got: {msg}"
        );
    }
}
