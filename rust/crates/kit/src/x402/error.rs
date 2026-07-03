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

    #[error("Payment transaction is older than the allowed max_age: {0}")]
    StaleTransaction(String),

    #[error("Signature-mode payments require a route-bound memo/nonce: {0}")]
    MissingSignatureBinding(String),

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

impl From<crate::core::Error> for Error {
    fn from(err: crate::core::Error) -> Self {
        match err {
            crate::core::Error::Serialization(msg) => Error::Other(msg),
            crate::core::Error::Other(msg) => Error::Other(msg),
        }
    }
}

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
            Error::WrongNetwork {
                expected: "solana:mainnet".to_string(),
                received: "solana:devnet".to_string(),
            }
            .to_string(),
            "Signed against solana:devnet but the server expects solana:mainnet. \
             Switch your client RPC to solana:mainnet and re-sign."
        );
        assert_eq!(
            Error::TransactionNotFound.to_string(),
            "Transaction not found or not yet confirmed"
        );
        assert_eq!(
            Error::MissingPaymentHeader.to_string(),
            "Payment header missing from 402 response"
        );
    }
}
