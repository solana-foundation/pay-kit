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
    fn from_core_errors_preserves_the_message() {
        for (core_error, expected) in [
            (
                crate::core::Error::Serialization("bad borsh".into()),
                "bad borsh",
            ),
            (crate::core::Error::Other("unexpected".into()), "unexpected"),
        ] {
            assert_eq!(Error::from(core_error).to_string(), expected);
        }
    }

    #[test]
    fn display_messages_cover_all_error_variants() {
        let cases = [
            (Error::Rpc("down".into()), "RPC error: down"),
            (
                Error::TransactionNotFound,
                "Transaction not found or not yet confirmed",
            ),
            (
                Error::TransactionFailed("reverted".into()),
                "Transaction failed on-chain: reverted",
            ),
            (
                Error::NoTransferInstruction,
                "No matching transfer instruction found",
            ),
            (
                Error::AmountMismatch {
                    expected: "10".into(),
                    actual: "9".into(),
                },
                "Amount mismatch: expected 10, got 9",
            ),
            (
                Error::RecipientMismatch {
                    expected: "alice".into(),
                    actual: "mallory".into(),
                },
                "Recipient mismatch: expected alice, got mallory",
            ),
            (
                Error::MintMismatch {
                    expected: "USDC".into(),
                    actual: "USDT".into(),
                },
                "Token mint mismatch: expected USDC, got USDT",
            ),
            (
                Error::AtaMismatch,
                "Destination ATA does not belong to expected recipient",
            ),
            (
                Error::SignatureConsumed,
                "Transaction signature already consumed",
            ),
            (
                Error::SimulationFailed("compute budget".into()),
                "Simulation failed: compute budget",
            ),
            (
                Error::MissingTransaction,
                "Missing transaction data in payment payload",
            ),
            (
                Error::MissingSignature,
                "Missing signature in payment payload",
            ),
            (
                Error::InvalidPayloadType("voucher".into()),
                "Invalid payload type: voucher",
            ),
            (Error::Http("503".into()), "HTTP error: 503"),
            (
                Error::InvalidPaymentRequired("missing accepts".into()),
                "Invalid 402 response: missing accepts",
            ),
            (
                Error::MissingPaymentHeader,
                "Payment header missing from 402 response",
            ),
            (Error::Other("plain".into()), "plain"),
        ];

        for (error, expected) in cases {
            assert_eq!(error.to_string(), expected);
        }

        assert_eq!(
            Error::WrongNetwork {
                expected: "solana-devnet".into(),
                received: "solana-mainnet".into(),
            }
            .to_string(),
            "Signed against solana-mainnet but the server expects solana-devnet. Switch your client RPC to solana-devnet and re-sign."
        );
    }
}
