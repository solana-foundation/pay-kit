//! Merchant-facing credit-provider policy, independent of payment protocols.
//!
//! Named providers are not raw payment-channel hook configurations. Selecting a
//! name never authorizes an arbitrary program or supplies issuer credentials.

use serde::{Deserialize, Serialize};

/// A recognized credit provider a merchant wants to accept alongside currency.
///
/// Recognition is not availability: validate the policy before starting payment
/// handlers. Coinflow and Musebook have no registered issuer integration yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CreditProvider {
    /// Reserved for the future reviewed Coinflow issuer integration.
    Coinflow,
    /// Reserved for the future reviewed Musebook issuer integration.
    Musebook,
}

impl std::fmt::Display for CreditProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Coinflow => f.write_str("coinflow"),
            Self::Musebook => f.write_str("musebook"),
        }
    }
}

/// A selected provider cannot safely be offered by this SDK.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CreditProviderError {
    /// No reviewed issuer integration is registered for this provider.
    #[error(
        "credit provider {provider} is unavailable: no reviewed issuer integration is registered"
    )]
    Unavailable {
        /// The provider explicitly selected by the merchant.
        provider: CreditProvider,
    },
}

/// Validate merchant credit-provider policy before starting payment handlers.
///
/// Empty policy preserves stablecoin-only behavior. Currently Coinflow and
/// Musebook are unavailable on every network, for every currency and payment
/// intent: their issuer programs, instruction ABIs and authorization rules
/// have not been integrated. Never silently discard an explicitly selected
/// provider.
///
/// This protocol-neutral check is shared by application startup and payment
/// handlers. Network/currency/intent-specific capabilities must be checked when
/// a reviewed integration is added; none are implied by recognizing a name.
pub fn validate_credit_providers(providers: &[CreditProvider]) -> Result<(), CreditProviderError> {
    providers.iter().try_for_each(|provider| match provider {
        CreditProvider::Coinflow => Err(CreditProviderError::Unavailable {
            provider: *provider,
        }),
        CreditProvider::Musebook => Err(CreditProviderError::Unavailable {
            provider: *provider,
        }),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credit_provider_serde_uses_reviewed_lowercase_names() {
        assert_eq!(
            serde_json::to_string(&CreditProvider::Coinflow).unwrap(),
            "\"coinflow\""
        );
        assert_eq!(
            serde_json::from_str::<CreditProvider>("\"coinflow\"").unwrap(),
            CreditProvider::Coinflow
        );
        assert_eq!(
            serde_json::to_string(&CreditProvider::Musebook).unwrap(),
            "\"musebook\""
        );
        assert_eq!(
            serde_json::from_str::<CreditProvider>("\"musebook\"").unwrap(),
            CreditProvider::Musebook
        );
        for name in [
            "\"Coinflow\"",
            "\"Musebook\"",
            "\"unknown\"",
            "\"\"",
            "null",
        ] {
            assert!(serde_json::from_str::<CreditProvider>(name).is_err());
        }
    }

    #[test]
    fn credit_provider_policy_preserves_empty_default() {
        assert_eq!(validate_credit_providers(&[]), Ok(()));
    }

    #[test]
    fn credit_provider_policy_fails_closed_for_coinflow() {
        let error = CreditProviderError::Unavailable {
            provider: CreditProvider::Coinflow,
        };
        assert_eq!(
            validate_credit_providers(&[CreditProvider::Coinflow]),
            Err(error.clone())
        );
        assert_eq!(
            validate_credit_providers(&[CreditProvider::Coinflow; 2]),
            Err(error)
        );
    }

    #[test]
    fn credit_provider_policy_fails_closed_for_musebook() {
        let error = CreditProviderError::Unavailable {
            provider: CreditProvider::Musebook,
        };
        assert_eq!(
            validate_credit_providers(&[CreditProvider::Musebook]),
            Err(error.clone())
        );
        assert_eq!(
            validate_credit_providers(&[CreditProvider::Musebook; 2]),
            Err(error)
        );
    }
}
