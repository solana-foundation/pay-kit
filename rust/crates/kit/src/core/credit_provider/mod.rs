//! Merchant-facing credit-provider policy, independent of payment protocols.
//!
//! Named providers are not raw payment-channel hook configurations. Selecting a
//! name never authorizes an arbitrary program or supplies issuer credentials.

use serde::{Deserialize, Serialize};

pub mod musebook;

/// A recognized credit provider a merchant wants to accept alongside currency.
///
/// Recognition is not availability: validate the policy before starting payment
/// handlers. Coinflow has no registered issuer integration yet. Musebook is
/// available only where [`musebook::deployment`] pins a reviewed deployment
/// (devnet today).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CreditProvider {
    /// Reserved for the future reviewed Coinflow issuer integration.
    Coinflow,
    /// Musebook token-backed API credits via V2 channel hooks ([`musebook`]).
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
/// Empty policy preserves stablecoin-only behavior. Currently Coinflow is
/// unavailable on every network, for every currency and payment intent: its
/// issuer program, instruction ABI and authorization rules have not been
/// integrated. Never silently discard an explicitly selected provider.
///
/// This protocol-neutral check is shared by application startup and payment
/// handlers. Network/currency/intent-specific capabilities must be checked when
/// a reviewed integration is added; none are implied by recognizing a name.
///
/// Without a network this fails closed for every provider; use
/// [`validate_credit_providers_for_network`] where the network is known.
pub fn validate_credit_providers(providers: &[CreditProvider]) -> Result<(), CreditProviderError> {
    providers.iter().try_for_each(|provider| {
        Err(CreditProviderError::Unavailable {
            provider: *provider,
        })
    })
}

/// Network-aware policy check used by [`crate::PayKit::new`]. Musebook passes
/// only on a network with a pinned deployment (devnet); Coinflow never passes.
pub fn validate_credit_providers_for_network(
    providers: &[CreditProvider],
    network: &str,
) -> Result<(), CreditProviderError> {
    providers.iter().try_for_each(|provider| match provider {
        CreditProvider::Musebook if musebook::deployment(network).is_some() => Ok(()),
        CreditProvider::Coinflow | CreditProvider::Musebook => {
            Err(CreditProviderError::Unavailable {
                provider: *provider,
            })
        }
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
        assert_eq!(CreditProvider::Musebook.to_string(), "musebook");
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
    fn musebook_is_available_only_on_devnet() {
        let m = [CreditProvider::Musebook];
        assert_eq!(validate_credit_providers_for_network(&m, "devnet"), Ok(()));
        assert_eq!(
            validate_credit_providers_for_network(&m, "solana:devnet"),
            Ok(())
        );
        for network in ["mainnet", "localnet", "testnet", ""] {
            assert_eq!(
                validate_credit_providers_for_network(&m, network),
                Err(CreditProviderError::Unavailable {
                    provider: CreditProvider::Musebook
                }),
                "{network}"
            );
        }
        // Network-less check stays fail-closed.
        assert!(validate_credit_providers(&m).is_err());
        // One unavailable provider fails the whole policy.
        assert!(validate_credit_providers_for_network(
            &[CreditProvider::Musebook, CreditProvider::Coinflow],
            "devnet"
        )
        .is_err());
        assert!(
            validate_credit_providers_for_network(&[CreditProvider::Coinflow], "devnet").is_err()
        );
    }
}
