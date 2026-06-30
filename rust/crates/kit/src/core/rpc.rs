//! Shared RPC send policies.
//!
//! Most payment transactions should use the node's default preflight. A few
//! server-side flows already have stronger local/on-chain validation and can
//! hit false-negative preflight simulations when the RPC bank lags a confirmed
//! dependency. Those flows broadcast directly and rely on the existing
//! confirmation/reconciliation path for the durable result.

use solana_client::rpc_config::RpcSendTransactionConfig;

#[derive(Debug, Clone, Copy)]
pub(crate) struct RpcSendPolicy {
    pub(crate) name: &'static str,
    pub(crate) skip_preflight: bool,
}

impl RpcSendPolicy {
    pub(crate) fn config(self) -> RpcSendTransactionConfig {
        RpcSendTransactionConfig {
            skip_preflight: self.skip_preflight,
            ..RpcSendTransactionConfig::default()
        }
    }
}

pub(crate) const SKIP_PREFLIGHT_SEND: RpcSendPolicy = RpcSendPolicy {
    name: "skip_preflight",
    skip_preflight: true,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn skip_preflight_send_policy_only_skips_preflight() {
        let policy = SKIP_PREFLIGHT_SEND;
        let config = policy.config();

        assert_eq!(policy.name, "skip_preflight");
        assert!(policy.skip_preflight);
        assert!(config.skip_preflight);
        assert_eq!(config.preflight_commitment, None);
        assert_eq!(config.encoding, None);
        assert_eq!(config.max_retries, None);
        assert_eq!(config.min_context_slot, None);
    }
}
