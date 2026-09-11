//! Shared RPC send and read-back policies.
//!
//! Most payment transactions should use the node's default preflight. A few
//! server-side flows already have stronger local/on-chain validation and can
//! hit false-negative preflight simulations when the RPC bank lags a confirmed
//! dependency. Those flows broadcast directly and rely on the existing
//! confirmation/reconciliation path for the durable result.
//!
//! [`ChannelReadPolicy`] covers the opposite direction: reading an account back
//! immediately after its transaction confirmed, where the replica serving the
//! read can briefly lag the one that served the status.

use std::time::Duration;

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

/// Attempts and backoff for re-reading an account right after the transaction
/// that wrote it confirmed.
///
/// RPC providers can serve transaction status and account state from different
/// replicas, so an account a confirmed transaction just wrote can still be
/// missing from the very next read. The backoff is linear (`backoff_step *
/// attempt`) rather than exponential: replica lag is a small multiple of
/// Solana's ~400ms slot time, so doubling spends the budget on single waits far
/// longer than the lag being absorbed. The defaults wait 200/400/600/800/1000ms
/// between six reads - 3.0s of total budget, 1s of longest single wait.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ChannelReadPolicy {
    pub(crate) max_attempts: u32,
    pub(crate) backoff_step: Duration,
}

/// Reads a post-broadcast account fetch makes before treating it as absent.
const CHANNEL_READ_MAX_ATTEMPTS: u32 = 6;

/// Linear step: the wait before attempt `n + 1` is `step * n`.
const CHANNEL_READ_BACKOFF_STEP: Duration = Duration::from_millis(200);

impl Default for ChannelReadPolicy {
    fn default() -> Self {
        Self {
            max_attempts: CHANNEL_READ_MAX_ATTEMPTS,
            backoff_step: CHANNEL_READ_BACKOFF_STEP,
        }
    }
}

impl ChannelReadPolicy {
    /// Resolve operator configuration. Unset or non-positive means "default",
    /// so a caller that always passes a value can pass zero.
    pub(crate) fn from_config(max_attempts: Option<u32>, backoff_step_ms: Option<u64>) -> Self {
        let default = Self::default();
        Self {
            max_attempts: max_attempts
                .filter(|attempts| *attempts > 0)
                .unwrap_or(default.max_attempts),
            backoff_step: backoff_step_ms
                .filter(|step| *step > 0)
                .map(Duration::from_millis)
                .unwrap_or(default.backoff_step),
        }
    }

    /// Wait owed after the 1-based `attempt`, or `None` when that attempt was
    /// the last one - the final read is never followed by a sleep.
    fn backoff_after(self, attempt: u32) -> Option<Duration> {
        (attempt < self.max_attempts).then(|| self.backoff_step * attempt)
    }
}

/// Re-read with the blocking RPC client until the account becomes visible.
///
/// `Ok(None)` is the only retryable answer, and whether a confirmed absence is
/// an error stays with the caller: some call sites use the same read as a
/// pre-broadcast existence probe, where absence is the expected result. An
/// `Err` is never retried - it means the read itself failed, or the caller
/// observed a state that is visible and wrong.
///
/// Sleeps the calling thread, so call this from inside an existing
/// `spawn_blocking` rather than spawning one per attempt.
pub(crate) fn read_back_blocking<T, E>(
    policy: ChannelReadPolicy,
    mut read: impl FnMut() -> Result<Option<T>, E>,
) -> Result<Option<T>, E> {
    for attempt in 1..=policy.max_attempts {
        if let Some(value) = read()? {
            return Ok(Some(value));
        }
        match policy.backoff_after(attempt) {
            Some(wait) => std::thread::sleep(wait),
            None => break,
        }
    }
    Ok(None)
}

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
    #[test]
    fn channel_read_defaults_are_six_reads_of_linear_backoff() {
        let policy = ChannelReadPolicy::default();

        assert_eq!(policy.max_attempts, 6);
        assert_eq!(policy.backoff_step, Duration::from_millis(200));
        // Linear, and no sleep after the final read: 200+400+600+800+1000ms.
        let schedule: Vec<_> = (1..=policy.max_attempts)
            .map(|attempt| policy.backoff_after(attempt))
            .collect();
        assert_eq!(
            schedule,
            vec![
                Some(Duration::from_millis(200)),
                Some(Duration::from_millis(400)),
                Some(Duration::from_millis(600)),
                Some(Duration::from_millis(800)),
                Some(Duration::from_millis(1000)),
                None,
            ]
        );
        let total: Duration = schedule.into_iter().flatten().sum();
        assert_eq!(total, Duration::from_millis(3000));
    }

    #[test]
    fn channel_read_config_treats_unset_and_zero_as_default() {
        let default = ChannelReadPolicy::default();
        for policy in [
            ChannelReadPolicy::from_config(None, None),
            ChannelReadPolicy::from_config(Some(0), Some(0)),
        ] {
            assert_eq!(policy.max_attempts, default.max_attempts);
            assert_eq!(policy.backoff_step, default.backoff_step);
        }

        let tuned = ChannelReadPolicy::from_config(Some(3), Some(50));
        assert_eq!(tuned.max_attempts, 3);
        assert_eq!(tuned.backoff_step, Duration::from_millis(50));
    }

    #[test]
    fn read_back_blocking_retries_absence_and_stops_at_the_first_hit() {
        let policy = ChannelReadPolicy {
            max_attempts: 6,
            backoff_step: Duration::from_millis(1),
        };
        let mut reads = 0;
        let found: Result<Option<u8>, ()> = read_back_blocking(policy, || {
            reads += 1;
            Ok((reads == 3).then_some(7))
        });

        assert_eq!(found, Ok(Some(7)));
        assert_eq!(reads, 3);
    }

    #[test]
    fn read_back_blocking_gives_up_after_max_attempts() {
        let policy = ChannelReadPolicy {
            max_attempts: 4,
            backoff_step: Duration::from_millis(1),
        };
        let mut reads = 0;
        let found: Result<Option<u8>, ()> = read_back_blocking(policy, || {
            reads += 1;
            Ok(None)
        });

        assert_eq!(found, Ok(None));
        assert_eq!(reads, 4);
    }

    #[test]
    fn read_back_blocking_never_retries_an_error() {
        let policy = ChannelReadPolicy {
            max_attempts: 6,
            backoff_step: Duration::from_millis(1),
        };
        let mut reads = 0;
        let found: Result<Option<u8>, &str> = read_back_blocking(policy, || {
            reads += 1;
            Err("visible and wrong")
        });

        assert_eq!(found, Err("visible and wrong"));
        assert_eq!(reads, 1);
    }
}
