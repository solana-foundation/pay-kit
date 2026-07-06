//! Shared, refresh-on-an-interval cache for a recent Solana blockhash.
//!
//! Challenge issuance (MPP `charge`, x402 `exact`/`upto`) embeds a
//! `recentBlockhash` (and, for x402, `lastValidBlockHeight`) so clients skip an
//! RPC round-trip when building their payment transaction. Fetching it inline
//! turns a single 402 into N blocking RPC calls — one per advertised currency
//! and scheme — which dominates challenge latency.
//!
//! This cache lets a single background task refresh the blockhash on an
//! interval while every challenge builder reads it cheaply. Builders fall back
//! to a direct RPC fetch only when the cache is empty or stale, so correctness
//! never depends on the refresher having run.

use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

/// Maximum age a cached entry may reach before readers ignore it and fall back
/// to a direct fetch. A Solana blockhash stays valid for ~150 slots (~60–90s);
/// the refresher is expected to run far more often (e.g. every 10s), so this
/// only trips if the refresher stalls or dies — bounding how stale an embedded
/// blockhash can get without ever serving an expired one.
const MAX_AGE: Duration = Duration::from_secs(45);

/// A recent blockhash plus the block height past which it can no longer be
/// used. Mirrors `RpcClient::get_latest_blockhash_with_commitment`.
#[derive(Clone, Debug)]
pub struct CachedBlockhash {
    pub blockhash: String,
    pub last_valid_block_height: u64,
}

/// Thread-safe handle to a single cached blockhash, cheaply cloneable (shares
/// one inner cell). Construct one, hand clones to each challenge handler via
/// `with_blockhash_cache`, and refresh it from a background task with
/// [`BlockhashCache::set`].
#[derive(Clone, Default)]
pub struct BlockhashCache {
    inner: Arc<RwLock<Option<(CachedBlockhash, Instant)>>>,
}

impl BlockhashCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Store a freshly-fetched blockhash, stamped at the current instant.
    ///
    /// Recovers from a poisoned lock (a reader/writer panicked while holding the
    /// guard) rather than silently skipping the update — otherwise a single
    /// panic would permanently disable the cache for the process lifetime,
    /// degrading every challenge to a direct RPC fetch with no diagnostics.
    pub fn set(&self, blockhash: String, last_valid_block_height: u64) {
        let mut guard = self.inner.write().unwrap_or_else(|e| e.into_inner());
        *guard = Some((
            CachedBlockhash {
                blockhash,
                last_valid_block_height,
            },
            Instant::now(),
        ));
    }

    /// Return the cached blockhash if present and younger than [`MAX_AGE`];
    /// otherwise `None`, signalling the caller to fetch directly.
    ///
    /// Recovers from a poisoned lock for the same reason as [`Self::set`]: a
    /// poisoned guard should not mask a perfectly valid cached entry.
    pub fn get(&self) -> Option<CachedBlockhash> {
        let guard = self.inner.read().unwrap_or_else(|e| e.into_inner());
        let (entry, stamped_at) = guard.as_ref()?;
        (stamped_at.elapsed() < MAX_AGE).then(|| entry.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::panic::{catch_unwind, AssertUnwindSafe};

    #[test]
    fn get_is_none_when_empty() {
        assert!(BlockhashCache::new().get().is_none());
        assert!(BlockhashCache::default().get().is_none());
    }

    #[test]
    fn set_then_get_returns_the_fresh_entry() {
        let cache = BlockhashCache::new();
        cache.set("hash-1".to_string(), 42);
        let got = cache.get().expect("a fresh entry is present");
        assert_eq!(got.blockhash, "hash-1");
        assert_eq!(got.last_valid_block_height, 42);

        // A later set replaces the entry.
        cache.set("hash-2".to_string(), 99);
        assert_eq!(cache.get().unwrap().blockhash, "hash-2");
    }

    #[test]
    fn stale_entry_is_ignored() {
        // Directly seed an entry stamped older than MAX_AGE so the age check's
        // false arm is exercised without a real 45s wait.
        let cache = BlockhashCache::new();
        {
            let mut guard = cache.inner.write().unwrap();
            *guard = Some((
                CachedBlockhash {
                    blockhash: "old".to_string(),
                    last_valid_block_height: 1,
                },
                Instant::now() - (MAX_AGE + Duration::from_secs(1)),
            ));
        }
        assert!(
            cache.get().is_none(),
            "an entry older than MAX_AGE is not served"
        );
    }

    #[test]
    fn recovers_from_a_poisoned_lock() {
        let cache = BlockhashCache::new();
        // Poison the inner lock by panicking while holding the write guard.
        let poisoner = cache.clone();
        let _ = catch_unwind(AssertUnwindSafe(|| {
            let _guard = poisoner.inner.write().unwrap();
            panic!("poison the lock");
        }));
        // Both set() and get() must recover the poisoned guard rather than panic.
        cache.set("after-poison".to_string(), 7);
        assert_eq!(cache.get().expect("recovered").blockhash, "after-poison");
    }
}
