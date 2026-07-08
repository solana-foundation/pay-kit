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

use solana_commitment_config::CommitmentConfig;
use solana_rpc_client::rpc_client::RpcClient;
use solana_rpc_client_api::config::RpcContextConfig;
use solana_rpc_client_api::request::RpcRequest;
use solana_rpc_client_api::response::{Response, RpcBlockhash};

/// Maximum age a cached entry may reach before readers ignore it and fall back
/// to a direct fetch. A Solana blockhash stays valid for ~150 slots (~60–90s);
/// the refresher is expected to run far more often (e.g. every 10s), so this
/// only trips if the refresher stalls or dies — bounding how stale an embedded
/// blockhash can get without ever serving an expired one.
const MAX_AGE: Duration = Duration::from_secs(45);

/// A recent blockhash plus the block height past which it can no longer be
/// used. Mirrors `RpcClient::get_latest_blockhash_with_commitment`, plus the
/// slot observed at the same refresh so challenges can embed the `recentSlot`
/// hint (the program's channel `openSlot`) without another RPC round-trip.
#[derive(Clone, Debug)]
pub struct CachedBlockhash {
    pub blockhash: String,
    pub last_valid_block_height: u64,
    /// Current slot observed when the entry was refreshed. Embedded as the
    /// `recentSlot` challenge hint — the payment-channels program accepts
    /// opens up to 1500 slots (~10 min) past it, far beyond [`MAX_AGE`].
    pub slot: u64,
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
    pub fn set(&self, blockhash: String, last_valid_block_height: u64, slot: u64) {
        let mut guard = self.inner.write().unwrap_or_else(|e| e.into_inner());
        *guard = Some((
            CachedBlockhash {
                blockhash,
                last_valid_block_height,
                slot,
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

/// Fetch the latest blockhash **and the slot it was observed at** in one RPC
/// call: `getLatestBlockhash`'s response context carries the current slot, so
/// challenge builders get `recentBlockhash` + `lastValidBlockHeight` +
/// `recentSlot` without a separate `getSlot` round-trip.
///
/// Blocking — call sites are the (already blocking) challenge builders and
/// cache refreshers.
pub fn fetch_blockhash_with_slot(
    rpc: &RpcClient,
    commitment: CommitmentConfig,
) -> Result<CachedBlockhash, String> {
    let response: Response<RpcBlockhash> = rpc
        .send(
            RpcRequest::GetLatestBlockhash,
            serde_json::json!([RpcContextConfig {
                commitment: Some(commitment),
                min_context_slot: None,
            }]),
        )
        .map_err(|e| e.to_string())?;
    Ok(CachedBlockhash {
        blockhash: response.value.blockhash,
        last_valid_block_height: response.value.last_valid_block_height,
        slot: response.context.slot,
    })
}
