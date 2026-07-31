//! Pluggable key-value and channel state stores, shared across the pay-kit
//! crates.
//!
//! Holds replay-protection (`Store`) and payment-channel session state
//! (`ChannelStore`/`ChannelState`). Extracted from `solana-mpp` so both
//! `solana-mpp` (the `session` intent) and `solana-x402` (the
//! `batch-settlement` scheme) share one implementation. `solana-mpp` re-exports
//! this module at `mpp::store`.

use std::future::Future;
use std::pin::Pin;
#[cfg(feature = "redis-store")]
use std::time::Duration;

/// Default time to retain a finalized channel record for reconciliation,
/// debugging, and idempotent retries before Redis removes it.
#[cfg(feature = "redis-store")]
pub const DEFAULT_FINALIZED_CHANNEL_RETENTION: Duration = Duration::from_secs(7 * 24 * 60 * 60);

/// Async key-value store interface.
pub trait Store: Send + Sync {
    fn get(
        &self,
        key: &str,
    ) -> Pin<Box<dyn Future<Output = Result<Option<serde_json::Value>, StoreError>> + Send + '_>>;

    fn put(
        &self,
        key: &str,
        value: serde_json::Value,
    ) -> Pin<Box<dyn Future<Output = Result<(), StoreError>> + Send + '_>>;

    fn delete(
        &self,
        key: &str,
    ) -> Pin<Box<dyn Future<Output = Result<(), StoreError>> + Send + '_>>;

    /// Atomically insert a value only if the key does not already exist.
    /// Returns `true` if the value was inserted, `false` if the key was already present.
    fn put_if_absent(
        &self,
        key: &str,
        value: serde_json::Value,
    ) -> Pin<Box<dyn Future<Output = Result<bool, StoreError>> + Send + '_>>;
}

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("Store error: {0}")]
    Internal(String),
    #[error("Serialization error: {0}")]
    Serialization(String),
}

/// In-memory store backed by a HashMap.
pub struct MemoryStore {
    data: std::sync::Mutex<std::collections::HashMap<String, String>>,
}

impl Default for MemoryStore {
    fn default() -> Self {
        Self {
            data: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }
}

impl MemoryStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Store for MemoryStore {
    fn get(
        &self,
        key: &str,
    ) -> Pin<Box<dyn Future<Output = Result<Option<serde_json::Value>, StoreError>> + Send + '_>>
    {
        let result = self.data.lock().unwrap().get(key).cloned();
        Box::pin(async move {
            match result {
                Some(raw) => {
                    let value = serde_json::from_str(&raw)
                        .map_err(|e| StoreError::Serialization(e.to_string()))?;
                    Ok(Some(value))
                }
                None => Ok(None),
            }
        })
    }

    fn put(
        &self,
        key: &str,
        value: serde_json::Value,
    ) -> Pin<Box<dyn Future<Output = Result<(), StoreError>> + Send + '_>> {
        let key = key.to_string();
        let serialized =
            serde_json::to_string(&value).map_err(|e| StoreError::Serialization(e.to_string()));
        Box::pin(async move {
            let serialized = serialized?;
            self.data.lock().unwrap().insert(key, serialized);
            Ok(())
        })
    }

    fn delete(
        &self,
        key: &str,
    ) -> Pin<Box<dyn Future<Output = Result<(), StoreError>> + Send + '_>> {
        self.data.lock().unwrap().remove(key);
        Box::pin(async { Ok(()) })
    }

    fn put_if_absent(
        &self,
        key: &str,
        value: serde_json::Value,
    ) -> Pin<Box<dyn Future<Output = Result<bool, StoreError>> + Send + '_>> {
        let key = key.to_string();
        let serialized =
            serde_json::to_string(&value).map_err(|e| StoreError::Serialization(e.to_string()));
        Box::pin(async move {
            let serialized = serialized?;
            use std::collections::hash_map::Entry;
            let mut data = self.data.lock().unwrap();
            match data.entry(key) {
                Entry::Occupied(_) => Ok(false),
                Entry::Vacant(e) => {
                    e.insert(serialized);
                    Ok(true)
                }
            }
        })
    }
}

// ── Channel store ──

/// A delivery reserved by the server but not yet committed by the client.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PendingDelivery {
    #[serde(rename = "deliveryId")]
    pub delivery_id: String,
    pub amount: u64,
    pub sequence: u64,
    #[serde(rename = "expiresAt")]
    pub expires_at: i64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CommittedDelivery {
    #[serde(rename = "deliveryId")]
    pub delivery_id: String,
    pub amount: u64,
    pub cumulative: u64,
    #[serde(rename = "voucherSignature")]
    pub voucher_signature: String,
}

/// Durable lifecycle scheduling metadata for a payment channel.
///
/// Request-serving processes only advance this deadline. A lifecycle worker
/// reads it through [`ChannelStore::list_channels`] and owns the clock and
/// close decision.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ChannelLifecycle {
    /// Ephemeral worker namespace used by an embedded lifecycle worker.
    ///
    /// Durable reconciliation workers may process every due channel regardless
    /// of owner.
    pub owner: String,

    /// Unix timestamp in milliseconds after which the channel is idle.
    #[serde(rename = "closeAfter")]
    pub close_after: u64,
}

/// Persisted state of a payment channel, managed by the server.
///
/// # Breaking change
///
/// Lifecycle scheduling is part of the channel state contract. Consumers
/// upgrading to this API must initialize [`ChannelState::lifecycle`] in struct
/// literals, typically to `None` before the first store-backed touch.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ChannelState {
    /// On-chain channel address (base58).
    ///
    /// - Push sessions: payment-channel address.
    /// - Pull sessions: FixedDelegation PDA address.
    pub channel_id: String,

    /// Public key authorized to sign vouchers for this session (base58).
    pub authorized_signer: String,

    /// Total deposit / approved amount locked for this session (base units).
    pub deposit: u64,

    /// Highest cumulative amount accepted by the server (settled watermark).
    pub cumulative: u64,

    /// True once the channel has been sealed on-chain (phase 1 of close).
    ///
    /// Persisted records from before the upstream finalize→seal rename are
    /// NOT decoded (no `finalized` alias): the epoch-addressed migration is
    /// pre-1.0 breaking across the board, and pre-rename channels reference
    /// the old program's addressing anyway.
    pub sealed: bool,

    /// Signature of the highest accepted voucher (base64url).
    /// Stored for idempotent replay detection.
    pub highest_voucher_signature: Option<String>,

    /// Expiry timestamp from the highest accepted voucher.
    /// Needed when the server later settles that voucher on-chain.
    pub highest_voucher_expires_at: Option<i64>,

    /// Unix timestamp (seconds) when cooperative close was requested.
    /// Once set, no further vouchers are accepted.
    pub close_requested_at: Option<u64>,

    /// Slot at which the channel was opened, when known.
    ///
    /// A channel-PDA seed since the epoch-addressed program update — persisted
    /// so the PDA can be re-derived and the `reclaim` gate
    /// (`clock.slot > open_slot + 1500`) evaluated later. `None` for pull
    /// sessions (no payment-channel PDA) and for state stored before the
    /// migration.
    #[serde(default)]
    pub open_slot: Option<u64>,

    /// Pull-mode only: the client's wallet pubkey (base58).
    ///
    /// `Some` for pull sessions (SPL delegation); `None` for push sessions.
    /// Stored at open time so the batch processor can derive the MultiDelegate
    /// PDA and build `TransferFixed` instruction data at settlement.
    pub operator: Option<String>,

    /// Next server-side metered delivery sequence.
    #[serde(default)]
    pub next_delivery_sequence: u64,

    /// Deliveries reserved by the server but not yet committed by the client.
    #[serde(default)]
    pub pending_deliveries: Vec<PendingDelivery>,

    /// Recently committed deliveries, kept for idempotent commit replay.
    #[serde(default)]
    pub committed_deliveries: Vec<CommittedDelivery>,

    /// Store-backed idle-close deadline.
    ///
    /// The Serde default keeps existing persisted channel records readable.
    /// Adding this public field is an intentional pre-1.0 Rust API change.
    #[serde(default)]
    pub lifecycle: Option<ChannelLifecycle>,
}

/// Async store for channel state with compare-and-swap watermark advancement.
///
/// Implementations MUST guarantee that `advance_cumulative` is atomic to
/// prevent double-spend under concurrent requests.
///
/// This trait deliberately requires the complete lifecycle contract. Custom
/// stores must implement enumeration, touch, deletion, and finalization rather
/// than inheriting defaults that fail only when a lifecycle worker runs.
pub trait ChannelStore: Send + Sync {
    /// Return a weakly-consistent snapshot of every channel in this store's
    /// namespace.
    ///
    /// This is intended for durable reconciliation workers. Implementations
    /// may observe concurrent inserts or updates on a later scan; callers must
    /// therefore reconcile each result against the authoritative chain state.
    fn list_channels(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<ChannelState>, StoreError>> + Send + '_>>;

    fn get_channel(
        &self,
        channel_id: &str,
    ) -> Pin<Box<dyn Future<Output = Result<Option<ChannelState>, StoreError>> + Send + '_>>;

    /// Atomically create a channel.
    ///
    /// Implementations MUST reject an existing `channel_id`; overwriting a
    /// live channel could reset its accepted voucher watermark and allow the
    /// same payment to serve twice.
    fn put_channel(
        &self,
        channel_id: &str,
        state: ChannelState,
    ) -> Pin<Box<dyn Future<Output = Result<(), StoreError>> + Send + '_>>;

    /// Delete a terminal channel record.
    ///
    /// This operation is idempotent. Callers must first establish from the
    /// authoritative chain state that the channel account no longer exists;
    /// deleting a live record could discard an accepted voucher watermark.
    fn delete_channel(
        &self,
        channel_id: &str,
    ) -> Pin<Box<dyn Future<Output = Result<(), StoreError>> + Send + '_>>;

    /// Atomically read-modify-write channel state.
    ///
    /// The `updater` closure receives the current state (None if absent) and
    /// returns the new state or an error. Implementations MUST guarantee the
    /// entire modifying read-modify-write is atomic — no concurrent update can
    /// interleave. If the updater returns the state unchanged, implementations
    /// may skip the write and return the snapshot originally passed to the
    /// updater; that snapshot can be stale if another writer commits afterward.
    fn update_channel(
        &self,
        channel_id: &str,
        updater: Box<dyn FnOnce(Option<ChannelState>) -> Result<ChannelState, StoreError> + Send>,
    ) -> Pin<Box<dyn Future<Output = Result<ChannelState, StoreError>> + Send + '_>>;

    /// Persist an idle-close deadline without allowing an older touch to move
    /// an existing deadline backwards. Once close is claimed or the channel is
    /// sealed, return the current state without changing its lifecycle.
    fn touch_channel_lifecycle(
        &self,
        channel_id: &str,
        lifecycle: ChannelLifecycle,
    ) -> Pin<Box<dyn Future<Output = Result<ChannelState, StoreError>> + Send + '_>>;

    /// Atomically advance the settled watermark from `expected` to `new`.
    ///
    /// Returns `true` if the swap succeeded (expected matched), `false` if
    /// the watermark was already changed by a concurrent request.
    fn advance_cumulative(
        &self,
        channel_id: &str,
        expected: u64,
        new: u64,
    ) -> Pin<Box<dyn Future<Output = Result<bool, StoreError>> + Send + '_>>;

    /// Update the deposit cap after a top-up transaction.
    fn update_deposit(
        &self,
        channel_id: &str,
        new_deposit: u64,
    ) -> Pin<Box<dyn Future<Output = Result<(), StoreError>> + Send + '_>>;

    /// Mark a channel as sealed (phase 1 close complete).
    fn mark_sealed(
        &self,
        channel_id: &str,
    ) -> Pin<Box<dyn Future<Output = Result<(), StoreError>> + Send + '_>>;

    /// Mark a channel's lifecycle as fully finalized.
    ///
    /// Callers must not invoke this after only the phase-1 seal; all required
    /// distribution work must be complete or the channel must already be
    /// absent on-chain.
    fn mark_finalized(
        &self,
        channel_id: &str,
    ) -> Pin<Box<dyn Future<Output = Result<(), StoreError>> + Send + '_>>;
}

impl<T> ChannelStore for std::sync::Arc<T>
where
    T: ChannelStore + ?Sized,
{
    fn list_channels(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<ChannelState>, StoreError>> + Send + '_>> {
        (**self).list_channels()
    }

    fn get_channel(
        &self,
        channel_id: &str,
    ) -> Pin<Box<dyn Future<Output = Result<Option<ChannelState>, StoreError>> + Send + '_>> {
        (**self).get_channel(channel_id)
    }

    fn put_channel(
        &self,
        channel_id: &str,
        state: ChannelState,
    ) -> Pin<Box<dyn Future<Output = Result<(), StoreError>> + Send + '_>> {
        (**self).put_channel(channel_id, state)
    }

    fn delete_channel(
        &self,
        channel_id: &str,
    ) -> Pin<Box<dyn Future<Output = Result<(), StoreError>> + Send + '_>> {
        (**self).delete_channel(channel_id)
    }

    fn update_channel(
        &self,
        channel_id: &str,
        updater: Box<dyn FnOnce(Option<ChannelState>) -> Result<ChannelState, StoreError> + Send>,
    ) -> Pin<Box<dyn Future<Output = Result<ChannelState, StoreError>> + Send + '_>> {
        (**self).update_channel(channel_id, updater)
    }

    fn touch_channel_lifecycle(
        &self,
        channel_id: &str,
        lifecycle: ChannelLifecycle,
    ) -> Pin<Box<dyn Future<Output = Result<ChannelState, StoreError>> + Send + '_>> {
        (**self).touch_channel_lifecycle(channel_id, lifecycle)
    }

    fn advance_cumulative(
        &self,
        channel_id: &str,
        expected: u64,
        new: u64,
    ) -> Pin<Box<dyn Future<Output = Result<bool, StoreError>> + Send + '_>> {
        (**self).advance_cumulative(channel_id, expected, new)
    }

    fn update_deposit(
        &self,
        channel_id: &str,
        new_deposit: u64,
    ) -> Pin<Box<dyn Future<Output = Result<(), StoreError>> + Send + '_>> {
        (**self).update_deposit(channel_id, new_deposit)
    }

    fn mark_sealed(
        &self,
        channel_id: &str,
    ) -> Pin<Box<dyn Future<Output = Result<(), StoreError>> + Send + '_>> {
        (**self).mark_sealed(channel_id)
    }

    fn mark_finalized(
        &self,
        channel_id: &str,
    ) -> Pin<Box<dyn Future<Output = Result<(), StoreError>> + Send + '_>> {
        (**self).mark_finalized(channel_id)
    }
}

/// In-memory channel store backed by a Mutex.
pub struct MemoryChannelStore {
    data: std::sync::Mutex<std::collections::HashMap<String, ChannelState>>,
}

impl Default for MemoryChannelStore {
    fn default() -> Self {
        Self {
            data: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }
}

impl MemoryChannelStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl ChannelStore for MemoryChannelStore {
    fn list_channels(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<ChannelState>, StoreError>> + Send + '_>> {
        let channels = self.data.lock().unwrap().values().cloned().collect();
        Box::pin(async move { Ok(channels) })
    }

    fn get_channel(
        &self,
        channel_id: &str,
    ) -> Pin<Box<dyn Future<Output = Result<Option<ChannelState>, StoreError>> + Send + '_>> {
        let result = self.data.lock().unwrap().get(channel_id).cloned();
        Box::pin(async move { Ok(result) })
    }

    fn put_channel(
        &self,
        channel_id: &str,
        state: ChannelState,
    ) -> Pin<Box<dyn Future<Output = Result<(), StoreError>> + Send + '_>> {
        let result = match self.data.lock().unwrap().entry(channel_id.to_string()) {
            std::collections::hash_map::Entry::Vacant(entry) => {
                entry.insert(state);
                Ok(())
            }
            std::collections::hash_map::Entry::Occupied(_) => Err(StoreError::Internal(format!(
                "Channel {channel_id} already exists"
            ))),
        };
        Box::pin(async move { result })
    }

    fn delete_channel(
        &self,
        channel_id: &str,
    ) -> Pin<Box<dyn Future<Output = Result<(), StoreError>> + Send + '_>> {
        self.data.lock().unwrap().remove(channel_id);
        Box::pin(async { Ok(()) })
    }

    fn update_channel(
        &self,
        channel_id: &str,
        updater: Box<dyn FnOnce(Option<ChannelState>) -> Result<ChannelState, StoreError> + Send>,
    ) -> Pin<Box<dyn Future<Output = Result<ChannelState, StoreError>> + Send + '_>> {
        let result = {
            let mut data = self.data.lock().unwrap();
            let current = data.get(channel_id).cloned();
            let key = channel_id.to_string();
            match updater(current) {
                Ok(new_state) => {
                    data.insert(key, new_state.clone());
                    Ok(new_state)
                }
                Err(e) => Err(e),
            }
        };
        Box::pin(async move { result })
    }

    fn touch_channel_lifecycle(
        &self,
        channel_id: &str,
        lifecycle: ChannelLifecycle,
    ) -> Pin<Box<dyn Future<Output = Result<ChannelState, StoreError>> + Send + '_>> {
        let result = {
            let mut data = self.data.lock().unwrap();
            let state = data
                .get_mut(channel_id)
                .ok_or_else(|| StoreError::Internal("Channel not found".to_string()));
            state.map(|state| {
                let replace = !state.sealed
                    && state.close_requested_at.is_none()
                    && state
                        .lifecycle
                        .as_ref()
                        .is_none_or(|current| lifecycle.close_after >= current.close_after);
                if replace {
                    state.lifecycle = Some(lifecycle);
                }
                state.clone()
            })
        };
        Box::pin(async move { result })
    }

    fn advance_cumulative(
        &self,
        channel_id: &str,
        expected: u64,
        new: u64,
    ) -> Pin<Box<dyn Future<Output = Result<bool, StoreError>> + Send + '_>> {
        let mut data = self.data.lock().unwrap();
        match data.get_mut(channel_id) {
            Some(state) if state.cumulative == expected => {
                state.cumulative = new;
                Box::pin(async { Ok(true) })
            }
            Some(_) => Box::pin(async { Ok(false) }),
            None => Box::pin(async { Err(StoreError::Internal("Channel not found".to_string())) }),
        }
    }

    fn update_deposit(
        &self,
        channel_id: &str,
        new_deposit: u64,
    ) -> Pin<Box<dyn Future<Output = Result<(), StoreError>> + Send + '_>> {
        let mut data = self.data.lock().unwrap();
        match data.get_mut(channel_id) {
            Some(state) => {
                state.deposit = new_deposit;
                Box::pin(async { Ok(()) })
            }
            None => Box::pin(async { Err(StoreError::Internal("Channel not found".to_string())) }),
        }
    }

    fn mark_sealed(
        &self,
        channel_id: &str,
    ) -> Pin<Box<dyn Future<Output = Result<(), StoreError>> + Send + '_>> {
        let mut data = self.data.lock().unwrap();
        match data.get_mut(channel_id) {
            Some(state) => {
                state.sealed = true;
                Box::pin(async { Ok(()) })
            }
            None => Box::pin(async { Err(StoreError::Internal("Channel not found".to_string())) }),
        }
    }

    fn mark_finalized(
        &self,
        channel_id: &str,
    ) -> Pin<Box<dyn Future<Output = Result<(), StoreError>> + Send + '_>> {
        self.mark_sealed(channel_id)
    }
}

// ── Redis channel store ──

/// Durable Redis-backed payment-channel state.
///
/// Enabled by the `redis-store` feature. Read/modify/write operations use Lua
/// scripts so multiple gateway instances cannot silently overwrite one
/// another. No-op updates return the state read by the updater without writing,
/// and that snapshot may be stale if another writer commits after the initial
/// read. A conflicting modifying update returns an error and is safe for the
/// caller to retry. Dedicated operations use the atomic semantics required by
/// their [`ChannelStore`] contracts.
#[cfg(feature = "redis-store")]
#[derive(Clone)]
pub struct RedisChannelStore {
    connection: redis::aio::ConnectionManager,
    key_prefix: String,
    finalized_retention_seconds: u64,
}

#[cfg(feature = "redis-store")]
impl RedisChannelStore {
    /// Connect to Redis and namespace channel records under `key_prefix`.
    ///
    /// The namespace is length-prefixed to keep scans disjoint. Raw-prefix
    /// keys written by pre-release builds are intentionally not read; clear
    /// those keys once when deploying the released key format.
    pub async fn connect(
        redis_url: &str,
        key_prefix: impl Into<String>,
    ) -> Result<Self, StoreError> {
        Self::connect_with_finalized_retention(
            redis_url,
            key_prefix,
            DEFAULT_FINALIZED_CHANNEL_RETENTION,
        )
        .await
    }

    /// Connect with a caller-selected finalized-record retention window.
    ///
    /// Durations shorter than one second are rejected instead of truncating
    /// them to an immediate delete.
    pub async fn connect_with_finalized_retention(
        redis_url: &str,
        key_prefix: impl Into<String>,
        finalized_retention: Duration,
    ) -> Result<Self, StoreError> {
        let finalized_retention_seconds = finalized_retention.as_secs();
        if finalized_retention_seconds == 0 {
            return Err(StoreError::Internal(
                "Finalized channel retention must be at least one second".to_string(),
            ));
        }
        let client = redis::Client::open(redis_url)
            .map_err(|e| StoreError::Internal(format!("Redis client: {e}")))?;
        let connection = client
            .get_connection_manager()
            .await
            .map_err(|e| StoreError::Internal(format!("Redis connect: {e}")))?;
        Ok(Self {
            connection,
            key_prefix: Self::namespace_key_prefix(key_prefix.into()),
            finalized_retention_seconds,
        })
    }

    fn namespace_key_prefix(key_prefix: String) -> String {
        // Length-prefix the configured namespace so no encoded namespace can
        // be a prefix of another, even when namespaces are nested.
        format!("{}:{key_prefix}:", key_prefix.len())
    }

    fn key(&self, channel_id: &str) -> String {
        format!("{}{}", self.key_prefix, channel_id)
    }

    fn scan_pattern(&self) -> String {
        // Redis MATCH uses glob syntax. Escape metacharacters so a configured
        // namespace is always interpreted literally.
        let mut pattern = String::with_capacity(self.key_prefix.len() + 1);
        for ch in self.key_prefix.chars() {
            if matches!(ch, '*' | '?' | '[' | ']' | '\\') {
                pattern.push('\\');
            }
            pattern.push(ch);
        }
        pattern.push('*');
        pattern
    }

    async fn get_raw(&self, channel_id: &str) -> Result<Option<String>, StoreError> {
        let mut connection = self.connection.clone();
        redis::cmd("GET")
            .arg(self.key(channel_id))
            .query_async(&mut connection)
            .await
            .map_err(|e| StoreError::Internal(format!("Redis GET: {e}")))
    }

    async fn compare_and_set(
        &self,
        channel_id: &str,
        expected: Option<&str>,
        new_value: &str,
    ) -> Result<bool, StoreError> {
        // Compare the complete serialized value. This works on ordinary Redis
        // (no RedisJSON dependency) and makes the write indivisible across
        // gateway instances.
        const SCRIPT: &str = r#"
local current = redis.call('GET', KEYS[1])
if ARGV[1] == '0' then
  if current then return 0 end
elseif (not current) or current ~= ARGV[2] then
  return 0
end
if ARGV[1] == '0' then
  redis.call('SET', KEYS[1], ARGV[3])
else
  redis.call('SET', KEYS[1], ARGV[3], 'KEEPTTL')
end
return 1
"#;
        let mut connection = self.connection.clone();
        let updated: i32 = redis::Script::new(SCRIPT)
            .key(self.key(channel_id))
            .arg(if expected.is_some() { "1" } else { "0" })
            .arg(expected.unwrap_or_default())
            .arg(new_value)
            .invoke_async(&mut connection)
            .await
            .map_err(|e| StoreError::Internal(format!("Redis CAS: {e}")))?;
        Ok(updated == 1)
    }

    async fn mark_sealed_atomic(&self, channel_id: &str) -> Result<(), StoreError> {
        // Mutate only the boolean field in one Redis script. Decoding and
        // re-encoding through Lua cjson would coerce large u64 values through
        // an imprecise floating-point representation.
        const SCRIPT: &str = r#"
local current = redis.call('GET', KEYS[1])
if not current then return 0 end

local sealed_false = '"sealed":false'
local sealed_true = '"sealed":true'
if string.find(current, sealed_true, 1, true) then return 1 end

local first, last = string.find(current, sealed_false, 1, true)
if not first then return -1 end

local updated = string.sub(current, 1, first - 1)
  .. sealed_true
  .. string.sub(current, last + 1)
redis.call('SET', KEYS[1], updated, 'KEEPTTL')
return 1
"#;
        let mut connection = self.connection.clone();
        let result: i32 = redis::Script::new(SCRIPT)
            .key(self.key(channel_id))
            .invoke_async(&mut connection)
            .await
            .map_err(|e| StoreError::Internal(format!("Redis mark sealed: {e}")))?;
        match result {
            1 => Ok(()),
            0 => Err(StoreError::Internal("Channel not found".to_string())),
            _ => Err(StoreError::Serialization(
                "Channel record is missing its sealed field".to_string(),
            )),
        }
    }

    async fn mark_finalized_atomic(&self, channel_id: &str) -> Result<(), StoreError> {
        // Apply the retention in the same script that flips the lifecycle bit.
        // Repeated reconciliation of an already-finalized record only backfills
        // a missing TTL; it never refreshes an existing expiry indefinitely.
        const SCRIPT: &str = r#"
local current = redis.call('GET', KEYS[1])
if not current then return 0 end

local sealed_false = '"sealed":false'
local sealed_true = '"sealed":true'
if string.find(current, sealed_true, 1, true) then
  if redis.call('TTL', KEYS[1]) == -1 then
    redis.call('EXPIRE', KEYS[1], ARGV[1])
  end
  return 1
end

local first, last = string.find(current, sealed_false, 1, true)
if not first then return -1 end

local updated = string.sub(current, 1, first - 1)
  .. sealed_true
  .. string.sub(current, last + 1)
redis.call('SET', KEYS[1], updated, 'EX', ARGV[1])
return 1
"#;
        let mut connection = self.connection.clone();
        let result: i32 = redis::Script::new(SCRIPT)
            .key(self.key(channel_id))
            .arg(self.finalized_retention_seconds)
            .invoke_async(&mut connection)
            .await
            .map_err(|e| StoreError::Internal(format!("Redis mark finalized: {e}")))?;
        match result {
            1 => Ok(()),
            0 => Err(StoreError::Internal("Channel not found".to_string())),
            _ => Err(StoreError::Serialization(
                "Channel record is missing its sealed field".to_string(),
            )),
        }
    }

    fn decode(raw: &str) -> Result<ChannelState, StoreError> {
        serde_json::from_str(raw).map_err(|e| StoreError::Serialization(e.to_string()))
    }

    fn encode(state: &ChannelState) -> Result<String, StoreError> {
        serde_json::to_string(state).map_err(|e| StoreError::Serialization(e.to_string()))
    }
}

#[cfg(feature = "redis-store")]
impl ChannelStore for RedisChannelStore {
    fn list_channels(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<ChannelState>, StoreError>> + Send + '_>> {
        Box::pin(async move {
            let mut connection = self.connection.clone();
            let pattern = self.scan_pattern();
            let mut cursor = 0_u64;
            let mut channels = Vec::new();
            let mut seen_keys = std::collections::HashSet::new();

            loop {
                let (next_cursor, keys): (u64, Vec<String>) = redis::cmd("SCAN")
                    .arg(cursor)
                    .arg("MATCH")
                    .arg(&pattern)
                    .arg("COUNT")
                    .arg(100)
                    .query_async(&mut connection)
                    .await
                    .map_err(|e| StoreError::Internal(format!("Redis SCAN: {e}")))?;

                let keys = keys
                    .into_iter()
                    // SCAN may return the same key more than once while the
                    // keyspace changes. Never enqueue a channel twice in one
                    // reconciliation pass.
                    .filter(|key| seen_keys.insert(key.clone()))
                    .collect::<Vec<_>>();
                if !keys.is_empty() {
                    let values: Vec<Option<String>> = redis::cmd("MGET")
                        .arg(&keys)
                        .query_async(&mut connection)
                        .await
                        .map_err(|e| StoreError::Internal(format!("Redis MGET: {e}")))?;
                    channels.extend(
                        values
                            .into_iter()
                            .flatten()
                            .map(|raw| Self::decode(&raw))
                            .collect::<Result<Vec<_>, _>>()?,
                    );
                }

                cursor = next_cursor;
                if cursor == 0 {
                    break;
                }
            }

            Ok(channels)
        })
    }

    fn get_channel(
        &self,
        channel_id: &str,
    ) -> Pin<Box<dyn Future<Output = Result<Option<ChannelState>, StoreError>> + Send + '_>> {
        let channel_id = channel_id.to_string();
        Box::pin(async move {
            self.get_raw(&channel_id)
                .await?
                .as_deref()
                .map(Self::decode)
                .transpose()
        })
    }

    fn put_channel(
        &self,
        channel_id: &str,
        state: ChannelState,
    ) -> Pin<Box<dyn Future<Output = Result<(), StoreError>> + Send + '_>> {
        let channel_id = channel_id.to_string();
        Box::pin(async move {
            let encoded = Self::encode(&state)?;
            if !self.compare_and_set(&channel_id, None, &encoded).await? {
                return Err(StoreError::Internal(format!(
                    "Channel {channel_id} already exists"
                )));
            }
            Ok(())
        })
    }

    fn delete_channel(
        &self,
        channel_id: &str,
    ) -> Pin<Box<dyn Future<Output = Result<(), StoreError>> + Send + '_>> {
        let channel_id = channel_id.to_string();
        Box::pin(async move {
            let mut connection = self.connection.clone();
            redis::cmd("DEL")
                .arg(self.key(&channel_id))
                .query_async::<u64>(&mut connection)
                .await
                .map_err(|error| StoreError::Internal(format!("Redis DEL: {error}")))?;
            Ok(())
        })
    }

    fn update_channel(
        &self,
        channel_id: &str,
        updater: Box<dyn FnOnce(Option<ChannelState>) -> Result<ChannelState, StoreError> + Send>,
    ) -> Pin<Box<dyn Future<Output = Result<ChannelState, StoreError>> + Send + '_>> {
        let channel_id = channel_id.to_string();
        Box::pin(async move {
            let current_raw = self.get_raw(&channel_id).await?;
            let current = current_raw.as_deref().map(Self::decode).transpose()?;
            let new_state = updater(current)?;
            let new_raw = Self::encode(&new_state)?;
            if current_raw.as_deref() == Some(new_raw.as_str()) {
                return Ok(new_state);
            }
            if !self
                .compare_and_set(&channel_id, current_raw.as_deref(), &new_raw)
                .await?
            {
                return Err(StoreError::Internal(
                    "Concurrent channel update; retry the request".to_string(),
                ));
            }
            Ok(new_state)
        })
    }

    fn touch_channel_lifecycle(
        &self,
        channel_id: &str,
        lifecycle: ChannelLifecycle,
    ) -> Pin<Box<dyn Future<Output = Result<ChannelState, StoreError>> + Send + '_>> {
        let channel_id = channel_id.to_string();
        Box::pin(async move {
            const MAX_ATTEMPTS: usize = 8;
            for _ in 0..MAX_ATTEMPTS {
                let Some(current_raw) = self.get_raw(&channel_id).await? else {
                    return Err(StoreError::Internal("Channel not found".to_string()));
                };
                let mut state = Self::decode(&current_raw)?;
                let replace = !state.sealed
                    && state.close_requested_at.is_none()
                    && state
                        .lifecycle
                        .as_ref()
                        .is_none_or(|current| lifecycle.close_after >= current.close_after);
                if !replace {
                    return Ok(state);
                }
                state.lifecycle = Some(lifecycle.clone());
                let new_raw = Self::encode(&state)?;
                if self
                    .compare_and_set(&channel_id, Some(&current_raw), &new_raw)
                    .await?
                {
                    return Ok(state);
                }
            }
            Err(StoreError::Internal(
                "Concurrent channel lifecycle updates; retry the request".to_string(),
            ))
        })
    }

    fn advance_cumulative(
        &self,
        channel_id: &str,
        expected: u64,
        new: u64,
    ) -> Pin<Box<dyn Future<Output = Result<bool, StoreError>> + Send + '_>> {
        let channel_id = channel_id.to_string();
        Box::pin(async move {
            let Some(current_raw) = self.get_raw(&channel_id).await? else {
                return Err(StoreError::Internal("Channel not found".to_string()));
            };
            let mut state = Self::decode(&current_raw)?;
            if state.cumulative != expected {
                return Ok(false);
            }
            state.cumulative = new;
            let new_raw = Self::encode(&state)?;
            self.compare_and_set(&channel_id, Some(&current_raw), &new_raw)
                .await
        })
    }

    fn update_deposit(
        &self,
        channel_id: &str,
        new_deposit: u64,
    ) -> Pin<Box<dyn Future<Output = Result<(), StoreError>> + Send + '_>> {
        let channel_id = channel_id.to_string();
        Box::pin(async move {
            self.update_channel(
                &channel_id,
                Box::new(move |state| {
                    let mut state = state
                        .ok_or_else(|| StoreError::Internal("Channel not found".to_string()))?;
                    state.deposit = new_deposit;
                    Ok(state)
                }),
            )
            .await
            .map(|_| ())
        })
    }

    fn mark_sealed(
        &self,
        channel_id: &str,
    ) -> Pin<Box<dyn Future<Output = Result<(), StoreError>> + Send + '_>> {
        let channel_id = channel_id.to_string();
        Box::pin(async move { self.mark_sealed_atomic(&channel_id).await })
    }

    fn mark_finalized(
        &self,
        channel_id: &str,
    ) -> Pin<Box<dyn Future<Output = Result<(), StoreError>> + Send + '_>> {
        let channel_id = channel_id.to_string();
        Box::pin(async move { self.mark_finalized_atomic(&channel_id).await })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn memory_store_get_put_delete() {
        let store = MemoryStore::new();
        assert!(store.get("missing").await.unwrap().is_none());

        let value = serde_json::json!({"name": "alice"});
        store.put("user:1", value.clone()).await.unwrap();
        assert_eq!(store.get("user:1").await.unwrap(), Some(value));

        store.delete("user:1").await.unwrap();
        assert!(store.get("user:1").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn memory_store_put_if_absent_inserts_once() {
        let store = MemoryStore::new();
        let v = serde_json::json!(1);
        assert!(store.put_if_absent("k", v.clone()).await.unwrap());
        assert!(!store
            .put_if_absent("k", serde_json::json!(2))
            .await
            .unwrap());
        assert_eq!(store.get("k").await.unwrap(), Some(v));
    }

    fn make_state(channel_id: &str, deposit: u64) -> ChannelState {
        ChannelState {
            channel_id: channel_id.to_string(),
            authorized_signer: "signer1".to_string(),
            deposit,
            cumulative: 0,
            sealed: false,
            highest_voucher_signature: None,
            highest_voucher_expires_at: None,
            close_requested_at: None,
            open_slot: None,
            operator: None,
            next_delivery_sequence: 0,
            pending_deliveries: vec![],
            committed_deliveries: vec![],
            lifecycle: None,
        }
    }

    #[tokio::test]
    async fn channel_store_put_and_get() {
        let store = MemoryChannelStore::new();
        assert!(store.get_channel("c1").await.unwrap().is_none());
        store
            .put_channel("c1", make_state("c1", 1_000_000))
            .await
            .unwrap();
        let state = store.get_channel("c1").await.unwrap().unwrap();
        assert_eq!(state.deposit, 1_000_000);
        assert_eq!(state.cumulative, 0);
        assert!(!state.sealed);
        assert_eq!(store.list_channels().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn channel_store_delete_is_idempotent() {
        let store = MemoryChannelStore::new();
        store
            .put_channel("c1", make_state("c1", 1_000_000))
            .await
            .unwrap();

        store.delete_channel("c1").await.unwrap();
        assert!(store.get_channel("c1").await.unwrap().is_none());
        store.delete_channel("c1").await.unwrap();
    }

    #[tokio::test]
    async fn channel_lifecycle_touch_is_store_backed_and_monotonic() {
        let store = MemoryChannelStore::new();
        store
            .put_channel("c1", make_state("c1", 1_000_000))
            .await
            .unwrap();

        let latest = ChannelLifecycle {
            owner: "worker-b".to_string(),
            close_after: 2_000,
        };
        store
            .touch_channel_lifecycle("c1", latest.clone())
            .await
            .unwrap();
        store
            .touch_channel_lifecycle(
                "c1",
                ChannelLifecycle {
                    owner: "worker-a".to_string(),
                    close_after: 1_000,
                },
            )
            .await
            .unwrap();

        assert_eq!(
            store.get_channel("c1").await.unwrap().unwrap().lifecycle,
            Some(latest.clone())
        );

        store
            .update_channel(
                "c1",
                Box::new(|state| {
                    let mut state = state.unwrap();
                    state.close_requested_at = Some(2);
                    Ok(state)
                }),
            )
            .await
            .unwrap();
        let claimed = store
            .touch_channel_lifecycle(
                "c1",
                ChannelLifecycle {
                    owner: "worker-c".to_string(),
                    close_after: 3_000,
                },
            )
            .await
            .unwrap();
        assert_eq!(claimed.lifecycle, Some(latest));
    }

    #[tokio::test]
    async fn channel_lifecycle_touch_does_not_update_sealed_memory_channel() {
        let store = MemoryChannelStore::new();
        store
            .put_channel("c1", make_state("c1", 1_000_000))
            .await
            .unwrap();
        let original = ChannelLifecycle {
            owner: "worker-a".to_string(),
            close_after: 1_000,
        };
        store
            .touch_channel_lifecycle("c1", original.clone())
            .await
            .unwrap();
        store.mark_sealed("c1").await.unwrap();

        let touched = store
            .touch_channel_lifecycle(
                "c1",
                ChannelLifecycle {
                    owner: "worker-b".to_string(),
                    close_after: 2_000,
                },
            )
            .await
            .unwrap();

        assert!(touched.sealed);
        assert_eq!(touched.lifecycle, Some(original));
    }

    #[test]
    fn channel_state_without_lifecycle_remains_decodable() {
        let persisted = serde_json::json!({
            "channel_id": "c1",
            "authorized_signer": "signer1",
            "deposit": 1_000_000,
            "cumulative": 42,
            "sealed": false,
            "highest_voucher_signature": null,
            "highest_voucher_expires_at": null,
            "close_requested_at": null,
            "operator": null
        });

        let decoded: ChannelState = serde_json::from_value(persisted).unwrap();
        assert!(decoded.lifecycle.is_none());
    }

    #[tokio::test]
    async fn channel_store_put_rejects_existing_without_reset() {
        let store = MemoryChannelStore::new();
        store
            .put_channel("c1", make_state("c1", 1_000_000))
            .await
            .unwrap();
        assert!(store
            .put_channel("c1", make_state("c1", 2_000_000))
            .await
            .is_err());
        assert_eq!(
            store.get_channel("c1").await.unwrap().unwrap().deposit,
            1_000_000
        );
    }

    #[tokio::test]
    async fn channel_store_works_behind_arc_trait_object() {
        let store: std::sync::Arc<dyn ChannelStore> =
            std::sync::Arc::new(MemoryChannelStore::new());
        store
            .put_channel("c1", make_state("c1", 1_000_000))
            .await
            .unwrap();
        assert_eq!(
            store.get_channel("c1").await.unwrap().unwrap().deposit,
            1_000_000
        );
    }

    #[cfg(feature = "redis-store")]
    #[test]
    fn redis_channel_store_prefix_has_namespace_boundary() {
        let tenant = RedisChannelStore::namespace_key_prefix("tenant:1".to_string());
        let adjacent = RedisChannelStore::namespace_key_prefix("tenant:10".to_string());
        let nested = RedisChannelStore::namespace_key_prefix("tenant:1:child".to_string());

        assert_eq!(tenant, "8:tenant:1:");
        assert_eq!(adjacent, "9:tenant:10:");
        assert_eq!(nested, "14:tenant:1:child:");
        assert!(!adjacent.starts_with(&tenant));
        assert!(!nested.starts_with(&tenant));
    }

    #[cfg(feature = "redis-store")]
    #[tokio::test]
    async fn redis_channel_store_rejects_subsecond_finalized_retention() {
        for retention in [Duration::ZERO, Duration::from_millis(500)] {
            let result = RedisChannelStore::connect_with_finalized_retention(
                "redis://127.0.0.1/",
                "test",
                retention,
            )
            .await;
            assert!(result.is_err());
        }
    }

    #[cfg(feature = "redis-store")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn redis_channel_store_roundtrip_and_atomic_watermark() {
        let redis_url = std::env::var("PAY_KIT_TEST_REDIS_URL")
            .expect("PAY_KIT_TEST_REDIS_URL is required for the Redis integration test");
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let store = RedisChannelStore::connect(
            &redis_url,
            format!("pay-kit:test:{}:{unique}:", std::process::id()),
        )
        .await
        .unwrap();
        store
            .put_channel("c1", make_state("c1", 1_000_000))
            .await
            .unwrap();

        let (left, right) = tokio::join!(
            store.advance_cumulative("c1", 0, 100),
            store.advance_cumulative("c1", 0, 200),
        );
        let successes = [left.unwrap(), right.unwrap()]
            .into_iter()
            .filter(|updated| *updated)
            .count();
        assert_eq!(successes, 1, "exactly one concurrent CAS must win");
        assert!(matches!(
            store.get_channel("c1").await.unwrap().unwrap().cumulative,
            100 | 200
        ));

        store
            .put_channel("noop-race", make_state("noop-race", 1_000_000))
            .await
            .unwrap();
        let no_op_store = store.clone();
        let writer_store = store.clone();
        let (read_tx, read_rx) = std::sync::mpsc::channel();
        let (continue_tx, continue_rx) = std::sync::mpsc::channel();
        let no_op = tokio::spawn(async move {
            no_op_store
                .update_channel(
                    "noop-race",
                    Box::new(move |state| {
                        read_tx.send(()).unwrap();
                        tokio::task::block_in_place(|| continue_rx.recv()).unwrap();
                        Ok(state.unwrap())
                    }),
                )
                .await
        });
        tokio::task::block_in_place(|| read_rx.recv()).unwrap();
        writer_store
            .advance_cumulative("noop-race", 0, 100)
            .await
            .unwrap();
        continue_tx.send(()).unwrap();
        let stale_read = no_op
            .await
            .unwrap()
            .expect("a no-op must not fail because another writer advanced the channel");
        assert_eq!(stale_read.cumulative, 0);
        assert_eq!(
            store
                .get_channel("noop-race")
                .await
                .unwrap()
                .unwrap()
                .cumulative,
            100,
            "the no-op must not overwrite the concurrent writer"
        );

        let lifecycle = ChannelLifecycle {
            owner: "redis-worker".to_string(),
            close_after: 120_000,
        };
        store
            .touch_channel_lifecycle("c1", lifecycle.clone())
            .await
            .unwrap();
        assert_eq!(
            store.get_channel("c1").await.unwrap().unwrap().lifecycle,
            Some(lifecycle)
        );

        store
            .put_channel("seal-race", make_state("seal-race", 1_000_000))
            .await
            .unwrap();
        let sealing_store = store.clone();
        let touching_store = store.clone();
        let (sealed, touched) = tokio::join!(sealing_store.mark_sealed("seal-race"), async move {
            for close_after in 1..=32 {
                touching_store
                    .touch_channel_lifecycle(
                        "seal-race",
                        ChannelLifecycle {
                            owner: "concurrent-worker".to_string(),
                            close_after,
                        },
                    )
                    .await?;
            }
            Ok::<_, StoreError>(())
        });
        sealed.unwrap();
        touched.unwrap();
        assert!(
            store
                .get_channel("seal-race")
                .await
                .unwrap()
                .unwrap()
                .sealed
        );

        store
            .put_channel("sealed-touch", make_state("sealed-touch", 1_000_000))
            .await
            .unwrap();
        let original = ChannelLifecycle {
            owner: "redis-worker-a".to_string(),
            close_after: 1_000,
        };
        store
            .touch_channel_lifecycle("sealed-touch", original.clone())
            .await
            .unwrap();
        store.mark_sealed("sealed-touch").await.unwrap();
        let touched = store
            .touch_channel_lifecycle(
                "sealed-touch",
                ChannelLifecycle {
                    owner: "redis-worker-b".to_string(),
                    close_after: 2_000,
                },
            )
            .await
            .unwrap();
        assert!(touched.sealed);
        assert_eq!(touched.lifecycle, Some(original));
        store.delete_channel("sealed-touch").await.unwrap();

        store.update_deposit("c1", 2_000_000).await.unwrap();
        store.mark_sealed("c1").await.unwrap();
        let state = store.get_channel("c1").await.unwrap().unwrap();
        assert_eq!(state.deposit, 2_000_000);
        assert!(state.sealed);

        store
            .put_channel("finalized", make_state("finalized", 1_000_000))
            .await
            .unwrap();
        store.mark_sealed("finalized").await.unwrap();
        let mut connection = store.connection.clone();
        let ttl_before: i64 = redis::cmd("TTL")
            .arg(store.key("finalized"))
            .query_async(&mut connection)
            .await
            .unwrap();
        assert_eq!(ttl_before, -1, "phase-1 seal must not start retention");

        store.mark_finalized("finalized").await.unwrap();
        let ttl_after: i64 = redis::cmd("TTL")
            .arg(store.key("finalized"))
            .query_async(&mut connection)
            .await
            .unwrap();
        assert!(
            ttl_after > 0 && ttl_after <= DEFAULT_FINALIZED_CHANNEL_RETENTION.as_secs() as i64,
            "finalization must attach the bounded retention TTL"
        );
        store.mark_sealed("finalized").await.unwrap();
        let ttl_after_reseal: i64 = redis::cmd("TTL")
            .arg(store.key("finalized"))
            .query_async(&mut connection)
            .await
            .unwrap();
        assert!(
            ttl_after_reseal > 0 && ttl_after_reseal <= ttl_after,
            "repeated sealing must preserve, not refresh, finalized retention"
        );

        store
            .put_channel("sealed-with-ttl", make_state("sealed-with-ttl", 1_000_000))
            .await
            .unwrap();
        redis::cmd("EXPIRE")
            .arg(store.key("sealed-with-ttl"))
            .arg(120)
            .query_async::<bool>(&mut connection)
            .await
            .unwrap();
        store.mark_sealed("sealed-with-ttl").await.unwrap();
        let sealed_ttl: i64 = redis::cmd("TTL")
            .arg(store.key("sealed-with-ttl"))
            .query_async(&mut connection)
            .await
            .unwrap();
        assert!(
            sealed_ttl > 0 && sealed_ttl <= 120,
            "sealing an expiring record must preserve its existing TTL"
        );
        store.delete_channel("sealed-with-ttl").await.unwrap();

        store
            .put_channel("deleted", make_state("deleted", 1_000_000))
            .await
            .unwrap();
        store.delete_channel("deleted").await.unwrap();
        assert!(store.get_channel("deleted").await.unwrap().is_none());
        store.delete_channel("deleted").await.unwrap();

        let channels = store.list_channels().await.unwrap();
        assert_eq!(channels.len(), 4);
        assert!(channels
            .iter()
            .any(|channel| channel.channel_id.as_str() == "c1"));

        let create_one = make_state("created-once", 1_000_000);
        let create_two = make_state("created-once", 2_000_000);
        let (left, right) = tokio::join!(
            store.put_channel("created-once", create_one),
            store.put_channel("created-once", create_two),
        );
        assert_eq!(
            [left, right].into_iter().filter(Result::is_ok).count(),
            1,
            "exactly one concurrent channel creation must win"
        );
        assert!(matches!(
            store
                .get_channel("created-once")
                .await
                .unwrap()
                .unwrap()
                .deposit,
            1_000_000 | 2_000_000
        ));

        let prefix = format!("pay-kit:test:{}:{unique}:tenant", std::process::id());
        let tenant_one = RedisChannelStore::connect(&redis_url, format!("{prefix}:1"))
            .await
            .unwrap();
        let tenant_ten = RedisChannelStore::connect(&redis_url, format!("{prefix}:10"))
            .await
            .unwrap();
        tenant_one
            .put_channel("one", make_state("one", 1_000_000))
            .await
            .unwrap();
        tenant_ten
            .put_channel("ten", make_state("ten", 10_000_000))
            .await
            .unwrap();

        assert_eq!(
            tenant_one
                .list_channels()
                .await
                .unwrap()
                .into_iter()
                .map(|state| state.channel_id)
                .collect::<Vec<_>>(),
            vec!["one"]
        );
        assert_eq!(
            tenant_ten
                .list_channels()
                .await
                .unwrap()
                .into_iter()
                .map(|state| state.channel_id)
                .collect::<Vec<_>>(),
            vec!["ten"]
        );
    }

    #[tokio::test]
    async fn channel_store_advance_cumulative_success() {
        let store = MemoryChannelStore::new();
        store
            .put_channel("c1", make_state("c1", 5_000_000))
            .await
            .unwrap();
        assert!(store.advance_cumulative("c1", 0, 1_000_000).await.unwrap());
        assert_eq!(
            store.get_channel("c1").await.unwrap().unwrap().cumulative,
            1_000_000
        );
    }

    #[tokio::test]
    async fn channel_store_advance_cumulative_wrong_expected_returns_false() {
        let store = MemoryChannelStore::new();
        store
            .put_channel("c1", make_state("c1", 5_000_000))
            .await
            .unwrap();
        assert!(!store
            .advance_cumulative("c1", 999, 1_000_000)
            .await
            .unwrap());
        assert_eq!(
            store.get_channel("c1").await.unwrap().unwrap().cumulative,
            0
        );
    }

    #[tokio::test]
    async fn channel_store_advance_cumulative_missing_channel_errors() {
        let store = MemoryChannelStore::new();
        assert!(store.advance_cumulative("ghost", 0, 100).await.is_err());
    }

    #[tokio::test]
    async fn channel_store_update_deposit_and_mark_sealed() {
        let store = MemoryChannelStore::new();
        store
            .put_channel("c1", make_state("c1", 1_000_000))
            .await
            .unwrap();
        store.update_deposit("c1", 5_000_000).await.unwrap();
        assert_eq!(
            store.get_channel("c1").await.unwrap().unwrap().deposit,
            5_000_000
        );
        store.mark_sealed("c1").await.unwrap();
        assert!(store.get_channel("c1").await.unwrap().unwrap().sealed);
        store.mark_finalized("c1").await.unwrap();
        assert!(store.get_channel("c1").await.unwrap().unwrap().sealed);
        assert!(store.update_deposit("ghost", 1).await.is_err());
        assert!(store.mark_sealed("ghost").await.is_err());
    }

    // Persisted state written before the upstream finalize→seal rename is
    // intentionally NOT decoded: the epoch-addressed migration is pre-1.0
    // breaking (pre-rename channels reference the old program's addressing),
    // so a legacy `finalized` record fails loudly on its missing `sealed`
    // field instead of silently reloading a closed channel as unsealed.
    #[test]
    fn channel_state_rejects_legacy_finalized_record() {
        let legacy = serde_json::json!({
            "channel_id": "c1",
            "authorized_signer": "signer1",
            "deposit": 1_000_000,
            "cumulative": 42,
            "finalized": true,
            "highest_voucher_signature": null,
            "highest_voucher_expires_at": null,
            "close_requested_at": null,
            "operator": null,
        });
        let decoded: Result<ChannelState, _> = serde_json::from_value(legacy);
        assert!(decoded.is_err(), "legacy pre-seal records must not decode");
    }

    #[tokio::test]
    async fn channel_store_update_channel_atomic_modify_and_abort() {
        let store = MemoryChannelStore::new();
        store
            .put_channel("c1", make_state("c1", 1_000_000))
            .await
            .unwrap();

        let state = store
            .update_channel(
                "c1",
                Box::new(|s| {
                    Ok(ChannelState {
                        cumulative: 500_000,
                        ..s.unwrap()
                    })
                }),
            )
            .await
            .unwrap();
        assert_eq!(state.cumulative, 500_000);

        let result = store
            .update_channel(
                "c1",
                Box::new(|_| Err(StoreError::Internal("rejected".to_string()))),
            )
            .await;
        assert!(result.is_err());
        // State unchanged after aborted update.
        assert_eq!(
            store.get_channel("c1").await.unwrap().unwrap().cumulative,
            500_000
        );
    }
}
