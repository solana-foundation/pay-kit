//! Pluggable key-value store for replay protection and channel state.
//!
//! Modeled after the mpp-rs Store interface.

use std::future::Future;
use std::pin::Pin;

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

/// Persisted state of a payment channel, managed by the server.
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

    /// True once the channel has been finalized on-chain.
    pub finalized: bool,

    /// Signature of the highest accepted voucher (base64url).
    /// Stored for idempotent replay detection.
    pub highest_voucher_signature: Option<String>,

    /// Expiry timestamp from the highest accepted voucher.
    /// Needed when the server later settles that voucher on-chain.
    pub highest_voucher_expires_at: Option<i64>,

    /// Unix timestamp (seconds) when cooperative close was requested.
    /// Once set, no further vouchers are accepted.
    pub close_requested_at: Option<u64>,

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
}

/// Async store for channel state with compare-and-swap watermark advancement.
///
/// Implementations MUST guarantee that `advance_cumulative` is atomic to
/// prevent double-spend under concurrent requests.
pub trait ChannelStore: Send + Sync {
    fn get_channel(
        &self,
        channel_id: &str,
    ) -> Pin<Box<dyn Future<Output = Result<Option<ChannelState>, StoreError>> + Send + '_>>;

    fn put_channel(
        &self,
        channel_id: &str,
        state: ChannelState,
    ) -> Pin<Box<dyn Future<Output = Result<(), StoreError>> + Send + '_>>;

    /// Atomically read-modify-write channel state.
    ///
    /// The `updater` closure receives the current state (None if absent) and
    /// returns the new state or an error. Implementations MUST guarantee the
    /// entire read-modify-write is atomic — no concurrent update can interleave.
    fn update_channel(
        &self,
        channel_id: &str,
        updater: Box<dyn FnOnce(Option<ChannelState>) -> Result<ChannelState, StoreError> + Send>,
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

    /// Mark a channel as finalized (phase 1 close complete).
    fn mark_finalized(
        &self,
        channel_id: &str,
    ) -> Pin<Box<dyn Future<Output = Result<(), StoreError>> + Send + '_>>;
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
        self.data
            .lock()
            .unwrap()
            .insert(channel_id.to_string(), state);
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

    fn mark_finalized(
        &self,
        channel_id: &str,
    ) -> Pin<Box<dyn Future<Output = Result<(), StoreError>> + Send + '_>> {
        let mut data = self.data.lock().unwrap();
        match data.get_mut(channel_id) {
            Some(state) => {
                state.finalized = true;
                Box::pin(async { Ok(()) })
            }
            None => Box::pin(async { Err(StoreError::Internal("Channel not found".to_string())) }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── MemoryStore ───────────────────────────────────────────────────────────

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
        // Original value unchanged
        assert_eq!(store.get("k").await.unwrap(), Some(v));
    }

    // ── MemoryChannelStore ────────────────────────────────────────────────────

    fn make_state(channel_id: &str, deposit: u64) -> ChannelState {
        ChannelState {
            channel_id: channel_id.to_string(),
            authorized_signer: "signer1".to_string(),
            deposit,
            cumulative: 0,
            finalized: false,
            highest_voucher_signature: None,
            highest_voucher_expires_at: None,
            close_requested_at: None,
            operator: None,
            next_delivery_sequence: 0,
            pending_deliveries: vec![],
            committed_deliveries: vec![],
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
        assert!(!state.finalized);
    }

    #[tokio::test]
    async fn channel_store_advance_cumulative_success() {
        let store = MemoryChannelStore::new();
        store
            .put_channel("c1", make_state("c1", 5_000_000))
            .await
            .unwrap();

        let advanced = store.advance_cumulative("c1", 0, 1_000_000).await.unwrap();
        assert!(advanced);

        let state = store.get_channel("c1").await.unwrap().unwrap();
        assert_eq!(state.cumulative, 1_000_000);
    }

    #[tokio::test]
    async fn channel_store_advance_cumulative_wrong_expected_returns_false() {
        let store = MemoryChannelStore::new();
        store
            .put_channel("c1", make_state("c1", 5_000_000))
            .await
            .unwrap();

        // Wrong expected value — simulates a lost race
        let advanced = store
            .advance_cumulative("c1", 999, 1_000_000)
            .await
            .unwrap();
        assert!(!advanced);

        // Watermark unchanged
        let state = store.get_channel("c1").await.unwrap().unwrap();
        assert_eq!(state.cumulative, 0);
    }

    #[tokio::test]
    async fn channel_store_advance_cumulative_missing_channel_errors() {
        let store = MemoryChannelStore::new();
        assert!(store.advance_cumulative("ghost", 0, 100).await.is_err());
    }

    #[tokio::test]
    async fn channel_store_update_deposit_success() {
        let store = MemoryChannelStore::new();
        store
            .put_channel("c1", make_state("c1", 1_000_000))
            .await
            .unwrap();

        store.update_deposit("c1", 5_000_000).await.unwrap();
        let state = store.get_channel("c1").await.unwrap().unwrap();
        assert_eq!(state.deposit, 5_000_000);
    }

    #[tokio::test]
    async fn channel_store_update_deposit_missing_channel_errors() {
        let store = MemoryChannelStore::new();
        assert!(store.update_deposit("ghost", 5_000_000).await.is_err());
    }

    #[tokio::test]
    async fn channel_store_mark_finalized_success() {
        let store = MemoryChannelStore::new();
        store
            .put_channel("c1", make_state("c1", 1_000_000))
            .await
            .unwrap();

        store.mark_finalized("c1").await.unwrap();
        let state = store.get_channel("c1").await.unwrap().unwrap();
        assert!(state.finalized);
    }

    #[tokio::test]
    async fn channel_store_mark_finalized_missing_channel_errors() {
        let store = MemoryChannelStore::new();
        assert!(store.mark_finalized("ghost").await.is_err());
    }

    #[tokio::test]
    async fn channel_store_put_overwrites_existing() {
        let store = MemoryChannelStore::new();
        store
            .put_channel("c1", make_state("c1", 1_000_000))
            .await
            .unwrap();
        let mut updated = make_state("c1", 5_000_000);
        updated.cumulative = 999;
        store.put_channel("c1", updated).await.unwrap();

        let state = store.get_channel("c1").await.unwrap().unwrap();
        assert_eq!(state.deposit, 5_000_000);
        assert_eq!(state.cumulative, 999);
    }

    // ── update_channel ────────────────────────────────────────────────────────

    #[tokio::test]
    async fn channel_store_update_channel_inserts_new() {
        let store = MemoryChannelStore::new();
        let state = store
            .update_channel(
                "c1",
                Box::new(|state_opt| {
                    assert!(state_opt.is_none());
                    Ok(ChannelState {
                        channel_id: "c1".to_string(),
                        authorized_signer: "signer1".to_string(),
                        deposit: 1_000_000,
                        cumulative: 0,
                        finalized: false,
                        highest_voucher_signature: None,
                        highest_voucher_expires_at: None,
                        close_requested_at: None,
                        operator: None,
                        next_delivery_sequence: 0,
                        pending_deliveries: vec![],
                        committed_deliveries: vec![],
                    })
                }),
            )
            .await
            .unwrap();
        assert_eq!(state.deposit, 1_000_000);
        let stored = store.get_channel("c1").await.unwrap().unwrap();
        assert_eq!(stored.deposit, 1_000_000);
    }

    #[tokio::test]
    async fn channel_store_update_channel_modifies_existing() {
        let store = MemoryChannelStore::new();
        store
            .put_channel("c1", make_state("c1", 1_000_000))
            .await
            .unwrap();

        let state = store
            .update_channel(
                "c1",
                Box::new(|state_opt| {
                    let s = state_opt.unwrap();
                    Ok(ChannelState {
                        cumulative: 500_000,
                        ..s
                    })
                }),
            )
            .await
            .unwrap();
        assert_eq!(state.cumulative, 500_000);
        let stored = store.get_channel("c1").await.unwrap().unwrap();
        assert_eq!(stored.cumulative, 500_000);
    }

    #[tokio::test]
    async fn channel_store_update_channel_error_aborts() {
        let store = MemoryChannelStore::new();
        store
            .put_channel("c1", make_state("c1", 1_000_000))
            .await
            .unwrap();

        let result = store
            .update_channel(
                "c1",
                Box::new(|_state_opt| Err(StoreError::Internal("rejected".to_string()))),
            )
            .await;
        assert!(result.is_err());
        // State unchanged
        let stored = store.get_channel("c1").await.unwrap().unwrap();
        assert_eq!(stored.deposit, 1_000_000);
        assert_eq!(stored.cumulative, 0);
    }

    #[tokio::test]
    async fn channel_store_update_channel_atomicity() {
        let store = MemoryChannelStore::new();
        store
            .put_channel("c1", make_state("c1", 1_000_000))
            .await
            .unwrap();

        // First update
        store
            .update_channel(
                "c1",
                Box::new(|state_opt| {
                    let s = state_opt.unwrap();
                    Ok(ChannelState {
                        cumulative: 100_000,
                        ..s
                    })
                }),
            )
            .await
            .unwrap();

        // Second update sees first update's result
        let state = store
            .update_channel(
                "c1",
                Box::new(|state_opt| {
                    let s = state_opt.unwrap();
                    assert_eq!(s.cumulative, 100_000);
                    Ok(ChannelState {
                        cumulative: 200_000,
                        ..s
                    })
                }),
            )
            .await
            .unwrap();
        assert_eq!(state.cumulative, 200_000);
    }
}
