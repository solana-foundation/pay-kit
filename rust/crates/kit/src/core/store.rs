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
use std::sync::Arc;
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

// ── Charge replay / idempotency store ──
//
// PayKit's original charge replay guard
// (`solana-charge:consumed:<signature>`, see
// `mpp::server::charge::Mpp::consume_signature`) is replay-safe — the same
// final signature can never be reserved twice — but produces the wrong
// error for a retry: Ed25519 signing is deterministic, so replaying an
// already-signed credential recomputes the same final signature and hits
// `consume_signature`'s generic internal error instead of the canonical
// `signature_consumed` reject every SDK is supposed to emit for a resettled
// credential. `ChargeReplayStore` adds a second, challenge-scoped record
// that a retried presentation of the SAME credential can look up and
// reject against directly, without attempting to resettle.

/// Default time a charge-settlement record is retained for idempotent
/// replay once it reaches a terminal (`Confirmed`/`Failed`) state. Chosen to
/// exceed Solana's transaction-history retention and typical client resume
/// windows; a Redis-backed [`Store`] should set this as the key's TTL.
pub const DEFAULT_CHARGE_RECORD_RETENTION: Duration = Duration::from_secs(24 * 60 * 60);

/// How long a charge record may sit in [`ChargeRecordState::Reserved`]
/// before a fresh presentation of the same challenge id + digest is allowed
/// to reclaim it.
///
/// Guards against a process that reserved a settlement and then crashed (or
/// hung) before calling `mark_confirmed`/`mark_failed`: without this lease,
/// that challenge id would be stuck returning `InProgress` forever.
pub const CHARGE_RESERVATION_LEASE: Duration = Duration::from_secs(2 * 60);

/// Settlement state of a [`ChargeRecord`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChargeRecordState {
    /// A caller has claimed this challenge id and is (or was) attempting to
    /// settle it. No final signature yet.
    Reserved,
    /// Settlement succeeded; `final_signature` is authoritative.
    Confirmed,
    /// Settlement failed terminally; `failure_reason` explains why.
    Failed,
}

/// A durable record of one charge-settlement attempt, keyed by challenge id.
///
/// See the module-level "Charge replay / idempotency store" docs above.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ChargeRecord {
    pub challenge_id: String,
    /// Digest over everything that must match for a retry to be considered
    /// "the same" settlement attempt (in `mpp::server::charge`, this is
    /// computed over the challenge id, the expected request, and the
    /// presented credential payload). This module treats it as an opaque
    /// caller-supplied string.
    pub normalized_request_digest: String,
    pub final_signature: Option<String>,
    pub failure_reason: Option<String>,
    pub state: ChargeRecordState,
    pub updated_at: i64,
    pub expires_at: i64,
}

/// Outcome of [`ChargeReplayStore::reserve`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChargeReservation {
    /// First presentation of this challenge id + digest (or a prior
    /// reservation's lease expired). The caller now owns this record and
    /// MUST eventually call `mark_confirmed` or `mark_failed` — no other
    /// concurrent caller can also receive `Reserved` for the same key.
    Reserved,
    /// An earlier presentation with the same digest already confirmed.
    /// Return `final_signature` to the caller instead of re-settling.
    AlreadyConfirmed { final_signature: String },
    /// An earlier presentation with the same digest already failed
    /// terminally.
    AlreadyFailed { reason: String },
    /// An earlier presentation with the same digest is still being settled
    /// (or its owner crashed before the lease expired). The caller must NOT
    /// settle again; it should ask the client to retry shortly.
    InProgress,
    /// The same challenge id was presented with a DIFFERENT digest — a
    /// different request or credential is trying to reuse this challenge.
    Conflict,
}

fn charge_record_key(challenge_id: &str) -> String {
    format!("solana-charge:record:{challenge_id}")
}

fn now_unix() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp()
}

/// Idempotent charge-settlement ledger built on top of a plain [`Store`].
///
/// Only the caller that receives [`ChargeReservation::Reserved`] from
/// [`Self::reserve`] may call [`Self::mark_confirmed`] or
/// [`Self::mark_failed`] for that challenge id — every other concurrent
/// caller is turned away with `InProgress` or `Conflict` before doing any
/// settlement work. That invariant is what lets `mark_confirmed`/
/// `mark_failed` use a plain read-then-write instead of a compare-and-swap:
/// there is never more than one writer per key between a `Reserved` outcome
/// and its matching `mark_*` call.
#[derive(Clone)]
pub struct ChargeReplayStore {
    store: Arc<dyn Store>,
}

impl ChargeReplayStore {
    pub fn new(store: Arc<dyn Store>) -> Self {
        Self { store }
    }

    /// Reserve `challenge_id` for settlement, or classify an existing
    /// record. See [`ChargeReservation`] for the possible outcomes.
    pub async fn reserve(
        &self,
        challenge_id: &str,
        normalized_request_digest: &str,
        lease: Duration,
    ) -> Result<ChargeReservation, StoreError> {
        let key = charge_record_key(challenge_id);
        let now = now_unix();
        let fresh = ChargeRecord {
            challenge_id: challenge_id.to_string(),
            normalized_request_digest: normalized_request_digest.to_string(),
            final_signature: None,
            failure_reason: None,
            state: ChargeRecordState::Reserved,
            updated_at: now,
            expires_at: now + lease.as_secs() as i64,
        };
        let fresh_value =
            serde_json::to_value(&fresh).map_err(|e| StoreError::Serialization(e.to_string()))?;

        if self.store.put_if_absent(&key, fresh_value.clone()).await? {
            return Ok(ChargeReservation::Reserved);
        }

        let existing = self.store.get(&key).await?.ok_or_else(|| {
            StoreError::Internal("charge record vanished after put_if_absent conflict".into())
        })?;
        let existing: ChargeRecord = serde_json::from_value(existing)
            .map_err(|e| StoreError::Serialization(e.to_string()))?;

        if existing.normalized_request_digest != normalized_request_digest {
            return Ok(ChargeReservation::Conflict);
        }

        match existing.state {
            ChargeRecordState::Confirmed => Ok(ChargeReservation::AlreadyConfirmed {
                final_signature: existing.final_signature.unwrap_or_default(),
            }),
            ChargeRecordState::Failed => Ok(ChargeReservation::AlreadyFailed {
                reason: existing.failure_reason.unwrap_or_default(),
            }),
            ChargeRecordState::Reserved if existing.expires_at <= now => {
                // The prior reservation's lease expired — presumed abandoned
                // (e.g. the process that reserved it crashed before
                // confirming or failing). Reclaim it via `put` (not
                // `put_if_absent`, which would fail since the key exists).
                self.store.put(&key, fresh_value).await?;
                Ok(ChargeReservation::Reserved)
            }
            ChargeRecordState::Reserved => Ok(ChargeReservation::InProgress),
        }
    }

    /// Transition a reserved record to `Confirmed`. Only the caller that
    /// received `Reserved` from `reserve` for this `challenge_id` may call
    /// this — see struct docs.
    pub async fn mark_confirmed(
        &self,
        challenge_id: &str,
        final_signature: &str,
    ) -> Result<(), StoreError> {
        self.settle(
            challenge_id,
            ChargeRecordState::Confirmed,
            Some(final_signature.to_string()),
            None,
        )
        .await
    }

    /// Transition a reserved record to `Failed`. Only the caller that
    /// received `Reserved` from `reserve` for this `challenge_id` may call
    /// this — see struct docs.
    pub async fn mark_failed(&self, challenge_id: &str, reason: &str) -> Result<(), StoreError> {
        self.settle(
            challenge_id,
            ChargeRecordState::Failed,
            None,
            Some(reason.to_string()),
        )
        .await
    }

    async fn settle(
        &self,
        challenge_id: &str,
        state: ChargeRecordState,
        final_signature: Option<String>,
        failure_reason: Option<String>,
    ) -> Result<(), StoreError> {
        let key = charge_record_key(challenge_id);
        let existing = self.store.get(&key).await?.ok_or_else(|| {
            StoreError::Internal(format!(
                "cannot settle charge record `{challenge_id}`: no reservation found"
            ))
        })?;
        let mut record: ChargeRecord = serde_json::from_value(existing)
            .map_err(|e| StoreError::Serialization(e.to_string()))?;
        record.state = state;
        record.final_signature = final_signature;
        record.failure_reason = failure_reason;
        record.updated_at = now_unix();
        record.expires_at = record.updated_at + DEFAULT_CHARGE_RECORD_RETENTION.as_secs() as i64;
        let value =
            serde_json::to_value(&record).map_err(|e| StoreError::Serialization(e.to_string()))?;
        self.store.put(&key, value).await
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

/// Schema version stamped on every channel record this crate writes.
///
/// A writer must refuse records stamped with a *newer* version than its own:
/// decoding one would drop the fields it does not know, and a subsequent
/// re-encode + CAS write would destroy them for every reader. Unknown fields
/// at the same or an older version round-trip verbatim through
/// [`ChannelState::extra`] instead.
pub const CHANNEL_STATE_SCHEMA_VERSION: u32 = 1;

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

    /// Original channel payer and refund destination.
    #[serde(default)]
    pub payer: String,

    /// Account that funded channel and escrow rent.
    #[serde(default)]
    pub rent_payer: String,

    /// Challenge identifier that was current when the channel was opened.
    #[serde(default)]
    pub opening_challenge_id: String,

    /// Canonical JSON for the reusable payer proof bound at open.
    #[serde(default)]
    pub authentication: Option<String>,

    /// `client` or `operator`, as negotiated by the opening challenge.
    #[serde(default)]
    pub voucher_signer: String,

    /// Effective negotiated idle timeout in seconds.
    #[serde(default)]
    pub idle_timeout_seconds: Option<u32>,

    /// Unix milliseconds of the most recent accepted activity.
    #[serde(default)]
    pub last_activity_at: u64,

    /// Cumulative amount charged for delivered service.
    #[serde(default)]
    pub spent_amount: u64,

    /// Highest cumulative amount confirmed settled on-chain.
    #[serde(default)]
    pub settled_on_chain: u64,

    /// Exactly-once operator-use results keyed by HTTP idempotency key.
    #[serde(default)]
    pub processed_uses: Vec<ProcessedUse>,

    /// Transaction signatures of top-ups already credited to `deposit`
    /// (base58). Checked inside the atomic top-up mutator so a resubmitted or
    /// concurrently duplicated top-up transaction credits exactly once.
    #[serde(default)]
    pub processed_topup_signatures: Vec<String>,

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

    /// Schema version stamped by the last writer. `0` for records persisted
    /// before versioning. Durable stores refuse records newer than
    /// [`CHANNEL_STATE_SCHEMA_VERSION`] instead of decoding them lossily.
    #[serde(default)]
    pub schema_version: u32,

    /// Fields this crate version does not know, preserved verbatim so a
    /// read-modify-write by an older writer can never strip a newer schema's
    /// fields off a shared record (the 2026-08-01 proof-binding wipe).
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

/// Cached result for one operator-signed `use` request.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProcessedUse {
    pub challenge_id: String,
    pub idempotency_key: String,
    pub cumulative: u64,
    pub voucher_signature: String,
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

/// In-memory channel store backed by a sharded concurrent map.
///
/// Uses [`DashMap`] rather than a single `Mutex<HashMap>` so that requests for
/// distinct channels contend only when they hash to the same internal shard,
/// not globally. Each session has its own channel, so under real load the
/// per-request `get_channel` + `update_channel` (two lock acquisitions per
/// voucher) previously serialized every gateway worker thread on one mutex —
/// a hard aggregate throughput ceiling regardless of core count. Sharding
/// removes that single point of contention. Per-channel operations remain
/// atomic: `update_channel`/`advance_cumulative`/`touch_channel_lifecycle`
/// hold the shard's lock (via the entry / `get_mut` guard) across their
/// read-modify-write, so concurrent updates to the *same* channel are still
/// serialized correctly.
pub struct MemoryChannelStore {
    data: dashmap::DashMap<String, ChannelState>,
}

impl Default for MemoryChannelStore {
    fn default() -> Self {
        Self {
            data: dashmap::DashMap::new(),
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
        // Iterates shard-by-shard rather than holding one global lock across
        // the whole clone, so a lifecycle sweep no longer stalls every request.
        let channels = self
            .data
            .iter()
            .map(|entry| entry.value().clone())
            .collect();
        Box::pin(async move { Ok(channels) })
    }

    fn get_channel(
        &self,
        channel_id: &str,
    ) -> Pin<Box<dyn Future<Output = Result<Option<ChannelState>, StoreError>> + Send + '_>> {
        let result = self.data.get(channel_id).map(|entry| entry.value().clone());
        Box::pin(async move { Ok(result) })
    }

    fn put_channel(
        &self,
        channel_id: &str,
        state: ChannelState,
    ) -> Pin<Box<dyn Future<Output = Result<(), StoreError>> + Send + '_>> {
        use dashmap::mapref::entry::Entry;
        let result = match self.data.entry(channel_id.to_string()) {
            Entry::Vacant(entry) => {
                entry.insert(state);
                Ok(())
            }
            Entry::Occupied(_) => Err(StoreError::Internal(format!(
                "Channel {channel_id} already exists"
            ))),
        };
        Box::pin(async move { result })
    }

    fn delete_channel(
        &self,
        channel_id: &str,
    ) -> Pin<Box<dyn Future<Output = Result<(), StoreError>> + Send + '_>> {
        self.data.remove(channel_id);
        Box::pin(async { Ok(()) })
    }

    fn update_channel(
        &self,
        channel_id: &str,
        updater: Box<dyn FnOnce(Option<ChannelState>) -> Result<ChannelState, StoreError> + Send>,
    ) -> Pin<Box<dyn Future<Output = Result<ChannelState, StoreError>> + Send + '_>> {
        use dashmap::mapref::entry::Entry;
        // Hold only this key's shard lock across the read-modify-write, so the
        // update is atomic per channel without blocking other channels. The
        // updater must not re-enter the store for the same key (same invariant
        // the previous single-mutex version required — a re-entrant lock would
        // have deadlocked there too).
        let result = match self.data.entry(channel_id.to_string()) {
            Entry::Occupied(mut entry) => {
                let current = Some(entry.get().clone());
                match updater(current) {
                    Ok(new_state) => {
                        entry.insert(new_state.clone());
                        Ok(new_state)
                    }
                    Err(e) => Err(e),
                }
            }
            Entry::Vacant(entry) => match updater(None) {
                Ok(new_state) => {
                    entry.insert(new_state.clone());
                    Ok(new_state)
                }
                Err(e) => Err(e),
            },
        };
        Box::pin(async move { result })
    }

    fn touch_channel_lifecycle(
        &self,
        channel_id: &str,
        lifecycle: ChannelLifecycle,
    ) -> Pin<Box<dyn Future<Output = Result<ChannelState, StoreError>> + Send + '_>> {
        let result = match self.data.get_mut(channel_id) {
            Some(mut state) => {
                let replace = !state.sealed
                    && state.close_requested_at.is_none()
                    && state
                        .lifecycle
                        .as_ref()
                        .is_none_or(|current| lifecycle.close_after >= current.close_after);
                if replace {
                    state.lifecycle = Some(lifecycle);
                }
                Ok(state.clone())
            }
            None => Err(StoreError::Internal("Channel not found".to_string())),
        };
        Box::pin(async move { result })
    }

    fn advance_cumulative(
        &self,
        channel_id: &str,
        expected: u64,
        new: u64,
    ) -> Pin<Box<dyn Future<Output = Result<bool, StoreError>> + Send + '_>> {
        match self.data.get_mut(channel_id) {
            Some(mut state) if state.cumulative == expected => {
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
        match self.data.get_mut(channel_id) {
            Some(mut state) => {
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
        match self.data.get_mut(channel_id) {
            Some(mut state) => {
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
        let state: ChannelState =
            serde_json::from_str(raw).map_err(|e| StoreError::Serialization(e.to_string()))?;
        if state.schema_version > CHANNEL_STATE_SCHEMA_VERSION {
            return Err(StoreError::Serialization(format!(
                "channel record schema_version {} is newer than this writer's {}; \
                 refusing lossy decode",
                state.schema_version, CHANNEL_STATE_SCHEMA_VERSION
            )));
        }
        Ok(state)
    }

    /// Stamp this writer's schema version and encode for persistence, so a
    /// record always reflects the newest schema that has written it.
    fn encode_for_write(mut state: ChannelState) -> Result<(String, ChannelState), StoreError> {
        state.schema_version = CHANNEL_STATE_SCHEMA_VERSION;
        let raw = Self::encode(&state)?;
        Ok((raw, state))
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
            let (encoded, _) = Self::encode_for_write(state)?;
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
            let (new_raw, new_state) = Self::encode_for_write(new_state)?;
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
                let (new_raw, state) = Self::encode_for_write(state)?;
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
            let (new_raw, _) = Self::encode_for_write(state)?;
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

    // ── ChargeReplayStore ──

    fn replay_store() -> ChargeReplayStore {
        ChargeReplayStore::new(Arc::new(MemoryStore::new()))
    }

    #[tokio::test]
    async fn charge_replay_reserve_first_presentation_wins() {
        let store = replay_store();
        let outcome = store
            .reserve("chal-1", "digest-a", CHARGE_RESERVATION_LEASE)
            .await
            .unwrap();
        assert_eq!(outcome, ChargeReservation::Reserved);
    }

    #[tokio::test]
    async fn charge_replay_reserve_identical_retry_while_in_progress_does_not_settle_again() {
        let store = replay_store();
        store
            .reserve("chal-2", "digest-a", CHARGE_RESERVATION_LEASE)
            .await
            .unwrap();

        // Still reserved (not yet confirmed/failed) — a second identical
        // presentation must not be allowed to settle again.
        let outcome = store
            .reserve("chal-2", "digest-a", CHARGE_RESERVATION_LEASE)
            .await
            .unwrap();
        assert_eq!(outcome, ChargeReservation::InProgress);
    }

    #[tokio::test]
    async fn charge_replay_identical_retry_after_confirmation_returns_same_signature() {
        let store = replay_store();
        store
            .reserve("chal-3", "digest-a", CHARGE_RESERVATION_LEASE)
            .await
            .unwrap();
        store.mark_confirmed("chal-3", "sig-abc").await.unwrap();

        // Response-loss-idempotent: an identical retry after the first
        // settled must return the SAME signature instead of erroring or
        // re-settling.
        let outcome = store
            .reserve("chal-3", "digest-a", CHARGE_RESERVATION_LEASE)
            .await
            .unwrap();
        assert_eq!(
            outcome,
            ChargeReservation::AlreadyConfirmed {
                final_signature: "sig-abc".to_string()
            }
        );
    }

    #[tokio::test]
    async fn charge_replay_identical_retry_after_failure_returns_same_reason() {
        let store = replay_store();
        store
            .reserve("chal-4", "digest-a", CHARGE_RESERVATION_LEASE)
            .await
            .unwrap();
        store
            .mark_failed("chal-4", "simulation failed")
            .await
            .unwrap();

        let outcome = store
            .reserve("chal-4", "digest-a", CHARGE_RESERVATION_LEASE)
            .await
            .unwrap();
        assert_eq!(
            outcome,
            ChargeReservation::AlreadyFailed {
                reason: "simulation failed".to_string()
            }
        );
    }

    #[tokio::test]
    async fn charge_replay_conflicting_digest_under_same_challenge_id_errors() {
        let store = replay_store();
        store
            .reserve("chal-5", "digest-a", CHARGE_RESERVATION_LEASE)
            .await
            .unwrap();

        // A different request/credential trying to reuse the same
        // challenge id must be rejected, whether the original is still
        // in flight...
        let outcome = store
            .reserve("chal-5", "digest-b", CHARGE_RESERVATION_LEASE)
            .await
            .unwrap();
        assert_eq!(outcome, ChargeReservation::Conflict);

        // ...or already confirmed.
        store.mark_confirmed("chal-5", "sig-abc").await.unwrap();
        let outcome = store
            .reserve("chal-5", "digest-b", CHARGE_RESERVATION_LEASE)
            .await
            .unwrap();
        assert_eq!(outcome, ChargeReservation::Conflict);
    }

    #[tokio::test]
    async fn charge_replay_expired_reservation_is_reclaimed() {
        let store = replay_store();
        // A lease of zero is immediately expired, simulating a process that
        // reserved and then crashed before confirming or failing.
        store
            .reserve("chal-6", "digest-a", Duration::from_secs(0))
            .await
            .unwrap();

        let outcome = store
            .reserve("chal-6", "digest-a", CHARGE_RESERVATION_LEASE)
            .await
            .unwrap();
        assert_eq!(outcome, ChargeReservation::Reserved);
    }

    #[tokio::test]
    async fn charge_replay_mark_confirmed_without_reservation_errors() {
        let store = replay_store();
        let err = store
            .mark_confirmed("never-reserved", "sig-abc")
            .await
            .unwrap_err();
        assert!(matches!(err, StoreError::Internal(_)));
    }

    // Concurrency regression: race N tasks reserving the SAME challenge
    // id + digest together. Exactly one may win `Reserved`; every other
    // task must observe `InProgress` — never a second `Reserved`, which
    // would mean two callers both think they own the settlement and could
    // double-broadcast.
    #[tokio::test(flavor = "multi_thread")]
    async fn charge_replay_concurrent_identical_reserve_wins_exactly_once() {
        const TASKS: usize = 16;
        let store = Arc::new(replay_store());
        let barrier = Arc::new(tokio::sync::Barrier::new(TASKS));

        let mut handles = Vec::with_capacity(TASKS);
        for _ in 0..TASKS {
            let store = store.clone();
            let barrier = barrier.clone();
            handles.push(tokio::spawn(async move {
                barrier.wait().await;
                store
                    .reserve("chal-concurrent", "digest-a", CHARGE_RESERVATION_LEASE)
                    .await
                    .unwrap()
            }));
        }

        let mut reserved = 0usize;
        let mut in_progress = 0usize;
        for handle in handles {
            match handle.await.expect("task panicked") {
                ChargeReservation::Reserved => reserved += 1,
                ChargeReservation::InProgress => in_progress += 1,
                other => panic!("unexpected outcome: {other:?}"),
            }
        }

        assert_eq!(reserved, 1, "exactly one task may reserve the challenge");
        assert_eq!(in_progress, TASKS - 1, "every other task must back off");
    }

    #[test]
    fn channel_state_roundtrips_unknown_fields() {
        // A record written by a newer schema, then read and re-encoded by
        // this writer: the unknown field must survive, not vanish.
        let mut value = serde_json::to_value(make_state("c1", 1_000)).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("proof_binding_v9".to_string(), serde_json::json!({"k": 1}));
        let decoded: ChannelState = serde_json::from_value(value).unwrap();
        assert_eq!(
            decoded.extra.get("proof_binding_v9"),
            Some(&serde_json::json!({"k": 1}))
        );
        let reencoded = serde_json::to_string(&decoded).unwrap();
        assert!(reencoded.contains("proof_binding_v9"));
    }

    #[cfg(feature = "redis-store")]
    #[test]
    fn redis_store_refuses_newer_schema_and_stamps_writes() {
        let mut state = make_state("c1", 1_000);
        state.schema_version = CHANNEL_STATE_SCHEMA_VERSION + 1;
        let raw = serde_json::to_string(&state).unwrap();
        let err = RedisChannelStore::decode(&raw).unwrap_err();
        assert!(err.to_string().contains("newer"), "got: {err}");

        state.schema_version = 0;
        let (encoded, stamped) = RedisChannelStore::encode_for_write(state).unwrap();
        assert_eq!(stamped.schema_version, CHANNEL_STATE_SCHEMA_VERSION);
        let decoded = RedisChannelStore::decode(&encoded).unwrap();
        assert_eq!(decoded.schema_version, CHANNEL_STATE_SCHEMA_VERSION);
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
            payer: String::new(),
            rent_payer: String::new(),
            opening_challenge_id: String::new(),
            authentication: None,
            voucher_signer: "client".to_string(),
            idle_timeout_seconds: None,
            last_activity_at: 0,
            spent_amount: 0,
            settled_on_chain: 0,
            processed_uses: vec![],
            processed_topup_signatures: vec![],
            next_delivery_sequence: 0,
            pending_deliveries: vec![],
            committed_deliveries: vec![],
            lifecycle: None,
            schema_version: CHANNEL_STATE_SCHEMA_VERSION,
            extra: Default::default(),
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
