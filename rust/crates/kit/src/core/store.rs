//! Pluggable key-value and channel state stores, shared across the pay-kit
//! crates.
//!
//! Holds replay-protection (`Store`) and payment-channel session state
//! (`ChannelStore`/`ChannelState`). Extracted from `solana-mpp` so both
//! `solana-mpp` (the `session` intent) and `solana-x402` (the
//! `batch-settlement` scheme) share one implementation. `solana-mpp` re-exports
//! this module at `mpp::store`.

use std::collections::VecDeque;
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

    /// Atomically write `value` only if the key currently holds `expected`
    /// (`None`: the key is absent). Returns `true` if the value was written.
    /// Implementations MUST compare and write in one atomic step;
    /// [`conformance::check_store`] exercises it.
    fn put_if_eq(
        &self,
        key: &str,
        expected: Option<serde_json::Value>,
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

    fn put_if_eq(
        &self,
        key: &str,
        expected: Option<serde_json::Value>,
        value: serde_json::Value,
    ) -> Pin<Box<dyn Future<Output = Result<bool, StoreError>> + Send + '_>> {
        let key = key.to_string();
        let serialized =
            serde_json::to_string(&value).map_err(|e| StoreError::Serialization(e.to_string()));
        Box::pin(async move {
            let serialized = serialized?;
            let mut data = self.data.lock().unwrap();
            let current = data
                .get(&key)
                .map(|raw| serde_json::from_str::<serde_json::Value>(raw))
                .transpose()
                .map_err(|e| StoreError::Serialization(e.to_string()))?;
            if current != expected {
                return Ok(false);
            }
            data.insert(key, serialized);
            Ok(true)
        })
    }
}

// ── Consumed transaction signatures ──

/// Protocol-independent ledger of Solana transaction signatures that already
/// authorized a protected response.
///
/// MPP charge and x402 `exact` both claim here, so one on-chain payment
/// authorizes one request whichever protocol presents it: a transaction
/// settled through MPP cannot be presented again as an x402 signature proof
/// on a gate that shares the store, and vice versa. The key is the signature
/// alone; a signature commits to a message carrying a cluster-specific
/// blockhash, so scoping by network would add nothing but a second
/// normalization that both protocols would have to agree on.
#[derive(Clone)]
pub struct ConsumedSignatures {
    store: Arc<dyn Store>,
}

fn consumed_signature_key(signature: &str) -> String {
    format!("solana:consumed-signature:{signature}")
}

/// CAIP-2 networks the x402 `exact` server scoped its pre-ledger claims by
/// (every value `caip2_network_for_cluster` returns).
const LEGACY_X402_NETWORKS: [&str; 3] = [
    "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
    "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
    "solana:4uhcVJyU9pJkvQyS88uRDiswHXSCkY3z",
];

/// Keys under which MPP charge and x402 `exact` claimed signatures before
/// they shared this ledger.
///
/// Every claim also takes these, so that during a rolling upgrade a replica
/// still running the previous release (which claims and checks only its own
/// legacy key) sees a payment this release accepted, and the other way round.
fn legacy_consumed_signature_keys(signature: &str) -> impl Iterator<Item = String> + '_ {
    std::iter::once(format!("solana-charge:consumed:{signature}")).chain(
        LEGACY_X402_NETWORKS
            .iter()
            .map(move |network| format!("x402-exact:consumed:{network}:{signature}")),
    )
}

impl ConsumedSignatures {
    pub fn new(store: Arc<dyn Store>) -> Self {
        Self { store }
    }

    /// Atomically claim `signature`. `false` means an earlier presentation,
    /// through any protocol and any release, already claimed it.
    pub async fn claim(&self, signature: &str) -> Result<bool, StoreError> {
        self.claim_with(signature, serde_json::json!(true)).await
    }

    /// Take every legacy key, then the ledger key holding `value`.
    ///
    /// The legacy keys come first and each is taken with `put_if_absent`, so
    /// a replica on the previous release, which claims its own legacy key the
    /// same way, contends on the very same key: at most one of them wins,
    /// with no window between a check and a write. A signature already held
    /// under any of them (a pre-ledger claim, or a previous release's) stays
    /// consumed and is never migrated. When the claim fails, refused or on a
    /// store error, the keys this call took are given back: the caller then
    /// neither sends nor serves anything for the signature.
    async fn claim_with(
        &self,
        signature: &str,
        value: serde_json::Value,
    ) -> Result<bool, StoreError> {
        let mut taken = Vec::new();
        for key in legacy_consumed_signature_keys(signature) {
            match self
                .store
                .put_if_absent(&key, serde_json::json!(true))
                .await
            {
                Ok(true) => taken.push(key),
                outcome => {
                    self.give_back(&taken).await;
                    return outcome;
                }
            }
        }
        let key = consumed_signature_key(signature);
        let outcome = match self.store.put_if_absent(&key, value.clone()).await {
            // A released claim reads as absent.
            Ok(false) => {
                self.store
                    .put_if_eq(&key, Some(released_marker()), value)
                    .await
            }
            outcome => outcome,
        };
        if !matches!(outcome, Ok(true)) {
            self.give_back(&taken).await;
        }
        outcome
    }

    async fn give_back(&self, keys: &[String]) {
        for key in keys {
            if let Err(error) = self.store.delete(key).await {
                tracing::warn!(%error, key, "failed to give back a legacy signature claim");
            }
        }
    }

    /// Claim `signature` for a transaction about to be broadcast, whose
    /// outcome may be unknown when the call returns.
    ///
    /// The claim is pending until [`Self::confirm`] (it landed) or
    /// [`Self::release`] (it provably never will). A pending claim is still
    /// taken: [`Self::claim`] refuses it, so no protocol can present the
    /// signature while its settlement is unresolved.
    pub async fn claim_pending(&self, signature: &str) -> Result<PendingClaim, StoreError> {
        if self.claim_with(signature, pending_marker()).await? {
            return Ok(PendingClaim::Fresh);
        }
        let key = consumed_signature_key(signature);
        Ok(if self.store.get(&key).await? == Some(pending_marker()) {
            PendingClaim::ResumePending
        } else {
            PendingClaim::Consumed
        })
    }

    /// Turn a pending claim into a consumed signature once its transaction
    /// landed. `false` means another caller already confirmed it (and served
    /// the request) or it was never pending.
    pub async fn confirm(&self, signature: &str) -> Result<bool, StoreError> {
        self.store
            .put_if_eq(
                &consumed_signature_key(signature),
                Some(pending_marker()),
                serde_json::json!(true),
            )
            .await
    }

    /// Release a [`Self::claim`] this caller made for a transaction that
    /// provably never landed (for example a preflight rejection), so the payer
    /// may retry it. Returns `false`, releasing nothing, when the claim no
    /// longer holds what this caller wrote.
    pub async fn release(&self, signature: &str) -> Result<bool, StoreError> {
        self.release_holding(signature, serde_json::json!(true))
            .await
    }

    /// Release a [`Self::claim_pending`] that provably never landed. Only a
    /// claim still pending is released: once any holder (a resumed
    /// settlement) confirmed it, a release from a holder that saw it as
    /// unlanded (say on a lagging node) must not erase it. Returns `false`,
    /// releasing nothing, in that case.
    pub async fn release_pending(&self, signature: &str) -> Result<bool, StoreError> {
        self.release_holding(signature, pending_marker()).await
    }

    /// Swap the ledger key from `held` to a released marker in one atomic
    /// step, then give back the legacy keys the claim took. The marker stays
    /// behind and a later claim takes it over (see [`Self::claim_with`]): the
    /// store cannot delete conditionally, and an unconditional delete could
    /// erase a claim that changed in between.
    async fn release_holding(
        &self,
        signature: &str,
        held: serde_json::Value,
    ) -> Result<bool, StoreError> {
        if !self
            .store
            .put_if_eq(
                &consumed_signature_key(signature),
                Some(held),
                released_marker(),
            )
            .await?
        {
            return Ok(false);
        }
        for key in legacy_consumed_signature_keys(signature) {
            self.store.delete(&key).await?;
        }
        Ok(true)
    }
}

/// What a released claim leaves behind: absent, for every claim.
fn released_marker() -> serde_json::Value {
    serde_json::json!({ "state": "released" })
}

fn pending_marker() -> serde_json::Value {
    serde_json::json!({ "state": "pending" })
}

/// Outcome of [`ConsumedSignatures::claim_pending`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PendingClaim {
    /// Newly claimed; this caller broadcasts.
    Fresh,
    /// An earlier broadcast of this signature has an unknown outcome. The
    /// same bytes may be broadcast again (a signature lands at most once),
    /// then confirmed or released.
    ResumePending,
    /// Already consumed by a settled presentation.
    Consumed,
}

// ── Charge replay / idempotency store ──
//
// PayKit's original charge replay guard (the consumed-signature claim in
// [`ConsumedSignatures`], see
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
///
/// It is also the floor for how long a [`Store`] keeps charge records and
/// [`ConsumedSignatures`] claims: an MPP server accepting push credentials
/// refuses any challenge that expires later than this from now, so a paid
/// signature cannot outlive its replay record.
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
    /// `final_signature` may have been broadcast (it is recorded before the
    /// send) and its outcome is not yet known. A retry reconciles it before
    /// any replacement payment is allowed; it is never lease-reclaimed.
    Pending,
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
    /// reservation's lease expired). The caller now owns `generation` of this
    /// record and MUST eventually call `mark_confirmed` or `mark_failed` — no
    /// other caller can receive `Reserved` for the same generation.
    Reserved { generation: u64 },
    /// An earlier presentation with the same digest already confirmed.
    /// Return `final_signature` to the caller instead of re-settling.
    AlreadyConfirmed { final_signature: String },
    /// An earlier presentation with the same digest already failed
    /// terminally.
    AlreadyFailed { reason: String },
    /// An earlier presentation with the same digest was broadcast but its
    /// outcome is unknown. The caller reconciles `final_signature` and settles
    /// it with `confirm_pending`, or `mark_failed` for `generation`; it must
    /// NOT broadcast again.
    PendingConfirmation {
        generation: u64,
        final_signature: String,
    },
    /// An earlier presentation with the same digest is still being settled
    /// (or its owner crashed before the lease expired). The caller must NOT
    /// settle again; it should ask the client to retry shortly.
    InProgress,
    /// The same challenge id was presented with a DIFFERENT digest — a
    /// different request or credential is trying to reuse this challenge.
    Conflict,
}

/// Bound on a record's generation chain. Each generation past the first is
/// an expired-lease takeover or a terminal outcome, so this is never reached
/// by a live challenge.
const MAX_CHARGE_RECORD_GENERATIONS: u64 = 64;

/// Key of `generation` of a charge record. Generation 0 keeps the original
/// key, so records written before generations existed read as generation 0.
fn charge_record_key(challenge_id: &str, generation: u64) -> String {
    if generation == 0 {
        format!("solana-charge:record:{challenge_id}")
    } else {
        format!("solana-charge:record:{challenge_id}:{generation}")
    }
}

fn now_unix() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp()
}

/// Idempotent charge-settlement ledger built on top of a plain [`Store`].
///
/// A record is an append-only chain of generations. Every transition out of
/// generation `g` — an expired-lease takeover or a terminal outcome — is a
/// `put_if_absent` of generation `g + 1`, so exactly one of them wins and a
/// stale owner whose lease was taken over can never overwrite the newer
/// owner's state. The latest generation is the record's state.
#[derive(Clone)]
pub struct ChargeReplayStore {
    store: Arc<dyn Store>,
}

impl ChargeReplayStore {
    pub fn new(store: Arc<dyn Store>) -> Self {
        Self { store }
    }

    async fn read(
        &self,
        challenge_id: &str,
        generation: u64,
    ) -> Result<Option<ChargeRecord>, StoreError> {
        self.store
            .get(&charge_record_key(challenge_id, generation))
            .await?
            .map(|value| {
                serde_json::from_value(value).map_err(|e| StoreError::Serialization(e.to_string()))
            })
            .transpose()
    }

    /// The latest generation of `challenge_id` and its record.
    async fn tip(&self, challenge_id: &str) -> Result<Option<(u64, ChargeRecord)>, StoreError> {
        let Some(mut record) = self.read(challenge_id, 0).await? else {
            return Ok(None);
        };
        let mut generation = 0;
        while let Some(next) = self.read(challenge_id, generation + 1).await? {
            generation += 1;
            if generation >= MAX_CHARGE_RECORD_GENERATIONS {
                return Err(StoreError::Internal(format!(
                    "charge record `{challenge_id}` exceeds {MAX_CHARGE_RECORD_GENERATIONS} generations"
                )));
            }
            record = next;
        }
        Ok(Some((generation, record)))
    }

    /// Append `record` as `generation`; `false` when another writer won it.
    async fn append(
        &self,
        challenge_id: &str,
        generation: u64,
        record: &ChargeRecord,
    ) -> Result<bool, StoreError> {
        let value =
            serde_json::to_value(record).map_err(|e| StoreError::Serialization(e.to_string()))?;
        self.store
            .put_if_absent(&charge_record_key(challenge_id, generation), value)
            .await
    }

    /// Reserve `challenge_id` for settlement, or classify an existing
    /// record. See [`ChargeReservation`] for the possible outcomes.
    pub async fn reserve(
        &self,
        challenge_id: &str,
        normalized_request_digest: &str,
        lease: Duration,
    ) -> Result<ChargeReservation, StoreError> {
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
        // A record's generations share one lifecycle: a store must expire
        // them together (the root key and every `:<generation>` key under one
        // TTL). A root missing while a descendant survives means retention was
        // applied per key; recreating the root there would hide a confirmed
        // or pending settlement and let the challenge settle again. Refuse,
        // both before claiming the root and after, in case the root expired
        // between the two.
        let orphaned = || {
            StoreError::Internal(format!(
                "charge record `{challenge_id}` lost its root while later generations remain; \
                 the store must expire a record's generations together"
            ))
        };
        if self.read(challenge_id, 1).await?.is_some()
            && self.read(challenge_id, 0).await?.is_none()
        {
            return Err(orphaned());
        }
        if self.append(challenge_id, 0, &fresh).await? {
            if self.read(challenge_id, 1).await?.is_some() {
                self.store
                    .delete(&charge_record_key(challenge_id, 0))
                    .await?;
                return Err(orphaned());
            }
            return Ok(ChargeReservation::Reserved { generation: 0 });
        }
        for _ in 0..MAX_CHARGE_RECORD_GENERATIONS {
            let (generation, existing) = self.tip(challenge_id).await?.ok_or_else(|| {
                StoreError::Internal("charge record vanished after put_if_absent conflict".into())
            })?;
            if existing.normalized_request_digest != normalized_request_digest {
                return Ok(ChargeReservation::Conflict);
            }
            match existing.state {
                ChargeRecordState::Confirmed => {
                    return Ok(ChargeReservation::AlreadyConfirmed {
                        final_signature: existing.final_signature.unwrap_or_default(),
                    })
                }
                ChargeRecordState::Failed => {
                    return Ok(ChargeReservation::AlreadyFailed {
                        reason: existing.failure_reason.unwrap_or_default(),
                    })
                }
                // Never lease-reclaimed: the broadcast may still land.
                ChargeRecordState::Pending => {
                    return Ok(ChargeReservation::PendingConfirmation {
                        generation,
                        final_signature: existing.final_signature.unwrap_or_default(),
                    })
                }
                ChargeRecordState::Reserved if existing.expires_at > now => {
                    return Ok(ChargeReservation::InProgress)
                }
                // The prior owner's lease expired — presumed crashed. Taking
                // over appends the next generation, which fences that owner.
                ChargeRecordState::Reserved => {
                    if self.append(challenge_id, generation + 1, &fresh).await? {
                        return Ok(ChargeReservation::Reserved {
                            generation: generation + 1,
                        });
                    }
                }
            }
        }
        Err(StoreError::Internal(format!(
            "charge record `{challenge_id}` is contended"
        )))
    }

    /// Record the confirmed settlement signature for the `generation` this
    /// caller owns: its reservation (a push signature, never broadcast here)
    /// or the pending broadcast of `final_signature` it recorded.
    ///
    /// Returns `false`, writing nothing, when that generation is no longer
    /// current. A stale owner whose lease was taken over can therefore never
    /// rewrite the newer generation's outcome, a recorded failure included.
    /// Fails when the challenge was never reserved.
    pub async fn mark_confirmed(
        &self,
        challenge_id: &str,
        generation: u64,
        final_signature: &str,
    ) -> Result<bool, StoreError> {
        let (tip, record) = self.tip(challenge_id).await?.ok_or_else(|| {
            StoreError::Internal(format!(
                "cannot settle charge record `{challenge_id}`: no reservation found"
            ))
        })?;
        let owned = match record.state {
            ChargeRecordState::Reserved => true,
            ChargeRecordState::Pending => {
                record.final_signature.as_deref() == Some(final_signature)
            }
            ChargeRecordState::Confirmed | ChargeRecordState::Failed => false,
        };
        if tip != generation || !owned {
            return Ok(false);
        }
        let confirmed = terminal(
            record,
            ChargeRecordState::Confirmed,
            Some(final_signature.to_string()),
            None,
        );
        self.append(challenge_id, generation + 1, &confirmed).await
    }

    /// Record a settlement confirmed outside this ledger's ownership (a
    /// payment-channel submission found on retry), whichever generation is
    /// current. It supersedes an unresolved (`Reserved`/`Pending`) record
    /// only: a recorded failure already released the client and is kept.
    /// Returns whether the record is now confirmed.
    pub async fn record_confirmed(
        &self,
        challenge_id: &str,
        final_signature: &str,
    ) -> Result<bool, StoreError> {
        for _ in 0..MAX_CHARGE_RECORD_GENERATIONS {
            let (generation, record) = self.tip(challenge_id).await?.ok_or_else(|| {
                StoreError::Internal(format!(
                    "cannot settle charge record `{challenge_id}`: no reservation found"
                ))
            })?;
            match record.state {
                ChargeRecordState::Confirmed => return Ok(true),
                ChargeRecordState::Failed => return Ok(false),
                ChargeRecordState::Reserved | ChargeRecordState::Pending => {}
            }
            let confirmed = terminal(
                record,
                ChargeRecordState::Confirmed,
                Some(final_signature.to_string()),
                None,
            );
            if self
                .append(challenge_id, generation + 1, &confirmed)
                .await?
            {
                return Ok(true);
            }
        }
        Err(StoreError::Internal(format!(
            "charge record `{challenge_id}` is contended"
        )))
    }

    /// Return the pending record at `generation` to an immediately
    /// reclaimable reservation, for a broadcast of `final_signature` that
    /// provably never left this process (a preflight rejection). Returns
    /// `false`, writing nothing, when that generation is no longer current.
    pub async fn release_pending(
        &self,
        challenge_id: &str,
        generation: u64,
        final_signature: &str,
    ) -> Result<bool, StoreError> {
        let (tip, mut record) = self.tip(challenge_id).await?.ok_or_else(|| {
            StoreError::Internal(format!(
                "cannot settle charge record `{challenge_id}`: no reservation found"
            ))
        })?;
        if tip != generation
            || record.state != ChargeRecordState::Pending
            || record.final_signature.as_deref() != Some(final_signature)
        {
            return Ok(false);
        }
        record.state = ChargeRecordState::Reserved;
        record.final_signature = None;
        record.updated_at = now_unix();
        record.expires_at = record.updated_at;
        self.append(challenge_id, generation + 1, &record).await
    }

    /// Confirm the pending broadcast at `generation` (from
    /// [`ChargeReservation::PendingConfirmation`]).
    ///
    /// Exactly one caller wins this claim; `false`, writing nothing, means the
    /// pending generation was already resolved by another caller.
    pub async fn confirm_pending(
        &self,
        challenge_id: &str,
        generation: u64,
        final_signature: &str,
    ) -> Result<bool, StoreError> {
        let (tip, record) = self.tip(challenge_id).await?.ok_or_else(|| {
            StoreError::Internal(format!(
                "cannot settle charge record `{challenge_id}`: no reservation found"
            ))
        })?;
        if tip != generation
            || record.state != ChargeRecordState::Pending
            || record.final_signature.as_deref() != Some(final_signature)
        {
            return Ok(false);
        }
        let confirmed = terminal(
            record,
            ChargeRecordState::Confirmed,
            Some(final_signature.to_string()),
            None,
        );
        self.append(challenge_id, generation + 1, &confirmed).await
    }

    /// The pending broadcast recorded for `challenge_id` under
    /// `normalized_request_digest`, as `(generation, final_signature)`.
    /// Never creates a reservation.
    pub async fn pending(
        &self,
        challenge_id: &str,
        normalized_request_digest: &str,
    ) -> Result<Option<(u64, String)>, StoreError> {
        Ok(match self.tip(challenge_id).await? {
            Some((generation, record))
                if record.state == ChargeRecordState::Pending
                    && record.normalized_request_digest == normalized_request_digest =>
            {
                record
                    .final_signature
                    .map(|signature| (generation, signature))
            }
            _ => None,
        })
    }

    /// Record that `final_signature` is about to be broadcast, for the
    /// reservation `generation` returned by [`Self::reserve`]. Settlement
    /// calls this BEFORE sending, so a reservation is only ever reclaimed by a
    /// lease takeover while nothing has been sent, and a pending record is
    /// never reclaimed.
    ///
    /// Returns `false`, writing nothing, when that reservation is no longer
    /// current: its lease was taken over, and the caller MUST NOT broadcast.
    pub async fn mark_pending(
        &self,
        challenge_id: &str,
        generation: u64,
        final_signature: &str,
    ) -> Result<bool, StoreError> {
        let (tip, record) = self.tip(challenge_id).await?.ok_or_else(|| {
            StoreError::Internal(format!(
                "cannot settle charge record `{challenge_id}`: no reservation found"
            ))
        })?;
        if tip != generation || record.state != ChargeRecordState::Reserved {
            return Ok(false);
        }
        let pending = terminal(
            record,
            ChargeRecordState::Pending,
            Some(final_signature.to_string()),
            None,
        );
        self.append(challenge_id, generation + 1, &pending).await
    }

    /// Record a terminal settlement failure for the `generation` returned by
    /// [`Self::reserve`] (a reservation, or a pending broadcast being
    /// reconciled).
    ///
    /// Returns `false`, writing nothing, when that generation is no longer
    /// current: its lease was taken over or another outcome was recorded.
    pub async fn mark_failed(
        &self,
        challenge_id: &str,
        generation: u64,
        reason: &str,
    ) -> Result<bool, StoreError> {
        let (tip, record) = self.tip(challenge_id).await?.ok_or_else(|| {
            StoreError::Internal(format!(
                "cannot settle charge record `{challenge_id}`: no reservation found"
            ))
        })?;
        if tip != generation
            || !matches!(
                record.state,
                ChargeRecordState::Reserved | ChargeRecordState::Pending
            )
        {
            return Ok(false);
        }
        let failed = terminal(
            record,
            ChargeRecordState::Failed,
            None,
            Some(reason.to_string()),
        );
        self.append(challenge_id, generation + 1, &failed).await
    }
}

fn terminal(
    mut record: ChargeRecord,
    state: ChargeRecordState,
    final_signature: Option<String>,
    failure_reason: Option<String>,
) -> ChargeRecord {
    record.state = state;
    record.final_signature = final_signature;
    record.failure_reason = failure_reason;
    record.updated_at = now_unix();
    record.expires_at = record.updated_at + DEFAULT_CHARGE_RECORD_RETENTION.as_secs() as i64;
    record
}

// ── Channel store ──

/// A delivery reserved by the server but not yet committed by the client.
///
/// Also carries an x402 `batch-settlement` payment authorization between its
/// reservation and its commitment — see [`ChannelState::reserve_authorization`].
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PendingDelivery {
    #[serde(rename = "deliveryId")]
    pub delivery_id: String,
    pub amount: u64,
    pub sequence: u64,
    #[serde(rename = "expiresAt")]
    pub expires_at: i64,

    /// Digest of the request that owns this reservation, when the flow binds
    /// one. A presentation of the same id under a different digest is a
    /// different request reusing the reservation, and is refused.
    #[serde(
        default,
        rename = "requestFingerprint",
        skip_serializing_if = "Option::is_none"
    )]
    pub request_fingerprint: Option<String>,

    /// True once the resource handler for this authorization returned success.
    ///
    /// This is the crash boundary: a retry that observes it MUST finish
    /// commitment and MUST NOT run the handler again, however long ago the
    /// lease in `expires_at` ran out.
    #[serde(default, rename = "handlerSucceeded")]
    pub handler_succeeded: bool,
}

impl PendingDelivery {
    /// Whether a close at `now` (unix seconds) must charge this reservation.
    ///
    /// A metered delivery (no request fingerprint) handed its directive to
    /// the host, which may already have sent the response, so it is owed
    /// until the client commits it or the host releases it with a zero
    /// usage. Its `expires_at` only bounds the commit window; the passage of
    /// time never proves the response was not delivered. An authorization is
    /// owed once its handler succeeded, or while its lease may still lead to
    /// a commit.
    pub fn owed_at_close(&self, now: i64) -> bool {
        self.request_fingerprint.is_none() || self.handler_succeeded || self.expires_at > now
    }
}

/// A committed delivery, retained so an exact retry can be answered without
/// charging or serving twice.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CommittedDelivery {
    #[serde(rename = "deliveryId")]
    pub delivery_id: String,
    pub amount: u64,
    pub cumulative: u64,
    #[serde(rename = "voucherSignature")]
    pub voucher_signature: String,

    /// Digest of the request this record was committed for; see
    /// [`PendingDelivery::request_fingerprint`].
    #[serde(
        default,
        rename = "requestFingerprint",
        skip_serializing_if = "Option::is_none"
    )]
    pub request_fingerprint: Option<String>,

    /// The exact protocol response returned when this authorization committed.
    ///
    /// Stored so a retry after a lost HTTP response gets the original result —
    /// its real charged amount and channel snapshot — rather than a synthesized
    /// one. Held as opaque JSON so this protocol-neutral record does not depend
    /// on any one scheme's response type.
    #[serde(
        default,
        rename = "settlementResponse",
        skip_serializing_if = "Option::is_none"
    )]
    pub settlement_response: Option<serde_json::Value>,

    /// Unix seconds after which this record may be dropped. `0` for records
    /// written before retention was tracked; those are kept.
    #[serde(default, rename = "retainUntil")]
    pub retain_until: i64,

    /// The resource handler's response, cached so a replay of this exact
    /// authorization can return the purchased representation itself — not
    /// just [`Self::settlement_response`] layered on top of it. `None` for
    /// records predating this field, or whose response exceeded the calling
    /// scheme's size cap for caching (a settlement-only replay still answers
    /// correctly in that case; only the original representation is lost).
    #[serde(
        default,
        rename = "cachedResponse",
        skip_serializing_if = "Option::is_none"
    )]
    pub cached_response: Option<CachedUpstreamResponse>,
}

/// A resource handler's response body, held verbatim for idempotent replay.
/// See [`CommittedDelivery::cached_response`].
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CachedUpstreamResponse {
    pub status: u16,
    #[serde(
        default,
        rename = "contentType",
        skip_serializing_if = "Option::is_none"
    )]
    pub content_type: Option<String>,
    /// End-to-end representation metadata needed to reproduce the response.
    /// Hop-by-hop and payment protocol headers are deliberately excluded by
    /// the HTTP adapter before persistence.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub headers: Vec<(String, String)>,
    #[serde(with = "cached_response_body_base64")]
    pub body: Vec<u8>,
}

mod cached_response_body_base64 {
    use base64::Engine;

    pub fn serialize<S: serde::Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&base64::engine::general_purpose::STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Vec<u8>, D::Error> {
        let encoded = <String as serde::Deserialize>::deserialize(deserializer)?;
        base64::engine::general_purpose::STANDARD
            .decode(&encoded)
            .map_err(serde::de::Error::custom)
    }
}

/// A setup transaction the server has validated and taken responsibility for,
/// but not yet broadcast and confirmed.
///
/// An initial deposit has no onchain channel to reserve against, so this is the
/// durable record that a channel is being opened — keyed, like a top-up, by the
/// payer's signature over the setup transaction, so one signed transaction can
/// never be credited twice.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PendingSetup {
    /// The channel payer's base58 signature over the setup transaction.
    #[serde(rename = "payerSignature")]
    pub payer_signature: String,

    /// Escrow the transaction adds, in atomic units.
    pub deposit: u64,

    /// Whether this transaction creates the channel (`open`) rather than
    /// topping up an existing one (`top_up`).
    #[serde(rename = "opensChannel")]
    pub opens_channel: bool,

    /// Unix seconds after which an abandoned pending setup may be reclaimed.
    #[serde(rename = "expiresAt")]
    pub expires_at: i64,
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
///
/// Version 2 adds policy-scoped MPP open intents. Older request servers must
/// reject these records rather than authorize them without the policy guard.
pub const CHANNEL_STATE_SCHEMA_VERSION: u32 = 2;

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

    /// The amount the close finalizer chose to seal the channel at, recorded
    /// in the same atomic transition that chose it. Once set, the watermark
    /// is frozen: [`ChannelState::commit_authorization`] refuses every further
    /// charge, because a seal carrying this amount may already be in flight
    /// and nothing above it could ever be redeemed.
    ///
    /// The Serde default keeps existing persisted channel records readable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub final_cumulative: Option<u64>,

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

    /// Highest cumulative amount confirmed distributed from escrow on-chain.
    #[serde(default)]
    pub distributed_on_chain: u64,

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
    pub committed_deliveries: VecDeque<CommittedDelivery>,

    /// A validated setup transaction awaiting broadcast and confirmation.
    ///
    /// Present between the moment the server takes responsibility for a client
    /// `open`/`top_up` and the moment the confirmed channel is recorded. While
    /// an `open` is pending the record holds no escrow yet, so it must not
    /// authorize anything.
    #[serde(default)]
    pub pending_setup: Option<PendingSetup>,

    /// Unix seconds of the last reconciliation against confirmed onchain state.
    /// `0` means never reconciled.
    ///
    /// Informational: admission trusts only
    /// [`ChannelState::onchain_observed_at`], which is written together with
    /// the lifecycle the read showed.
    #[serde(default)]
    pub onchain_checked_at: u64,

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

/// The deployment a channel record belongs to, stamped by the scheme that
/// created it. Two ledgers that can name the same channel address (another
/// payment scheme, recipient, cluster or program) refuse each other's records
/// instead of accepting a voucher against the wrong one.
///
/// Persisted inside [`ChannelState::extra`], so stores and older readers carry
/// it without a schema change. A field left `None` was not recorded.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChannelBinding {
    /// Payment scheme that owns the record (e.g. `batch-settlement`).
    pub scheme: String,
    /// Receiver the channel's distribution pays.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pay_to: Option<String>,
    /// Network the channel lives on, as the owning scheme names it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<String>,
    /// Payment-channels program that owns the channel account (base58).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub program_id: Option<String>,
}

impl ChannelBinding {
    /// The first recorded field `current` disagrees with, if any.
    pub fn mismatch(&self, current: &ChannelBinding) -> Option<&'static str> {
        fn differs(recorded: &Option<String>, current: &Option<String>) -> bool {
            matches!((recorded, current), (Some(a), Some(b)) if a != b)
        }
        if self.scheme != current.scheme {
            Some("scheme")
        } else if differs(&self.pay_to, &current.pay_to) {
            Some("payTo")
        } else if differs(&self.network, &current.network) {
            Some("network")
        } else if differs(&self.program_id, &current.program_id) {
            Some("programId")
        } else {
            None
        }
    }

    /// Whether every deployment field is recorded. A partial binding predates
    /// the newer fields and cannot by itself place the channel in a deployment.
    pub fn is_complete(&self) -> bool {
        self.pay_to.is_some() && self.network.is_some() && self.program_id.is_some()
    }

    /// This binding with any field it did not record taken from `current`.
    pub fn filled_from(&self, current: &ChannelBinding) -> ChannelBinding {
        ChannelBinding {
            scheme: self.scheme.clone(),
            pay_to: self.pay_to.clone().or_else(|| current.pay_to.clone()),
            network: self.network.clone().or_else(|| current.network.clone()),
            program_id: self
                .program_id
                .clone()
                .or_else(|| current.program_id.clone()),
        }
    }
}

const CHANNEL_BINDING_KEY: &str = "channelBinding";

/// [`ChannelState::extra`] key holding [`ChannelState::grace_period`].
const GRACE_PERIOD_KEY: &str = "gracePeriod";

/// [`ChannelState::extra`] key holding [`ChannelState::onchain_observed_slot`].
const ONCHAIN_OBSERVED_SLOT_KEY: &str = "onchainObservedSlot";

/// [`ChannelState::extra`] key holding [`ChannelState::onchain_observed_at`].
const ONCHAIN_OBSERVED_AT_KEY: &str = "onchainObservedAt";

/// The lifecycle an onchain read showed for a channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObservedLifecycle {
    /// Open, with no close started.
    Open,
    /// A payer close started at `started_at` (unix seconds); still claimable.
    Closing { started_at: u64 },
    /// Sealed, distributed or otherwise past accepting vouchers.
    Terminal { started_at: Option<u64> },
}

/// One onchain read of a channel; see [`ChannelState::record_onchain_observation`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OnchainObservation {
    /// Slot of the bank that served the read, when the read reported one.
    pub slot: Option<u64>,
    /// What the read showed.
    pub lifecycle: ObservedLifecycle,
}

/// Whether [`ChannelState::record_onchain_observation`] renewed the snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObservationOutcome {
    /// The snapshot now stands at this observation.
    Fresh,
    /// The read came from a bank behind `recorded`: its fences were applied,
    /// the snapshot was not renewed.
    Behind { recorded: u64 },
}

impl ChannelState {
    /// The deployment binding stamped on this record, if any.
    pub fn binding(&self) -> Result<Option<ChannelBinding>, StoreError> {
        self.extra
            .get(CHANNEL_BINDING_KEY)
            .map(|value| {
                serde_json::from_value(value.clone()).map_err(|e| {
                    StoreError::Internal(format!(
                        "channel {} has an unreadable binding: {e}",
                        self.channel_id
                    ))
                })
            })
            .transpose()
    }

    /// Record `current` on a record that has no binding, or fill the fields an
    /// older binding did not record.
    pub fn adopt_binding(&mut self, current: &ChannelBinding) -> Result<(), StoreError> {
        let recorded = self.binding()?;
        let adopted = recorded
            .as_ref()
            .map_or_else(|| current.clone(), |recorded| recorded.filled_from(current));
        if recorded.as_ref() != Some(&adopted) {
            self.set_binding(&adopted);
        }
        Ok(())
    }

    /// The channel's immutable onchain grace period (seconds), when recorded.
    /// It is not a PDA seed, so a policy change can leave an open channel with
    /// a shorter close window than the server now plans its leases around.
    pub fn grace_period(&self) -> Option<u32> {
        self.extra
            .get(GRACE_PERIOD_KEY)
            .and_then(serde_json::Value::as_u64)
            .and_then(|value| u32::try_from(value).ok())
    }

    /// Record the channel's onchain grace period.
    pub fn set_grace_period(&mut self, grace_period: u32) {
        self.extra
            .insert(GRACE_PERIOD_KEY.to_string(), grace_period.into());
    }

    /// Require the recorded grace period to be `withdraw_delay`, the window
    /// the server sizes its reservation leases and snapshots against. A record
    /// without one must first be completed from its confirmed channel.
    pub fn check_grace_period(&self, withdraw_delay: u32) -> Result<(), StoreError> {
        match self.grace_period() {
            Some(recorded) if recorded == withdraw_delay => Ok(()),
            Some(recorded) => Err(StoreError::Internal(format!(
                "channel {} has a {recorded}s grace period, not the {withdraw_delay}s this \
                 server requires",
                self.channel_id
            ))),
            None => Err(StoreError::Internal(format!(
                "channel {} has no recorded grace period",
                self.channel_id
            ))),
        }
    }

    /// Slot of the bank that served the newest onchain observation this
    /// record accepted, `0` when none recorded one.
    pub fn onchain_observed_slot(&self) -> u64 {
        self.extra
            .get(ONCHAIN_OBSERVED_SLOT_KEY)
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0)
    }

    /// Unix seconds of the newest onchain observation recorded through
    /// [`Self::record_onchain_observation`], `0` when none was.
    ///
    /// This, not [`Self::onchain_checked_at`], is what may stand in for a
    /// fresh read at admission: it is only written together with the lifecycle
    /// the read showed, so a refreshed timestamp can never hide a close or a
    /// distribution the same read saw.
    pub fn onchain_observed_at(&self) -> u64 {
        self.extra
            .get(ONCHAIN_OBSERVED_AT_KEY)
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0)
    }

    /// Apply an onchain observation of this channel in one step.
    ///
    /// The lifecycle fences it carries are applied first and unconditionally:
    /// they only ever close a channel, so even a stale read may set them. The
    /// snapshot is renewed (`onchain_observed_at`, `onchain_checked_at`) only
    /// when the read is not behind the newest accepted slot; a lagging node
    /// can return a channel as open after it closed, and must never renew the
    /// admission window.
    pub fn record_onchain_observation(
        &mut self,
        observation: OnchainObservation,
        now: u64,
    ) -> ObservationOutcome {
        match observation.lifecycle {
            ObservedLifecycle::Open => {}
            ObservedLifecycle::Closing { started_at } => {
                self.close_requested_at = Some(self.close_requested_at.unwrap_or(started_at));
            }
            ObservedLifecycle::Terminal { started_at } => {
                self.sealed = true;
                if let Some(started_at) = started_at {
                    self.close_requested_at = Some(self.close_requested_at.unwrap_or(started_at));
                }
            }
        }
        let recorded = self.onchain_observed_slot();
        if let Some(slot) = observation.slot {
            if slot < recorded {
                return ObservationOutcome::Behind { recorded };
            }
            self.extra
                .insert(ONCHAIN_OBSERVED_SLOT_KEY.to_string(), slot.into());
        }
        self.extra
            .insert(ONCHAIN_OBSERVED_AT_KEY.to_string(), now.into());
        self.onchain_checked_at = now;
        ObservationOutcome::Fresh
    }

    /// Stamp `binding` on this record.
    pub fn set_binding(&mut self, binding: &ChannelBinding) {
        if let Ok(value) = serde_json::to_value(binding) {
            self.extra.insert(CHANNEL_BINDING_KEY.to_string(), value);
        }
    }

    /// Require this record to be bound to exactly `current`, every field
    /// recorded. This is the check that admits a charge: a record without a
    /// binding, or with a partial one, must first be completed from a
    /// confirmed read of its channel with [`Self::adopt_binding`].
    pub fn check_binding_complete(&self, current: &ChannelBinding) -> Result<(), StoreError> {
        self.check_binding(current)?;
        match self.binding()? {
            Some(recorded) if recorded == *current && recorded.is_complete() => Ok(()),
            _ => Err(StoreError::Internal(format!(
                "channel {} has no complete deployment binding",
                self.channel_id
            ))),
        }
    }

    /// Refuse a record bound to a different deployment. A record that
    /// predates bindings carries none and is accepted.
    ///
    /// See [`Self::adopt_binding`] for completing an older binding.
    pub fn check_binding(&self, current: &ChannelBinding) -> Result<(), StoreError> {
        match self.binding()? {
            Some(recorded) => match recorded.mismatch(current) {
                Some(field) => Err(StoreError::Internal(format!(
                    "channel {} belongs to another deployment ({field} differs)",
                    self.channel_id
                ))),
                None => Ok(()),
            },
            None => Ok(()),
        }
    }
}

/// Cached result for one operator-signed `use` request.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProcessedUse {
    pub challenge_id: String,
    pub idempotency_key: String,
    pub cumulative: u64,
    pub voucher_signature: String,
}

// ── Durable payment authorizations ──
//
// An authorization must have exactly one outcome: a failed handler releases it
// for retry, a successful handler runs at most once, and a retry after a lost
// response returns the stored result. That needs three durable stages, because
// a reservation alone cannot tell a crash *before* the handler ran from a crash
// *after* it succeeded. What it also cannot tell is a crash *during* the
// handler, so a reservation nobody reported an outcome for is terminal rather
// than reclaimable — see `BatchReservation::Abandoned`.
//
// The stages reuse the session records rather than adding a parallel ledger:
// `pending_deliveries` is the reservation (identity plus lease, as in
// `mpp::server::session::SessionServer::begin_delivery`),
// `committed_deliveries` is the completed record (as in `process_commit`), and
// `PendingDelivery::handler_succeeded` is the one stage added between them.

/// Most committed authorizations retained per channel.
///
/// A long-lived channel serves far more requests than any client will retry, so
/// the tail is bounded. Dropping a record only costs the cached response: the
/// watermark rule still refuses the stale voucher behind it, so an evicted
/// authorization can never be served a second time.
pub const MAX_COMMITTED_AUTHORIZATIONS: usize = 64;

/// One request asking to reserve an authorization: it would step the channel's
/// watermark by `amount` to the voucher's `cumulative`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationRequest {
    pub authorization_id: String,
    pub request_fingerprint: String,
    pub amount: u64,
    pub cumulative: u64,
    pub lease: Duration,
    /// Unix seconds.
    pub now: i64,
}

/// Proof that a store transition reserved one authorization stepping the
/// watermark to `cumulative`.
///
/// Only [`ChannelState::reserve_authorization`] mints one, after its step
/// check, and [`ChannelState::commit_authorization`] requires one, so no
/// caller can commit work that was not reserved through that check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReservationToken {
    authorization_id: String,
    request_fingerprint: String,
    cumulative: u64,
    sequence: u64,
}

impl ReservationToken {
    pub fn authorization_id(&self) -> &str {
        &self.authorization_id
    }

    pub fn request_fingerprint(&self) -> &str {
        &self.request_fingerprint
    }

    /// The voucher cumulative this reservation commits to.
    pub fn cumulative(&self) -> u64 {
        self.cumulative
    }
}

#[cfg(test)]
impl ReservationToken {
    /// The token for the reservation `id` already holds on `state`, as the
    /// reserve that took it would have returned.
    pub(crate) fn for_pending(state: &ChannelState, id: &str, fp: &str, cumulative: u64) -> Self {
        Self {
            authorization_id: id.to_string(),
            request_fingerprint: fp.to_string(),
            cumulative,
            sequence: state
                .pending_index(id)
                .map_or(0, |index| state.pending_deliveries[index].sequence),
        }
    }
}

/// Outcome of [`ChannelState::reserve_authorization`].
///
/// Mirrors [`ChargeReservation`]: only the caller that receives
/// [`Self::Reserved`] owns the authorization and may run the handler.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BatchReservation {
    /// This caller now owns the authorization: run the handler exactly once,
    /// then either release it or commit it with the token.
    Reserved(ReservationToken),
    /// A live reservation for this authorization is owned by another in-flight
    /// request. Do not run the handler; the client may retry shortly.
    InProgress,
    /// An earlier attempt's handler already succeeded. Finish commitment with
    /// the token and return its result; never run the handler again.
    HandlerSucceeded(ReservationToken),
    /// Already committed. Answer with the response stored on the record —
    /// see [`ChannelState::committed_authorization`].
    Committed,
    /// The same authorization id was presented by a different request.
    Conflict,
    /// A reservation outlived its lease without reporting either outcome, so
    /// whether its handler ran is unknown. Reported both for that
    /// authorization and for any other one on the channel while it stands.
    ///
    /// The reservation is taken immediately before the handler is invoked, so
    /// an unreported one means the handler may well have run — a process that
    /// crashed between returning and marking success, or one still running
    /// past its lease. Serving it again would execute the same authorization
    /// twice, which the scheme forbids outright, so it is never reclaimed.
    ///
    /// This is deliberately terminal for the channel: the client cannot reuse
    /// the voucher, and no other voucher may step past it while its handler
    /// could still finish unaccounted, so recovery is a new channel unless the
    /// owner releases or commits it late. That liveness cost
    /// falls only on a crashed or overrunning request, and it is the price of
    /// never serving a paid request twice.
    Abandoned,
    /// The voucher does not step the current watermark by the reserved amount:
    /// it was priced from a watermark another commit has since moved. Do not
    /// serve it; the client re-signs from the current watermark.
    Stale,
    /// The channel is sealed or a close was requested: no new charge may start,
    /// since the close finalizer seals the committed watermark once nothing is
    /// reserved.
    Closing,
}

impl ChannelState {
    /// The committed record for `authorization_id`, carrying the response that
    /// answered it.
    pub fn committed_authorization(&self, authorization_id: &str) -> Option<&CommittedDelivery> {
        self.committed_deliveries
            .iter()
            .find(|entry| entry.delivery_id == authorization_id)
    }

    fn pending_index(&self, authorization_id: &str) -> Option<usize> {
        self.pending_deliveries
            .iter()
            .position(|entry| entry.delivery_id == authorization_id)
    }

    /// Classify `authorization_id` without changing anything; `None` when it
    /// has no record and is free to reserve.
    ///
    /// `now` is unix seconds. A record whose fingerprint disagrees with
    /// `request_fingerprint` is a different request reusing the id, and is
    /// reported as [`BatchReservation::Conflict`] rather than served.
    fn classify_authorization(
        &self,
        authorization_id: &str,
        request_fingerprint: &str,
        cumulative: u64,
        now: i64,
    ) -> Option<BatchReservation> {
        if let Some(committed) = self.committed_authorization(authorization_id) {
            if committed.request_fingerprint.as_deref() != Some(request_fingerprint) {
                return Some(BatchReservation::Conflict);
            }
            return Some(BatchReservation::Committed);
        }
        let index = self.pending_index(authorization_id)?;
        let pending = &self.pending_deliveries[index];
        Some(
            if pending.request_fingerprint.as_deref() != Some(request_fingerprint) {
                BatchReservation::Conflict
            } else if pending.handler_succeeded {
                // A succeeded handler outranks the lease. The work is already
                // done; the only safe continuation is to finish committing it.
                BatchReservation::HandlerSucceeded(ReservationToken {
                    authorization_id: authorization_id.to_string(),
                    request_fingerprint: request_fingerprint.to_string(),
                    cumulative,
                    sequence: pending.sequence,
                })
            } else if pending.expires_at > now {
                BatchReservation::InProgress
            } else {
                BatchReservation::Abandoned
            },
        )
    }

    /// Whether a later reservation was taken over this one's dead lease,
    /// whether it is still pending or has already committed. Its work can no
    /// longer be marked or committed: the later one stepped from the same
    /// watermark.
    fn is_superseded(&self, sequence: u64) -> bool {
        self.next_delivery_sequence > sequence
    }

    /// The pending entry `token` was minted for.
    fn token_pending_index(&self, token: &ReservationToken) -> Result<usize, StoreError> {
        let index = self
            .owned_pending_index(&token.authorization_id, &token.request_fingerprint)?
            .filter(|&index| self.pending_deliveries[index].sequence == token.sequence)
            .ok_or_else(|| {
                StoreError::Internal(format!(
                    "authorization {} is no longer reserved",
                    token.authorization_id
                ))
            })?;
        if self.is_superseded(token.sequence) {
            return Err(StoreError::Internal(format!(
                "authorization {} outlived its lease and was superseded",
                token.authorization_id
            )));
        }
        Ok(index)
    }

    /// The index of the reservation `request_fingerprint` owns, erroring when
    /// another request holds it.
    fn owned_pending_index(
        &self,
        authorization_id: &str,
        request_fingerprint: &str,
    ) -> Result<Option<usize>, StoreError> {
        let Some(index) = self.pending_index(authorization_id) else {
            return Ok(None);
        };
        if self.pending_deliveries[index]
            .request_fingerprint
            .as_deref()
            != Some(request_fingerprint)
        {
            return Err(StoreError::Internal(format!(
                "authorization {authorization_id} is reserved by a different request"
            )));
        }
        Ok(Some(index))
    }

    /// Reserve `authorization_id` for this request, or classify the record that
    /// already holds it.
    ///
    /// On [`BatchReservation::Reserved`] the caller owns the authorization and
    /// MUST eventually call [`Self::release_authorization`] or
    /// [`Self::commit_authorization`]. Call this inside a
    /// [`ChannelStore::update_channel`] transition so the decision and the
    /// record are one atomic step.
    ///
    /// Only an authorization with no record at all is reservable. An existing
    /// reservation is never taken over or stepped past, however long its lease
    /// has been dead — see [`BatchReservation::Abandoned`].
    ///
    /// One cumulative step is in flight per channel: while another
    /// authorization holds a live or handler-succeeded reservation this one is
    /// [`BatchReservation::InProgress`]. Both would step from the same
    /// watermark, and whichever committed second could only charge what was
    /// left above the first.
    ///
    /// The request's `amount` must step the current watermark to its
    /// `cumulative`; otherwise the reservation is [`BatchReservation::Stale`],
    /// so a voucher priced from a watermark another commit has since moved is
    /// never served. A sealed or closing channel is
    /// [`BatchReservation::Closing`].
    pub fn reserve_authorization(&mut self, request: &AuthorizationRequest) -> BatchReservation {
        self.refuse_reservation(request)
            .unwrap_or_else(|| self.take_reservation(request))
    }

    /// [`Self::reserve_authorization`] with a staged setup: `stage` reads the
    /// record and returns the pending setup to install, which is applied only
    /// together with a [`BatchReservation::Reserved`] outcome. Any other
    /// outcome, or an error from `stage`, leaves the record untouched.
    pub fn reserve_authorization_staged(
        &mut self,
        request: &AuthorizationRequest,
        stage: impl FnOnce(&Self) -> Result<Option<PendingSetup>, StoreError>,
    ) -> Result<BatchReservation, StoreError> {
        if let Some(refused) = self.refuse_reservation(request) {
            return Ok(refused);
        }
        if let Some(setup) = stage(self)? {
            self.pending_setup = Some(setup);
        }
        Ok(self.take_reservation(request))
    }

    /// The outcome when `request` cannot take a new reservation; `None` when
    /// it can. Reads only.
    fn refuse_reservation(&self, request: &AuthorizationRequest) -> Option<BatchReservation> {
        let AuthorizationRequest {
            authorization_id,
            request_fingerprint,
            amount,
            cumulative,
            now,
            ..
        } = request;
        let (amount, cumulative, now) = (*amount, *cumulative, *now);
        if self.sealed || self.close_requested_at.is_some() {
            return Some(BatchReservation::Closing);
        }
        if let Some(outcome) =
            self.classify_authorization(authorization_id, request_fingerprint, cumulative, now)
        {
            return Some(outcome);
        }
        let mut others = self
            .pending_deliveries
            .iter()
            .filter(|pending| pending.delivery_id != *authorization_id);
        // Another authorization that outlived its lease without reporting may
        // still be running, or may have served its request before a crash.
        // Stepping past it would leave that work out of the watermark, so it
        // fences the channel until its owner releases or commits it.
        if others
            .clone()
            .any(|pending| !pending.handler_succeeded && pending.expires_at <= now)
        {
            return Some(BatchReservation::Abandoned);
        }
        if others.any(|pending| pending.handler_succeeded || pending.expires_at > now) {
            return Some(BatchReservation::InProgress);
        }
        if self.cumulative.checked_add(amount) != Some(cumulative) {
            return Some(BatchReservation::Stale);
        }
        None
    }

    /// Take the reservation [`Self::refuse_reservation`] cleared.
    fn take_reservation(&mut self, request: &AuthorizationRequest) -> BatchReservation {
        let AuthorizationRequest {
            authorization_id,
            request_fingerprint,
            amount,
            cumulative,
            lease,
            now,
        } = request;
        let (amount, cumulative, now) = (*amount, *cumulative, *now);
        self.prune_authorizations(now);
        self.next_delivery_sequence = self.next_delivery_sequence.saturating_add(1);
        let sequence = self.next_delivery_sequence;
        self.pending_deliveries.push(PendingDelivery {
            delivery_id: authorization_id.clone(),
            amount,
            sequence,
            // Past this the reservation is suspect rather than free: a retry is
            // refused instead of taking it over.
            expires_at: now.saturating_add(lease.as_secs() as i64),
            request_fingerprint: Some(request_fingerprint.clone()),
            handler_succeeded: false,
        });
        BatchReservation::Reserved(ReservationToken {
            authorization_id: authorization_id.clone(),
            request_fingerprint: request_fingerprint.clone(),
            cumulative,
            sequence,
        })
    }

    /// Record that the resource handler for `authorization_id` succeeded.
    ///
    /// This is the crash boundary: after it, no retry may run the handler
    /// again, only finish commitment.
    ///
    /// A reservation superseded over its dead lease is refused, so it can
    /// never come to block the channel as handler-succeeded.
    pub fn mark_authorization_handler_succeeded(
        &mut self,
        token: &ReservationToken,
    ) -> Result<(), StoreError> {
        // Already committed: the handler ran and its result is durable.
        if self
            .committed_authorization(&token.authorization_id)
            .is_some()
        {
            return Ok(());
        }
        let index = self.token_pending_index(token)?;
        self.pending_deliveries[index].handler_succeeded = true;
        Ok(())
    }

    /// Release the reservation on `authorization_id` after a handler failure,
    /// so the same authorization can be presented again.
    ///
    /// Idempotent. A reservation whose handler already succeeded is never
    /// released — that would let the same authorization run the handler twice.
    pub fn release_authorization(
        &mut self,
        authorization_id: &str,
        request_fingerprint: &str,
    ) -> Result<(), StoreError> {
        let Some(index) = self.owned_pending_index(authorization_id, request_fingerprint)? else {
            return Ok(());
        };
        if self.pending_deliveries[index].handler_succeeded {
            return Err(StoreError::Internal(format!(
                "authorization {authorization_id} already served its handler"
            )));
        }
        self.pending_deliveries.remove(index);
        Ok(())
    }

    /// Commit `authorization_id`: advance the voucher watermark and store the
    /// response that answered the request, in one transition.
    ///
    /// `response` is called on the committed state, so the stored response can
    /// carry the snapshot the client is being told about.
    ///
    /// Idempotent — committing an already-committed authorization leaves the
    /// stored response in place, so a retried transition (a CAS store re-running
    /// its updater) cannot charge twice.
    pub fn commit_authorization(
        &mut self,
        token: &ReservationToken,
        voucher_signature: &str,
        voucher_expires_at: i64,
        now: i64,
        response: impl FnOnce(&Self) -> Option<serde_json::Value>,
    ) -> Result<(), StoreError> {
        let authorization_id = token.authorization_id.as_str();
        let request_fingerprint = token.request_fingerprint.as_str();
        let cumulative = token.cumulative;
        if let Some(committed) = self.committed_authorization(authorization_id) {
            if committed.request_fingerprint.as_deref() != Some(request_fingerprint)
                || committed.cumulative != cumulative
            {
                return Err(StoreError::Internal(format!(
                    "authorization {authorization_id} was committed by a different request"
                )));
            }
            return Ok(());
        }
        let index = self.token_pending_index(token)?;
        // The counterpart of `has_blocking_authorization`: once the finalizer
        // has chosen the amount to seal at (`freeze_watermark_at`), or the
        // seal has landed, the watermark is frozen and a charge written now
        // could never be redeemed. Both transitions happen on this record
        // under the store's per-channel atomicity, so a commit either lands
        // before the choice and is included in it, or finds the fence and is
        // refused — however long its store call was delayed in between. The
        // request was served and the operator forfeits the charge; the
        // reservation lease exists to keep a handler inside the window where
        // its charge can still be applied.
        if self.sealed {
            return Err(StoreError::Internal(format!(
                "authorization {authorization_id} cannot be charged: the channel is sealed"
            )));
        }
        if let Some(fence) = self.final_cumulative {
            return Err(StoreError::Internal(format!(
                "authorization {authorization_id} cannot be charged: the channel's final \
                 watermark is fixed at {fence} for sealing"
            )));
        }
        if cumulative < self.cumulative {
            return Err(StoreError::Internal(format!(
                "authorization {authorization_id} would lower the watermark from {} to {cumulative}",
                self.cumulative
            )));
        }
        // The reservation priced one step from the watermark it was taken at;
        // if another commit moved it since, this voucher no longer pays for
        // the step it reserved.
        let reserved = self.pending_deliveries[index].amount;
        if self.cumulative.checked_add(reserved) != Some(cumulative) {
            return Err(StoreError::Internal(format!(
                "authorization {authorization_id} reserved {reserved} above the watermark, \
                 which is now {} and does not step to {cumulative}",
                self.cumulative
            )));
        }
        let charged = cumulative - self.cumulative;
        self.pending_deliveries.remove(index);
        self.cumulative = cumulative;
        self.spent_amount = self.spent_amount.max(cumulative);
        self.highest_voucher_signature = Some(voucher_signature.to_string());
        self.highest_voucher_expires_at = Some(voucher_expires_at);
        // Keep expiry non-decreasing with insertion order. This preserves the
        // deque's O(1) expired-prefix pruning even if a later voucher carries
        // an earlier expiry than its predecessor.
        let retain_until = voucher_expires_at
            .max(now)
            .saturating_add(DEFAULT_CHARGE_RECORD_RETENTION.as_secs() as i64)
            .max(
                self.committed_deliveries
                    .back()
                    .map_or(0, |entry| entry.retain_until),
            );
        self.committed_deliveries.push_back(CommittedDelivery {
            delivery_id: authorization_id.to_string(),
            amount: charged,
            cumulative,
            voucher_signature: voucher_signature.to_string(),
            request_fingerprint: Some(request_fingerprint.to_string()),
            settlement_response: None,
            cached_response: None,
            retain_until,
        });
        self.prune_authorizations(now);
        let stored = response(self);
        if let Some(index) = self
            .committed_deliveries
            .iter()
            .position(|entry| entry.delivery_id == authorization_id)
        {
            self.committed_deliveries[index].settlement_response = stored;
        }
        Ok(())
    }

    /// Attach a resource handler's response to an already-committed
    /// authorization, for [`CommittedDelivery::cached_response`].
    ///
    /// A separate step from [`Self::commit_authorization`] because the
    /// caller (the HTTP adapter) only has the response bytes available after
    /// the handler has already returned and the commit has already run — see
    /// `settle_batch`'s post-response hook. A missing target record (already
    /// pruned, or committed by a different, since-superseded request) is not
    /// an error: caching is a best-effort improvement to a future replay,
    /// never a requirement for this request's own success.
    pub fn attach_cached_response(
        &mut self,
        authorization_id: &str,
        cached: CachedUpstreamResponse,
    ) {
        if let Some(entry) = self
            .committed_deliveries
            .iter_mut()
            .find(|entry| entry.delivery_id == authorization_id)
        {
            entry.cached_response = Some(cached);
        }
    }

    /// Whether this record is carrying work that has not reached an outcome.
    ///
    /// Such a record must survive even when the chain says its channel does not
    /// exist: a channel being opened has a record before it has a PDA, because
    /// its setup transaction is only broadcast once the handler has succeeded.
    /// Dropping it would take the authorization with it — losing a charge that
    /// was served but never committed, or freeing one whose handler already ran
    /// to be served a second time.
    pub fn has_in_flight_authorization(&self) -> bool {
        self.pending_setup.is_some() || !self.pending_deliveries.is_empty()
    }

    /// Whether reserved work could still reach an outcome a close finalizer
    /// should wait for before sealing the channel.
    ///
    /// A reservation whose lease is still running may commit its charge, so
    /// sealing under it would strand that charge. A lease that has run out
    /// belongs to a request whose owner crashed or overran; nobody else ever
    /// takes it over or releases it (see [`Self::reserve_authorization`]), so
    /// waiting on it would block the seal forever, so it is treated as gone.
    /// The finalizer records its choice with [`Self::freeze_watermark_at`] in
    /// the same transition that consults this, and
    /// [`Self::commit_authorization`] refuses a fenced record, so a request
    /// that outlived its lease is either included in the seal or refused —
    /// never charged behind it.
    pub fn has_blocking_authorization(&self, now: i64) -> bool {
        let live = |expires_at: i64| expires_at > now;
        self.pending_setup
            .as_ref()
            .is_some_and(|setup| live(setup.expires_at))
            || self
                .pending_deliveries
                .iter()
                .any(|delivery| live(delivery.expires_at))
    }

    /// Record that the close finalizer will seal this channel carrying
    /// `cumulative`, so no later commit can advance the watermark past what
    /// the seal redeems. Must be called in the same atomic store transition
    /// that chose the amount. A later pass may revise the amount (an early
    /// seal that failed to land becomes a frozen seal after the deadline);
    /// the fence itself is never lifted.
    pub fn freeze_watermark_at(&mut self, cumulative: u64) {
        self.final_cumulative = Some(cumulative);
    }

    /// Drop the expired committed prefix, then bound the committed tail to
    /// [`MAX_COMMITTED_AUTHORIZATIONS`].
    ///
    /// Reservations are never dropped. A reservation is removed only by the
    /// request that owns it, releasing or committing it; anything left behind
    /// is the record that a handler may have run without reporting, and
    /// dropping it would make that authorization reservable — and servable —
    /// a second time. They accumulate one per crashed or overrunning request,
    /// which is bounded by how often that happens rather than by traffic.
    pub fn prune_authorizations(&mut self, now: i64) {
        while self
            .committed_deliveries
            .front()
            .is_some_and(|entry| entry.retain_until != 0 && entry.retain_until <= now)
        {
            self.committed_deliveries.pop_front();
        }
        // Commits append in non-decreasing cumulative order, so the front is
        // always the oldest authorization. A deque makes steady-state pruning
        // O(1); the previous Vec retained, sorted, and shifted up to 256 large
        // replay records on every paid request.
        while self.committed_deliveries.len() > MAX_COMMITTED_AUTHORIZATIONS {
            self.committed_deliveries.pop_front();
        }
    }
}

/// A decision about one channel record, made against the state a store
/// holds at the moment it acts; see [`ChannelStore::delete_channel_if`].
pub type ChannelPredicate = Box<dyn FnOnce(&ChannelState) -> bool + Send>;

/// An atomic in-place step on one channel record.
pub type ChannelMutator = Box<dyn FnOnce(&mut ChannelState) -> Result<(), StoreError> + Send>;

/// Borrowing reader passed to [`ChannelStore::read_channel`].
pub type ChannelReader = Box<dyn FnOnce(Option<&ChannelState>) -> Result<(), StoreError> + Send>;

/// Reads a channel record and returns the pending setup a reservation should
/// install with it; see [`ChannelState::reserve_authorization_staged`]. It
/// cannot write, so a refused reservation leaves nothing behind.
pub type ReservationStage =
    Box<dyn FnOnce(&ChannelState) -> Result<Option<PendingSetup>, StoreError> + Send>;

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

    /// Return the channel ids in this store without cloning channel records.
    ///
    /// Embedded lifecycle loops use this to apply a bounded scan budget before
    /// reading state. The default preserves compatibility for custom stores;
    /// in-memory stores override it so growing delivery histories never get
    /// copied merely to choose the next reconciliation candidates.
    fn list_channel_ids(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<String>, StoreError>> + Send + '_>> {
        Box::pin(async move {
            Ok(self
                .list_channels()
                .await?
                .into_iter()
                .map(|state| state.channel_id)
                .collect())
        })
    }

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

    /// Atomically delete the record only if `keep_unless` approves the state
    /// it holds at the moment of deletion. Returns whether it was deleted
    /// (`false` when absent, refused, or changed concurrently).
    ///
    /// A reconciler that decides from an earlier snapshot (no in-flight
    /// authorization, say) must delete through this, not
    /// [`Self::delete_channel`]: a request may reserve new work between the
    /// read and the delete, and the decision has to be re-made against the
    /// record that is actually removed. A lock-based store evaluates the
    /// predicate under the lock; an optimistic store evaluates it on a read
    /// and deletes only if the record is still byte-identical, reporting
    /// `false` otherwise so the caller retries on its next pass.
    fn delete_channel_if(
        &self,
        channel_id: &str,
        approve: ChannelPredicate,
    ) -> Pin<Box<dyn Future<Output = Result<bool, StoreError>> + Send + '_>>;

    /// Atomically read-modify-write channel state.
    ///
    /// The `updater` closure receives the current state (None if absent) and
    /// returns the new state or an error. Implementations MUST guarantee the
    /// entire read-modify-write is atomic, including unchanged results. A
    /// lock-based store must hold the lock through the updater; an optimistic
    /// store must validate the observed state with CAS even for a no-op, and
    /// report a conflict rather than succeed with an invalidated snapshot.
    fn update_channel(
        &self,
        channel_id: &str,
        updater: Box<dyn FnOnce(Option<ChannelState>) -> Result<ChannelState, StoreError> + Send>,
    ) -> Pin<Box<dyn Future<Output = Result<ChannelState, StoreError>> + Send + '_>>;

    /// Read channel state in place, without cloning the record.
    ///
    /// The `reader` receives `Option<&ChannelState>` (borrowed under the read
    /// guard) and extracts only the small values the caller needs, so a hot
    /// path can inspect a few fields without deep-cloning the whole state
    /// (String fields, the `extra` map, and the growing delivery Vecs). The
    /// reader MUST NOT re-enter the store for the same key.
    fn read_channel(
        &self,
        channel_id: &str,
        reader: ChannelReader,
    ) -> Pin<Box<dyn Future<Output = Result<(), StoreError>> + Send + '_>>;

    /// Atomically mutate channel state in place, without cloning the record.
    ///
    /// This is the allocation-free counterpart to [`Self::update_channel`] for
    /// the batch-settlement hot path. The `mutator` receives `&mut ChannelState`
    /// and returns only a small caller-selected result (typically captured out
    /// through the closure), so an in-memory backend can apply it under the
    /// shard write guard with ZERO clone of the state. Implementations MUST
    /// still guarantee the read-modify-write is atomic per channel.
    ///
    /// When the channel is absent, `seed` (if provided) is inserted first and
    /// then mutated in place; if the channel is absent and `seed` is `None`,
    /// the call fails. The mutator MUST NOT re-enter the store for the same key.
    fn mutate_channel(
        &self,
        channel_id: &str,
        seed: Option<ChannelState>,
        mutator: ChannelMutator,
    ) -> Pin<Box<dyn Future<Output = Result<(), StoreError>> + Send + '_>>;

    /// Atomically check and reserve one authorization on `channel_id`.
    ///
    /// One transition runs [`ChannelState::reserve_authorization_staged`]:
    /// its close fence and watermark step check decide the outcome, `prepare`
    /// (which may refuse by erroring) stages a setup applied only with a
    /// reservation, and a commit needs the token only that check mints. An
    /// override MUST keep all of it in one atomic read-modify-write and leave a
    /// refused record unchanged; [`conformance`] exercises it.
    fn reserve_authorization(
        &self,
        channel_id: &str,
        seed: Option<ChannelState>,
        request: AuthorizationRequest,
        prepare: ReservationStage,
    ) -> Pin<Box<dyn Future<Output = Result<BatchReservation, StoreError>> + Send + '_>> {
        let channel_id = channel_id.to_string();
        Box::pin(async move {
            let out = Arc::new(std::sync::Mutex::new(None));
            let sink = Arc::clone(&out);
            self.mutate_channel(
                &channel_id,
                seed,
                Box::new(move |state| {
                    let outcome = state.reserve_authorization_staged(&request, prepare)?;
                    *sink.lock().unwrap_or_else(|e| e.into_inner()) = Some(outcome);
                    Ok(())
                }),
            )
            .await?;
            let outcome = out.lock().unwrap_or_else(|e| e.into_inner()).take();
            outcome.ok_or_else(|| StoreError::Internal("reservation did not run".to_string()))
        })
    }

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

    fn list_channel_ids(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<String>, StoreError>> + Send + '_>> {
        (**self).list_channel_ids()
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

    fn delete_channel_if(
        &self,
        channel_id: &str,
        approve: ChannelPredicate,
    ) -> Pin<Box<dyn Future<Output = Result<bool, StoreError>> + Send + '_>> {
        (**self).delete_channel_if(channel_id, approve)
    }

    fn update_channel(
        &self,
        channel_id: &str,
        updater: Box<dyn FnOnce(Option<ChannelState>) -> Result<ChannelState, StoreError> + Send>,
    ) -> Pin<Box<dyn Future<Output = Result<ChannelState, StoreError>> + Send + '_>> {
        (**self).update_channel(channel_id, updater)
    }

    fn read_channel(
        &self,
        channel_id: &str,
        reader: Box<dyn FnOnce(Option<&ChannelState>) -> Result<(), StoreError> + Send>,
    ) -> Pin<Box<dyn Future<Output = Result<(), StoreError>> + Send + '_>> {
        (**self).read_channel(channel_id, reader)
    }

    fn mutate_channel(
        &self,
        channel_id: &str,
        seed: Option<ChannelState>,
        mutator: Box<dyn FnOnce(&mut ChannelState) -> Result<(), StoreError> + Send>,
    ) -> Pin<Box<dyn Future<Output = Result<(), StoreError>> + Send + '_>> {
        (**self).mutate_channel(channel_id, seed, mutator)
    }

    fn reserve_authorization(
        &self,
        channel_id: &str,
        seed: Option<ChannelState>,
        request: AuthorizationRequest,
        prepare: ReservationStage,
    ) -> Pin<Box<dyn Future<Output = Result<BatchReservation, StoreError>> + Send + '_>> {
        (**self).reserve_authorization(channel_id, seed, request, prepare)
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

    fn list_channel_ids(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<String>, StoreError>> + Send + '_>> {
        // Copy only the map keys. Channel records contain growing delivery
        // histories, so cloning every value for candidate selection makes a
        // lifecycle sweep increasingly expensive as traffic accumulates.
        let channel_ids = self.data.iter().map(|entry| entry.key().clone()).collect();
        Box::pin(async move { Ok(channel_ids) })
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

    fn delete_channel_if(
        &self,
        channel_id: &str,
        approve: ChannelPredicate,
    ) -> Pin<Box<dyn Future<Output = Result<bool, StoreError>> + Send + '_>> {
        // `remove_if` evaluates the predicate under the key's shard write
        // guard, so no request can change the record in between.
        let mut approve = Some(approve);
        let removed = self
            .data
            .remove_if(channel_id, |_, state| {
                approve.take().is_some_and(|approve| approve(state))
            })
            .is_some();
        Box::pin(async move { Ok(removed) })
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

    fn read_channel(
        &self,
        channel_id: &str,
        reader: Box<dyn FnOnce(Option<&ChannelState>) -> Result<(), StoreError> + Send>,
    ) -> Pin<Box<dyn Future<Output = Result<(), StoreError>> + Send + '_>> {
        // Borrow the record behind the key's shard read guard and let the
        // reader copy out only what it needs — no clone of the full state.
        let result = {
            let guard = self.data.get(channel_id);
            reader(guard.as_deref())
        };
        Box::pin(async move { result })
    }

    fn mutate_channel(
        &self,
        channel_id: &str,
        seed: Option<ChannelState>,
        mutator: Box<dyn FnOnce(&mut ChannelState) -> Result<(), StoreError> + Send>,
    ) -> Pin<Box<dyn Future<Output = Result<(), StoreError>> + Send + '_>> {
        use dashmap::mapref::entry::Entry;
        // Apply the mutation directly to the record behind this key's shard
        // write guard — no clone in, no clone out. The atomicity guarantee is
        // identical to `update_channel`; only the allocation is gone.
        let result = match self.data.entry(channel_id.to_string()) {
            Entry::Occupied(mut entry) => mutator(entry.get_mut()),
            Entry::Vacant(entry) => match seed {
                // Only an initial deposit seeds a new record; the seed is
                // inserted and then mutated in place, still under the guard.
                Some(seed) => {
                    let mut guard = entry.insert(seed);
                    mutator(guard.value_mut())
                }
                None => Err(StoreError::Internal("Channel not found".to_string())),
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

    fn delete_channel_if(
        &self,
        channel_id: &str,
        approve: ChannelPredicate,
    ) -> Pin<Box<dyn Future<Output = Result<bool, StoreError>> + Send + '_>> {
        let channel_id = channel_id.to_string();
        Box::pin(async move {
            let Some(raw) = self.get_raw(&channel_id).await? else {
                return Ok(false);
            };
            if !approve(&Self::decode(&raw)?) {
                return Ok(false);
            }
            // Delete only the exact value the predicate approved.
            const SCRIPT: &str = r#"
if redis.call('GET', KEYS[1]) == ARGV[1] then
  return redis.call('DEL', KEYS[1])
end
return 0
"#;
            let mut connection = self.connection.clone();
            let deleted: i32 = redis::Script::new(SCRIPT)
                .key(self.key(&channel_id))
                .arg(raw)
                .invoke_async(&mut connection)
                .await
                .map_err(|e| StoreError::Internal(format!("Redis compare-and-delete: {e}")))?;
            Ok(deleted == 1)
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

    fn read_channel(
        &self,
        channel_id: &str,
        reader: Box<dyn FnOnce(Option<&ChannelState>) -> Result<(), StoreError> + Send>,
    ) -> Pin<Box<dyn Future<Output = Result<(), StoreError>> + Send + '_>> {
        let channel_id = channel_id.to_string();
        Box::pin(async move {
            let raw = self.get_raw(&channel_id).await?;
            let state = raw.as_deref().map(Self::decode).transpose()?;
            reader(state.as_ref())
        })
    }

    fn mutate_channel(
        &self,
        channel_id: &str,
        seed: Option<ChannelState>,
        mutator: Box<dyn FnOnce(&mut ChannelState) -> Result<(), StoreError> + Send>,
    ) -> Pin<Box<dyn Future<Output = Result<(), StoreError>> + Send + '_>> {
        let channel_id = channel_id.to_string();
        Box::pin(async move {
            // A durable backend has to serialize regardless, so this decodes,
            // applies the mutation, and re-writes under the same compare-and-set
            // guard `update_channel` uses. The in-place win is the memory store's.
            let current_raw = self.get_raw(&channel_id).await?;
            let mut state = match current_raw.as_deref().map(Self::decode).transpose()? {
                Some(state) => state,
                None => {
                    seed.ok_or_else(|| StoreError::Internal("Channel not found".to_string()))?
                }
            };
            mutator(&mut state)?;
            let (new_raw, _) = Self::encode_for_write(state)?;
            if !self
                .compare_and_set(&channel_id, current_raw.as_deref(), &new_raw)
                .await?
            {
                return Err(StoreError::Internal(
                    "Concurrent channel update; retry the request".to_string(),
                ));
            }
            Ok(())
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

/// Behaviour every [`ChannelStore`] implementation must show, as one suite
/// each implementation's tests run.
#[cfg(any(test, feature = "testkit"))]
pub mod conformance {
    use super::*;

    const LEASE: Duration = CHARGE_RESERVATION_LEASE;

    fn request(id: &str, amount: u64, cumulative: u64, now: i64) -> AuthorizationRequest {
        AuthorizationRequest {
            authorization_id: id.to_string(),
            request_fingerprint: format!("fp-{id}"),
            amount,
            cumulative,
            lease: LEASE,
            now,
        }
    }

    async fn reserve(
        store: &dyn ChannelStore,
        channel_id: &str,
        request: AuthorizationRequest,
    ) -> BatchReservation {
        store
            .reserve_authorization(channel_id, None, request, Box::new(|_| Ok(None)))
            .await
            .unwrap()
    }

    async fn commit(store: &dyn ChannelStore, channel_id: &str, token: &ReservationToken) {
        let token = token.clone();
        store
            .mutate_channel(
                channel_id,
                None,
                Box::new(move |state| {
                    state.mark_authorization_handler_succeeded(&token)?;
                    state.commit_authorization(&token, "sig", 0, 100, |_| None)
                }),
            )
            .await
            .unwrap();
    }

    fn token(outcome: BatchReservation) -> ReservationToken {
        match outcome {
            BatchReservation::Reserved(token) => token,
            other => panic!("expected a reservation, got {other:?}"),
        }
    }

    /// An open channel record with a 10_000 deposit and a zero watermark.
    pub fn channel_state(channel_id: &str) -> ChannelState {
        let deposit = 10_000;
        ChannelState {
            channel_id: channel_id.to_string(),
            authorized_signer: "signer1".to_string(),
            deposit,
            cumulative: 0,
            sealed: false,
            highest_voucher_signature: None,
            highest_voucher_expires_at: None,
            close_requested_at: None,
            final_cumulative: None,
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
            distributed_on_chain: 0,
            processed_uses: vec![],
            processed_topup_signatures: vec![],
            next_delivery_sequence: 0,
            pending_deliveries: vec![],
            committed_deliveries: Default::default(),
            pending_setup: None,
            onchain_checked_at: 0,
            lifecycle: None,
            schema_version: CHANNEL_STATE_SCHEMA_VERSION,
            extra: Default::default(),
        }
    }

    /// The [`Store`] contract: conditional writes are atomic and exact.
    pub async fn check_store(store: &dyn Store) {
        let key = "conformance-store-cas";
        let v1 = serde_json::json!({ "v": 1 });
        let v2 = serde_json::json!({ "v": 2 });
        let v3 = serde_json::json!({ "v": 3 });
        assert!(!store
            .put_if_eq(key, Some(v1.clone()), v2.clone())
            .await
            .unwrap());
        assert_eq!(store.get(key).await.unwrap(), None);
        assert!(store.put_if_eq(key, None, v1.clone()).await.unwrap());
        assert!(!store.put_if_eq(key, None, v2.clone()).await.unwrap());
        assert!(!store
            .put_if_eq(key, Some(v3.clone()), v2.clone())
            .await
            .unwrap());
        assert!(store
            .put_if_eq(key, Some(v1.clone()), v2.clone())
            .await
            .unwrap());
        assert_eq!(store.get(key).await.unwrap(), Some(v2.clone()));
        assert!(!store.put_if_absent(key, v3.clone()).await.unwrap());

        // Writers racing from the same read: exactly one lands.
        let (left, right) = tokio::join!(
            store.put_if_eq(key, Some(v2.clone()), serde_json::json!({ "v": "left" })),
            store.put_if_eq(key, Some(v2.clone()), serde_json::json!({ "v": "right" })),
        );
        assert_eq!(
            [left.unwrap(), right.unwrap()]
                .iter()
                .filter(|won| **won)
                .count(),
            1
        );
    }

    /// Run the suite. `fresh` builds an open channel record with a deposit of
    /// at least 10_000 and a zero watermark that `store` accepts.
    pub async fn check_channel_store(
        store: &dyn ChannelStore,
        fresh: &(dyn Fn(&str) -> ChannelState + Sync),
    ) {
        refuses_a_reservation_from_a_moved_watermark(store, fresh).await;
        refuses_to_step_past_a_dead_unreported_lease(store, fresh).await;
        refuses_reservations_on_a_closing_channel(store, fresh).await;
        a_refused_preparation_reserves_nothing(store, fresh).await;
        a_refused_reservation_leaves_the_record_unchanged(store, fresh).await;
    }

    /// Run the deletion suite against a store a reconciliation worker uses.
    /// Request-path wrappers that refuse deletion outright skip it.
    pub async fn check_channel_store_deletion(
        store: &dyn ChannelStore,
        fresh: &(dyn Fn(&str) -> ChannelState + Sync),
    ) {
        a_conditional_delete_judges_the_record_it_removes(store, fresh).await;
    }

    /// A reconciler read the record with nothing in flight, then a request
    /// reserved work before the delete: the delete must see the reservation
    /// and keep the record.
    async fn a_conditional_delete_judges_the_record_it_removes(
        store: &dyn ChannelStore,
        fresh: &(dyn Fn(&str) -> ChannelState + Sync),
    ) {
        let id = "conformance-conditional-delete";
        store.put_channel(id, fresh(id)).await.unwrap();
        let snapshot = store.get_channel(id).await.unwrap().unwrap();
        assert!(!snapshot.has_in_flight_authorization());

        token(reserve(store, id, request("a", 500, 500, 100)).await);
        let idle =
            || -> ChannelPredicate { Box::new(|state| !state.has_in_flight_authorization()) };
        assert!(!store.delete_channel_if(id, idle()).await.unwrap());
        assert!(store
            .get_channel(id)
            .await
            .unwrap()
            .unwrap()
            .has_in_flight_authorization());

        store
            .update_channel(
                id,
                Box::new(|state| {
                    let mut state = state.unwrap();
                    state.pending_deliveries.clear();
                    Ok(state)
                }),
            )
            .await
            .unwrap();
        assert!(store.delete_channel_if(id, idle()).await.unwrap());
        assert!(store.get_channel(id).await.unwrap().is_none());
        assert!(!store.delete_channel_if(id, idle()).await.unwrap());
    }

    /// Two replicas price vouchers from the same watermark and the first
    /// commits before the second reserves: the second is refused before it is
    /// served, and leaves nothing that blocks the channel.
    async fn refuses_a_reservation_from_a_moved_watermark(
        store: &dyn ChannelStore,
        fresh: &(dyn Fn(&str) -> ChannelState + Sync),
    ) {
        let id = "conformance-moved";
        store.put_channel(id, fresh(id)).await.unwrap();
        let a = token(reserve(store, id, request("a", 500, 500, 100)).await);
        assert_eq!(
            reserve(store, id, request("b", 2_000, 2_000, 100)).await,
            BatchReservation::InProgress
        );
        commit(store, id, &a).await;
        assert_eq!(
            reserve(store, id, request("b", 2_000, 2_000, 100)).await,
            BatchReservation::Stale
        );
        let state = store.get_channel(id).await.unwrap().unwrap();
        assert_eq!(state.cumulative, 500);
        assert!(state.pending_deliveries.is_empty());
        let b = token(reserve(store, id, request("b2", 1_500, 2_000, 100)).await);
        commit(store, id, &b).await;
        assert_eq!(
            store.get_channel(id).await.unwrap().unwrap().cumulative,
            2_000
        );
    }

    /// A reservation whose lease ran out without reporting is never stepped
    /// past: its handler may still be running, and a later voucher committing
    /// first would leave that work out of the watermark. The overrunning owner
    /// can still account for it; a release reopens the channel.
    async fn refuses_to_step_past_a_dead_unreported_lease(
        store: &dyn ChannelStore,
        fresh: &(dyn Fn(&str) -> ChannelState + Sync),
    ) {
        let id = "conformance-lease";
        store.put_channel(id, fresh(id)).await.unwrap();
        let slow = token(reserve(store, id, request("slow", 500, 500, 100)).await);
        let after_lease = 100 + LEASE.as_secs() as i64 + 1;
        assert_eq!(
            reserve(store, id, request("next", 700, 700, after_lease)).await,
            BatchReservation::Abandoned
        );
        // The overrunning handler finishes and is charged.
        commit(store, id, &slow).await;
        assert_eq!(
            store.get_channel(id).await.unwrap().unwrap().cumulative,
            500
        );
        assert!(matches!(
            reserve(store, id, request("after", 200, 700, after_lease)).await,
            BatchReservation::Reserved(_)
        ));

        // Positive control: a dead lease its owner released does not block.
        let id = "conformance-lease-released";
        store.put_channel(id, fresh(id)).await.unwrap();
        token(reserve(store, id, request("slow", 500, 500, 100)).await);
        store
            .mutate_channel(
                id,
                None,
                Box::new(|state| state.release_authorization("slow", "fp-slow")),
            )
            .await
            .unwrap();
        assert!(matches!(
            reserve(store, id, request("next", 700, 700, after_lease)).await,
            BatchReservation::Reserved(_)
        ));
    }

    async fn refuses_reservations_on_a_closing_channel(
        store: &dyn ChannelStore,
        fresh: &(dyn Fn(&str) -> ChannelState + Sync),
    ) {
        let id = "conformance-closing";
        let mut state = fresh(id);
        state.close_requested_at = Some(1);
        store.put_channel(id, state).await.unwrap();
        assert_eq!(
            reserve(store, id, request("a", 500, 500, 100)).await,
            BatchReservation::Closing
        );
        assert!(store
            .get_channel(id)
            .await
            .unwrap()
            .unwrap()
            .pending_deliveries
            .is_empty());
    }

    async fn a_refused_preparation_reserves_nothing(
        store: &dyn ChannelStore,
        fresh: &(dyn Fn(&str) -> ChannelState + Sync),
    ) {
        let id = "conformance-prepare";
        store.put_channel(id, fresh(id)).await.unwrap();
        assert!(store
            .reserve_authorization(
                id,
                None,
                request("a", 500, 500, 100),
                Box::new(|_| Err(StoreError::Internal("refused".to_string()))),
            )
            .await
            .is_err());
        assert!(store
            .get_channel(id)
            .await
            .unwrap()
            .unwrap()
            .pending_deliveries
            .is_empty());
    }

    fn staged_setup(signature: &str) -> ReservationStage {
        let signature = signature.to_string();
        Box::new(move |_| {
            Ok(Some(PendingSetup {
                payer_signature: signature,
                deposit: 1_000,
                opens_channel: false,
                expires_at: i64::MAX,
            }))
        })
    }

    async fn snapshot(store: &dyn ChannelStore, id: &str) -> serde_json::Value {
        serde_json::to_value(store.get_channel(id).await.unwrap().unwrap()).unwrap()
    }

    /// Whatever refuses a reservation (a moved watermark, another request in
    /// flight, a closing channel), the setup it staged is never written, so a
    /// later reservation is not blocked by it.
    async fn a_refused_reservation_leaves_the_record_unchanged(
        store: &dyn ChannelStore,
        fresh: &(dyn Fn(&str) -> ChannelState + Sync),
    ) {
        let id = "conformance-refused";
        store.put_channel(id, fresh(id)).await.unwrap();
        let first = token(reserve(store, id, request("a", 500, 500, 100)).await);
        commit(store, id, &first).await;

        let before = snapshot(store, id).await;
        let stale = store
            .reserve_authorization(
                id,
                None,
                request("stale", 1_000, 1_000, 100),
                staged_setup("topup-stale"),
            )
            .await
            .unwrap();
        assert_eq!(stale, BatchReservation::Stale);
        assert_eq!(snapshot(store, id).await, before);

        let held = token(reserve(store, id, request("held", 500, 1_000, 100)).await);
        let before = snapshot(store, id).await;
        let busy = store
            .reserve_authorization(
                id,
                None,
                request("busy", 1_000, 2_000, 100),
                staged_setup("topup-busy"),
            )
            .await
            .unwrap();
        assert_eq!(busy, BatchReservation::InProgress);
        assert_eq!(snapshot(store, id).await, before);
        commit(store, id, &held).await;

        // A fresh reservation still installs its own staged setup.
        let fresh_topup = store
            .reserve_authorization(
                id,
                None,
                request("fresh", 500, 1_500, 100),
                staged_setup("topup-fresh"),
            )
            .await
            .unwrap();
        assert!(matches!(fresh_topup, BatchReservation::Reserved(_)));
        let state = store.get_channel(id).await.unwrap().unwrap();
        assert_eq!(
            state.pending_setup.map(|setup| setup.payer_signature),
            Some("topup-fresh".to_string())
        );

        let closing = "conformance-refused-closing";
        let mut state = fresh(closing);
        state.close_requested_at = Some(1);
        store.put_channel(closing, state).await.unwrap();
        let before = snapshot(store, closing).await;
        let refused = store
            .reserve_authorization(
                closing,
                None,
                request("a", 500, 500, 100),
                staged_setup("topup-closing"),
            )
            .await
            .unwrap();
        assert_eq!(refused, BatchReservation::Closing);
        assert_eq!(snapshot(store, closing).await, before);
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

    // A signature claimed under a pre-ledger key (by an older replica, or
    // just before an upgrade) stays consumed for every claim path, and the
    // legacy record is only read, never rewritten.
    async fn assert_legacy_key_stays_consumed(legacy_key: &str) {
        let raw: Arc<dyn Store> = Arc::new(MemoryStore::new());
        let ledger = ConsumedSignatures::new(raw.clone());
        raw.put(legacy_key, serde_json::json!(true)).await.unwrap();

        assert!(!ledger.claim("sig-legacy").await.unwrap(), "{legacy_key}");
        assert_eq!(
            ledger.claim_pending("sig-legacy").await.unwrap(),
            PendingClaim::Consumed,
            "{legacy_key}"
        );
        assert!(raw
            .get(&consumed_signature_key("sig-legacy"))
            .await
            .unwrap()
            .is_none());
        assert_eq!(
            raw.get(legacy_key).await.unwrap(),
            Some(serde_json::json!(true))
        );

        // Signatures without a legacy record claim normally.
        assert!(ledger.claim("sig-fresh").await.unwrap());
        assert_eq!(
            ledger.claim_pending("sig-other").await.unwrap(),
            PendingClaim::Fresh
        );
    }

    // Rolling upgrade: a replica on the previous release claims and checks
    // only its own legacy key. Every claim takes those keys too, so such a
    // replica refuses a payment this release accepted.
    #[tokio::test]
    async fn a_claim_is_visible_to_replicas_on_the_previous_release() {
        let raw: Arc<dyn Store> = Arc::new(MemoryStore::new());
        let ledger = ConsumedSignatures::new(raw.clone());
        let old_replica_claims = |raw: Arc<dyn Store>, key: String| async move {
            raw.put_if_absent(&key, serde_json::json!(true))
                .await
                .unwrap()
        };

        assert!(ledger.claim("sig-new").await.unwrap());
        assert_eq!(
            ledger.claim_pending("sig-pending").await.unwrap(),
            PendingClaim::Fresh
        );
        for signature in ["sig-new", "sig-pending"] {
            for key in legacy_consumed_signature_keys(signature) {
                assert!(!old_replica_claims(raw.clone(), key.clone()).await, "{key}");
            }
        }
        // Resuming this release's own pending claim is still a resume.
        assert_eq!(
            ledger.claim_pending("sig-pending").await.unwrap(),
            PendingClaim::ResumePending
        );

        // A release gives every key back, so the payer may retry and an
        // older replica is not left refusing a payment that never landed.
        assert!(ledger.release_pending("sig-pending").await.unwrap());
        for key in legacy_consumed_signature_keys("sig-pending") {
            assert!(raw.get(&key).await.unwrap().is_none(), "{key}");
        }
        assert!(ledger.claim("sig-pending").await.unwrap());
    }

    // A release only gives back a claim still holding what its caller wrote.
    // A holder that saw the transaction as unlanded (say on a lagging node)
    // must not erase a claim a resumed settlement has since confirmed.
    #[tokio::test]
    async fn a_release_never_erases_a_confirmed_claim() {
        let raw: Arc<dyn Store> = Arc::new(MemoryStore::new());
        let ledger = ConsumedSignatures::new(raw.clone());
        assert_eq!(
            ledger.claim_pending("sig-race").await.unwrap(),
            PendingClaim::Fresh
        );
        assert_eq!(
            ledger.claim_pending("sig-race").await.unwrap(),
            PendingClaim::ResumePending
        );
        assert!(ledger.confirm("sig-race").await.unwrap());

        assert!(!ledger.release_pending("sig-race").await.unwrap());
        assert_eq!(
            ledger.claim_pending("sig-race").await.unwrap(),
            PendingClaim::Consumed
        );
        for key in legacy_consumed_signature_keys("sig-race") {
            assert!(raw.get(&key).await.unwrap().is_some(), "{key}");
        }

        // Positive control: an unconfirmed pending claim is released, and a
        // later claim takes the released key over.
        assert_eq!(
            ledger.claim_pending("sig-free").await.unwrap(),
            PendingClaim::Fresh
        );
        assert!(ledger.release_pending("sig-free").await.unwrap());
        assert!(ledger.claim("sig-free").await.unwrap());
        assert!(!ledger.claim("sig-free").await.unwrap());
    }

    // A previous release's claim on one legacy key refuses the signature, and
    // the keys this claim took before finding it are given back.
    #[tokio::test]
    async fn a_refused_claim_gives_back_the_legacy_keys_it_took() {
        let raw: Arc<dyn Store> = Arc::new(MemoryStore::new());
        let ledger = ConsumedSignatures::new(raw.clone());
        let held = format!("x402-exact:consumed:{}:sig-old", LEGACY_X402_NETWORKS[2]);
        raw.put(&held, serde_json::json!(true)).await.unwrap();

        assert!(!ledger.claim("sig-old").await.unwrap());
        for key in legacy_consumed_signature_keys("sig-old") {
            let expected = (key == held).then_some(serde_json::Value::Bool(true));
            assert_eq!(raw.get(&key).await.unwrap(), expected, "{key}");
        }
        assert!(raw
            .get(&consumed_signature_key("sig-old"))
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn legacy_mpp_charge_claim_stays_consumed() {
        assert_legacy_key_stays_consumed("solana-charge:consumed:sig-legacy").await;
    }

    #[tokio::test]
    async fn legacy_x402_exact_claim_stays_consumed_on_every_network() {
        for network in LEGACY_X402_NETWORKS {
            assert_legacy_key_stays_consumed(&format!("x402-exact:consumed:{network}:sig-legacy"))
                .await;
        }
    }

    // The legacy x402 key was scoped by `caip2_network_for_cluster`; every
    // network it can return must be checked.
    #[cfg(feature = "x402")]
    #[test]
    fn legacy_x402_networks_cover_every_caip2_cluster() {
        use crate::x402::protocol::schemes::exact::caip2_network_for_cluster;
        for cluster in ["mainnet", "devnet", "testnet", "localnet", "unknown"] {
            assert!(
                LEGACY_X402_NETWORKS.contains(&caip2_network_for_cluster(cluster)),
                "{cluster}"
            );
        }
    }

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
        assert_eq!(outcome, ChargeReservation::Reserved { generation: 0 });
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
        assert!(store.mark_confirmed("chal-3", 0, "sig-abc").await.unwrap());

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
        assert!(store
            .mark_failed("chal-4", 0, "simulation failed")
            .await
            .unwrap());

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
    async fn charge_replay_pending_record_hands_back_its_signature() {
        let store = replay_store();
        let ChargeReservation::Reserved { generation } = store
            .reserve("chal-p", "digest-a", Duration::from_secs(0))
            .await
            .unwrap()
        else {
            panic!("expected a fresh reservation");
        };
        assert!(store
            .mark_pending("chal-p", generation, "sig-pending")
            .await
            .unwrap());
        // Only the reservation's owner records the broadcast.
        assert!(!store
            .mark_pending("chal-p", generation, "sig-other")
            .await
            .unwrap());

        // Never lease-reclaimed into a fresh settlement: the broadcast may land.
        let outcome = store
            .reserve("chal-p", "digest-a", Duration::from_secs(0))
            .await
            .unwrap();
        assert_eq!(
            outcome,
            ChargeReservation::PendingConfirmation {
                generation: generation + 1,
                final_signature: "sig-pending".to_string()
            }
        );
        let outcome = store
            .reserve("chal-p", "digest-b", CHARGE_RESERVATION_LEASE)
            .await
            .unwrap();
        assert_eq!(outcome, ChargeReservation::Conflict);

        assert!(store
            .mark_confirmed("chal-p", generation + 1, "sig-pending")
            .await
            .unwrap());
        let outcome = store
            .reserve("chal-p", "digest-a", CHARGE_RESERVATION_LEASE)
            .await
            .unwrap();
        assert_eq!(
            outcome,
            ChargeReservation::AlreadyConfirmed {
                final_signature: "sig-pending".to_string()
            }
        );
    }

    #[tokio::test]
    async fn charge_replay_pending_confirmation_has_one_winner() {
        let store = replay_store();
        let ChargeReservation::Reserved { generation } = store
            .reserve("chal-pc", "digest-a", CHARGE_RESERVATION_LEASE)
            .await
            .unwrap()
        else {
            panic!("expected a fresh reservation");
        };
        assert!(store
            .mark_pending("chal-pc", generation, "sig-pending")
            .await
            .unwrap());
        let pending = generation + 1;
        // Only the recorded signature at the current generation confirms.
        assert!(!store
            .confirm_pending("chal-pc", generation, "sig-pending")
            .await
            .unwrap());
        assert!(!store
            .confirm_pending("chal-pc", pending, "sig-other")
            .await
            .unwrap());
        assert!(store
            .confirm_pending("chal-pc", pending, "sig-pending")
            .await
            .unwrap());
        // A concurrent reconciler of the same pending generation loses.
        assert!(!store
            .confirm_pending("chal-pc", pending, "sig-pending")
            .await
            .unwrap());
        assert_eq!(
            store
                .reserve("chal-pc", "digest-a", CHARGE_RESERVATION_LEASE)
                .await
                .unwrap(),
            ChargeReservation::AlreadyConfirmed {
                final_signature: "sig-pending".to_string()
            }
        );
    }

    #[tokio::test]
    async fn charge_replay_pending_record_fails_only_for_its_generation() {
        let store = replay_store();
        let ChargeReservation::Reserved { generation } = store
            .reserve("chal-pf", "digest-a", CHARGE_RESERVATION_LEASE)
            .await
            .unwrap()
        else {
            panic!("expected a fresh reservation");
        };
        assert!(store
            .mark_pending("chal-pf", generation, "sig-pending")
            .await
            .unwrap());
        // The reservation generation is superseded by the pending one.
        assert!(!store
            .mark_failed("chal-pf", generation, "stale")
            .await
            .unwrap());
        assert!(store
            .mark_failed("chal-pf", generation + 1, "expired without landing")
            .await
            .unwrap());
        assert_eq!(
            store
                .reserve("chal-pf", "digest-a", CHARGE_RESERVATION_LEASE)
                .await
                .unwrap(),
            ChargeReservation::AlreadyFailed {
                reason: "expired without landing".to_string()
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
        assert!(store.mark_confirmed("chal-5", 0, "sig-abc").await.unwrap());
        let outcome = store
            .reserve("chal-5", "digest-b", CHARGE_RESERVATION_LEASE)
            .await
            .unwrap();
        assert_eq!(outcome, ChargeReservation::Conflict);
    }

    // A store that expired the root key of a record independently of its
    // generations must not let the challenge settle again: the surviving
    // confirmed generation is authoritative.
    #[tokio::test]
    async fn charge_replay_never_recreates_a_root_over_surviving_generations() {
        let raw: Arc<dyn Store> = Arc::new(MemoryStore::new());
        let store = ChargeReplayStore::new(raw.clone());
        store
            .reserve("chal-ttl", "digest-a", CHARGE_RESERVATION_LEASE)
            .await
            .unwrap();
        assert!(store.mark_confirmed("chal-ttl", 0, "sig-a").await.unwrap());
        raw.delete("solana-charge:record:chal-ttl").await.unwrap();

        for digest in ["digest-a", "digest-b"] {
            let err = store
                .reserve("chal-ttl", digest, CHARGE_RESERVATION_LEASE)
                .await
                .unwrap_err();
            assert!(err.to_string().contains("lost its root"), "{err}");
        }
        assert!(raw
            .get("solana-charge:record:chal-ttl")
            .await
            .unwrap()
            .is_none());

        // A challenge with no record at all still reserves normally.
        assert_eq!(
            store
                .reserve("chal-new", "digest-a", CHARGE_RESERVATION_LEASE)
                .await
                .unwrap(),
            ChargeReservation::Reserved { generation: 0 }
        );
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
        assert_eq!(outcome, ChargeReservation::Reserved { generation: 1 });
    }

    #[tokio::test]
    async fn charge_replay_mark_confirmed_without_reservation_errors() {
        let store = replay_store();
        let err = store
            .mark_confirmed("never-reserved", 0, "sig-abc")
            .await
            .unwrap_err();
        assert!(matches!(err, StoreError::Internal(_)));
    }

    #[tokio::test]
    async fn charge_replay_stale_owner_cannot_overwrite_a_takeover() {
        let store = replay_store();
        // Owner A's lease has expired while it is still settling.
        let stale = store
            .reserve("chal-stale", "digest-a", Duration::ZERO)
            .await
            .unwrap();
        assert_eq!(stale, ChargeReservation::Reserved { generation: 0 });
        let takeover = store
            .reserve("chal-stale", "digest-a", CHARGE_RESERVATION_LEASE)
            .await
            .unwrap();
        assert_eq!(takeover, ChargeReservation::Reserved { generation: 1 });

        // While B holds the takeover, A's late failure is fenced out.
        assert!(!store
            .mark_failed("chal-stale", 0, "stale-worker-rpc-timeout")
            .await
            .unwrap());
        assert_eq!(
            store
                .reserve("chal-stale", "digest-a", CHARGE_RESERVATION_LEASE)
                .await
                .unwrap(),
            ChargeReservation::InProgress
        );

        // ...and so is its late confirmation.
        assert!(!store
            .mark_confirmed("chal-stale", 0, "stale-worker-signature")
            .await
            .unwrap());
        assert!(store
            .mark_confirmed("chal-stale", 1, "newer-worker-signature")
            .await
            .unwrap());
        // Neither the stale owner nor the confirmed owner can fail it now.
        assert!(!store
            .mark_failed("chal-stale", 0, "stale-worker-rpc-timeout")
            .await
            .unwrap());
        assert!(!store.mark_failed("chal-stale", 1, "late").await.unwrap());
        assert_eq!(
            store
                .reserve("chal-stale", "digest-a", CHARGE_RESERVATION_LEASE)
                .await
                .unwrap(),
            ChargeReservation::AlreadyConfirmed {
                final_signature: "newer-worker-signature".to_string()
            }
        );
    }

    #[tokio::test]
    async fn charge_replay_confirmed_record_survives_a_stale_failure() {
        let raw: Arc<dyn Store> = Arc::new(MemoryStore::new());
        let store = ChargeReplayStore::new(raw.clone());
        assert_eq!(
            store
                .reserve("chal-keep", "same-credential", Duration::ZERO)
                .await
                .unwrap(),
            ChargeReservation::Reserved { generation: 0 }
        );
        assert_eq!(
            store
                .reserve("chal-keep", "same-credential", CHARGE_RESERVATION_LEASE)
                .await
                .unwrap(),
            ChargeReservation::Reserved { generation: 1 }
        );
        assert!(store
            .mark_confirmed("chal-keep", 1, "confirmed-by-reclaimer")
            .await
            .unwrap());
        assert!(!store
            .mark_failed("chal-keep", 0, "stale-owner-settlement-error")
            .await
            .unwrap());

        // The confirmed generation is the latest one, with its signature.
        assert!(raw
            .get("solana-charge:record:chal-keep:3")
            .await
            .unwrap()
            .is_none());
        let record: ChargeRecord = serde_json::from_value(
            raw.get("solana-charge:record:chal-keep:2")
                .await
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(record.state, ChargeRecordState::Confirmed);
        assert_eq!(
            record.final_signature.as_deref(),
            Some("confirmed-by-reclaimer")
        );
        assert_eq!(record.failure_reason, None);
        assert_eq!(
            store
                .reserve("chal-keep", "same-credential", CHARGE_RESERVATION_LEASE)
                .await
                .unwrap(),
            ChargeReservation::AlreadyConfirmed {
                final_signature: "confirmed-by-reclaimer".to_string()
            }
        );

        // The current owner of a live reservation still records its failure.
        store
            .reserve("chal-own", "same-credential", CHARGE_RESERVATION_LEASE)
            .await
            .unwrap();
        assert!(store
            .mark_failed("chal-own", 0, "simulation failed")
            .await
            .unwrap());
        assert!(!store
            .mark_failed("chal-own", 0, "second failure")
            .await
            .unwrap());
    }

    // A failure recorded by a takeover already let the client move on (the
    // gate re-challenges it), so a stale owner's late confirmation must not
    // rewrite it into a second, silent success; and an owner that recorded
    // its broadcast as pending is never taken over at all.
    #[tokio::test]
    async fn charge_replay_stale_owner_cannot_confirm_over_a_takeover() {
        let store = replay_store();
        store
            .reserve("chal-late", "digest-a", Duration::ZERO)
            .await
            .unwrap();
        // B takes over A's expired lease and fails.
        assert_eq!(
            store
                .reserve("chal-late", "digest-a", CHARGE_RESERVATION_LEASE)
                .await
                .unwrap(),
            ChargeReservation::Reserved { generation: 1 }
        );
        assert!(store
            .mark_failed("chal-late", 1, "signature already consumed")
            .await
            .unwrap());
        // A, fenced at generation 0, can neither begin a broadcast nor confirm.
        assert!(!store.mark_pending("chal-late", 0, "sig-a").await.unwrap());
        assert!(!store.mark_confirmed("chal-late", 0, "sig-a").await.unwrap());
        assert!(!store.record_confirmed("chal-late", "sig-a").await.unwrap());
        assert_eq!(
            store
                .reserve("chal-late", "digest-a", CHARGE_RESERVATION_LEASE)
                .await
                .unwrap(),
            ChargeReservation::AlreadyFailed {
                reason: "signature already consumed".to_string()
            }
        );

        // An owner that recorded its broadcast first keeps the record past
        // its lease, and only its own signature confirms it.
        store
            .reserve("chal-own", "digest-a", Duration::ZERO)
            .await
            .unwrap();
        assert!(store.mark_pending("chal-own", 0, "sig-a").await.unwrap());
        assert_eq!(
            store
                .reserve("chal-own", "digest-a", CHARGE_RESERVATION_LEASE)
                .await
                .unwrap(),
            ChargeReservation::PendingConfirmation {
                generation: 1,
                final_signature: "sig-a".to_string()
            }
        );
        assert!(!store
            .mark_confirmed("chal-own", 1, "sig-other")
            .await
            .unwrap());
        assert!(store.mark_confirmed("chal-own", 1, "sig-a").await.unwrap());
    }

    // A pending broadcast proven unsent returns to a reclaimable reservation.
    #[tokio::test]
    async fn charge_replay_released_pending_record_is_reclaimable() {
        let store = replay_store();
        store
            .reserve("chal-rel", "digest-a", CHARGE_RESERVATION_LEASE)
            .await
            .unwrap();
        assert!(store.mark_pending("chal-rel", 0, "sig-a").await.unwrap());
        assert!(!store
            .release_pending("chal-rel", 1, "sig-other")
            .await
            .unwrap());
        assert!(store.release_pending("chal-rel", 1, "sig-a").await.unwrap());
        assert_eq!(
            store
                .reserve("chal-rel", "digest-a", CHARGE_RESERVATION_LEASE)
                .await
                .unwrap(),
            ChargeReservation::Reserved { generation: 3 }
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn charge_replay_concurrent_takeover_of_expired_lease_wins_exactly_once() {
        const TASKS: usize = 16;
        let store = Arc::new(replay_store());
        store
            .reserve("chal-takeover", "digest-a", Duration::ZERO)
            .await
            .unwrap();
        let barrier = Arc::new(tokio::sync::Barrier::new(TASKS));
        let mut handles = Vec::with_capacity(TASKS);
        for _ in 0..TASKS {
            let store = store.clone();
            let barrier = barrier.clone();
            handles.push(tokio::spawn(async move {
                barrier.wait().await;
                store
                    .reserve("chal-takeover", "digest-a", CHARGE_RESERVATION_LEASE)
                    .await
                    .unwrap()
            }));
        }
        let mut winners = Vec::new();
        for handle in handles {
            match handle.await.unwrap() {
                ChargeReservation::Reserved { generation } => winners.push(generation),
                ChargeReservation::InProgress => {}
                other => panic!("unexpected outcome: {other:?}"),
            }
        }
        assert_eq!(winners, vec![1]);
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
                ChargeReservation::Reserved { .. } => reserved += 1,
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
            final_cumulative: None,
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
            distributed_on_chain: 0,
            processed_uses: vec![],
            processed_topup_signatures: vec![],
            next_delivery_sequence: 0,
            pending_deliveries: vec![],
            committed_deliveries: Default::default(),
            pending_setup: None,
            onchain_checked_at: 0,
            lifecycle: None,
            schema_version: CHANNEL_STATE_SCHEMA_VERSION,
            extra: Default::default(),
        }
    }

    const LEASE: Duration = CHARGE_RESERVATION_LEASE;

    fn req(id: &str, fp: &str, amount: u64, cumulative: u64, now: i64) -> AuthorizationRequest {
        AuthorizationRequest {
            authorization_id: id.to_string(),
            request_fingerprint: fp.to_string(),
            amount,
            cumulative,
            lease: LEASE,
            now,
        }
    }

    fn token_for(state: &ChannelState, id: &str, fp: &str, cumulative: u64) -> ReservationToken {
        ReservationToken::for_pending(state, id, fp, cumulative)
    }

    /// A handler failure releases the authorization, and the same request may
    /// then reserve it again — the retry the client is entitled to.
    #[test]
    fn a_released_authorization_is_reservable_again() {
        let mut state = make_state("c1", 10_000);
        let reserve = |state: &mut ChannelState| {
            state.reserve_authorization(&req("access:c1:1000", "fp", 1_000, 1_000, 100))
        };
        assert!(matches!(reserve(&mut state), BatchReservation::Reserved(_)));
        // A second attempt while the first is live must not run the handler.
        assert_eq!(reserve(&mut state), BatchReservation::InProgress);

        state.release_authorization("access:c1:1000", "fp").unwrap();
        assert!(matches!(reserve(&mut state), BatchReservation::Reserved(_)));
        assert_eq!(
            state.cumulative, 0,
            "a released authorization charges nothing"
        );
    }

    /// The crash boundary: once the handler has succeeded, no retry may run it
    /// again — not even after the reservation lease has run out.
    #[test]
    fn a_succeeded_handler_outranks_its_lease() {
        let mut state = make_state("c1", 10_000);
        state.reserve_authorization(&req("access:c1:1000", "fp", 1_000, 1_000, 100));
        state
            .mark_authorization_handler_succeeded(&token_for(&state, "access:c1:1000", "fp", 0))
            .unwrap();

        let after_lease = 100 + LEASE.as_secs() as i64 + 1;
        assert!(matches!(
            state.reserve_authorization(&req("access:c1:1000", "fp", 1_000, 1_000, after_lease)),
            BatchReservation::HandlerSucceeded(_)
        ));
        // And it is not swept as an abandoned reservation.
        state.prune_authorizations(after_lease);
        assert!(matches!(
            state.classify_authorization("access:c1:1000", "fp", 1_000, after_lease),
            Some(BatchReservation::HandlerSucceeded(_))
        ));
        // Releasing it would let the same voucher serve twice.
        assert!(state.release_authorization("access:c1:1000", "fp").is_err());
    }

    /// A record with work in flight must survive a chain that says its channel
    /// is not there — that is the normal state of a channel being opened.
    #[test]
    fn a_record_with_work_in_flight_is_not_droppable() {
        let mut state = make_state("c1", 10_000);
        assert!(
            !state.has_in_flight_authorization(),
            "a settled record is droppable"
        );

        state.reserve_authorization(&req("access:c1:1000", "fp", 1_000, 1_000, 100));
        assert!(
            state.has_in_flight_authorization(),
            "a reservation must be kept"
        );

        state
            .mark_authorization_handler_succeeded(&token_for(&state, "access:c1:1000", "fp", 0))
            .unwrap();
        assert!(
            state.has_in_flight_authorization(),
            "a served-but-uncharged authorization must be kept"
        );

        state
            .commit_authorization(
                &token_for(&state, "access:c1:1000", "fp", 1_000),
                "sig",
                0,
                100,
                |_| None,
            )
            .unwrap();
        assert!(
            !state.has_in_flight_authorization(),
            "once committed there is nothing left in flight"
        );

        // A channel being opened holds no reservation of its own once released,
        // but its setup transaction has not been broadcast yet.
        state.pending_setup = Some(PendingSetup {
            deposit: 10_000,
            expires_at: 200,
            opens_channel: true,
            payer_signature: "sig".to_string(),
        });
        assert!(state.has_in_flight_authorization());
    }

    /// A reservation nobody reported an outcome for is terminal. The handler
    /// may have run, and the scheme forbids serving one authorization twice.
    #[test]
    fn an_abandoned_reservation_is_never_served_again() {
        let mut state = make_state("c1", 10_000);
        assert!(matches!(
            state.reserve_authorization(&req("access:c1:1000", "fp", 1_000, 1_000, 100)),
            BatchReservation::Reserved(_)
        ));

        // Its owner crashed mid-request: no release, no success marker.
        let after_lease = 100 + LEASE.as_secs() as i64 + 1;
        assert_eq!(
            state.reserve_authorization(&req("access:c1:1000", "fp", 1_000, 1_000, after_lease)),
            BatchReservation::Abandoned,
            "an unreported reservation must never be taken over"
        );

        // Pruning must not launder it into a fresh reservation either.
        state.prune_authorizations(after_lease);
        assert_eq!(
            state.reserve_authorization(&req("access:c1:1000", "fp", 1_000, 1_000, after_lease)),
            BatchReservation::Abandoned
        );
        assert_eq!(state.cumulative, 0, "and it is never charged");
    }

    /// A retry after a lost response returns the original result rather than
    /// re-serving or synthesizing a zero charge.
    #[test]
    fn a_committed_authorization_replays_its_stored_response() {
        let mut state = make_state("c1", 10_000);
        state.reserve_authorization(&req("access:c1:1000", "fp", 1_000, 1_000, 100));
        state
            .mark_authorization_handler_succeeded(&token_for(&state, "access:c1:1000", "fp", 0))
            .unwrap();
        state
            .commit_authorization(
                &token_for(&state, "access:c1:1000", "fp", 1_000),
                "sig",
                0,
                100,
                |committed| {
                    Some(serde_json::json!({ "chargedAmount": committed.cumulative.to_string() }))
                },
            )
            .unwrap();

        assert_eq!(state.cumulative, 1_000);
        assert_eq!(state.highest_voucher_signature.as_deref(), Some("sig"));
        assert_eq!(
            state.reserve_authorization(&req("access:c1:1000", "fp", 1_000, 1_000, 200)),
            BatchReservation::Committed,
            "a committed authorization must replay, not reserve"
        );
        let stored = state
            .committed_authorization("access:c1:1000")
            .and_then(|committed| committed.settlement_response.clone())
            .expect("the response returned for it is stored");
        assert_eq!(stored["chargedAmount"], serde_json::json!("1000"));
        // Re-committing is a no-op: the watermark cannot advance twice.
        state
            .commit_authorization(
                &token_for(&state, "access:c1:1000", "fp", 1_000),
                "sig",
                0,
                200,
                |_| None,
            )
            .unwrap();
        assert_eq!(state.cumulative, 1_000);
    }

    /// The id names the authorization; the fingerprint proves it is the same
    /// request. A different request presenting the same id is refused rather
    /// than handed another request's reservation.
    #[test]
    fn a_different_request_cannot_reuse_an_authorization() {
        let mut state = make_state("c1", 10_000);
        state.reserve_authorization(&req("access:c1:1000", "fp", 1_000, 1_000, 100));
        assert_eq!(
            state.reserve_authorization(&req("access:c1:1000", "other", 1_000, 1_000, 100)),
            BatchReservation::Conflict
        );
        assert!(state
            .mark_authorization_handler_succeeded(&token_for(&state, "access:c1:1000", "other", 0))
            .is_err());
        assert!(state
            .release_authorization("access:c1:1000", "other")
            .is_err());
    }

    /// Two different cumulative vouchers from the same watermark cannot both be
    /// reserved, and a commit must still step from the watermark its
    /// reservation priced.
    #[test]
    fn one_cumulative_step_is_reserved_at_a_time() {
        let mut state = make_state("c1", 10_000);
        assert!(matches!(
            state.reserve_authorization(&req("access:c1:500", "low", 500, 500, 100)),
            BatchReservation::Reserved(_)
        ));
        assert_eq!(
            state.reserve_authorization(&req("access:c1:2000", "high", 2_000, 2_000, 100)),
            BatchReservation::InProgress,
            "a second step from the same watermark must wait"
        );
        state
            .commit_authorization(
                &token_for(&state, "access:c1:500", "low", 500),
                "sig-low",
                0,
                100,
                |_| None,
            )
            .unwrap();
        // The high voucher was priced from the old watermark: it is refused
        // before serving, not served and then refused at commit.
        assert_eq!(
            state.reserve_authorization(&req("access:c1:2000", "high", 2_000, 2_000, 100)),
            BatchReservation::Stale
        );
        assert!(state.pending_deliveries.is_empty());
        // Commit keeps its own check for a reservation taken before the move.
        state.pending_deliveries.push(PendingDelivery {
            delivery_id: "access:c1:2000".to_string(),
            amount: 2_000,
            sequence: 99,
            expires_at: 100 + LEASE.as_secs() as i64,
            request_fingerprint: Some("high".to_string()),
            handler_succeeded: false,
        });
        assert!(state
            .commit_authorization(
                &token_for(&state, "access:c1:2000", "high", 2_000),
                "sig-high",
                0,
                100,
                |_| { None }
            )
            .is_err());
        assert_eq!(state.cumulative, 500);

        // A dead lease that never reported fences the channel: its handler
        // may still finish, so no other voucher steps past it.
        let mut state = make_state("c2", 10_000);
        state.reserve_authorization(&req("access:c2:500", "a", 500, 500, 100));
        let after_lease = 100 + LEASE.as_secs() as i64 + 1;
        assert_eq!(
            state.reserve_authorization(&req("access:c2:700", "b", 700, 700, after_lease)),
            BatchReservation::Abandoned
        );
        // Released by its owner, it no longer blocks.
        state.release_authorization("access:c2:500", "a").unwrap();
        assert!(matches!(
            state.reserve_authorization(&req("access:c2:700", "b", 700, 700, after_lease)),
            BatchReservation::Reserved(_)
        ));

        // A voucher that does step from the moved watermark reserves.
        let mut state = make_state("c3", 10_000);
        state.reserve_authorization(&req("access:c3:500", "a", 500, 500, 100));
        state
            .commit_authorization(
                &token_for(&state, "access:c3:500", "a", 500),
                "sig-a",
                0,
                100,
                |_| None,
            )
            .unwrap();
        assert!(matches!(
            state.reserve_authorization(&req("access:c3:2000", "b", 1_500, 2_000, 100)),
            BatchReservation::Reserved(_)
        ));
    }

    #[test]
    fn a_channel_binding_round_trips_and_refuses_other_deployments() {
        let mut state = make_state("c1", 10_000);
        let batch = ChannelBinding {
            scheme: "batch-settlement".to_string(),
            pay_to: Some("api-a".to_string()),
            network: Some("devnet".to_string()),
            program_id: Some("program-a".to_string()),
        };
        assert_eq!(state.binding().unwrap(), None);
        state
            .check_binding(&batch)
            .expect("an unbound legacy record is accepted");
        state.set_binding(&batch);
        let decoded: ChannelState =
            serde_json::from_value(serde_json::to_value(&state).unwrap()).unwrap();
        assert_eq!(decoded.binding().unwrap(), Some(batch.clone()));
        decoded.check_binding(&batch).unwrap();
        let session = ChannelBinding {
            scheme: "session".to_string(),
            ..batch.clone()
        };
        assert!(decoded.check_binding(&session).is_err());
        let other_receiver = ChannelBinding {
            pay_to: Some("api-b".to_string()),
            ..batch.clone()
        };
        assert!(decoded.check_binding(&other_receiver).is_err());
        let other_network = ChannelBinding {
            network: Some("mainnet".to_string()),
            ..batch.clone()
        };
        assert!(decoded.check_binding(&other_network).is_err());
        let other_program = ChannelBinding {
            program_id: Some("program-b".to_string()),
            ..batch.clone()
        };
        assert!(decoded.check_binding(&other_program).is_err());

        // An older binding without a receiver passes the mismatch check but
        // admits no charge until it is completed.
        let mut older = make_state("c2", 10_000);
        older.set_binding(&ChannelBinding {
            scheme: "batch-settlement".to_string(),
            pay_to: None,
            network: None,
            program_id: None,
        });
        older.check_binding(&batch).unwrap();
        assert!(older.check_binding_complete(&batch).is_err());
        assert!(make_state("c3", 10_000)
            .check_binding_complete(&batch)
            .is_err());
        older.adopt_binding(&batch).unwrap();
        assert_eq!(older.binding().unwrap(), Some(batch.clone()));
        older.check_binding_complete(&batch).unwrap();

        state
            .extra
            .insert(CHANNEL_BINDING_KEY.to_string(), serde_json::json!(7));
        assert!(
            state.check_binding(&batch).is_err(),
            "an unreadable binding fails closed"
        );
    }

    /// Committed records are retained for retries, not forever.
    #[test]
    fn committed_authorizations_are_bounded_and_expire() {
        let mut state = make_state("c1", 10_000_000);
        for step in 1..=(MAX_COMMITTED_AUTHORIZATIONS as u64 + 10) {
            let cumulative = step * 1_000;
            let id = format!("access:c1:{cumulative}");
            state.reserve_authorization(&req(&id, "fp", 1_000, cumulative, 100));
            state
                .mark_authorization_handler_succeeded(&token_for(&state, &id, "fp", 0))
                .unwrap();
            state
                .commit_authorization(
                    &token_for(&state, &id, "fp", cumulative),
                    "sig",
                    0,
                    100,
                    |_| None,
                )
                .unwrap();
        }
        assert_eq!(
            state.committed_deliveries.len(),
            MAX_COMMITTED_AUTHORIZATIONS
        );
        // The newest are kept: those are the ones a client could still retry.
        let newest = (MAX_COMMITTED_AUTHORIZATIONS as u64 + 10) * 1_000;
        assert!(state
            .committed_authorization(&format!("access:c1:{newest}"))
            .is_some());

        let past_retention = 100 + DEFAULT_CHARGE_RECORD_RETENTION.as_secs() as i64 + 1;
        state.prune_authorizations(past_retention);
        assert!(state.committed_deliveries.is_empty());
    }

    #[test]
    fn committed_authorization_expiry_remains_ordered() {
        let mut state = make_state("c1", 10_000_000);
        for (step, voucher_expiry) in [(1, 1_000), (2, 500), (3, 1_500)] {
            let cumulative = step * 1_000;
            let id = format!("access:c1:{cumulative}");
            state.reserve_authorization(&req(&id, "fp", 1_000, cumulative, 100));
            state
                .mark_authorization_handler_succeeded(&token_for(&state, &id, "fp", 0))
                .unwrap();
            state
                .commit_authorization(
                    &token_for(&state, &id, "fp", cumulative),
                    "sig",
                    voucher_expiry,
                    100,
                    |_| None,
                )
                .unwrap();
        }

        let expiries: Vec<_> = state
            .committed_deliveries
            .iter()
            .map(|entry| entry.retain_until)
            .collect();
        assert!(expiries.windows(2).all(|pair| pair[0] <= pair[1]));
        state.prune_authorizations(expiries[1]);
        assert_eq!(state.committed_deliveries.len(), 1);
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
        assert_eq!(store.list_channel_ids().await.unwrap(), ["c1"]);
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
        assert_eq!(store.list_channel_ids().await.unwrap(), ["c1"]);
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
    async fn redis_channel_store_fences_unchanged_and_changed_mutations() {
        let redis_url = std::env::var("PAY_KIT_TEST_REDIS_URL")
            .expect("PAY_KIT_TEST_REDIS_URL is required for the Redis integration test");
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let store = RedisChannelStore::connect(
            &redis_url,
            format!("pay-kit:test:fenced:{}:{unique}", std::process::id()),
        )
        .await
        .unwrap();

        for in_place in [false, true] {
            for changed in [false, true] {
                for concurrent in [false, true] {
                    let id = format!("{in_place}-{changed}-{concurrent}");
                    store
                        .put_channel(&id, make_state(&id, 1_000_000))
                        .await
                        .unwrap();
                    let worker_store = store.clone();
                    let worker_id = id.clone();
                    let (read_tx, read_rx) = tokio::sync::oneshot::channel();
                    let (resume_tx, resume_rx) = std::sync::mpsc::channel();
                    let worker = tokio::spawn(async move {
                        let mutate = move |state: &mut ChannelState| {
                            read_tx.send(()).unwrap();
                            // Pause after GET and before CAS, without blocking
                            // the runtime needed by the competing writer.
                            tokio::task::block_in_place(|| {
                                resume_rx.recv_timeout(Duration::from_secs(10))
                            })
                            .unwrap();
                            if changed {
                                state.cumulative = 50;
                            }
                            Ok(())
                        };
                        if in_place {
                            worker_store
                                .mutate_channel(&worker_id, None, Box::new(mutate))
                                .await
                        } else {
                            worker_store
                                .update_channel(
                                    &worker_id,
                                    Box::new(move |state| {
                                        let mut state = state.unwrap();
                                        mutate(&mut state)?;
                                        Ok(state)
                                    }),
                                )
                                .await
                                .map(|_| ())
                        }
                    });
                    tokio::time::timeout(Duration::from_secs(10), read_rx)
                        .await
                        .unwrap()
                        .unwrap();
                    if concurrent {
                        store.mark_sealed(&id).await.unwrap();
                    }
                    resume_tx.send(()).unwrap();
                    let result = worker.await.unwrap();
                    if concurrent {
                        assert!(matches!(
                            result,
                            Err(StoreError::Internal(message))
                                if message == "Concurrent channel update; retry the request"
                        ));
                    } else {
                        result.unwrap();
                    }
                    let persisted = store.get_channel(&id).await.unwrap().unwrap();
                    assert_eq!(persisted.sealed, concurrent);
                    assert_eq!(
                        persisted.cumulative,
                        if changed && !concurrent { 50 } else { 0 }
                    );
                    store.delete_channel(&id).await.unwrap();
                }
            }
        }
    }

    fn conformance_state(channel_id: &str) -> ChannelState {
        make_state(channel_id, 10_000)
    }

    #[tokio::test]
    async fn memory_kv_store_passes_conformance() {
        conformance::check_store(&MemoryStore::new()).await;
    }

    #[tokio::test]
    async fn memory_store_passes_conformance() {
        let store = MemoryChannelStore::new();
        conformance::check_channel_store(&store, &conformance_state).await;
        conformance::check_channel_store_deletion(&store, &conformance_state).await;
    }

    #[tokio::test]
    async fn arc_store_passes_conformance() {
        let store: Arc<dyn ChannelStore> = Arc::new(MemoryChannelStore::new());
        conformance::check_channel_store(&store, &conformance_state).await;
        conformance::check_channel_store_deletion(&store, &conformance_state).await;
    }

    #[cfg(feature = "redis-store")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn redis_store_passes_conformance() {
        let redis_url = std::env::var("PAY_KIT_TEST_REDIS_URL")
            .expect("PAY_KIT_TEST_REDIS_URL is required for the Redis integration test");
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let store = RedisChannelStore::connect(
            &redis_url,
            format!("pay-kit:test:conformance:{}:{unique}:", std::process::id()),
        )
        .await
        .unwrap();
        conformance::check_channel_store(&store, &conformance_state).await;
        conformance::check_channel_store_deletion(&store, &conformance_state).await;
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
            format!("pay-kit:test:roundtrip:{}:{unique}:", std::process::id()),
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
        assert!(matches!(
            no_op.await.unwrap(),
            Err(StoreError::Internal(message))
                if message == "Concurrent channel update; retry the request"
        ));
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
