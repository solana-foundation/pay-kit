//! Shared asynchronous transaction submission, confirmation, and read-back.
//!
//! A pipeline owns one pooled RPC client. All callers share a confirmation
//! tracker (`getSignatureStatuses`, up to 256 signatures per request) and an
//! account read-back queue (`getMultipleAccounts`, up to 100 accounts per
//! request). This keeps high-cardinality session opens from multiplying RPC
//! round trips while preserving confirmed, state-matched acceptance.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use solana_account_decoder_client_types::UiAccountEncoding;
use solana_commitment_config::CommitmentConfig;
use solana_hash::Hash;
use solana_pubkey::Pubkey;
use solana_rpc_client::nonblocking::rpc_client::RpcClient;
use solana_rpc_client::rpc_client::SerializableTransaction;
use solana_rpc_client_api::config::RpcAccountInfoConfig;
use solana_signature::Signature;
use tokio::sync::{mpsc, oneshot, Mutex, Semaphore};

use crate::core::rpc::SKIP_PREFLIGHT_SEND;

const CONFIRM_BATCH_LIMIT: usize = 256;
const ACCOUNT_BATCH_LIMIT: usize = 100;

/// Runtime controls for [`TxPipeline`].
#[derive(Debug, Clone)]
pub struct TxPipelineConfig {
    /// Maximum concurrent `sendTransaction` calls.
    pub max_send_concurrency: usize,
    /// Maximum attempts for transient `sendTransaction` failures.
    pub submission_max_attempts: usize,
    /// Initial retry delay for failed submissions.
    pub submission_initial_backoff: Duration,
    /// Maximum retry delay for failed submissions.
    pub submission_max_backoff: Duration,
    /// Minimum spacing between submissions through this pipeline.
    pub send_interval: Duration,
    /// Delay between batched signature-status polls.
    pub confirmation_poll_interval: Duration,
    /// Maximum time to wait for a submitted signature to confirm.
    pub confirmation_timeout: Duration,
    /// Short coalescing window used to form RPC batches.
    pub batch_coalesce_interval: Duration,
    /// Maximum age of the shared cluster-slot observation.
    pub slot_cache_ttl: Duration,
    /// Maximum age of a recent blockhash used by server-built transactions.
    pub blockhash_cache_ttl: Duration,
    /// Maximum read-back retries while a confirmed write reaches the RPC node.
    pub account_read_retries: usize,
}

impl Default for TxPipelineConfig {
    fn default() -> Self {
        Self {
            max_send_concurrency: 256,
            submission_max_attempts: 4,
            submission_initial_backoff: Duration::from_millis(50),
            submission_max_backoff: Duration::from_secs(1),
            send_interval: Duration::from_millis(1),
            confirmation_poll_interval: Duration::from_millis(250),
            confirmation_timeout: Duration::from_secs(90),
            batch_coalesce_interval: Duration::from_millis(2),
            slot_cache_ttl: Duration::from_millis(400),
            blockhash_cache_ttl: Duration::from_secs(5),
            account_read_retries: 7,
        }
    }
}

/// A confirmed transaction observation returned by the shared tracker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConfirmedTransaction {
    pub signature: Signature,
    /// Slot reported by `getSignatureStatuses` at confirmed commitment.
    pub slot: u64,
}

/// Sanitized pipeline failures. RPC URLs and provider credentials are never
/// copied from client errors into these messages.
#[derive(Debug, Clone, thiserror::Error)]
pub enum TxPipelineError {
    #[error("transaction is missing its fee-payer signature")]
    MissingSignature,
    #[error("transaction {signature} was rejected on-chain: {reason}")]
    TransactionFailed {
        signature: Signature,
        reason: String,
    },
    #[error("transaction {signature} did not reach confirmed commitment before timeout")]
    ConfirmationTimeout { signature: Signature },
    #[error("RPC submission and confirmation failed for transaction {signature}")]
    SubmissionFailed { signature: Signature },
    #[error("confirmed account read failed after bounded retries")]
    AccountReadFailed,
    #[error("failed to refresh the confirmed cluster slot")]
    SlotReadFailed,
    #[error("failed to refresh the recent blockhash")]
    BlockhashReadFailed,
    #[error("RPC returned malformed account data for {address}")]
    AccountDecodeFailed { address: Pubkey },
    #[error("transaction pipeline stopped unexpectedly")]
    Stopped,
}

type PipelineResult<T> = std::result::Result<T, TxPipelineError>;

#[derive(Clone)]
pub struct TxPipeline {
    inner: Arc<Inner>,
}

struct Inner {
    rpc: Arc<RpcClient>,
    config: TxPipelineConfig,
    send_permits: Semaphore,
    next_send_at: Mutex<Instant>,
    slot_cache: Mutex<Option<(u64, Instant)>>,
    blockhash_cache: Mutex<Option<(Hash, Instant)>>,
    confirmations: mpsc::UnboundedSender<ConfirmationRequest>,
    account_reads: mpsc::UnboundedSender<AccountReadRequest>,
}

struct ConfirmationRequest {
    signature: Signature,
    deadline: Instant,
    response: oneshot::Sender<PipelineResult<ConfirmedTransaction>>,
}

struct PendingConfirmation {
    deadline: Instant,
    responses: Vec<oneshot::Sender<PipelineResult<ConfirmedTransaction>>>,
}

struct AccountReadRequest {
    address: Pubkey,
    min_context_slot: Option<u64>,
    response: oneshot::Sender<PipelineResult<Option<Vec<u8>>>>,
}

impl TxPipeline {
    /// Create a pipeline backed by one pooled nonblocking RPC client.
    ///
    /// This must be called from a Tokio runtime because it starts the shared
    /// confirmation and account-read actors immediately.
    pub fn new(rpc_url: impl Into<String>, config: TxPipelineConfig) -> Self {
        let rpc = Arc::new(RpcClient::new_with_commitment(
            rpc_url.into(),
            CommitmentConfig::confirmed(),
        ));
        let (confirmation_tx, confirmation_rx) = mpsc::unbounded_channel();
        let (account_tx, account_rx) = mpsc::unbounded_channel();

        tokio::spawn(run_confirmation_tracker(
            Arc::clone(&rpc),
            config.clone(),
            confirmation_rx,
        ));
        tokio::spawn(run_account_reader(
            Arc::clone(&rpc),
            config.clone(),
            account_rx,
        ));

        Self {
            inner: Arc::new(Inner {
                rpc,
                send_permits: Semaphore::new(config.max_send_concurrency.max(1)),
                next_send_at: Mutex::new(Instant::now()),
                slot_cache: Mutex::new(None),
                blockhash_cache: Mutex::new(None),
                confirmations: confirmation_tx,
                account_reads: account_tx,
                config,
            }),
        }
    }

    /// Submit a transaction whose exact instruction and account shape has
    /// already been verified locally, then await confirmed commitment.
    ///
    /// Only this API skips preflight. Callers must not pass arbitrary client
    /// transactions without first performing byte-exact validation.
    pub async fn submit_verified<T>(&self, transaction: &T) -> PipelineResult<ConfirmedTransaction>
    where
        T: SerializableTransaction + Sync,
    {
        let signature = *transaction.get_signature();
        // A send failure is not authoritative: the same signed transaction
        // may already have landed while its prior response was lost. Always
        // ask the shared confirmation tracker before deciding the outcome.
        let submitted = self.broadcast_verified(transaction).await.is_ok();

        match self.confirm(signature).await {
            Ok(confirmed) => Ok(confirmed),
            Err(TxPipelineError::ConfirmationTimeout { .. }) if !submitted => {
                Err(TxPipelineError::SubmissionFailed { signature })
            }
            Err(error) => Err(error),
        }
    }

    /// Broadcast a locally verified transaction without preflight and return
    /// immediately. Confirmation can be awaited separately through [`Self::confirm`].
    pub async fn broadcast_verified<T>(&self, transaction: &T) -> PipelineResult<Signature>
    where
        T: SerializableTransaction + Sync,
    {
        let signature = *transaction.get_signature();
        let permit = self
            .inner
            .send_permits
            .acquire()
            .await
            .map_err(|_| TxPipelineError::Stopped)?;
        let attempts = self.inner.config.submission_max_attempts.max(1);
        let mut backoff = self.inner.config.submission_initial_backoff;
        let mut result = Err(TxPipelineError::SubmissionFailed { signature });
        for attempt in 1..=attempts {
            self.pace_submission().await;
            result = self
                .inner
                .rpc
                .send_transaction_with_config(transaction, SKIP_PREFLIGHT_SEND.config())
                .await
                .map_err(|_| TxPipelineError::SubmissionFailed { signature });
            if result.is_ok() || attempt == attempts {
                break;
            }
            tokio::time::sleep(backoff).await;
            backoff = backoff
                .saturating_mul(2)
                .min(self.inner.config.submission_max_backoff);
        }
        drop(permit);
        result
    }

    /// Await confirmed commitment for a signature through the shared batcher.
    pub async fn confirm(&self, signature: Signature) -> PipelineResult<ConfirmedTransaction> {
        let (response_tx, response_rx) = oneshot::channel();
        self.inner
            .confirmations
            .send(ConfirmationRequest {
                signature,
                deadline: Instant::now() + self.inner.config.confirmation_timeout,
                response: response_tx,
            })
            .map_err(|_| TxPipelineError::Stopped)?;
        response_rx.await.map_err(|_| TxPipelineError::Stopped)?
    }

    /// Read one account at confirmed commitment, optionally requiring the RPC
    /// node to have reached the transaction's confirmation slot. Concurrent
    /// callers are coalesced into `getMultipleAccounts` requests.
    pub async fn read_account_data(
        &self,
        address: Pubkey,
        min_context_slot: Option<u64>,
    ) -> PipelineResult<Option<Vec<u8>>> {
        let (response_tx, response_rx) = oneshot::channel();
        self.inner
            .account_reads
            .send(AccountReadRequest {
                address,
                min_context_slot,
                response: response_tx,
            })
            .map_err(|_| TxPipelineError::Stopped)?;
        response_rx.await.map_err(|_| TxPipelineError::Stopped)?
    }

    /// Return a short-lived shared cluster-slot observation. Concurrent session
    /// opens refresh it once rather than issuing one `getSlot` call per open.
    pub async fn current_slot(&self) -> PipelineResult<u64> {
        let mut cached = self.inner.slot_cache.lock().await;
        if let Some((slot, observed_at)) = *cached {
            if observed_at.elapsed() <= self.inner.config.slot_cache_ttl {
                return Ok(slot);
            }
        }
        let slot = self
            .inner
            .rpc
            .get_slot()
            .await
            .map_err(|_| TxPipelineError::SlotReadFailed)?;
        *cached = Some((slot, Instant::now()));
        Ok(slot)
    }

    /// Return a short-lived shared recent blockhash for server-built
    /// transactions.
    pub async fn latest_blockhash(&self) -> PipelineResult<Hash> {
        let mut cached = self.inner.blockhash_cache.lock().await;
        if let Some((blockhash, observed_at)) = *cached {
            if observed_at.elapsed() <= self.inner.config.blockhash_cache_ttl {
                return Ok(blockhash);
            }
        }
        let blockhash = self
            .inner
            .rpc
            .get_latest_blockhash()
            .await
            .map_err(|_| TxPipelineError::BlockhashReadFailed)?;
        *cached = Some((blockhash, Instant::now()));
        Ok(blockhash)
    }

    async fn pace_submission(&self) {
        let mut next = self.inner.next_send_at.lock().await;
        let now = Instant::now();
        if *next > now {
            tokio::time::sleep(*next - now).await;
        }
        *next = Instant::now() + self.inner.config.send_interval;
    }
}

async fn run_confirmation_tracker(
    rpc: Arc<RpcClient>,
    config: TxPipelineConfig,
    mut requests: mpsc::UnboundedReceiver<ConfirmationRequest>,
) {
    let mut pending = HashMap::<Signature, PendingConfirmation>::new();
    let mut receiver_open = true;
    loop {
        if pending.is_empty() {
            if !receiver_open {
                break;
            }
            let Some(request) = requests.recv().await else {
                break;
            };
            add_confirmation(&mut pending, request);
        }

        tokio::time::sleep(config.batch_coalesce_interval).await;
        while let Ok(request) = requests.try_recv() {
            add_confirmation(&mut pending, request);
        }

        let signatures = pending.keys().copied().collect::<Vec<_>>();
        for chunk in signatures.chunks(CONFIRM_BATCH_LIMIT) {
            let Ok(statuses) = rpc.get_signature_statuses(chunk).await else {
                continue;
            };
            for (signature, status) in chunk.iter().zip(statuses.value) {
                let Some(status) = status else {
                    continue;
                };
                if let Some(error) = status.err {
                    complete_confirmation(
                        &mut pending,
                        signature,
                        Err(TxPipelineError::TransactionFailed {
                            signature: *signature,
                            reason: format!("{error:?}"),
                        }),
                    );
                } else if status.satisfies_commitment(CommitmentConfig::confirmed()) {
                    complete_confirmation(
                        &mut pending,
                        signature,
                        Ok(ConfirmedTransaction {
                            signature: *signature,
                            slot: status.slot,
                        }),
                    );
                }
            }
        }

        let now = Instant::now();
        let expired = pending
            .iter()
            .filter_map(|(signature, item)| (item.deadline <= now).then_some(*signature))
            .collect::<Vec<_>>();
        for signature in expired {
            complete_confirmation(
                &mut pending,
                &signature,
                Err(TxPipelineError::ConfirmationTimeout { signature }),
            );
        }

        if !pending.is_empty() {
            let delay = tokio::time::sleep(config.confirmation_poll_interval);
            tokio::pin!(delay);
            loop {
                tokio::select! {
                    request = requests.recv(), if receiver_open => {
                        match request {
                            Some(request) => add_confirmation(&mut pending, request),
                            None => receiver_open = false,
                        }
                    }
                    () = &mut delay => break,
                }
            }
        }
    }
}

fn add_confirmation(
    pending: &mut HashMap<Signature, PendingConfirmation>,
    request: ConfirmationRequest,
) {
    let entry = pending
        .entry(request.signature)
        .or_insert_with(|| PendingConfirmation {
            deadline: request.deadline,
            responses: Vec::new(),
        });
    entry.deadline = entry.deadline.max(request.deadline);
    entry.responses.push(request.response);
}

fn complete_confirmation(
    pending: &mut HashMap<Signature, PendingConfirmation>,
    signature: &Signature,
    result: PipelineResult<ConfirmedTransaction>,
) {
    if let Some(item) = pending.remove(signature) {
        for response in item.responses {
            let _ = response.send(result.clone());
        }
    }
}

async fn run_account_reader(
    rpc: Arc<RpcClient>,
    config: TxPipelineConfig,
    mut requests: mpsc::UnboundedReceiver<AccountReadRequest>,
) {
    while let Some(first) = requests.recv().await {
        let mut batch = vec![first];
        tokio::time::sleep(config.batch_coalesce_interval).await;
        while batch.len() < ACCOUNT_BATCH_LIMIT {
            match requests.try_recv() {
                Ok(request) => batch.push(request),
                Err(_) => break,
            }
        }

        let addresses = batch.iter().map(|item| item.address).collect::<Vec<_>>();
        let min_context_slot = batch.iter().filter_map(|item| item.min_context_slot).max();
        let mut backoff = Duration::from_millis(25);
        let mut response = None;
        for attempt in 0..=config.account_read_retries {
            let request_config = RpcAccountInfoConfig {
                encoding: Some(UiAccountEncoding::Base64),
                commitment: Some(CommitmentConfig::confirmed()),
                min_context_slot,
                ..RpcAccountInfoConfig::default()
            };
            match rpc
                .get_multiple_ui_accounts_with_config(&addresses, request_config)
                .await
            {
                Ok(accounts) => {
                    response = Some(accounts.value);
                    break;
                }
                Err(_) if attempt < config.account_read_retries => {
                    tokio::time::sleep(backoff).await;
                    backoff = backoff.saturating_mul(2);
                }
                Err(_) => break,
            }
        }

        match response {
            Some(accounts) if accounts.len() == batch.len() => {
                for (request, account) in batch.into_iter().zip(accounts) {
                    let value = match account {
                        Some(account) => account
                            .to_account()
                            .map(|account| account.data)
                            .ok_or(TxPipelineError::AccountDecodeFailed {
                                address: request.address,
                            })
                            .map(Some),
                        None => Ok(None),
                    };
                    let _ = request.response.send(value);
                }
            }
            Some(_) | None => {
                for request in batch {
                    let _ = request
                        .response
                        .send(Err(TxPipelineError::AccountReadFailed));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use axum::{extract::State, routing::post, Json, Router};
    use base64::Engine;
    use serde_json::{json, Value};

    use super::*;

    type AccountBatchObservations = Arc<std::sync::Mutex<Vec<(usize, Option<u64>)>>>;

    #[derive(Clone, Default)]
    struct RpcState {
        status_calls: Arc<AtomicUsize>,
        account_batches: AccountBatchObservations,
    }

    async fn rpc_handler(State(state): State<RpcState>, Json(request): Json<Value>) -> Json<Value> {
        let result = match request["method"].as_str().unwrap() {
            "getSignatureStatuses" => {
                state.status_calls.fetch_add(1, Ordering::SeqCst);
                let values = request["params"][0]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|_| {
                        json!({
                            "slot": 77,
                            "confirmations": 1,
                            "err": null,
                            "confirmationStatus": "confirmed",
                            "status": { "Ok": null }
                        })
                    })
                    .collect::<Vec<_>>();
                json!({ "context": { "slot": 77 }, "value": values })
            }
            "getMultipleAccounts" => {
                let addresses = request["params"][0].as_array().unwrap();
                let min_context_slot = request["params"][1]["minContextSlot"].as_u64();
                state
                    .account_batches
                    .lock()
                    .unwrap()
                    .push((addresses.len(), min_context_slot));
                let encoded = base64::engine::general_purpose::STANDARD.encode([1_u8, 2, 3]);
                let values = addresses
                    .iter()
                    .map(|_| {
                        json!({
                            "data": [encoded, "base64"],
                            "executable": false,
                            "lamports": 1,
                            "owner": Pubkey::new_unique().to_string(),
                            "rentEpoch": 0,
                            "space": 3
                        })
                    })
                    .collect::<Vec<_>>();
                json!({ "context": { "slot": 77 }, "value": values })
            }
            method => panic!("unexpected RPC method {method}"),
        };
        Json(json!({
            "jsonrpc": "2.0",
            "id": request["id"].clone(),
            "result": result
        }))
    }

    async fn mock_rpc() -> (String, RpcState, tokio::task::JoinHandle<()>) {
        let state = RpcState::default();
        let app = Router::new()
            .route("/", post(rpc_handler))
            .with_state(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (url, state, server)
    }

    fn test_config() -> TxPipelineConfig {
        TxPipelineConfig {
            batch_coalesce_interval: Duration::from_millis(25),
            confirmation_timeout: Duration::from_secs(2),
            ..TxPipelineConfig::default()
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn confirmation_tracker_batches_up_to_rpc_limit() {
        let (url, state, server) = mock_rpc().await;
        let pipeline = TxPipeline::new(url, test_config());
        let confirmations = (0..300)
            .map(|_| {
                let pipeline = pipeline.clone();
                tokio::spawn(
                    async move { pipeline.confirm(Signature::new_unique()).await.unwrap() },
                )
            })
            .collect::<Vec<_>>();
        for confirmation in confirmations {
            assert_eq!(confirmation.await.unwrap().slot, 77);
        }
        assert_eq!(state.status_calls.load(Ordering::SeqCst), 2);
        server.abort();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn account_reader_batches_and_uses_strongest_min_context_slot() {
        let (url, state, server) = mock_rpc().await;
        let pipeline = TxPipeline::new(url, test_config());
        let reads = (1..=120)
            .map(|slot| {
                let pipeline = pipeline.clone();
                tokio::spawn(async move {
                    pipeline
                        .read_account_data(Pubkey::new_unique(), Some(slot))
                        .await
                        .unwrap()
                        .unwrap()
                })
            })
            .collect::<Vec<_>>();
        for read in reads {
            assert_eq!(read.await.unwrap(), vec![1, 2, 3]);
        }
        let batches = state.account_batches.lock().unwrap().clone();
        assert_eq!(batches.iter().map(|(size, _)| size).sum::<usize>(), 120);
        assert!(batches.iter().all(|(size, _)| *size <= ACCOUNT_BATCH_LIMIT));
        assert_eq!(batches.len(), 2);
        assert!(batches.iter().all(|(_, min_slot)| min_slot.is_some()));
        server.abort();
    }
}
