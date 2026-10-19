//! End-to-end activation tests against a scripted JSON-RPC node.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::{routing::post, Json, Router};
use base64::Engine;
use solana_keychain::{MemorySigner, SolanaSigner};

use super::*;
use crate::mpp::client::{
    build_subscription_activation_transaction_with_options, sign_subscription_authentication,
    BuildSubscriptionActivationOptions,
};
use crate::mpp::protocol::solana::CredentialPayload;

pub(super) const INIT_ID: i64 = 77;
pub(super) const AMOUNT: u64 = 10_000_000;
pub(super) const PERIOD_HOURS: u64 = 720;

/// Scripted chain state served by [`RpcFixture`].
#[derive(Default)]
pub(super) struct ChainState {
    /// Accounts visible at every commitment.
    pub accounts: HashMap<String, Vec<u8>>,
    /// Accounts a successful `sendTransaction` creates. They are visible at
    /// `confirmed` only, after `hidden_landed_reads` reads have missed them.
    pub landed: HashMap<String, Vec<u8>>,
    pub hidden_landed_reads: usize,
    /// JSON-RPC error object returned by `sendTransaction`.
    pub send_error: Option<serde_json::Value>,
    /// Signature statuses keyed by signature.
    pub statuses: HashMap<String, serde_json::Value>,
    pub sends: usize,
    pub sent: bool,
    pub account_read_commitments: Vec<String>,
}

pub(super) struct RpcFixture {
    pub url: String,
    pub state: Arc<Mutex<ChainState>>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for RpcFixture {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn status(err: serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "slot": 1, "confirmations": null, "err": err.clone(),
        "status": if err.is_null() { serde_json::json!({"Ok": null}) } else { serde_json::json!({"Err": err}) },
        "confirmationStatus": "confirmed"
    })
}

pub(super) fn success_status() -> serde_json::Value {
    status(serde_json::Value::Null)
}

pub(super) fn failed_status() -> serde_json::Value {
    status(serde_json::json!({"InstructionError": [0, {"Custom": 1}]}))
}

impl RpcFixture {
    /// Record `signature` as a transaction that landed with `status`.
    pub fn set_status(&self, signature: &str, status: serde_json::Value) {
        self.state
            .lock()
            .unwrap()
            .statuses
            .insert(signature.to_string(), status);
    }

    pub async fn start(owner: Pubkey, state: ChainState) -> Self {
        let state = Arc::new(Mutex::new(state));
        let shared = Arc::clone(&state);
        let owner = owner.to_string();
        let app = Router::new().route(
            "/",
            post(move |Json(request): Json<serde_json::Value>| {
                let state = Arc::clone(&shared);
                let owner = owner.clone();
                async move {
                    let mut state = state.lock().unwrap();
                    let params = &request["params"];
                    let result = match request["method"].as_str().unwrap() {
                        "getLatestBlockhash" => serde_json::json!({
                            "context": {"slot": 1},
                            "value": {"blockhash": "11111111111111111111111111111111", "lastValidBlockHeight": 100}
                        }),
                        "isBlockhashValid" => {
                            serde_json::json!({"context": {"slot": 1}, "value": true})
                        }
                        "getAccountInfo" => {
                            let address = params[0].as_str().unwrap().to_string();
                            let commitment = params[1]["commitment"]
                                .as_str()
                                .unwrap_or("finalized")
                                .to_string();
                            state.account_read_commitments.push(commitment.clone());
                            let mut data = state.accounts.get(&address).cloned();
                            if data.is_none() && state.sent && state.landed.contains_key(&address) {
                                if state.hidden_landed_reads > 0 {
                                    state.hidden_landed_reads -= 1;
                                } else if commitment != "finalized" {
                                    data = state.landed.get(&address).cloned();
                                }
                            }
                            let value = data.map(|data| {
                                serde_json::json!({
                                    "data": [base64::engine::general_purpose::STANDARD.encode(&data), "base64"],
                                    "executable": false, "lamports": 1, "owner": owner,
                                    "rentEpoch": 0, "space": data.len()
                                })
                            });
                            serde_json::json!({"context": {"slot": 1}, "value": value})
                        }
                        "getSignatureStatuses" => {
                            let value: Vec<serde_json::Value> = params[0]
                                .as_array()
                                .unwrap()
                                .iter()
                                .map(|sig| {
                                    state
                                        .statuses
                                        .get(sig.as_str().unwrap())
                                        .cloned()
                                        .unwrap_or(serde_json::Value::Null)
                                })
                                .collect();
                            serde_json::json!({"context": {"slot": 1}, "value": value})
                        }
                        "sendTransaction" => {
                            state.sends += 1;
                            if let Some(error) = state.send_error.clone() {
                                return Json(serde_json::json!({
                                    "jsonrpc": "2.0", "id": request["id"], "error": error
                                }));
                            }
                            let tx = crate::core::tx::decode(params[0].as_str().unwrap()).unwrap();
                            let signature = tx.signatures[0].to_string();
                            state.statuses.insert(signature.clone(), success_status());
                            state.sent = true;
                            serde_json::json!(signature)
                        }
                        method => panic!("unexpected RPC method {method}"),
                    };
                    Json(serde_json::json!({"jsonrpc": "2.0", "id": request["id"], "result": result}))
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        Self { url, state, task }
    }
}

pub(super) fn deterministic_signer(seed: u8) -> MemorySigner {
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
    let mut keypair = [0u8; 64];
    keypair[..32].copy_from_slice(signing_key.as_bytes());
    keypair[32..].copy_from_slice(signing_key.verifying_key().as_bytes());
    MemorySigner::from_bytes(&keypair).unwrap()
}

pub(super) struct DelegationState {
    pub init_id: i64,
    pub amount_per_period: u64,
    pub amount_pulled_in_period: u64,
    pub current_period_start_ts: i64,
    pub expires_at_ts: i64,
}

impl Default for DelegationState {
    fn default() -> Self {
        Self {
            init_id: INIT_ID,
            amount_per_period: AMOUNT,
            amount_pulled_in_period: AMOUNT,
            current_period_start_ts: now_unix_secs() - 60,
            expires_at_ts: 0,
        }
    }
}

pub(super) fn delegation_bytes(
    subscriber: &Pubkey,
    plan: &Pubkey,
    state: DelegationState,
) -> Vec<u8> {
    let mut data = vec![4, 1, 255];
    data.extend_from_slice(subscriber.as_ref());
    data.extend_from_slice(plan.as_ref());
    data.extend_from_slice(Pubkey::new_unique().as_ref());
    data.extend_from_slice(&state.init_id.to_le_bytes());
    data.extend_from_slice(&state.amount_per_period.to_le_bytes());
    data.extend_from_slice(&PERIOD_HOURS.to_le_bytes());
    data.extend_from_slice(&1_700_000_000i64.to_le_bytes());
    data.extend_from_slice(&state.amount_pulled_in_period.to_le_bytes());
    data.extend_from_slice(&state.current_period_start_ts.to_le_bytes());
    data.extend_from_slice(&state.expires_at_ts.to_le_bytes());
    data
}

pub(super) fn authority_bytes(init_id: i64) -> Vec<u8> {
    let mut data = vec![0u8; SUBSCRIPTION_AUTHORITY_LEN];
    data[SUBSCRIPTION_AUTHORITY_INIT_ID_OFFSET..].copy_from_slice(&init_id.to_le_bytes());
    data
}

/// One subscriber activating one plan on the canonical program.
pub(super) struct Scenario {
    pub signer: MemorySigner,
    pub subscriber: Pubkey,
    pub plan: Pubkey,
    pub mint: Pubkey,
    pub puller: Pubkey,
    pub recipient: Pubkey,
    pub delegation: Pubkey,
    pub authority: Pubkey,
}

impl Scenario {
    pub fn new() -> Self {
        let signer = deterministic_signer(29);
        let subscriber = signer.pubkey();
        let program_id = Pubkey::from_str_const(SUBSCRIPTIONS_PROGRAM_ID);
        let plan = Pubkey::new_unique();
        let mint = Pubkey::new_unique();
        Self {
            subscriber,
            plan,
            mint,
            puller: Pubkey::new_unique(),
            recipient: Pubkey::new_unique(),
            delegation: find_subscription_pda(&plan, &subscriber, &program_id).0,
            authority: find_subscription_authority_pda(&subscriber, &mint, &program_id).0,
            signer,
        }
    }

    pub fn delegation_bytes(&self, state: DelegationState) -> Vec<u8> {
        delegation_bytes(&self.subscriber, &self.plan, state)
    }

    pub fn config(&self, rpc_url: &str) -> SubscriptionConfig {
        SubscriptionConfig {
            plan_id: self.plan.to_string(),
            mint: self.mint.to_string(),
            token_program: crate::mpp::protocol::solana::programs::TOKEN_PROGRAM.into(),
            puller: self.puller.to_string(),
            recipient: self.recipient.to_string(),
            rpc_url: Some(rpc_url.to_string()),
            challenge_binding_secret: "test-secret".into(),
            realm: "test-realm".into(),
            plan_id_numeric: Some(1),
            plan_bump: Some(255),
            plan_created_at: Some(1_700_000_000),
            ..Default::default()
        }
    }

    pub fn server(&self, rpc_url: &str) -> SubscriptionServer {
        SubscriptionServer::new(self.config(rpc_url)).unwrap()
    }

    /// Build the canonical activation credential for a fresh challenge.
    /// Returns the credential and the activation transaction's signature.
    pub async fn activation(&self, server: &SubscriptionServer) -> (PaymentCredential, String) {
        let challenge = server.subscription_challenge(&AMOUNT.to_string()).unwrap();
        self.activation_for(&challenge).await
    }

    pub async fn activation_for(
        &self,
        challenge: &PaymentChallenge,
    ) -> (PaymentCredential, String) {
        let request: SubscriptionRequest = challenge.request.decode().unwrap();
        let details =
            SubscriptionMethodDetails::from_json(request.method_details.as_ref().unwrap()).unwrap();
        let CredentialPayload::Transaction { transaction } =
            build_subscription_activation_transaction_with_options(
                &self.signer,
                &solana_rpc_client::rpc_client::RpcClient::new_mock("succeeds"),
                &details,
                BuildSubscriptionActivationOptions {
                    subscription_authority_init_id: Some(INIT_ID),
                    ..Default::default()
                },
            )
            .await
            .unwrap()
        else {
            panic!("expected transaction payload")
        };
        let signature = crate::core::tx::decode(&transaction).unwrap().signatures[0].to_string();
        let authentication = sign_subscription_authentication(
            &self.signer,
            &challenge.id,
            &self.delegation.to_string(),
        )
        .await
        .unwrap();
        let credential = PaymentCredential::new(
            challenge.to_echo(),
            ActivatePayload {
                payload_type: "transaction".into(),
                transaction: Some(transaction),
                signature: None,
                authentication: Some(authentication),
            },
        );
        (credential, signature)
    }
}

/// Chain state for a fresh activation: the authority exists and the
/// delegation is created by the broadcast.
pub(super) fn fresh_activation_state(scenario: &Scenario) -> ChainState {
    let mut state = ChainState::default();
    state
        .accounts
        .insert(scenario.authority.to_string(), authority_bytes(INIT_ID));
    state.landed.insert(
        scenario.delegation.to_string(),
        scenario.delegation_bytes(DelegationState::default()),
    );
    state
}

pub(super) fn program_owner() -> Pubkey {
    Pubkey::from_str_const(SUBSCRIPTIONS_PROGRAM_ID)
}

// ── SOLA1-45: confirmed activation reads ────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn confirmed_activation_is_read_back_at_confirmed_commitment() {
    let scenario = Scenario::new();
    let rpc = RpcFixture::start(program_owner(), fresh_activation_state(&scenario)).await;
    let server = scenario.server(&rpc.url);
    let (credential, signature) = scenario.activation(&server).await;

    let receipt = server
        .verify_credential(&credential)
        .await
        .expect("a confirmed activation must not fail on the finalized read gap");
    let ReceiptKind::Subscription { base, .. } = receipt else {
        panic!("expected subscription receipt")
    };
    assert_eq!(base.reference, signature);
    let state = rpc.state.lock().unwrap();
    assert_eq!(state.sends, 1);
    assert!(state
        .account_read_commitments
        .iter()
        .all(|commitment| commitment == "confirmed"));
}

#[tokio::test(flavor = "multi_thread")]
async fn confirmed_activation_tolerates_a_lagging_account_read() {
    let scenario = Scenario::new();
    let mut state = fresh_activation_state(&scenario);
    state.hidden_landed_reads = 2;
    let rpc = RpcFixture::start(program_owner(), state).await;
    let server = scenario.server(&rpc.url);
    let (credential, _) = scenario.activation(&server).await;

    server
        .verify_credential(&credential)
        .await
        .expect("the delegation read retries until the node catches up");
}

#[tokio::test(flavor = "multi_thread")]
async fn activation_fails_when_the_delegation_never_appears() {
    let scenario = Scenario::new();
    let mut state = fresh_activation_state(&scenario);
    state.hidden_landed_reads = usize::MAX;
    let rpc = RpcFixture::start(program_owner(), state).await;
    let server = scenario.server(&rpc.url);
    let (credential, _) = scenario.activation(&server).await;

    let err = server.verify_credential(&credential).await.unwrap_err();
    assert!(err.message.contains("not found"), "{}", err.message);
    assert_eq!(rpc.state.lock().unwrap().sends, 1);
}

// ── SOLA1-80: stale delegations are not prior activations ──────────────────

/// Chain state where the delegation PDA already exists with `delegation`.
pub(super) fn existing_delegation_state(
    scenario: &Scenario,
    delegation: DelegationState,
) -> ChainState {
    let mut state = ChainState::default();
    state
        .accounts
        .insert(scenario.authority.to_string(), authority_bytes(INIT_ID));
    state.accounts.insert(
        scenario.delegation.to_string(),
        scenario.delegation_bytes(delegation),
    );
    state
}

#[tokio::test(flavor = "multi_thread")]
async fn expired_cancelled_delegation_is_not_accepted_as_activation() {
    let scenario = Scenario::new();
    let now = now_unix_secs();
    let rpc = RpcFixture::start(
        program_owner(),
        existing_delegation_state(
            &scenario,
            DelegationState {
                current_period_start_ts: now - 60,
                expires_at_ts: now - 1,
                ..Default::default()
            },
        ),
    )
    .await;
    let server = scenario.server(&rpc.url);
    let (credential, signature) = scenario.activation(&server).await;
    rpc.set_status(&signature, success_status());

    let err = server.verify_credential(&credential).await.unwrap_err();
    assert!(err.message.contains("cancellation"), "{}", err.message);
    assert_eq!(rpc.state.lock().unwrap().sends, 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn delegation_cancelled_at_this_second_is_not_accepted() {
    let scenario = Scenario::new();
    let now = now_unix_secs();
    let rpc = RpcFixture::start(
        program_owner(),
        existing_delegation_state(
            &scenario,
            DelegationState {
                expires_at_ts: now,
                ..Default::default()
            },
        ),
    )
    .await;
    let server = scenario.server(&rpc.url);
    let (credential, signature) = scenario.activation(&server).await;
    rpc.set_status(&signature, success_status());

    let err = server.verify_credential(&credential).await.unwrap_err();
    assert!(err.message.contains("cancellation"), "{}", err.message);
}

#[tokio::test(flavor = "multi_thread")]
async fn delegation_from_an_ended_billing_period_is_not_accepted() {
    let scenario = Scenario::new();
    let period = PERIOD_HOURS as i64 * 3600;
    let rpc = RpcFixture::start(
        program_owner(),
        existing_delegation_state(
            &scenario,
            DelegationState {
                current_period_start_ts: now_unix_secs() - period,
                ..Default::default()
            },
        ),
    )
    .await;
    let server = scenario.server(&rpc.url);
    let (credential, signature) = scenario.activation(&server).await;
    rpc.set_status(&signature, success_status());

    let err = server.verify_credential(&credential).await.unwrap_err();
    assert!(err.message.contains("not paid"), "{}", err.message);
    assert_eq!(rpc.state.lock().unwrap().sends, 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn cancelled_delegation_inside_its_paid_period_is_still_live() {
    let scenario = Scenario::new();
    let rpc = RpcFixture::start(
        program_owner(),
        existing_delegation_state(
            &scenario,
            DelegationState {
                expires_at_ts: now_unix_secs() + 3600,
                ..Default::default()
            },
        ),
    )
    .await;
    let server = scenario.server(&rpc.url);
    let (credential, signature) = scenario.activation(&server).await;
    rpc.set_status(&signature, success_status());

    server
        .verify_credential(&credential)
        .await
        .expect("a cancellation that has not taken effect keeps the paid period");
}

// ── SOLA1-85: existing-PDA retries are bound to the submitted transaction ──

#[tokio::test(flavor = "multi_thread")]
async fn failed_activation_transaction_is_not_accepted_for_an_existing_pda() {
    let scenario = Scenario::new();
    let rpc = RpcFixture::start(
        program_owner(),
        existing_delegation_state(&scenario, DelegationState::default()),
    )
    .await;
    let server = scenario.server(&rpc.url);
    let (credential, signature) = scenario.activation(&server).await;
    rpc.set_status(&signature, failed_status());

    let err = server.verify_credential(&credential).await.unwrap_err();
    assert!(err.message.contains("failed on-chain"), "{}", err.message);
    assert_eq!(rpc.state.lock().unwrap().sends, 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn unrelated_history_does_not_stand_in_for_the_activation() {
    let scenario = Scenario::new();
    let rpc = RpcFixture::start(
        program_owner(),
        existing_delegation_state(&scenario, DelegationState::default()),
    )
    .await;
    // Another transaction touched the PDA; the submitted one never landed.
    rpc.set_status(&Signature::from([7u8; 64]).to_string(), success_status());
    let server = scenario.server(&rpc.url);
    let (credential, _) = scenario.activation(&server).await;

    let err = server.verify_credential(&credential).await.unwrap_err();
    assert!(err.message.contains("already exists"), "{}", err.message);
    assert_eq!(rpc.state.lock().unwrap().sends, 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn retry_of_a_landed_activation_reports_its_own_signature() {
    let scenario = Scenario::new();
    let rpc = RpcFixture::start(
        program_owner(),
        existing_delegation_state(&scenario, DelegationState::default()),
    )
    .await;
    let server = scenario.server(&rpc.url);
    let (credential, signature) = scenario.activation(&server).await;
    rpc.set_status(&signature, success_status());

    let ReceiptKind::Subscription { base, .. } =
        server.verify_credential(&credential).await.unwrap()
    else {
        panic!("expected subscription receipt")
    };
    assert_eq!(base.reference, signature);
    assert_eq!(rpc.state.lock().unwrap().sends, 0);
}
