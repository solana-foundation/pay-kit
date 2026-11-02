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
    /// Status recorded for a sent transaction; success when `None`.
    pub sent_status: Option<serde_json::Value>,
    /// JSON-RPC error object returned by `getSignatureStatuses`.
    pub status_error: Option<serde_json::Value>,
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
                        "getSignatureStatuses" if state.status_error.is_some() => {
                            return Json(serde_json::json!({
                                "jsonrpc": "2.0", "id": request["id"],
                                "error": state.status_error.clone().unwrap()
                            }));
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
                            let status = state.sent_status.clone().unwrap_or_else(success_status);
                            state.sent = status["err"].is_null();
                            state.statuses.insert(signature.clone(), status);
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
            amount_base_units: AMOUNT.to_string(),
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
        let details = crate::mpp::client::subscription::assume_plan(
            &request,
            parse_pubkey(&self.config("http://127.0.0.1:1").puller, "puller").unwrap(),
        );
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
                authentication,
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

// ── Activation scope fixtures ──────────────────────────────────────────────

/// Canonical activation instructions for `scenario`, optionally sponsored.
pub(super) struct ScopeFixture {
    pub scenario: Scenario,
    pub config: SubscriptionConfig,
    pub request: SubscriptionRequest,
    pub fee_payer: Option<Pubkey>,
}

impl ScopeFixture {
    pub fn new(fee_payer: Option<Pubkey>) -> Self {
        let scenario = Scenario::new();
        let mut config = scenario.config("http://127.0.0.1:1");
        if let Some(fee_payer) = fee_payer {
            config.fee_payer = true;
            config.fee_payer_pubkey = Some(fee_payer.to_string());
        }
        let request = SubscriptionRequest {
            amount: AMOUNT.to_string(),
            recipient: scenario.recipient.to_string(),
            ..Default::default()
        };
        Self {
            scenario,
            config,
            request,
            fee_payer,
        }
    }

    pub fn ata(&self, owner: &Pubkey, mint: &Pubkey) -> Pubkey {
        let token_program =
            Pubkey::from_str_const(crate::mpp::protocol::solana::programs::TOKEN_PROGRAM);
        Pubkey::find_program_address(
            &[owner.as_ref(), token_program.as_ref(), mint.as_ref()],
            &Pubkey::from_str_const(ASSOCIATED_TOKEN_PROGRAM_ID),
        )
        .0
    }

    pub fn subscribe(&self) -> solana_instruction::Instruction {
        use crate::mpp::program::subscriptions::{
            build_subscribe_ix, SubscribeAccounts, SubscribeData,
        };
        let s = &self.scenario;
        build_subscribe_ix(
            program_owner(),
            SubscribeAccounts {
                subscriber: s.subscriber,
                merchant: s.puller,
                plan_pda: s.plan,
                subscription_pda: s.delegation,
                subscription_authority_pda: s.authority,
                event_authority: find_event_authority_pda(&program_owner()).0,
                payer: self.fee_payer,
            },
            &SubscribeData {
                plan_id: 1,
                plan_bump: 255,
                expected_mint: s.mint,
                expected_amount: AMOUNT,
                expected_period_hours: PERIOD_HOURS,
                expected_created_at: 1_700_000_000,
                expected_subscription_authority_init_id: INIT_ID,
            },
        )
    }

    pub fn transfer(&self) -> solana_instruction::Instruction {
        use crate::mpp::program::subscriptions::{
            build_transfer_subscription_ix, TransferData, TransferSubscriptionAccounts,
        };
        let s = &self.scenario;
        build_transfer_subscription_ix(
            program_owner(),
            TransferSubscriptionAccounts {
                subscription_pda: s.delegation,
                plan_pda: s.plan,
                subscription_authority: s.authority,
                delegator_ata: self.ata(&s.subscriber, &s.mint),
                receiver_ata: self.ata(&s.recipient, &s.mint),
                caller: s.puller,
                token_mint: s.mint,
                token_program: Pubkey::from_str_const(
                    crate::mpp::protocol::solana::programs::TOKEN_PROGRAM,
                ),
                event_authority: find_event_authority_pda(&program_owner()).0,
            },
            &TransferData {
                amount: AMOUNT,
                delegator: s.subscriber,
                mint: s.mint,
            },
        )
    }

    pub fn tx(&self, instructions: &[solana_instruction::Instruction]) -> VersionedTransaction {
        crate::core::tx::build_unsigned_unchecked(
            crate::core::tx::TxVersion::V0,
            &self.fee_payer.unwrap_or(self.scenario.subscriber),
            instructions,
            solana_hash::Hash::default(),
            None,
        )
        .unwrap()
    }

    pub fn validate(&self, tx: &VersionedTransaction) -> Result<(), VerificationError> {
        validate_activation_scope(
            tx,
            &self.request,
            SUBSCRIPTIONS_PROGRAM_ID,
            self.scenario.subscriber,
            &self.config,
        )
    }
}

// ── SOLA1-131: setup instructions are bound to the challenged activation ───

fn init_authority_ix(
    fixture: &ScopeFixture,
    mint: Pubkey,
    payer: Option<Pubkey>,
) -> solana_instruction::Instruction {
    use solana_instruction::AccountMeta;
    let s = &fixture.scenario;
    let mut accounts = vec![
        AccountMeta::new(s.subscriber, true),
        AccountMeta::new(
            find_subscription_authority_pda(&s.subscriber, &mint, &program_owner()).0,
            false,
        ),
        AccountMeta::new_readonly(mint, false),
        AccountMeta::new(fixture.ata(&s.subscriber, &mint), false),
        AccountMeta::new_readonly(Pubkey::from_str_const(SYSTEM_PROGRAM_ID), false),
        AccountMeta::new_readonly(
            Pubkey::from_str_const(crate::mpp::protocol::solana::programs::TOKEN_PROGRAM),
            false,
        ),
    ];
    if let Some(payer) = payer {
        accounts.push(AccountMeta::new(payer, true));
    }
    solana_instruction::Instruction {
        program_id: program_owner(),
        accounts,
        data: vec![INSTRUCTION_INITIALIZE_SUBSCRIPTION_AUTHORITY],
    }
}

#[test]
fn sponsored_activation_rejects_unrelated_authority_init() {
    let fee_payer = Pubkey::new_unique();
    let fixture = ScopeFixture::new(Some(fee_payer));
    let unrelated = init_authority_ix(&fixture, Pubkey::new_unique(), Some(fee_payer));
    let tx = fixture.tx(&[unrelated, fixture.subscribe(), fixture.transfer()]);

    let err = fixture.validate(&tx).unwrap_err();
    assert!(err.message.contains("initialize_subscription_authority"));
}

#[test]
fn activation_rejects_authority_init_even_for_the_challenged_mint() {
    let fixture = ScopeFixture::new(None);
    let init = init_authority_ix(&fixture, fixture.scenario.mint, None);
    let tx = fixture.tx(&[init, fixture.subscribe(), fixture.transfer()]);

    assert!(fixture.validate(&tx).is_err());
}

#[test]
fn canonical_activation_passes_scope_validation() {
    let sponsored = ScopeFixture::new(Some(Pubkey::new_unique()));
    sponsored
        .validate(&sponsored.tx(&[sponsored.subscribe(), sponsored.transfer()]))
        .unwrap();
    let unsponsored = ScopeFixture::new(None);
    unsponsored
        .validate(&unsponsored.tx(&[unsponsored.subscribe(), unsponsored.transfer()]))
        .unwrap();
}

#[test]
fn subscribe_for_another_plan_is_rejected() {
    let fixture = ScopeFixture::new(None);
    let mut subscribe = fixture.subscribe();
    subscribe.accounts[2].pubkey = Pubkey::new_unique();
    let tx = fixture.tx(&[subscribe, fixture.transfer()]);

    let err = fixture.validate(&tx).unwrap_err();
    assert!(err.message.contains("subscribe accounts"));
}

#[test]
fn subscribe_rent_payer_must_be_the_sponsor() {
    let fixture = ScopeFixture::new(None);
    let mut subscribe = fixture.subscribe();
    subscribe
        .accounts
        .push(solana_instruction::AccountMeta::new(
            Pubkey::new_unique(),
            true,
        ));
    let tx = fixture.tx(&[subscribe, fixture.transfer()]);

    assert!(fixture.validate(&tx).is_err());
}

// ── SOLA1-148: identity proofs need a live on-chain subscription ───────────

#[tokio::test(flavor = "multi_thread")]
async fn wallet_without_a_delegation_has_no_active_subscription() {
    let scenario = Scenario::new();
    let mut state = ChainState::default();
    state
        .accounts
        .insert(scenario.authority.to_string(), authority_bytes(INIT_ID));
    let rpc = RpcFixture::start(program_owner(), state).await;
    let server = scenario.server(&rpc.url);

    let err = server
        .verify_active_subscription(&scenario.subscriber, &AMOUNT.to_string())
        .await
        .unwrap_err();
    assert!(err.message.contains("not found"), "{}", err.message);
}

#[tokio::test(flavor = "multi_thread")]
async fn live_delegation_is_an_active_subscription() {
    let scenario = Scenario::new();
    let rpc = RpcFixture::start(
        program_owner(),
        existing_delegation_state(&scenario, DelegationState::default()),
    )
    .await;
    let server = scenario.server(&rpc.url);

    let delegation = server
        .verify_active_subscription(&scenario.subscriber, &AMOUNT.to_string())
        .await
        .unwrap();
    assert_eq!(delegation.subscriber, scenario.subscriber);
    // A different price is a different subscription.
    assert!(server
        .verify_active_subscription(&scenario.subscriber, &(AMOUNT - 1).to_string())
        .await
        .is_err());
}

#[tokio::test(flavor = "multi_thread")]
async fn unpaid_or_revoked_delegations_are_not_active() {
    let scenario = Scenario::new();
    let unpaid = RpcFixture::start(
        program_owner(),
        existing_delegation_state(
            &scenario,
            DelegationState {
                amount_pulled_in_period: 0,
                ..Default::default()
            },
        ),
    )
    .await;
    assert!(scenario
        .server(&unpaid.url)
        .verify_active_subscription(&scenario.subscriber, &AMOUNT.to_string())
        .await
        .is_err());

    let mut state = existing_delegation_state(&scenario, DelegationState::default());
    state
        .accounts
        .insert(scenario.authority.to_string(), authority_bytes(INIT_ID + 1));
    let revoked = RpcFixture::start(program_owner(), state).await;
    let err = scenario
        .server(&revoked.url)
        .verify_active_subscription(&scenario.subscriber, &AMOUNT.to_string())
        .await
        .unwrap_err();
    assert!(err.message.contains("invalidated"), "{}", err.message);
}

// ── SOLA1-159: the required signer set is exactly the canonical one ────────

fn compute_price_ix_with_signers(signers: &[Pubkey]) -> solana_instruction::Instruction {
    let mut data = vec![3];
    data.extend_from_slice(&1u64.to_le_bytes());
    solana_instruction::Instruction {
        program_id: Pubkey::from_str_const(COMPUTE_BUDGET_PROGRAM_ID),
        accounts: signers
            .iter()
            .map(|signer| solana_instruction::AccountMeta::new_readonly(*signer, true))
            .collect(),
        data,
    }
}

#[test]
fn sponsored_activation_rejects_extra_signer_slots() {
    let fixture = ScopeFixture::new(Some(Pubkey::new_unique()));
    let extra = compute_price_ix_with_signers(&[Pubkey::new_unique(), Pubkey::new_unique()]);
    let tx = fixture.tx(&[extra, fixture.subscribe(), fixture.transfer()]);
    assert_eq!(tx.message.header().num_required_signatures, 5);

    let err = fixture.validate(&tx).unwrap_err();
    assert!(err.message.contains("signers"));
}

#[test]
fn single_extra_signer_is_rejected_in_both_modes() {
    for fee_payer in [Some(Pubkey::new_unique()), None] {
        let fixture = ScopeFixture::new(fee_payer);
        let extra = compute_price_ix_with_signers(&[Pubkey::new_unique()]);
        let tx = fixture.tx(&[extra, fixture.subscribe(), fixture.transfer()]);
        assert!(fixture.validate(&tx).is_err());
    }
}

#[test]
fn canonical_signers_may_be_named_by_other_instructions() {
    let fixture = ScopeFixture::new(Some(Pubkey::new_unique()));
    let named = compute_price_ix_with_signers(&[fixture.scenario.subscriber]);
    let tx = fixture.tx(&[named, fixture.subscribe(), fixture.transfer()]);
    fixture.validate(&tx).unwrap();
}

#[test]
fn sponsored_puller_may_share_the_fee_payer_key() {
    let mut fixture = ScopeFixture::new(None);
    let puller = fixture.scenario.puller;
    fixture.fee_payer = Some(puller);
    fixture.config.fee_payer = true;
    fixture.config.fee_payer_pubkey = Some(puller.to_string());
    let tx = fixture.tx(&[fixture.subscribe(), fixture.transfer()]);
    assert_eq!(tx.message.header().num_required_signatures, 2);
    fixture.validate(&tx).unwrap();
}

#[test]
fn signature_vector_must_match_the_required_signer_count() {
    let fixture = ScopeFixture::new(Some(Pubkey::new_unique()));
    let mut tx = fixture.tx(&[fixture.subscribe(), fixture.transfer()]);
    tx.signatures.push(Signature::default());
    assert!(fixture.validate(&tx).is_err());
}

// ── SOLA1-162: server challenges satisfy the client's consistency check ────

#[test]
fn issued_challenge_passes_client_method_details_validation() {
    let scenario = Scenario::new();
    let server = scenario.server("http://127.0.0.1:1");
    let challenge = server.subscription_challenge(&AMOUNT.to_string()).unwrap();
    let request: SubscriptionRequest = challenge.request.decode().unwrap();
    request.terms().unwrap();
}

// ── SOLA1-199: challenges are bound to the server's network ────────────────

#[tokio::test(flavor = "multi_thread")]
async fn challenge_from_another_network_is_rejected() {
    let scenario = Scenario::new();
    let rpc = RpcFixture::start(program_owner(), fresh_activation_state(&scenario)).await;
    let devnet = SubscriptionServer::new(SubscriptionConfig {
        network: "devnet".into(),
        ..scenario.config(&rpc.url)
    })
    .unwrap();
    let mainnet = scenario.server(&rpc.url);
    let (credential, _) = scenario.activation(&devnet).await;

    let err = mainnet.verify_credential(&credential).await.unwrap_err();
    assert!(err.message.contains("network"), "{}", err.message);
    assert_eq!(rpc.state.lock().unwrap().sends, 0);

    devnet
        .verify_credential(&credential)
        .await
        .expect("the issuing network accepts its own challenge");
}

#[tokio::test(flavor = "multi_thread")]
async fn challenge_without_a_network_is_rejected() {
    let scenario = Scenario::new();
    let server = scenario.server("http://127.0.0.1:1");
    let issued = server.subscription_challenge(&AMOUNT.to_string()).unwrap();
    let mut request: SubscriptionRequest = issued.request.decode().unwrap();
    request
        .method_details
        .as_mut()
        .unwrap()
        .as_object_mut()
        .unwrap()
        .remove("network");
    let challenge = PaymentChallenge::with_challenge_binding_secret_full(
        "test-secret",
        "test-realm",
        "solana",
        "subscription",
        crate::mpp::protocol::core::Base64UrlJson::from_typed(&request).unwrap(),
        issued.expires.as_deref(),
        None,
        None,
        None,
    );
    let credential = PaymentCredential::new(challenge.to_echo(), serde_json::json!({}));

    let err = server.verify_credential(&credential).await.unwrap_err();
    assert!(err.message.contains("network"), "{}", err.message);
}

// ── SOLA1-211: activation retries require the current authority ────────────

#[tokio::test(flavor = "multi_thread")]
async fn activation_retry_after_authority_revocation_is_rejected() {
    let scenario = Scenario::new();
    let mut state = existing_delegation_state(&scenario, DelegationState::default());
    state.accounts.remove(&scenario.authority.to_string());
    let rpc = RpcFixture::start(program_owner(), state).await;
    let server = scenario.server(&rpc.url);
    let (credential, signature) = scenario.activation(&server).await;
    rpc.set_status(&signature, success_status());

    let err = server.verify_credential(&credential).await.unwrap_err();
    assert!(
        err.message.contains("SubscriptionAuthority"),
        "{}",
        err.message
    );
    assert_eq!(rpc.state.lock().unwrap().sends, 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn activation_retry_after_authority_reinitialization_is_rejected() {
    let scenario = Scenario::new();
    let mut state = existing_delegation_state(&scenario, DelegationState::default());
    state
        .accounts
        .insert(scenario.authority.to_string(), authority_bytes(INIT_ID + 1));
    let rpc = RpcFixture::start(program_owner(), state).await;
    let server = scenario.server(&rpc.url);
    let (credential, signature) = scenario.activation(&server).await;
    rpc.set_status(&signature, success_status());

    let err = server.verify_credential(&credential).await.unwrap_err();
    assert!(err.message.contains("invalidated"), "{}", err.message);
}

// ── SOLA1-214: failed broadcasts release their replay reservation ──────────

fn consumed_key(signature: &str) -> String {
    format!("solana-subscription:consumed:{signature}")
}

async fn server_with_store(
    scenario: &Scenario,
    rpc: &RpcFixture,
) -> (SubscriptionServer, Arc<MemoryStore>) {
    let store = Arc::new(MemoryStore::new());
    let server = SubscriptionServer::new(SubscriptionConfig {
        store: Some(store.clone()),
        ..scenario.config(&rpc.url)
    })
    .unwrap();
    (server, store)
}

#[tokio::test(flavor = "multi_thread")]
async fn preflight_rejected_activation_releases_its_reservation() {
    let scenario = Scenario::new();
    let mut state = fresh_activation_state(&scenario);
    state.send_error = Some(serde_json::json!({
        "code": -32002,
        "message": "Transaction simulation failed: Attempt to debit an account but found no record of a prior credit."
    }));
    let rpc = RpcFixture::start(program_owner(), state).await;
    let (server, store) = server_with_store(&scenario, &rpc).await;
    let (credential, signature) = scenario.activation(&server).await;

    assert!(server.verify_credential(&credential).await.is_err());
    assert_eq!(store.get(&consumed_key(&signature)).await.unwrap(), None);

    // The same signed transaction is not reported as consumed afterwards.
    let challenge = server.subscription_challenge(&AMOUNT.to_string()).unwrap();
    let (retry, retry_signature) = scenario.activation_for(&challenge).await;
    assert_eq!(retry_signature, signature);
    let err = server.verify_credential(&retry).await.unwrap_err();
    assert!(!err.message.contains("consumed"), "{}", err.message);
    assert_eq!(rpc.state.lock().unwrap().sends, 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn activation_that_failed_on_chain_releases_its_reservation() {
    let scenario = Scenario::new();
    let mut state = fresh_activation_state(&scenario);
    state.sent_status = Some(failed_status());
    let rpc = RpcFixture::start(program_owner(), state).await;
    let (server, store) = server_with_store(&scenario, &rpc).await;
    let (credential, signature) = scenario.activation(&server).await;

    assert!(server.verify_credential(&credential).await.is_err());
    assert_eq!(store.get(&consumed_key(&signature)).await.unwrap(), None);
}

#[tokio::test(flavor = "multi_thread")]
async fn ambiguous_broadcast_keeps_its_reservation() {
    let scenario = Scenario::new();
    let mut state = fresh_activation_state(&scenario);
    state.status_error = Some(serde_json::json!({"code": -32005, "message": "node is behind"}));
    // The outcome stays unknown: nothing is visible on-chain yet.
    state.landed.clear();
    let rpc = RpcFixture::start(program_owner(), state).await;
    let (server, store) = server_with_store(&scenario, &rpc).await;
    let (credential, signature) = scenario.activation(&server).await;

    assert!(server.verify_credential(&credential).await.is_err());
    assert!(store
        .get(&consumed_key(&signature))
        .await
        .unwrap()
        .is_some());

    // Another challenge must not reuse a transaction that may have landed.
    let challenge = server.subscription_challenge(&AMOUNT.to_string()).unwrap();
    let (retry, _) = scenario.activation_for(&challenge).await;
    let err = server.verify_credential(&retry).await.unwrap_err();
    assert!(err.message.contains("consumed"), "{}", err.message);
}

#[tokio::test(flavor = "multi_thread")]
async fn confirmed_activation_keeps_its_reservation() {
    let scenario = Scenario::new();
    let rpc = RpcFixture::start(program_owner(), fresh_activation_state(&scenario)).await;
    let (server, store) = server_with_store(&scenario, &rpc).await;
    let (credential, signature) = scenario.activation(&server).await;

    server.verify_credential(&credential).await.unwrap();
    assert!(store
        .get(&consumed_key(&signature))
        .await
        .unwrap()
        .is_some());
}
