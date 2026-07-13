//! Test-only Solana JSON-RPC fixture for x402 server integration tests.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::{extract::State, routing::post, Json, Router};
use base64::Engine as _;
use serde_json::{json, Value};
use solana_transaction::versioned::VersionedTransaction;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

const BLOCKHASH: &str = "11111111111111111111111111111111";

#[derive(Default)]
struct StateData {
    accounts: HashMap<String, Account>,
    send_error: Option<String>,
    blockhash_error: Option<String>,
}

#[derive(Clone)]
struct Account {
    data: Vec<u8>,
    owner: String,
}

pub(crate) struct MockRpc {
    url: String,
    state: Arc<Mutex<StateData>>,
    task: JoinHandle<()>,
}

impl MockRpc {
    pub(crate) async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock rpc");
        let url = format!(
            "http://{}",
            listener.local_addr().expect("mock rpc address")
        );
        let state = Arc::new(Mutex::new(StateData::default()));
        let app = Router::new()
            .route("/", post(dispatch))
            .with_state(state.clone());
        let task = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        Self { url, state, task }
    }

    pub(crate) fn url(&self) -> String {
        self.url.clone()
    }

    pub(crate) fn set_account(&self, pubkey: String, data: Vec<u8>, owner: String) {
        self.state
            .lock()
            .expect("mock rpc state")
            .accounts
            .insert(pubkey, Account { data, owner });
    }

    pub(crate) fn fail_send(&self, message: impl Into<String>) {
        self.state.lock().expect("mock rpc state").send_error = Some(message.into());
    }

    pub(crate) fn fail_blockhash(&self, message: impl Into<String>) {
        self.state.lock().expect("mock rpc state").blockhash_error = Some(message.into());
    }
}

impl Drop for MockRpc {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn dispatch(
    State(state): State<Arc<Mutex<StateData>>>,
    Json(request): Json<Value>,
) -> Json<Value> {
    let id = request.get("id").cloned().unwrap_or(Value::Null);
    let method = request
        .get("method")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let params = request.get("params").cloned().unwrap_or(Value::Null);
    let state = state.lock().expect("mock rpc state");

    let response = match method {
        "getLatestBlockhash" => match &state.blockhash_error {
            Some(message) => error(id, -32000, message),
            None => result(
                id,
                json!({
                    "context": { "slot": 314 },
                    "value": { "blockhash": BLOCKHASH, "lastValidBlockHeight": 1000 },
                }),
            ),
        },
        "sendTransaction" => match &state.send_error {
            Some(message) => error(id, -32002, message),
            None => signature_of(&params)
                .map(|signature| result(id.clone(), Value::String(signature)))
                .unwrap_or_else(|| error(id, -32602, "could not decode transaction")),
        },
        "getSignatureStatuses" => result(
            id,
            json!({
                "context": { "slot": 314 },
                "value": [{
                    "slot": 314,
                    "confirmations": null,
                    "status": { "Ok": null },
                    "err": null,
                    "confirmationStatus": "finalized",
                }],
            }),
        ),
        "getAccountInfo" => {
            let key = params.get(0).and_then(Value::as_str).unwrap_or_default();
            match state.accounts.get(key) {
                Some(account) => {
                    let data = base64::engine::general_purpose::STANDARD.encode(&account.data);
                    result(
                        id,
                        json!({
                            "context": { "slot": 314 },
                            "value": {
                                "lamports": 2_039_280u64,
                                "data": [data, "base64"],
                                "owner": account.owner,
                                "executable": false,
                                "rentEpoch": 0,
                                "space": account.data.len(),
                            },
                        }),
                    )
                }
                None => result(id, json!({ "context": { "slot": 314 }, "value": null })),
            }
        }
        _ => result(id, Value::Null),
    };

    Json(response)
}

fn signature_of(params: &Value) -> Option<String> {
    let encoded = params.get(0)?.as_str()?;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .ok()?;
    let transaction: VersionedTransaction = bincode::deserialize(&bytes).ok()?;
    transaction.signatures.first().map(ToString::to_string)
}

fn result(id: Value, result: Value) -> Value {
    json!({ "jsonrpc": "2.0", "result": result, "id": id })
}

fn error(id: Value, code: i64, message: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "error": { "code": code, "message": message },
        "id": id,
    })
}
