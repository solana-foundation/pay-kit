//! Test-only Solana JSON-RPC fixture for x402 server integration tests.

use std::collections::{HashMap, HashSet};
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
    accepted_signatures: HashSet<String>,
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
    let mut state = state.lock().expect("mock rpc state");

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
            None => match verified_signature_of(&params) {
                Ok(signature) => {
                    state.accepted_signatures.insert(signature.clone());
                    result(id, Value::String(signature))
                }
                Err(message) => error(id, -32602, message),
            },
        },
        "getSignatureStatuses" => match signature_statuses(&params, &state.accepted_signatures) {
            Ok(value) => result(
                id,
                json!({
                    "context": { "slot": 314 },
                    "value": value,
                }),
            ),
            Err(message) => error(id, -32602, message),
        },
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

fn verified_signature_of(params: &Value) -> Result<String, &'static str> {
    let encoded = params
        .get(0)
        .and_then(Value::as_str)
        .ok_or("missing encoded transaction")?;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|_| "transaction is not valid base64")?;
    let transaction: VersionedTransaction =
        bincode::deserialize(&bytes).map_err(|_| "could not decode transaction")?;
    transaction
        .sanitize()
        .map_err(|_| "transaction failed sanitization")?;

    let message = transaction.message.serialize();
    let signer_keys = transaction.message.static_account_keys();
    if !transaction
        .signatures
        .iter()
        .zip(signer_keys)
        .all(|(signature, pubkey)| signature.verify(pubkey.as_ref(), &message))
    {
        return Err("transaction signature verification failed");
    }

    transaction
        .signatures
        .first()
        .map(ToString::to_string)
        .ok_or("transaction has no fee-payer signature")
}

fn signature_statuses(
    params: &Value,
    accepted_signatures: &HashSet<String>,
) -> Result<Vec<Value>, &'static str> {
    let signatures = params
        .get(0)
        .and_then(Value::as_array)
        .ok_or("missing signature list")?;

    Ok(signatures
        .iter()
        .map(|signature| {
            signature
                .as_str()
                .filter(|signature| accepted_signatures.contains(*signature))
                .map(|_| {
                    json!({
                        "slot": 314,
                        "confirmations": null,
                        "status": { "Ok": null },
                        "err": null,
                        "confirmationStatus": "finalized",
                    })
                })
                .unwrap_or(Value::Null)
        })
        .collect())
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

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer as _, SigningKey};
    use solana_message::Message;
    use solana_pubkey::Pubkey;
    use solana_signature::Signature;
    use solana_transaction::Transaction;

    fn transaction_params(transaction: &VersionedTransaction) -> Value {
        let encoded = base64::engine::general_purpose::STANDARD
            .encode(bincode::serialize(transaction).expect("serialize transaction"));
        json!([encoded])
    }

    #[test]
    fn only_returns_a_signature_for_a_fully_signed_transaction() {
        let fee_payer = SigningKey::from_bytes(&[71; 32]);
        let fee_payer_pubkey = Pubkey::new_from_array(fee_payer.verifying_key().to_bytes());
        let message = Message::new(&[], Some(&fee_payer_pubkey));
        let unsigned = VersionedTransaction::from(Transaction::new_unsigned(message.clone()));
        assert_eq!(
            verified_signature_of(&transaction_params(&unsigned)),
            Err("transaction signature verification failed")
        );

        let mut signed = Transaction::new_unsigned(message);
        let signature = fee_payer.sign(&signed.message_data());
        signed.signatures[0] = Signature::from(signature.to_bytes());
        let signed = VersionedTransaction::from(signed);
        assert_eq!(
            verified_signature_of(&transaction_params(&signed)),
            signed
                .signatures
                .first()
                .map(ToString::to_string)
                .ok_or("missing")
        );
    }

    #[test]
    fn only_reports_status_for_an_accepted_signature() {
        let accepted = HashSet::from(["accepted-signature".to_string()]);
        let statuses = signature_statuses(
            &json!([["accepted-signature", "unknown-signature"]]),
            &accepted,
        )
        .expect("valid status request");

        assert!(statuses[0].is_object());
        assert!(statuses[1].is_null());
    }
}
