//! Test-only Solana JSON-RPC fixture for x402 server integration tests.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use axum::{extract::State, routing::post, Json, Router};
use base64::Engine as _;
use serde_json::{json, Value};
use solana_hash::Hash;
use solana_instruction::Instruction;
use solana_message::{Message, VersionedMessage};
use solana_pubkey::Pubkey;
use solana_transaction::versioned::VersionedTransaction;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

const BLOCKHASH: &str = "11111111111111111111111111111111";

#[derive(Default)]
struct StateData {
    accounts: HashMap<String, Account>,
    accepted_signatures: HashSet<String>,
    expected_transaction: Option<TransactionExpectation>,
    signatures_for_address: HashMap<String, Vec<String>>,
    send_error: Option<String>,
    blockhash_error: Option<String>,
}

#[derive(Clone)]
struct Account {
    data: Vec<u8>,
    owner: String,
}

/// One exact transaction the fixture will accept and apply to its account state.
///
/// The complete legacy message is compared, so program IDs, instruction order,
/// account metas, data, fee payer, and blockhash all have to match.
#[derive(Clone)]
pub(crate) struct TransactionExpectation {
    expected_message: Message,
    account_transitions: Vec<AccountDataTransition>,
}

#[derive(Clone)]
struct AccountDataTransition {
    address: String,
    expected_data: Vec<u8>,
    updated_data: Vec<u8>,
}

impl TransactionExpectation {
    pub(crate) fn new(fee_payer: Pubkey, instructions: Vec<Instruction>) -> Self {
        Self {
            expected_message: Message::new_with_blockhash(
                &instructions,
                Some(&fee_payer),
                &Hash::default(),
            ),
            account_transitions: Vec::new(),
        }
    }

    /// Expect a transaction whose legacy message equals `message` exactly.
    ///
    /// Use when the transaction under test is assembled by production code
    /// (so its `Instruction`s cannot be reconstructed field-by-field) and the
    /// test can capture the built message directly. Signing the message later
    /// only fills the signature slots, so the message stays byte-identical.
    pub(crate) fn matching(message: Message) -> Self {
        Self {
            expected_message: message,
            account_transitions: Vec::new(),
        }
    }

    pub(crate) fn with_account_data_transition(
        mut self,
        address: String,
        expected_data: Vec<u8>,
        updated_data: Vec<u8>,
    ) -> Self {
        self.account_transitions.push(AccountDataTransition {
            address,
            expected_data,
            updated_data,
        });
        self
    }

    fn validate(
        &self,
        transaction: &VersionedTransaction,
        accounts: &HashMap<String, Account>,
    ) -> Result<(), &'static str> {
        match &transaction.message {
            VersionedMessage::Legacy(message) if message == &self.expected_message => {}
            _ => return Err("transaction does not match configured schema"),
        }

        for transition in &self.account_transitions {
            let account = accounts
                .get(&transition.address)
                .ok_or("transaction transition account is missing")?;
            if account.data != transition.expected_data {
                return Err("transaction transition precondition failed");
            }
        }

        Ok(())
    }

    fn apply(self, accounts: &mut HashMap<String, Account>) {
        for transition in self.account_transitions {
            accounts
                .get_mut(&transition.address)
                .expect("transition account checked above")
                .data = transition.updated_data;
        }
    }
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

    pub(crate) fn expect_transaction(&self, expectation: TransactionExpectation) {
        let mut state = self.state.lock().expect("mock rpc state");
        assert!(
            state.expected_transaction.is_none(),
            "cannot replace an unconsumed transaction expectation"
        );
        state.expected_transaction = Some(expectation);
    }

    pub(crate) fn assert_transaction_consumed(&self) {
        assert!(
            self.state
                .lock()
                .expect("mock rpc state")
                .expected_transaction
                .is_none(),
            "transaction expectation was not consumed"
        );
    }

    /// Seed the `getSignaturesForAddress` response for `address`. The server's
    /// idempotent-activation lookup treats the *last* entry (oldest, since the
    /// RPC returns newest-first) as the account's creation signature.
    pub(crate) fn set_signatures(&self, address: String, signatures: Vec<String>) {
        self.state
            .lock()
            .expect("mock rpc state")
            .signatures_for_address
            .insert(address, signatures);
    }

    pub(crate) fn account_data(&self, pubkey: &str) -> Option<Vec<u8>> {
        self.state
            .lock()
            .expect("mock rpc state")
            .accounts
            .get(pubkey)
            .map(|account| account.data.clone())
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
            None => match verified_transaction_of(&params) {
                Ok((signature, transaction)) => {
                    let Some(expectation) = state.expected_transaction.as_ref() else {
                        return Json(error(
                            id,
                            -32602,
                            "transaction expectation is not configured",
                        ));
                    };
                    if let Err(message) = expectation.validate(&transaction, &state.accounts) {
                        return Json(error(id, -32602, message));
                    }
                    state
                        .expected_transaction
                        .take()
                        .expect("validated transaction expectation")
                        .apply(&mut state.accounts);
                    state.accepted_signatures.insert(signature.clone());
                    result(id, Value::String(signature))
                }
                Err(message) => error(id, -32602, message),
            },
        },
        "getSignaturesForAddress" => {
            let address = params.get(0).and_then(Value::as_str).unwrap_or_default();
            let entries = state
                .signatures_for_address
                .get(address)
                .cloned()
                .unwrap_or_default();
            result(
                id,
                Value::Array(
                    entries
                        .into_iter()
                        .map(|signature| {
                            json!({
                                "signature": signature,
                                "slot": 314,
                                "err": null,
                                "memo": null,
                                "blockTime": null,
                                "confirmationStatus": "finalized",
                            })
                        })
                        .collect(),
                ),
            )
        }
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

fn verified_transaction_of(params: &Value) -> Result<(String, VersionedTransaction), &'static str> {
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

    let signature = transaction
        .signatures
        .first()
        .map(ToString::to_string)
        .ok_or("transaction has no fee-payer signature")?;

    Ok((signature, transaction))
}

fn verified_signature_of(params: &Value) -> Result<String, &'static str> {
    verified_transaction_of(params).map(|(signature, _)| signature)
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
    use solana_instruction::{AccountMeta, Instruction};
    use solana_message::Message;
    use solana_pubkey::Pubkey;
    use solana_signature::Signature;
    use solana_transaction::Transaction;

    fn transaction_params(transaction: &VersionedTransaction) -> Value {
        let encoded = base64::engine::general_purpose::STANDARD
            .encode(bincode::serialize(transaction).expect("serialize transaction"));
        json!([encoded])
    }

    fn signed_transaction(
        fee_payer: &SigningKey,
        instructions: &[Instruction],
    ) -> VersionedTransaction {
        let fee_payer_pubkey = Pubkey::new_from_array(fee_payer.verifying_key().to_bytes());
        let mut transaction =
            Transaction::new_unsigned(Message::new(instructions, Some(&fee_payer_pubkey)));
        transaction.signatures[0] =
            Signature::from(fee_payer.sign(&transaction.message_data()).to_bytes());
        VersionedTransaction::from(transaction)
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

    #[tokio::test]
    async fn rejects_signed_transactions_without_an_expectation() {
        let fee_payer = SigningKey::from_bytes(&[72; 32]);
        let transaction = signed_transaction(&fee_payer, &[]);
        let state = Arc::new(Mutex::new(StateData::default()));

        let response = dispatch(
            State(state.clone()),
            Json(json!({
                "id": 1,
                "method": "sendTransaction",
                "params": transaction_params(&transaction),
            })),
        )
        .await
        .0;
        assert_eq!(
            response["error"]["message"],
            Value::String("transaction expectation is not configured".to_string())
        );
        assert!(state
            .lock()
            .expect("mock rpc state")
            .accepted_signatures
            .is_empty());
    }

    #[tokio::test]
    #[should_panic(expected = "cannot replace an unconsumed transaction expectation")]
    async fn refuses_to_replace_an_unconsumed_expectation() {
        let mock = MockRpc::start().await;
        let fee_payer = Pubkey::new_unique();
        mock.expect_transaction(TransactionExpectation::new(fee_payer, Vec::new()));
        mock.expect_transaction(TransactionExpectation::new(fee_payer, Vec::new()));
    }

    #[tokio::test]
    async fn rejects_signed_transactions_with_wrong_program_or_data() {
        let fee_payer = SigningKey::from_bytes(&[72; 32]);
        let fee_payer_pubkey = Pubkey::new_from_array(fee_payer.verifying_key().to_bytes());
        let channel = Pubkey::new_unique();
        let expected = Instruction {
            program_id: Pubkey::new_unique(),
            accounts: vec![AccountMeta::new(channel, false)],
            data: vec![4, 1],
        };

        for wrong in [
            Instruction {
                program_id: Pubkey::new_unique(),
                accounts: expected.accounts.clone(),
                data: expected.data.clone(),
            },
            Instruction {
                program_id: expected.program_id,
                accounts: expected.accounts.clone(),
                data: vec![4, 0],
            },
        ] {
            let state = Arc::new(Mutex::new(StateData {
                accounts: HashMap::from([(
                    channel.to_string(),
                    Account {
                        data: vec![0],
                        owner: "payment-channels".to_string(),
                    },
                )]),
                expected_transaction: Some(
                    TransactionExpectation::new(fee_payer_pubkey, vec![expected.clone()])
                        .with_account_data_transition(channel.to_string(), vec![0], vec![1]),
                ),
                ..StateData::default()
            }));
            let transaction = signed_transaction(&fee_payer, &[wrong]);
            assert!(verified_signature_of(&transaction_params(&transaction)).is_ok());

            let response = dispatch(
                State(state.clone()),
                Json(json!({
                    "id": 1,
                    "method": "sendTransaction",
                    "params": transaction_params(&transaction),
                })),
            )
            .await
            .0;
            assert_eq!(
                response["error"]["message"],
                Value::String("transaction does not match configured schema".to_string())
            );

            let state = state.lock().expect("mock rpc state");
            assert!(state.accepted_signatures.is_empty());
            assert_eq!(state.accounts[&channel.to_string()].data, vec![0]);
        }
    }

    #[tokio::test]
    async fn rejects_signed_transactions_when_the_transition_precondition_fails() {
        let fee_payer = SigningKey::from_bytes(&[73; 32]);
        let fee_payer_pubkey = Pubkey::new_from_array(fee_payer.verifying_key().to_bytes());
        let channel = Pubkey::new_unique();
        let instruction = Instruction {
            program_id: Pubkey::new_unique(),
            accounts: vec![AccountMeta::new(channel, false)],
            data: vec![4, 1],
        };
        let state = Arc::new(Mutex::new(StateData {
            accounts: HashMap::from([(
                channel.to_string(),
                Account {
                    data: vec![9],
                    owner: "payment-channels".to_string(),
                },
            )]),
            expected_transaction: Some(
                TransactionExpectation::new(fee_payer_pubkey, vec![instruction.clone()])
                    .with_account_data_transition(channel.to_string(), vec![0], vec![1]),
            ),
            ..StateData::default()
        }));
        let transaction = signed_transaction(&fee_payer, &[instruction]);
        assert!(verified_signature_of(&transaction_params(&transaction)).is_ok());

        let response = dispatch(
            State(state.clone()),
            Json(json!({
                "id": 1,
                "method": "sendTransaction",
                "params": transaction_params(&transaction),
            })),
        )
        .await
        .0;
        assert_eq!(
            response["error"]["message"],
            Value::String("transaction transition precondition failed".to_string())
        );

        let state = state.lock().expect("mock rpc state");
        assert!(state.accepted_signatures.is_empty());
        assert!(state.expected_transaction.is_some());
        assert_eq!(state.accounts[&channel.to_string()].data, vec![9]);
    }

    #[tokio::test]
    async fn rejected_transaction_preserves_expectation_for_a_correct_retry() {
        let fee_payer = SigningKey::from_bytes(&[74; 32]);
        let fee_payer_pubkey = Pubkey::new_from_array(fee_payer.verifying_key().to_bytes());
        let channel = Pubkey::new_unique();
        let expected = Instruction {
            program_id: Pubkey::new_unique(),
            accounts: vec![AccountMeta::new(channel, false)],
            data: vec![4, 1],
        };
        let state = Arc::new(Mutex::new(StateData {
            accounts: HashMap::from([(
                channel.to_string(),
                Account {
                    data: vec![0],
                    owner: "payment-channels".to_string(),
                },
            )]),
            expected_transaction: Some(
                TransactionExpectation::new(fee_payer_pubkey, vec![expected.clone()])
                    .with_account_data_transition(channel.to_string(), vec![0], vec![1]),
            ),
            ..StateData::default()
        }));
        let wrong = signed_transaction(
            &fee_payer,
            &[Instruction {
                data: vec![4, 0],
                ..expected.clone()
            }],
        );

        let rejected = dispatch(
            State(state.clone()),
            Json(json!({
                "id": 1,
                "method": "sendTransaction",
                "params": transaction_params(&wrong),
            })),
        )
        .await
        .0;
        assert_eq!(
            rejected["error"]["message"],
            Value::String("transaction does not match configured schema".to_string())
        );
        {
            let state = state.lock().expect("mock rpc state");
            assert!(state.expected_transaction.is_some());
            assert!(state.accepted_signatures.is_empty());
            assert_eq!(state.accounts[&channel.to_string()].data, vec![0]);
        }

        let correct = signed_transaction(&fee_payer, &[expected]);
        let signature = correct
            .signatures
            .first()
            .expect("fee payer signature")
            .to_string();
        let accepted = dispatch(
            State(state.clone()),
            Json(json!({
                "id": 2,
                "method": "sendTransaction",
                "params": transaction_params(&correct),
            })),
        )
        .await
        .0;
        assert_eq!(accepted["result"], Value::String(signature.clone()));

        let state = state.lock().expect("mock rpc state");
        assert!(state.expected_transaction.is_none());
        assert!(state.accepted_signatures.contains(&signature));
        assert_eq!(state.accounts[&channel.to_string()].data, vec![1]);
    }
}
