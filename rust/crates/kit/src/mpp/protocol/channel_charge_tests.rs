use super::*;
use crate::mpp::{
    client::build_channel_charge_credential,
    protocol::{
        core::{Base64UrlJson, PaymentChallenge},
        solana::{mints::USDC_DEVNET as MINT, CredentialPayload, Split},
    },
    server::{ChannelChargeConfig, Config, Mpp},
};
use solana_keychain::{MemorySigner, SolanaSigner};
use std::sync::Arc;

const SECRET: &str = "channel-charge-test-secret-32-bytes-minimum";

fn signer(seed: u8) -> Arc<MemorySigner> {
    let key = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
    let mut bytes = [0; 64];
    bytes[..32].copy_from_slice(key.as_bytes());
    bytes[32..].copy_from_slice(key.verifying_key().as_bytes());
    Arc::new(MemorySigner::from_bytes(&bytes).unwrap())
}

fn request(hooks: v2::ChannelHooks, sponsored: bool) -> ChargeRequest {
    ChargeRequest {
        amount: "1000000".into(),
        currency: MINT.into(),
        recipient: Some(signer(3).pubkey().to_string()),
        external_id: Some("resource:unique-request".into()),
        method_details: Some(
            serde_json::to_value(MethodDetails {
                network: Some("devnet".into()),
                decimals: Some(6),
                token_program: Some(super::super::solana::programs::TOKEN_PROGRAM.into()),
                transaction_versions: Some(vec![tx::TxVersion::V0]),
                fee_payer: sponsored.then_some(true),
                fee_payer_key: sponsored.then(|| signer(4).pubkey().to_string()),
                recent_blockhash: Some(Hash::new_from_array([5; 32]).to_string()),
                channel_charge: Some(ChannelChargeProfile {
                    channel_program: v2::PAYMENT_CHANNELS_PROGRAM_ID.into(),
                    channel_version: 2,
                    channel_hooks: hooks,
                    recent_slot: 42,
                }),
                ..Default::default()
            })
            .unwrap(),
        ),
        ..Default::default()
    }
}

fn challenge(request: &ChargeRequest) -> PaymentChallenge {
    PaymentChallenge::with_challenge_binding_secret_full(
        SECRET,
        "channel-test",
        "solana",
        "charge",
        Base64UrlJson::from_typed(request).unwrap(),
        Some("2099-01-01T00:00:00Z"),
        None,
        None,
        None,
    )
}

async fn transaction(
    challenge: &PaymentChallenge,
    hooks: &v2::ChannelHooks,
) -> VersionedTransaction {
    let credential = build_channel_charge_credential(
        signer(1).as_ref(),
        signer(2).as_ref(),
        challenge,
        hooks,
        99,
    )
    .await
    .unwrap();
    let CredentialPayload::Transaction { transaction } =
        serde_json::from_value(credential.payload).unwrap()
    else {
        panic!("transaction credential required")
    };
    tx::decode(&transaction).unwrap()
}

fn message(tx: &mut VersionedTransaction) -> &mut solana_message::v0::Message {
    let solana_message::VersionedMessage::V0(message) = &mut tx.message else {
        panic!("v0")
    };
    message
}

async fn resign_payer(tx: &mut VersionedTransaction) {
    crate::core::signing::sign_versioned_transaction_slot(signer(1).as_ref(), tx)
        .await
        .unwrap();
    let index = tx
        .message
        .static_account_keys()
        .iter()
        .position(|key| *key == signer(1).pubkey())
        .unwrap();
    assert!(tx.signatures[index].verify(signer(1).pubkey().as_ref(), &tx.message.serialize()));
}

#[tokio::test]
async fn channel_charge_real_partial_signatures_and_server_cosign() {
    for sponsored in [false, true] {
        let hooks = v2::ChannelHooks::default();
        let challenge = challenge(&request(hooks.clone(), sponsored));
        let mut tx = transaction(&challenge, &hooks).await;
        assert_eq!(
            tx.signatures
                .iter()
                .filter(|s| **s == Signature::default())
                .count(),
            1
        );
        verify_transaction(&tx, &challenge.to_echo(), &hooks).unwrap();
        let payer_signature = *tx
            .signatures
            .iter()
            .find(|s| **s != Signature::default())
            .unwrap();
        let payee = signer(if sponsored { 4 } else { 3 });
        crate::core::signing::sign_versioned_transaction_slot(payee.as_ref(), &mut tx)
            .await
            .unwrap();
        tx.verify_and_hash_message().unwrap();
        assert!(tx.signatures.contains(&payer_signature));
        verify_transaction(&tx, &challenge.to_echo(), &hooks).unwrap();
        eprintln!(
            "channel charge sponsored={sponsored}: {} bytes",
            tx::serialized_size(&tx).unwrap()
        );
    }
}

#[tokio::test]
async fn channel_charge_rejects_every_instruction_data_and_account_mutation() {
    let hooks = v2::ChannelHooks::default();
    let challenge = challenge(&request(hooks.clone(), true));
    let tx = transaction(&challenge, &hooks).await;
    for ix in 0..tx.message.instructions().len() {
        for byte in 0..tx.message.instructions()[ix].data.len() {
            let mut changed = tx.clone();
            message(&mut changed).instructions[ix].data[byte] ^= 1;
            resign_payer(&mut changed).await;
            assert!(
                verify_transaction(&changed, &challenge.to_echo(), &hooks).is_err(),
                "ix={ix} byte={byte}"
            );
        }
        for index in 0..tx.message.instructions()[ix].accounts.len() {
            let mut changed = tx.clone();
            message(&mut changed).instructions[ix].accounts[index] = 255;
            resign_payer(&mut changed).await;
            assert!(verify_transaction(&changed, &challenge.to_echo(), &hooks).is_err());
        }
        let mut changed = tx.clone();
        message(&mut changed).instructions[ix].program_id_index = 255;
        resign_payer(&mut changed).await;
        assert!(verify_transaction(&changed, &challenge.to_echo(), &hooks).is_err());
    }
}

#[tokio::test]
async fn channel_charge_rejects_injection_signers_blockhash_and_cross_challenge() {
    let hooks = v2::ChannelHooks::default();
    let challenge = challenge(&request(hooks.clone(), true));
    let tx = transaction(&challenge, &hooks).await;
    let mut changed = tx.clone();
    let extra = changed.message.instructions()[0].clone();
    message(&mut changed).instructions.push(extra);
    resign_payer(&mut changed).await;
    assert!(verify_transaction(&changed, &challenge.to_echo(), &hooks).is_err());
    let mut changed = tx.clone();
    message(&mut changed)
        .account_keys
        .push(Pubkey::new_unique());
    resign_payer(&mut changed).await;
    assert!(verify_transaction(&changed, &challenge.to_echo(), &hooks).is_err());
    let mut changed = tx.clone();
    message(&mut changed).header.num_required_signatures += 1;
    changed.signatures.push(Signature::default());
    resign_payer(&mut changed).await;
    assert!(verify_transaction(&changed, &challenge.to_echo(), &hooks).is_err());
    let mut changed = tx.clone();
    message(&mut changed).recent_blockhash = Hash::new_unique();
    resign_payer(&mut changed).await;
    assert!(verify_transaction(&changed, &challenge.to_echo(), &hooks).is_err());
    let mut other = challenge.to_echo();
    other.id.push('x');
    assert!(verify_transaction(&tx, &other, &hooks).is_err());
}

#[tokio::test]
async fn channel_charge_rejects_forged_payer_and_voucher_signatures() {
    let hooks = v2::ChannelHooks::default();
    let challenge = challenge(&request(hooks.clone(), true));
    let tx = transaction(&challenge, &hooks).await;
    let mut forged_payer = tx.clone();
    let payer_index = tx
        .message
        .static_account_keys()
        .iter()
        .position(|key| *key == signer(1).pubkey())
        .unwrap();
    forged_payer.signatures[payer_index] = signer(9)
        .sign_message(&tx.message.serialize())
        .await
        .unwrap();
    assert!(
        verify_transaction(&forged_payer, &challenge.to_echo(), &hooks)
            .unwrap_err()
            .to_string()
            .contains("invalid or missing transaction signature")
    );

    let mut forged_voucher = tx;
    message(&mut forged_voucher).instructions[1].data[48] ^= 1;
    resign_payer(&mut forged_voucher).await;
    assert!(
        verify_transaction(&forged_voucher, &challenge.to_echo(), &hooks)
            .unwrap_err()
            .to_string()
            .contains("invalid voucher signature")
    );
}

#[test]
fn channel_charge_exact_inclusive_split_amounts() {
    let mut request = request(v2::ChannelHooks::default(), true);
    let mut details: MethodDetails =
        serde_json::from_value(request.method_details.take().unwrap()).unwrap();
    details.splits = Some(vec![Split {
        recipient: signer(6).pubkey().to_string(),
        amount: "250000".into(),
        ata_creation_required: None,
        label: None,
        memo: None,
    }]);
    let t = terms(
        &request,
        &details,
        "2099-01-01T00:00:00Z",
        signer(1).pubkey(),
        signer(2).pubkey(),
        99,
    )
    .unwrap();
    assert_eq!(t.params.deposit, 1_000_000);
    assert_eq!(t.params.recipients[0].bps, 7500);
    assert_eq!(t.params.recipients[1].bps, 2500);
    details.splits.as_mut().unwrap()[0].amount = "1".into();
    assert!(terms(
        &request,
        &details,
        "2099-01-01T00:00:00Z",
        signer(1).pubkey(),
        signer(2).pubkey(),
        99
    )
    .is_err());
    details.splits = None;
    request.amount = "0".into();
    assert!(terms(
        &request,
        &details,
        "2099-01-01T00:00:00Z",
        signer(1).pubkey(),
        signer(2).pubkey(),
        99
    )
    .is_err());
}

#[tokio::test]
async fn channel_charge_hook_policy_and_packet_limit() {
    let hook = v2::HookDescriptor {
        program_id: signer(8).pubkey().to_string(),
        entrypoint: [1; 8],
        accounts: vec![],
        static_data: vec![],
    };
    let hooks = v2::ChannelHooks {
        pre_fund: Some(hook.clone()),
        post_distribute: Some(hook),
        ..Default::default()
    };
    let challenge = challenge(&request(hooks.clone(), true));
    let error = build_channel_charge_credential(
        signer(1).as_ref(),
        signer(2).as_ref(),
        &challenge,
        &v2::ChannelHooks::default(),
        99,
    )
    .await
    .unwrap_err();
    assert!(error.to_string().contains("hook policy mismatch"));
    let result = build_channel_charge_credential(
        signer(1).as_ref(),
        signer(2).as_ref(),
        &challenge,
        &hooks,
        99,
    )
    .await;
    assert!(result.unwrap_err().to_string().contains("1232-byte limit"));
    let mut v1_request: ChargeRequest = challenge.request.decode().unwrap();
    v1_request.method_details.as_mut().unwrap()["transactionVersions"] = serde_json::json!([0, 1]);
    let v1_challenge = super::tests::challenge(&v1_request);
    let tx = transaction(&v1_challenge, &hooks).await;
    assert_eq!(tx::TxVersion::of(&tx.message).unwrap(), tx::TxVersion::V1);
    verify_transaction(&tx, &v1_challenge.to_echo(), &hooks).unwrap();
    eprintln!(
        "two-hook V1 profile: {} bytes",
        tx::serialized_size(&tx).unwrap()
    );
}

#[test]
fn channel_charge_server_opt_in_and_direct_transfer_wire() {
    let config = || Config {
        recipient: signer(3).pubkey().to_string(),
        currency: MINT.into(),
        network: "devnet".into(),
        challenge_binding_secret: Some(SECRET.into()),
        realm: Some("channel-test".into()),
        fee_payer: true,
        fee_payer_signer: Some(signer(4)),
        store: Some(std::sync::Arc::new(crate::mpp::store::MemoryStore::new())),
        ..Default::default()
    };
    let request = request(v2::ChannelHooks::default(), true);
    let disabled = Mpp::new(config()).unwrap();
    assert!(!disabled.channel_charge_enabled());
    assert!(disabled.charge_challenge(&request).is_err());
    let enabled = Mpp::new(Config {
        store: Some(std::sync::Arc::new(crate::mpp::store::MemoryStore::new())),
        realm: Some("test-realm".to_string()),
        channel_charge: Some(ChannelChargeConfig {
            payee_signer: signer(4),
            hooks: v2::ChannelHooks::default(),
        }),
        ..config()
    })
    .unwrap();
    enabled.charge_challenge(&request).unwrap();
    assert!(serde_json::to_value(MethodDetails::default())
        .unwrap()
        .get("channelCharge")
        .is_none());
    let mut malformed = serde_json::to_value(ChannelChargeProfile {
        channel_program: v2::PAYMENT_CHANNELS_PROGRAM_ID.into(),
        channel_version: 2,
        channel_hooks: v2::ChannelHooks::default(),
        recent_slot: 42,
    })
    .unwrap();
    malformed["unknown"] = serde_json::json!(true);
    assert!(serde_json::from_value::<ChannelChargeProfile>(malformed).is_err());
}

#[tokio::test]
async fn channel_charge_network_is_checked_during_issuance_signing_and_verification() {
    let hooks = v2::ChannelHooks::default();
    let server = workflow_server(Arc::new(std::sync::Mutex::new(WorkflowState::default())));
    let valid_request = request(hooks.clone(), true);
    let valid_transaction = transaction(&challenge(&valid_request), &hooks).await;

    for network in ["mainnet", "testnet", "unknown"] {
        let expected_error = if network == "mainnet" {
            "only devnet and localnet"
        } else {
            "network"
        };
        let mut unsupported = valid_request.clone();
        unsupported.method_details.as_mut().unwrap()["network"] = network.into();
        let unsupported_challenge = challenge(&unsupported);
        let issuance_error = server.charge_challenge(&unsupported).unwrap_err();
        assert!(
            issuance_error
                .to_string()
                .contains("channel charge server policy mismatch"),
            "{network}: {issuance_error}"
        );
        let signing_error = build_channel_charge_credential(
            signer(1).as_ref(),
            signer(2).as_ref(),
            &unsupported_challenge,
            &hooks,
            99,
        )
        .await
        .unwrap_err();
        assert!(
            signing_error.to_string().contains(expected_error),
            "{network}: {signing_error}"
        );
        let verification_error =
            verify_transaction(&valid_transaction, &unsupported_challenge.to_echo(), &hooks)
                .unwrap_err();
        assert!(
            verification_error.to_string().contains(expected_error),
            "{network}: {verification_error}"
        );
    }

    for network in ["devnet", "localnet"] {
        let mut supported = valid_request.clone();
        supported.method_details.as_mut().unwrap()["network"] = network.into();
        let supported_challenge = challenge(&supported);
        let transaction = transaction(&supported_challenge, &hooks).await;
        verify_transaction(&transaction, &supported_challenge.to_echo(), &hooks).unwrap();
    }
}

#[test]
fn channel_charge_mainnet_configuration_fails_without_changing_direct_charge() {
    let config = || Config {
        realm: Some("test-realm".to_string()),
        recipient: signer(3).pubkey().to_string(),
        currency: "USDC".into(),
        network: "mainnet".into(),
        challenge_binding_secret: Some(SECRET.into()),
        rpc_url: Some("http://127.0.0.1:1".into()),
        store: Some(std::sync::Arc::new(crate::mpp::store::MemoryStore::new())),
        ..Default::default()
    };
    assert!(Mpp::new(config()).is_ok());
    let error = match Mpp::new(Config {
        store: Some(std::sync::Arc::new(crate::mpp::store::MemoryStore::new())),
        realm: Some("test-realm".to_string()),
        channel_charge: Some(ChannelChargeConfig {
            payee_signer: signer(3),
            hooks: v2::ChannelHooks::default(),
        }),
        ..config()
    }) {
        Err(error) => error,
        Ok(_) => panic!("unsupported deployment must fail before handler construction"),
    };
    assert!(error.to_string().contains("only devnet and localnet"));
}

struct WorkflowRpc {
    state: Arc<std::sync::Mutex<WorkflowState>>,
}

/// Negative-path fixtures must fail before accessing either server signing API.
struct MustNotSign;

#[async_trait::async_trait]
impl SolanaSigner for MustNotSign {
    fn pubkey(&self) -> Pubkey {
        signer(4).pubkey()
    }

    async fn sign_message(
        &self,
        _message: &[u8],
    ) -> std::result::Result<Signature, solana_keychain::SignerError> {
        panic!("rejected channel charge must not request a server signature")
    }

    async fn is_available(&self) -> bool {
        true
    }
}

#[async_trait::async_trait]
impl solana_keychain::TransactionSigner for MustNotSign {
    async fn sign_transaction(
        &self,
        _transaction: &mut VersionedTransaction,
    ) -> std::result::Result<solana_keychain::SignTransactionResult, solana_keychain::SignerError>
    {
        panic!("rejected channel charge must not request a server signature")
    }
}

fn forbid_server_signing(server: &mut Mpp) {
    server.channel_charge.as_mut().unwrap().payee_signer = Arc::new(MustNotSign);
    server.fee_payer_signer = Some(Arc::new(MustNotSign));
}

#[derive(Default)]
struct WorkflowState {
    sent: Option<VersionedTransaction>,
    simulations: usize,
    sends: usize,
    simulation_credit: Option<u64>,
    confirmed_credit: Option<u64>,
    svm: Option<litesvm::LiteSVM>,
    simulated_meta: Option<serde_json::Value>,
    confirmed_meta: Option<serde_json::Value>,
    allow_signed_simulation: bool,
}

fn payout_meta(tx: &VersionedTransaction, credit: u64) -> serde_json::Value {
    let owner = signer(3).pubkey();
    let mint = key(MINT).unwrap();
    let token = key(super::super::solana::programs::TOKEN_PROGRAM).unwrap();
    let ata = v1::find_associated_token_address(&owner, &mint, &token).0;
    let index = tx
        .message
        .static_account_keys()
        .iter()
        .position(|k| *k == ata)
        .unwrap();
    let row = |amount: u64| {
        serde_json::json!({
            "accountIndex": index, "mint": MINT, "owner": owner.to_string(),
            "programId": token.to_string(), "uiTokenAmount": {"amount": amount.to_string(), "decimals": 6}
        })
    };
    serde_json::json!({
        "err": null, "preTokenBalances": [row(7)],
        "postTokenBalances": [row(7 + credit)]
    })
}

#[async_trait::async_trait]
impl solana_rpc_client::rpc_sender::RpcSender for WorkflowRpc {
    async fn send(
        &self,
        request: solana_rpc_client_api::request::RpcRequest,
        params: serde_json::Value,
    ) -> solana_rpc_client_api::client_error::Result<serde_json::Value> {
        use serde_json::json;
        use solana_rpc_client_api::request::RpcRequest;
        let mut state = self.state.lock().unwrap();
        Ok(match request {
            RpcRequest::SimulateTransaction => {
                let tx = tx::decode(params[0].as_str().unwrap()).unwrap();
                assert!(
                    state.allow_signed_simulation
                        || tx.signatures.iter().any(|sig| *sig == Signature::default())
                );
                assert_eq!(params[1]["sigVerify"], false);
                assert_eq!(params[1]["replaceRecentBlockhash"], false);
                state.simulations += 1;
                let meta = if let Some(svm) = &state.svm {
                    let before = sbf::token_snapshot(svm, &tx);
                    let mut simulated = svm.clone().with_sigverify(false);
                    let result = simulated.send_transaction(tx.clone());
                    match result {
                        Ok(result) => json!({"err":null, "logs":result.logs,
                            "preTokenBalances":before, "postTokenBalances":sbf::token_snapshot(&simulated,&tx)}),
                        Err(error) => {
                            assert_eq!(
                                before,
                                sbf::token_snapshot(&simulated, &tx),
                                "failed execution must roll token effects back"
                            );
                            for key in tx.message.static_account_keys() {
                                assert_eq!(
                                    svm.get_account(key).map(|a| a.data),
                                    simulated.get_account(key).map(|a| a.data),
                                    "failed execution must roll account data back"
                                );
                            }
                            json!({"err":format!("{:?}",error.err),"logs":error.meta.logs})
                        }
                    }
                } else {
                    payout_meta(&tx, state.simulation_credit.unwrap_or(1_000_000))
                };
                state.simulated_meta = Some(meta.clone());
                json!({"context": {"slot": 42}, "value": meta})
            }
            RpcRequest::SendTransaction => {
                let tx = tx::decode(params[0].as_str().unwrap()).unwrap();
                tx.verify_and_hash_message().unwrap();
                assert_ne!(params[1]["skipPreflight"], true);
                let signature = tx.signatures[0].to_string();
                if let Some(svm) = state.svm.as_mut() {
                    let before = sbf::token_snapshot(svm, &tx);
                    let result = svm.send_transaction(tx.clone()).unwrap();
                    let meta = json!({"err":null, "logs":result.logs,
                        "preTokenBalances":before, "postTokenBalances":sbf::token_snapshot(svm,&tx)});
                    state.confirmed_meta = Some(meta);
                }
                state.sent = Some(tx);
                state.sends += 1;
                json!(signature)
            }
            RpcRequest::GetSignatureStatuses => json!({"context":{"slot":42}, "value":[{
                "slot":42, "confirmations":1, "err":null, "status":{"Ok":null}, "confirmationStatus":"confirmed"
            }]}),
            RpcRequest::GetTransaction => {
                assert_eq!(params[1]["commitment"], "confirmed");
                if state.sent.is_none() {
                    return Ok(serde_json::Value::Null);
                }
                let tx = state.sent.as_ref().unwrap();
                json!({"slot":42, "transaction":[tx::encode(tx).unwrap(),"base64"],
                    "meta":state.confirmed_meta.clone().unwrap_or_else(|| payout_meta(tx,state.confirmed_credit.unwrap_or(1_000_000)))})
            }
            _ => panic!("unexpected channel RPC request: {request:?}"),
        })
    }

    fn get_transport_stats(&self) -> solana_rpc_client::rpc_sender::RpcTransportStats {
        Default::default()
    }

    fn url(&self) -> String {
        "http://channel-charge-test.invalid".into()
    }
}

#[path = "channel_charge_sbf_tests.rs"]
mod sbf;

fn workflow_server(state: Arc<std::sync::Mutex<WorkflowState>>) -> Mpp {
    let mut server = Mpp::new(Config {
        recipient: signer(3).pubkey().to_string(),
        currency: MINT.into(),
        network: "devnet".into(),
        challenge_binding_secret: Some(SECRET.into()),
        realm: Some("channel-test".into()),
        fee_payer: true,
        fee_payer_signer: Some(signer(4)),
        channel_charge: Some(ChannelChargeConfig {
            payee_signer: signer(4),
            hooks: v2::ChannelHooks::default(),
        }),
        store: Some(std::sync::Arc::new(crate::mpp::store::MemoryStore::new())),
        ..Default::default()
    })
    .unwrap();
    server.rpc = Arc::new(solana_rpc_client::rpc_client::RpcClient::new_sender(
        WorkflowRpc { state },
        Default::default(),
    ));
    server
}

#[tokio::test(flavor = "multi_thread")]
async fn channel_charge_malformed_grammar_rejected_before_simulation_and_signing() {
    for mutation in [
        "amount",
        "memo",
        "order",
        "extra-instruction",
        "privileges",
        "hooks",
    ] {
        let state = Arc::new(std::sync::Mutex::new(WorkflowState::default()));
        let mut server = workflow_server(state.clone());
        forbid_server_signing(&mut server);
        let hooks = v2::ChannelHooks::default();
        let expected = request(hooks.clone(), true);
        let challenge = server.charge_challenge(&expected).unwrap();
        let mut changed = transaction(&challenge, &hooks).await;
        let message = message(&mut changed);
        match mutation {
            // settleAndSeal starts with its tag followed by the cumulative amount.
            "amount" => message.instructions[2].data[1] ^= 1,
            "memo" => message.instructions[4].data[0] ^= 1,
            "order" => message.instructions.swap(2, 3),
            "extra-instruction" => message.instructions.push(message.instructions[4].clone()),
            "privileges" => message.header.num_readonly_unsigned_accounts -= 1,
            // The final open byte is the empty hook-slot mask.
            "hooks" => *message.instructions[0].data.last_mut().unwrap() ^= 1,
            _ => unreachable!(),
        }
        resign_payer(&mut changed).await;
        let error = verify_transaction(&changed, &challenge.to_echo(), &hooks).unwrap_err();
        assert!(
            error
                .to_string()
                .contains(if mutation == "extra-instruction" {
                    "expected open, Ed25519, settleAndSeal, distribute, memo"
                } else {
                    "transaction differs from exact channel-charge grammar"
                }),
            "{mutation}: {error}"
        );
        let credential = crate::mpp::protocol::core::PaymentCredential::new(
            challenge.to_echo(),
            CredentialPayload::Transaction {
                transaction: tx::encode(&changed).unwrap(),
            },
        );
        let error = server.verify(&credential, &expected).await.unwrap_err();
        assert!(
            error.message.contains(if mutation == "extra-instruction" {
                "expected open, Ed25519, settleAndSeal, distribute, memo"
            } else {
                "transaction differs from exact channel-charge grammar"
            }),
            "{mutation}: {error:?}"
        );
        let state = state.lock().unwrap();
        assert_eq!(state.simulations, 0, "{mutation}");
        assert_eq!(state.sends, 0, "{mutation}");
        assert!(state.sent.is_none(), "{mutation}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn channel_charge_full_workflow_confirmation_and_replay() {
    let state = Arc::new(std::sync::Mutex::new(WorkflowState::default()));
    let server = workflow_server(state.clone());
    let mut expected = request(v2::ChannelHooks::default(), true);
    let challenge = server.charge_challenge(&expected).unwrap();
    let credential = build_channel_charge_credential(
        signer(1).as_ref(),
        signer(2).as_ref(),
        &challenge,
        &v2::ChannelHooks::default(),
        99,
    )
    .await
    .unwrap();
    // Route expectations may be rebuilt with fresh ephemeral context; the
    // authenticated original challenge still pins the transaction's slot/hash.
    expected.method_details.as_mut().unwrap()["channelCharge"]["recentSlot"] =
        serde_json::json!(43);
    expected.method_details.as_mut().unwrap()["recentBlockhash"] =
        serde_json::json!(Hash::new_unique().to_string());
    server.verify(&credential, &expected).await.unwrap();
    let replay = server.verify(&credential, &expected).await.unwrap_err();
    assert_eq!(replay.code, Some("signature-consumed"));
    let state = state.lock().unwrap();
    assert_eq!(state.simulations, 1);
    assert_eq!(state.sends, 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn channel_charge_rejects_simulated_redirect_before_cosign_and_confirmed_clawback() {
    for (simulation_credit, confirmed_credit, sends) in
        [(Some(0), None, 0), (None, Some(999_999), 1)]
    {
        let state = Arc::new(std::sync::Mutex::new(WorkflowState {
            simulation_credit,
            confirmed_credit,
            ..Default::default()
        }));
        let server = workflow_server(state.clone());
        let expected = request(v2::ChannelHooks::default(), true);
        let challenge = server.charge_challenge(&expected).unwrap();
        let credential = build_channel_charge_credential(
            signer(1).as_ref(),
            signer(2).as_ref(),
            &challenge,
            &v2::ChannelHooks::default(),
            99,
        )
        .await
        .unwrap();
        assert!(server.verify(&credential, &expected).await.is_err());
        assert_eq!(state.lock().unwrap().sends, sends);
        if sends == 1 {
            let retry = server.verify(&credential, &expected).await.unwrap_err();
            assert_eq!(retry.code, Some("settlement-in-progress"));
            assert!(retry.message.contains("do not pay again"));
            assert_eq!(state.lock().unwrap().sends, 1);
        }
    }
}

async fn submitted_fixture(
    server: &Mpp,
    challenge: &PaymentChallenge,
) -> (
    crate::mpp::protocol::core::PaymentCredential,
    VersionedTransaction,
) {
    // This helper models a client that signed before expiry, followed by a
    // server crash after the durable write-ahead marker.
    let request: ChargeRequest = challenge.request.decode().unwrap();
    let details: MethodDetails =
        serde_json::from_value(request.method_details.clone().unwrap()).unwrap();
    let t = terms(
        &request,
        &details,
        challenge.expires.as_deref().unwrap(),
        signer(1).pubkey(),
        signer(2).pubkey(),
        99,
    )
    .unwrap();
    let voucher = v1::voucher_message_bytes(
        &v1::derive_channel_addresses(&t.params).channel,
        t.params.deposit,
        t.expires_at,
    )
    .unwrap();
    let sig = signer(2).sign_message(&voucher).await.unwrap();
    let sig: [u8; 64] = sig.as_ref().try_into().unwrap();
    let mut transaction = compile(&t, &challenge.id, &sig).unwrap();
    crate::core::signing::sign_versioned_transaction_slot(signer(1).as_ref(), &mut transaction)
        .await
        .unwrap();
    let original = tx::encode(&transaction).unwrap();
    let credential = crate::mpp::protocol::core::PaymentCredential::new(
        challenge.to_echo(),
        CredentialPayload::Transaction {
            transaction: original.clone(),
        },
    );
    crate::core::signing::sign_versioned_transaction_slot(signer(4).as_ref(), &mut transaction)
        .await
        .unwrap();
    crate::core::store::ChargeReplayStore::new(server.store.clone())
        .reserve(
            &challenge.id,
            "test-reservation",
            std::time::Duration::from_secs(120),
        )
        .await
        .unwrap();
    server
        .record_channel_submission(&challenge.to_echo(), &original, &transaction)
        .await
        .unwrap();
    (credential, transaction)
}

#[tokio::test(flavor = "multi_thread")]
async fn channel_charge_recovers_crashes_without_new_message_or_duplicate_receipt() {
    for (already_broadcast, missing_record) in
        [(false, false), (true, false), (false, true), (true, true)]
    {
        let state = Arc::new(std::sync::Mutex::new(WorkflowState {
            allow_signed_simulation: true,
            ..Default::default()
        }));
        let server = workflow_server(state.clone());
        let expected = request(v2::ChannelHooks::default(), true);
        let challenge = server.charge_challenge(&expected).unwrap();
        let (credential, signed) = submitted_fixture(&server, &challenge).await;
        if missing_record {
            server
                .store
                .delete(&format!("solana-charge:record:{}", challenge.id))
                .await
                .unwrap();
        }
        if already_broadcast {
            let mut state = state.lock().unwrap();
            state.sent = Some(signed.clone());
            state.sends = 1;
        }
        server.verify(&credential, &expected).await.unwrap();
        assert_eq!(state.lock().unwrap().sent.as_ref(), Some(&signed));
        assert_eq!(state.lock().unwrap().sends, 1);
        assert_eq!(
            server
                .verify(&credential, &expected)
                .await
                .unwrap_err()
                .code,
            Some("signature-consumed")
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn channel_charge_expiry_allows_only_existing_confirmed_reconciliation() {
    for already_landed in [false, true] {
        let state = Arc::new(std::sync::Mutex::new(WorkflowState::default()));
        let server = workflow_server(state.clone());
        let expected = request(v2::ChannelHooks::default(), true);
        let challenge = server
            .charge_challenge_with_options(&expected, Some("2000-01-01T00:00:00Z"), None)
            .unwrap();
        assert!(build_channel_charge_credential(
            signer(1).as_ref(),
            signer(2).as_ref(),
            &challenge,
            &v2::ChannelHooks::default(),
            99
        )
        .await
        .is_err());
        let (credential, signed) = submitted_fixture(&server, &challenge).await;
        if already_landed {
            state.lock().unwrap().sent = Some(signed);
        }
        let result = server.verify(&credential, &expected).await;
        assert_eq!(result.is_ok(), already_landed);
        assert_eq!(state.lock().unwrap().sends, 0);
        assert_eq!(state.lock().unwrap().simulations, 0);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn channel_charge_unknown_outcome_recovers_and_concurrent_receipt_claim_is_atomic() {
    let state = Arc::new(std::sync::Mutex::new(WorkflowState {
        confirmed_credit: Some(0),
        ..Default::default()
    }));
    let server = Arc::new(workflow_server(state.clone()));
    let expected = request(v2::ChannelHooks::default(), true);
    let challenge = server.charge_challenge(&expected).unwrap();
    let credential = build_channel_charge_credential(
        signer(1).as_ref(),
        signer(2).as_ref(),
        &challenge,
        &v2::ChannelHooks::default(),
        99,
    )
    .await
    .unwrap();
    assert_eq!(
        server
            .verify(&credential, &expected)
            .await
            .unwrap_err()
            .code,
        Some("settlement-in-progress")
    );
    state.lock().unwrap().confirmed_credit = None;
    let mut tasks = Vec::new();
    for _ in 0..8 {
        let server = server.clone();
        let credential = credential.clone();
        let expected = expected.clone();
        tasks.push(tokio::spawn(async move {
            server.verify(&credential, &expected).await
        }));
    }
    let mut receipts = 0;
    for task in tasks {
        match task.await.unwrap() {
            Ok(_) => receipts += 1,
            Err(error) => assert_eq!(error.code, Some("signature-consumed")),
        }
    }
    assert_eq!(receipts, 1);
    assert_eq!(state.lock().unwrap().sends, 1);
}
