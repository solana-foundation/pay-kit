//! Client-side activation transaction builder for the Solana subscription intent.
//!
//! Builds the activation transaction defined by `draft-solana-subscription-00`:
//!
//!   `[compute_budget_*, initialize_subscription_authority?, subscribe,
//!     transfer_subscription, memo(externalId)?]`
//!
//! The transaction is signed (or partially signed when the server is fee
//! payer) and returned as a `CredentialPayload::Transaction` ready to send
//! to the server.

use std::str::FromStr;

use solana_instruction::{AccountMeta, Instruction};
use solana_keychain::SolanaSigner;
use solana_message::Message;
use solana_pubkey::Pubkey;
use solana_rpc_client::rpc_client::RpcClient;
use solana_signature::Signature;
use solana_transaction::Transaction;

use crate::error::Error;
use crate::program::subscriptions::{
    default_program_id, find_subscription_authority_pda, find_subscription_pda, parse_pubkey,
    INSTRUCTION_INITIALIZE_SUBSCRIPTION_AUTHORITY, INSTRUCTION_SUBSCRIBE,
    INSTRUCTION_TRANSFER_SUBSCRIPTION,
};
use crate::protocol::solana::CredentialPayload;

/// Decoded `methodDetails` for a subscription challenge.
#[derive(Debug, Clone)]
pub struct SubscriptionMethodDetails {
    pub plan_id: String,
    pub mint: String,
    pub token_program: String,
    pub puller: String,
    pub program_id: Option<String>,
    pub fee_payer: bool,
    pub fee_payer_key: Option<String>,
    pub recent_blockhash: Option<String>,
}

impl SubscriptionMethodDetails {
    pub fn from_json(value: &serde_json::Value) -> Result<Self, Error> {
        let plan_id = require_string(value, "planId")?;
        let mint = require_string(value, "mint")?;
        let token_program = require_string(value, "tokenProgram")?;
        let puller = require_string(value, "puller")?;
        let program_id = value
            .get("programId")
            .and_then(|v| v.as_str())
            .map(str::to_string);
        let fee_payer = value
            .get("feePayer")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let fee_payer_key = value
            .get("feePayerKey")
            .and_then(|v| v.as_str())
            .map(str::to_string);
        let recent_blockhash = value
            .get("recentBlockhash")
            .and_then(|v| v.as_str())
            .map(str::to_string);

        Ok(Self {
            plan_id,
            mint,
            token_program,
            puller,
            program_id,
            fee_payer,
            fee_payer_key,
            recent_blockhash,
        })
    }
}

fn require_string(value: &serde_json::Value, field: &str) -> Result<String, Error> {
    value
        .get(field)
        .and_then(|v| v.as_str())
        .ok_or_else(|| Error::Other(format!("methodDetails.{field} is required")))
        .map(str::to_string)
}

/// Options for building a Solana subscription activation transaction.
#[derive(Debug, Clone, Default)]
pub struct BuildSubscriptionActivationOptions {
    /// Optional memo with the merchant's external reference, embedded as a
    /// trailing memo instruction.
    pub external_id: Option<String>,
    /// Compute unit limit. Defaults to 400,000 (activation includes up to
    /// three subscriptions-program instructions plus token transfers).
    pub compute_unit_limit: Option<u32>,
    /// Compute unit price in microlamports. Defaults to 1.
    pub compute_unit_price: Option<u64>,
}

/// Build the subscription activation transaction.
///
/// The returned payload is a `CredentialPayload::Transaction` carrying the
/// base64-encoded serialized transaction. When `method_details.fee_payer`
/// is `true`, the transaction is partially signed; the server completes
/// the fee-payer signature before broadcasting.
pub async fn build_subscription_activation_transaction(
    signer: &dyn SolanaSigner,
    rpc: &RpcClient,
    method_details: &SubscriptionMethodDetails,
) -> Result<CredentialPayload, Error> {
    build_subscription_activation_transaction_with_options(
        signer,
        rpc,
        method_details,
        BuildSubscriptionActivationOptions::default(),
    )
    .await
}

/// Build the subscription activation transaction with additional options.
pub async fn build_subscription_activation_transaction_with_options(
    signer: &dyn SolanaSigner,
    rpc: &RpcClient,
    method_details: &SubscriptionMethodDetails,
    options: BuildSubscriptionActivationOptions,
) -> Result<CredentialPayload, Error> {
    let program_id = match method_details.program_id.as_deref() {
        Some(p) => parse_pubkey(p, "programId")?,
        None => default_program_id(),
    };

    let subscriber = signer.pubkey();
    let mint = parse_pubkey(&method_details.mint, "mint")?;
    let token_program = parse_pubkey(&method_details.token_program, "tokenProgram")?;
    let plan_pda = parse_pubkey(&method_details.plan_id, "planId")?;
    let puller = parse_pubkey(&method_details.puller, "puller")?;

    let (subscription_authority, _) =
        find_subscription_authority_pda(&subscriber, &mint, &program_id);
    let (subscription_pda, _) = find_subscription_pda(&plan_pda, &subscriber, &program_id);

    // ATA derivation: SPL Token associated-token program seeds are
    // `[owner, token_program, mint]`. Both SPL Token and Token-2022 share
    // the same associated-token-program ID.
    let associated_token_program = parse_pubkey(
        "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL",
        "associated_token_program",
    )?;
    let system_program = parse_pubkey("11111111111111111111111111111111", "system_program")?;

    let (subscriber_ata, _) = Pubkey::find_program_address(
        &[subscriber.as_ref(), token_program.as_ref(), mint.as_ref()],
        &associated_token_program,
    );

    // The recipient ATA is determined on-chain by the program from
    // `plan.destinations`; we pass the primary recipient ATA as a hint.
    // For v0 we use the subscriber's ATA as a placeholder and let the
    // program resolve destinations from the plan.
    // Note: a follow-up should resolve plan.destinations via RPC and
    // include the correct destination ATA(s) here.

    let mut instructions: Vec<Instruction> = Vec::new();

    instructions.push(compute_unit_price_ix(
        options.compute_unit_price.unwrap_or(1),
    ));
    instructions.push(compute_unit_limit_ix(
        options.compute_unit_limit.unwrap_or(400_000),
    ));

    // Check if SubscriptionAuthority already exists; only include the init
    // ix when needed.
    let authority_exists = rpc.get_account(&subscription_authority).is_ok();
    if !authority_exists {
        instructions.push(build_init_subscription_authority_ix(
            program_id,
            subscriber,
            subscription_authority,
            mint,
            subscriber_ata,
            token_program,
            system_program,
        ));
    }

    // Determine the rent payer for the subscribe ix: the fee payer when
    // configured, otherwise the subscriber.
    let subscribe_payer = if method_details.fee_payer {
        match method_details.fee_payer_key.as_deref() {
            Some(k) => parse_pubkey(k, "feePayerKey")?,
            None => {
                return Err(Error::Other(
                    "feePayer=true requires feePayerKey in methodDetails".into(),
                ));
            }
        }
    } else {
        subscriber
    };

    instructions.push(build_subscribe_ix(
        program_id,
        subscriber,
        subscribe_payer,
        plan_pda,
        subscription_pda,
        subscription_authority,
        system_program,
    ));

    instructions.push(build_transfer_subscription_ix(
        program_id,
        puller,
        subscription_pda,
        plan_pda,
        subscription_authority,
        subscriber,
        subscriber_ata,
        subscriber_ata, // recipient ATA hint — see note above
        mint,
        token_program,
    ));

    if let Some(external_id) = options.external_id.as_deref() {
        instructions.push(build_memo_instruction(external_id));
    }

    // Fee payer + blockhash.
    let fee_payer_pubkey = if method_details.fee_payer {
        method_details
            .fee_payer_key
            .as_deref()
            .map(|k| parse_pubkey(k, "feePayerKey"))
            .transpose()?
            .unwrap_or(subscriber)
    } else {
        subscriber
    };

    let blockhash = if let Some(hash_str) = method_details.recent_blockhash.as_deref() {
        hash_str
            .parse()
            .map_err(|e| Error::Other(format!("Invalid recentBlockhash: {e}")))?
    } else {
        rpc.get_latest_blockhash()
            .map_err(|e| Error::Other(format!("Failed to fetch blockhash: {e}")))?
    };

    let message = Message::new_with_blockhash(&instructions, Some(&fee_payer_pubkey), &blockhash);
    let mut tx = Transaction::new_unsigned(message);

    // Sign as subscriber; the server adds the puller and fee-payer
    // signatures (puller is the server, so the server holds the puller key
    // too). For v0 the subscriber is the only client-side signer; when fee
    // sponsorship is in play, the tx is broadcast partially signed.
    let serialized_msg = tx.message_data();
    let sig_bytes = signer
        .sign_message(&serialized_msg)
        .await
        .map_err(|e| Error::Other(format!("Subscriber signature failed: {e}")))?;
    let sig = Signature::from(<[u8; 64]>::from(sig_bytes));
    let subscriber_idx = tx
        .message
        .account_keys
        .iter()
        .position(|k| k == &subscriber)
        .ok_or_else(|| Error::Other("Subscriber not in account keys".into()))?;
    tx.signatures[subscriber_idx] = sig;

    let serialized = bincode::serialize(&tx)
        .map_err(|e| Error::Other(format!("Failed to serialize tx: {e}")))?;
    let b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &serialized);
    Ok(CredentialPayload::Transaction { transaction: b64 })
}

// ── Instruction builders (v0, hand-rolled) ──

fn build_init_subscription_authority_ix(
    program_id: Pubkey,
    subscriber: Pubkey,
    subscription_authority: Pubkey,
    mint: Pubkey,
    subscriber_ata: Pubkey,
    token_program: Pubkey,
    system_program: Pubkey,
) -> Instruction {
    Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new(subscriber, true),
            AccountMeta::new(subscription_authority, false),
            AccountMeta::new_readonly(mint, false),
            AccountMeta::new(subscriber_ata, false),
            AccountMeta::new_readonly(token_program, false),
            AccountMeta::new_readonly(system_program, false),
        ],
        data: vec![INSTRUCTION_INITIALIZE_SUBSCRIPTION_AUTHORITY],
    }
}

fn build_subscribe_ix(
    program_id: Pubkey,
    subscriber: Pubkey,
    payer: Pubkey,
    plan_pda: Pubkey,
    subscription_pda: Pubkey,
    subscription_authority: Pubkey,
    system_program: Pubkey,
) -> Instruction {
    Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new(subscriber, true),
            AccountMeta::new(payer, true),
            AccountMeta::new_readonly(plan_pda, false),
            AccountMeta::new(subscription_pda, false),
            AccountMeta::new_readonly(subscription_authority, false),
            AccountMeta::new_readonly(system_program, false),
        ],
        data: vec![INSTRUCTION_SUBSCRIBE],
    }
}

#[allow(clippy::too_many_arguments)]
fn build_transfer_subscription_ix(
    program_id: Pubkey,
    puller: Pubkey,
    subscription_pda: Pubkey,
    plan_pda: Pubkey,
    subscription_authority: Pubkey,
    subscriber: Pubkey,
    subscriber_ata: Pubkey,
    recipient_ata: Pubkey,
    mint: Pubkey,
    token_program: Pubkey,
) -> Instruction {
    Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new(puller, true),
            AccountMeta::new(subscription_pda, false),
            AccountMeta::new_readonly(plan_pda, false),
            AccountMeta::new_readonly(subscription_authority, false),
            AccountMeta::new_readonly(subscriber, false),
            AccountMeta::new(subscriber_ata, false),
            AccountMeta::new(recipient_ata, false),
            AccountMeta::new_readonly(mint, false),
            AccountMeta::new_readonly(token_program, false),
        ],
        data: vec![INSTRUCTION_TRANSFER_SUBSCRIPTION],
    }
}

fn build_memo_instruction(memo: &str) -> Instruction {
    let data = memo.as_bytes().to_vec();
    Instruction {
        program_id: Pubkey::from_str("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr")
            .expect("valid memo program id"),
        accounts: vec![],
        data,
    }
}

// ── Compute budget instructions (inline, no heavy dep) ──
//
// Mirror the inline builders used by `client::charge` to avoid pulling in
// `solana-compute-budget-interface`.

fn compute_unit_price_ix(micro_lamports: u64) -> Instruction {
    let program_id =
        Pubkey::from_str("ComputeBudget111111111111111111111111111111").expect("valid program id");
    let mut data = vec![3u8]; // SetComputeUnitPrice discriminator
    data.extend_from_slice(&micro_lamports.to_le_bytes());
    Instruction {
        program_id,
        accounts: vec![],
        data,
    }
}

fn compute_unit_limit_ix(units: u32) -> Instruction {
    let program_id =
        Pubkey::from_str("ComputeBudget111111111111111111111111111111").expect("valid program id");
    let mut data = vec![2u8]; // SetComputeUnitLimit discriminator
    data.extend_from_slice(&units.to_le_bytes());
    Instruction {
        program_id,
        accounts: vec![],
        data,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::subscriptions::SUBSCRIPTIONS_PROGRAM_ID;

    #[test]
    fn method_details_parse_required_fields() {
        let value = serde_json::json!({
            "planId": "8tWbqLkUJoYy7zXc5h2EvCRoaQEv2xnQjUuYhc3rzCgT",
            "mint": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
            "tokenProgram": "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
            "puller": "5fKb5cF22cFybZB1H4hLDydFhwoQy9JzKzRWaSbMkB6h",
            "feePayer": true,
            "feePayerKey": "5fKb5cF22cFybZB1H4hLDydFhwoQy9JzKzRWaSbMkB6h"
        });
        let md = SubscriptionMethodDetails::from_json(&value).unwrap();
        assert!(md.fee_payer);
        assert_eq!(md.plan_id, "8tWbqLkUJoYy7zXc5h2EvCRoaQEv2xnQjUuYhc3rzCgT");
        assert_eq!(
            md.fee_payer_key.as_deref(),
            Some("5fKb5cF22cFybZB1H4hLDydFhwoQy9JzKzRWaSbMkB6h")
        );
    }

    #[test]
    fn method_details_rejects_missing_required_field() {
        let value = serde_json::json!({
            "mint": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
        });
        assert!(SubscriptionMethodDetails::from_json(&value).is_err());
    }

    fn make_signer() -> Box<dyn SolanaSigner> {
        let sk = ed25519_dalek::SigningKey::from_bytes(&[42u8; 32]);
        let mut kp = [0u8; 64];
        kp[..32].copy_from_slice(sk.as_bytes());
        kp[32..].copy_from_slice(sk.verifying_key().as_bytes());
        Box::new(solana_keychain::MemorySigner::from_bytes(&kp).expect("valid keypair"))
    }

    fn make_method_details(
        fee_payer: bool,
        fee_payer_key: Option<&str>,
    ) -> SubscriptionMethodDetails {
        SubscriptionMethodDetails {
            plan_id: "8tWbqLkUJoYy7zXc5h2EvCRoaQEv2xnQjUuYhc3rzCgT".into(),
            mint: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v".into(),
            token_program: crate::protocol::solana::programs::TOKEN_PROGRAM.into(),
            puller: "5fKb5cF22cFybZB1H4hLDydFhwoQy9JzKzRWaSbMkB6h".into(),
            program_id: None,
            fee_payer,
            fee_payer_key: fee_payer_key.map(str::to_string),
            // Avoid the RPC blockhash fetch by pre-supplying one.
            recent_blockhash: Some("11111111111111111111111111111111".into()),
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn builds_activation_tx_with_init_authority_on_fresh_subscriber() {
        // `RpcClient::new_mock("succeeds")` returns Value::Null for
        // getAccountInfo, so `rpc.get_account(...).is_ok()` is false and
        // initialize_subscription_authority is included.
        let signer = make_signer();
        let rpc = RpcClient::new_mock("succeeds".to_string());
        let md = make_method_details(false, None);
        let payload = build_subscription_activation_transaction(&*signer, &rpc, &md)
            .await
            .expect("activation tx");
        match payload {
            CredentialPayload::Transaction { transaction } => {
                assert!(!transaction.is_empty());
            }
            _ => panic!("expected Transaction payload"),
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn builds_activation_tx_with_options_and_external_id_memo() {
        let signer = make_signer();
        let rpc = RpcClient::new_mock("succeeds".to_string());
        let md = make_method_details(false, None);
        let payload = build_subscription_activation_transaction_with_options(
            &*signer,
            &rpc,
            &md,
            BuildSubscriptionActivationOptions {
                external_id: Some("order-42".into()),
                compute_unit_limit: Some(123_456),
                compute_unit_price: Some(1_000),
            },
        )
        .await
        .expect("activation tx");
        match payload {
            CredentialPayload::Transaction { transaction } => {
                let raw = base64::Engine::decode(
                    &base64::engine::general_purpose::STANDARD,
                    &transaction,
                )
                .expect("base64 decode");
                let tx: Transaction = bincode::deserialize(&raw).expect("bincode tx");
                // [compute_price, compute_limit, init_authority, subscribe, transfer, memo]
                assert_eq!(tx.message.instructions.len(), 6);
                // Last instruction must be the memo.
                let last = &tx.message.instructions[5];
                let memo_program_id =
                    Pubkey::from_str("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr").unwrap();
                let last_program = tx.message.account_keys[last.program_id_index as usize];
                assert_eq!(last_program, memo_program_id);
                assert_eq!(last.data, b"order-42");
            }
            _ => panic!("expected Transaction payload"),
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn fee_payer_true_without_fee_payer_key_errors() {
        let signer = make_signer();
        let rpc = RpcClient::new_mock("succeeds".to_string());
        let md = make_method_details(true, None);
        let err = build_subscription_activation_transaction(&*signer, &rpc, &md)
            .await
            .expect_err("missing feePayerKey");
        assert!(format!("{err}").contains("feePayerKey"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn fee_payer_true_with_fee_payer_key_sets_fee_payer_account() {
        let signer = make_signer();
        let rpc = RpcClient::new_mock("succeeds".to_string());
        let fee_payer_key = "FeePayerJ7vuK99c7cFwqbixzL3bFrzPy9PUhCtDPAYJ";
        let md = make_method_details(true, Some(fee_payer_key));
        let payload = build_subscription_activation_transaction(&*signer, &rpc, &md)
            .await
            .expect("activation tx");
        match payload {
            CredentialPayload::Transaction { transaction } => {
                let raw = base64::Engine::decode(
                    &base64::engine::general_purpose::STANDARD,
                    &transaction,
                )
                .expect("base64 decode");
                let tx: Transaction = bincode::deserialize(&raw).expect("bincode tx");
                // In a v0 message the fee payer is account_keys[0].
                let expected_fee_payer = Pubkey::from_str(fee_payer_key).unwrap();
                assert_eq!(tx.message.account_keys[0], expected_fee_payer);
            }
            _ => panic!("expected Transaction payload"),
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn invalid_pubkey_in_method_details_surfaces_typed_error() {
        let signer = make_signer();
        let rpc = RpcClient::new_mock("succeeds".to_string());
        let mut md = make_method_details(false, None);
        md.mint = "not-a-pubkey".into();
        let err = build_subscription_activation_transaction(&*signer, &rpc, &md)
            .await
            .expect_err("invalid mint");
        assert!(format!("{err}").contains("mint"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn explicit_program_id_override_is_honored() {
        let signer = make_signer();
        let rpc = RpcClient::new_mock("succeeds".to_string());
        let mut md = make_method_details(false, None);
        md.program_id = Some(SUBSCRIPTIONS_PROGRAM_ID.into());
        let payload = build_subscription_activation_transaction(&*signer, &rpc, &md)
            .await
            .expect("activation tx");
        assert!(matches!(payload, CredentialPayload::Transaction { .. }));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn invalid_recent_blockhash_in_method_details_errors() {
        let signer = make_signer();
        let rpc = RpcClient::new_mock("succeeds".to_string());
        let mut md = make_method_details(false, None);
        md.recent_blockhash = Some("not-a-valid-blockhash".into());
        let err = build_subscription_activation_transaction(&*signer, &rpc, &md)
            .await
            .expect_err("bad blockhash");
        assert!(format!("{err}").contains("blockhash") || format!("{err}").contains("Invalid"));
    }

    #[test]
    fn method_details_default_program_id_when_absent() {
        let value = serde_json::json!({
            "planId": "8tWbqLkUJoYy7zXc5h2EvCRoaQEv2xnQjUuYhc3rzCgT",
            "mint": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
            "tokenProgram": "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
            "puller": "5fKb5cF22cFybZB1H4hLDydFhwoQy9JzKzRWaSbMkB6h",
        });
        let md = SubscriptionMethodDetails::from_json(&value).unwrap();
        assert!(md.program_id.is_none());
        assert!(!md.fee_payer);
        assert!(md.fee_payer_key.is_none());
        assert!(md.recent_blockhash.is_none());
    }

    #[test]
    fn method_details_parses_recent_blockhash_and_program_id() {
        let value = serde_json::json!({
            "planId": "8tWbqLkUJoYy7zXc5h2EvCRoaQEv2xnQjUuYhc3rzCgT",
            "mint": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
            "tokenProgram": "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
            "puller": "5fKb5cF22cFybZB1H4hLDydFhwoQy9JzKzRWaSbMkB6h",
            "programId": SUBSCRIPTIONS_PROGRAM_ID,
            "recentBlockhash": "11111111111111111111111111111111",
        });
        let md = SubscriptionMethodDetails::from_json(&value).unwrap();
        assert_eq!(md.program_id.as_deref(), Some(SUBSCRIPTIONS_PROGRAM_ID));
        assert_eq!(
            md.recent_blockhash.as_deref(),
            Some("11111111111111111111111111111111")
        );
    }

    #[test]
    fn build_memo_instruction_carries_payload() {
        let ix = build_memo_instruction("hello");
        assert_eq!(ix.data, b"hello");
        let memo = Pubkey::from_str("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr").unwrap();
        assert_eq!(ix.program_id, memo);
    }

    #[test]
    fn compute_unit_price_and_limit_have_correct_discriminators() {
        let price_ix = compute_unit_price_ix(1_000);
        assert_eq!(price_ix.data[0], 3);
        assert_eq!(price_ix.data.len(), 9);
        let limit_ix = compute_unit_limit_ix(200_000);
        assert_eq!(limit_ix.data[0], 2);
        assert_eq!(limit_ix.data.len(), 5);
    }

    #[test]
    fn instruction_builders_produce_expected_discriminators() {
        let program = default_program_id();
        let any = Pubkey::new_unique();
        let init_ix = build_init_subscription_authority_ix(program, any, any, any, any, any, any);
        assert_eq!(
            init_ix.data[0],
            INSTRUCTION_INITIALIZE_SUBSCRIPTION_AUTHORITY
        );

        let sub_ix = build_subscribe_ix(program, any, any, any, any, any, any);
        assert_eq!(sub_ix.data[0], INSTRUCTION_SUBSCRIBE);

        let xfer_ix =
            build_transfer_subscription_ix(program, any, any, any, any, any, any, any, any, any);
        assert_eq!(xfer_ix.data[0], INSTRUCTION_TRANSFER_SUBSCRIPTION);
    }
}
