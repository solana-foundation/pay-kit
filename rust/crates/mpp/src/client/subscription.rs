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
};
use crate::protocol::solana::CredentialPayload;

/// Raw byte length of the on-chain `SubscriptionAuthority` PDA. Mirrors
/// `#[repr(C, packed)]` layout: discriminator(1) + user(32) + token_mint(32)
/// + payer(32) + bump(1) + init_id(8) = 106.
const SUBSCRIPTION_AUTHORITY_ACCOUNT_LEN: usize = 1 + 32 + 32 + 32 + 1 + 8;
/// Offset of `init_id` (i64, LE) inside a serialised `SubscriptionAuthority`.
const SUBSCRIPTION_AUTHORITY_INIT_ID_OFFSET: usize = 1 + 32 + 32 + 32 + 1;

pub use crate::protocol::intents::SubscriptionMethodDetails;

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
    /// Pre-resolved `SubscriptionAuthority::init_id`. When set, the builder
    /// skips the on-chain SA lookup and the init-tx broadcast — useful for
    /// tests, and for callers that have already resolved the SA state.
    pub subscription_authority_init_id: Option<i64>,
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
    // Plan owner — defaults to the puller when the operator publishes
    // its own plan and is its own puller (the common pay-server case).
    let merchant = match method_details.merchant.as_deref() {
        Some(m) => parse_pubkey(m, "merchant")?,
        None => puller,
    };
    let recipient = match method_details.recipient.as_deref() {
        Some(r) => parse_pubkey(r, "recipient")?,
        None => puller,
    };

    let (subscription_authority, _) =
        find_subscription_authority_pda(&subscriber, &mint, &program_id);
    let (subscription_pda, _) = find_subscription_pda(&plan_pda, &subscriber, &program_id);
    let (event_authority, _) = crate::program::subscriptions::find_event_authority_pda(&program_id);

    // ATA derivation: SPL Token associated-token program seeds are
    // `[owner, token_program, mint]`. Both SPL Token and Token-2022 share
    // the same associated-token-program ID.
    let associated_token_program = parse_pubkey(
        "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL",
        "associated_token_program",
    )?;

    let (subscriber_ata, _) = Pubkey::find_program_address(
        &[subscriber.as_ref(), token_program.as_ref(), mint.as_ref()],
        &associated_token_program,
    );
    let (recipient_ata, _) = Pubkey::find_program_address(
        &[recipient.as_ref(), token_program.as_ref(), mint.as_ref()],
        &associated_token_program,
    );

    // Required `SubscribeData` fields the on-chain program reads to
    // validate the subscriber consented to the live Plan terms. Without
    // these the program rejects with `InvalidInstructionData`.
    let plan_id_numeric = method_details.plan_id_numeric.ok_or_else(|| {
        Error::Other(
            "methodDetails.planIdNumeric is required to build SubscribeData. \
             Re-run `pay server plans publish` so the YAML carries the numeric id."
                .into(),
        )
    })?;
    let plan_bump = method_details.plan_bump.ok_or_else(|| {
        Error::Other("methodDetails.planBump is required to build SubscribeData".into())
    })?;
    let expected_period_hours = method_details.expected_period_hours.ok_or_else(|| {
        Error::Other("methodDetails.expectedPeriodHours is required to build SubscribeData".into())
    })?;
    let expected_created_at = method_details.expected_created_at.ok_or_else(|| {
        Error::Other(
            "methodDetails.expectedCreatedAt is required to build SubscribeData. \
             The Plan's on-chain created_at must be threaded into the challenge."
                .into(),
        )
    })?;
    let amount: u64 = method_details
        .amount
        .as_deref()
        .ok_or_else(|| {
            Error::Other("methodDetails.amount is required to build SubscribeData".into())
        })?
        .parse()
        .map_err(|e| Error::Other(format!("Invalid methodDetails.amount: {e}")))?;

    let mut instructions: Vec<Instruction> = Vec::new();

    instructions.push(compute_unit_price_ix(
        options.compute_unit_price.unwrap_or(1),
    ));
    instructions.push(compute_unit_limit_ix(
        options.compute_unit_limit.unwrap_or(400_000),
    ));

    // ATA bootstrap. The on-chain `init_subscription_authority` (and
    // every subsequent transfer) requires the subscriber's USDC ATA to
    // exist and be owned by the token program. Brand-new wallets don't
    // have an ATA yet — the account exists in name only (system-owned,
    // zero bytes), which trips `InvalidTokenProgram` on the server.
    // `CreateIdempotent` is a no-op when the ATA is already in place,
    // so we always prepend it. Rent is paid by the fee_payer when
    // sponsorship is on, otherwise by the subscriber.
    let ata_funder = match (
        method_details.fee_payer,
        method_details.fee_payer_key.as_deref(),
    ) {
        (true, Some(k)) => parse_pubkey(k, "feePayerKey")?,
        _ => subscriber,
    };
    instructions.push(build_create_idempotent_ata_ix(
        ata_funder,
        subscriber_ata,
        subscriber,
        mint,
        token_program,
        associated_token_program,
    ));

    // The on-chain `Subscribe` instruction binds the subscriber's signature
    // to a specific `SubscriptionAuthority::init_id`, set from `Clock::slot`
    // at SA creation. If the SA is created in the same tx as `Subscribe`,
    // the client can't predict the landing slot — so SA must exist (and
    // we must read its `init_id`) before signing the activation tx. When
    // missing, broadcast a one-off init tx as the subscriber, paid by the
    // subscriber (~0.002 SOL rent + ~5k lamports fee).
    let blockhash_str = method_details.recent_blockhash.as_deref().ok_or_else(|| {
        Error::Other(
            "Challenge is missing methodDetails.recentBlockhash — the server failed \
             to pre-fetch one. Check the server's operator.rpc_url config."
                .into(),
        )
    })?;
    let blockhash: solana_hash::Hash = blockhash_str
        .parse()
        .map_err(|e| Error::Other(format!("Invalid recentBlockhash: {e}")))?;

    let expected_subscription_authority_init_id = match options.subscription_authority_init_id {
        Some(id) => id,
        None => {
            ensure_subscription_authority_init_id(
                signer,
                rpc,
                program_id,
                subscriber,
                mint,
                subscriber_ata,
                subscription_authority,
                token_program,
                &blockhash,
            )
            .await?
        }
    };

    // Optional rent payer for the subscribe ix: fee_payer when
    // configured, otherwise the subscriber pays its own rent (no extra
    // account meta).
    let subscribe_payer = if method_details.fee_payer {
        match method_details.fee_payer_key.as_deref() {
            Some(k) => Some(parse_pubkey(k, "feePayerKey")?),
            None => {
                return Err(Error::Other(
                    "feePayer=true requires feePayerKey in methodDetails".into(),
                ));
            }
        }
    } else {
        None
    };

    instructions.push(crate::program::subscriptions::build_subscribe_ix(
        program_id,
        crate::program::subscriptions::SubscribeAccounts {
            subscriber,
            merchant,
            plan_pda,
            subscription_pda,
            subscription_authority_pda: subscription_authority,
            event_authority,
            payer: subscribe_payer,
        },
        &crate::program::subscriptions::SubscribeData {
            plan_id: plan_id_numeric,
            plan_bump,
            expected_mint: mint,
            expected_amount: amount,
            expected_period_hours,
            expected_created_at,
            expected_subscription_authority_init_id,
        },
    ));

    instructions.push(
        crate::program::subscriptions::build_transfer_subscription_ix(
            program_id,
            crate::program::subscriptions::TransferSubscriptionAccounts {
                subscription_pda,
                plan_pda,
                subscription_authority,
                delegator_ata: subscriber_ata,
                receiver_ata: recipient_ata,
                caller: puller,
                token_mint: mint,
                token_program,
                event_authority,
            },
            &crate::program::subscriptions::TransferData {
                amount,
                delegator: subscriber,
                mint,
            },
        ),
    );

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

    // Blockhash was already parsed above for the SA-init pre-step; reuse it
    // for the activation tx. Both transactions share the same recentBlockhash
    // so they land in the same ~150-slot window.
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

/// Resolve the `SubscriptionAuthority::init_id` the activation tx must
/// reference, broadcasting a one-off subscriber-signed init tx when the SA
/// PDA hasn't been created yet.
///
/// The init tx is intentionally paid by the subscriber (no fee-payer
/// trailing account): the on-chain `init` records the funder as the rent
/// recipient on close, and we want that to be the subscriber so they get
/// their rent back when they tear the SA down later. Subscribers must
/// hold ~0.002 SOL the first time they subscribe with a given mint.
#[allow(clippy::too_many_arguments)]
async fn ensure_subscription_authority_init_id(
    signer: &dyn SolanaSigner,
    rpc: &RpcClient,
    program_id: Pubkey,
    subscriber: Pubkey,
    mint: Pubkey,
    subscriber_ata: Pubkey,
    subscription_authority: Pubkey,
    token_program: Pubkey,
    blockhash: &solana_hash::Hash,
) -> Result<i64, Error> {
    if let Ok(account) = rpc.get_account(&subscription_authority) {
        return parse_subscription_authority_init_id(&account.data);
    }

    // SA doesn't exist — broadcast a subscriber-only-signed init tx so the
    // SA lands on-chain (and its `init_id` is recorded) before we sign the
    // activation tx.
    let init_ix = crate::program::subscriptions::build_initialize_subscription_authority_ix(
        program_id,
        crate::program::subscriptions::InitializeSubscriptionAuthorityAccounts {
            owner: subscriber,
            subscription_authority,
            token_mint: mint,
            user_ata: subscriber_ata,
            token_program,
        },
    );

    let message = Message::new_with_blockhash(&[init_ix], Some(&subscriber), blockhash);
    let mut tx = Transaction::new_unsigned(message);
    let sig_bytes = signer
        .sign_message(&tx.message_data())
        .await
        .map_err(|e| Error::Other(format!("SA init signature failed: {e}")))?;
    let sig = Signature::from(<[u8; 64]>::from(sig_bytes));
    tx.signatures[0] = sig;

    rpc.send_and_confirm_transaction(&tx).map_err(|e| {
        Error::Other(format!(
            "Failed to broadcast SubscriptionAuthority init: {e}"
        ))
    })?;

    let account = rpc.get_account(&subscription_authority).map_err(|e| {
        Error::Other(format!(
            "SubscriptionAuthority still missing after init broadcast: {e}"
        ))
    })?;
    parse_subscription_authority_init_id(&account.data)
}

/// Extract `init_id` (i64 LE) from a serialised `SubscriptionAuthority`
/// account. The on-chain struct is `#[repr(C, packed)]` with `init_id` as
/// the last field, so it lives at offset 98 in a 106-byte account.
fn parse_subscription_authority_init_id(bytes: &[u8]) -> Result<i64, Error> {
    if bytes.len() != SUBSCRIPTION_AUTHORITY_ACCOUNT_LEN {
        return Err(Error::Other(format!(
            "Unexpected SubscriptionAuthority length: got {}, expected {SUBSCRIPTION_AUTHORITY_ACCOUNT_LEN}",
            bytes.len()
        )));
    }
    let raw: [u8; 8] = bytes
        [SUBSCRIPTION_AUTHORITY_INIT_ID_OFFSET..SUBSCRIPTION_AUTHORITY_INIT_ID_OFFSET + 8]
        .try_into()
        .expect("8-byte slice");
    Ok(i64::from_le_bytes(raw))
}

/// Build a `CreateIdempotent` instruction for the SPL Associated Token
/// Program. No-op when the ATA already exists; otherwise creates it and
/// charges rent to `funder`.
///
/// Account layout per the Associated Token Program spec:
///   0. funder (signer, writable)
///   1. ata (writable)
///   2. wallet (the ATA owner — readonly)
///   3. mint (readonly)
///   4. system_program (readonly)
///   5. token_program (readonly)
///
/// Instruction data: a single byte `1` (the `CreateIdempotent`
/// discriminator); the older `0` discriminator (`Create`) errors when
/// the ATA exists.
fn build_create_idempotent_ata_ix(
    funder: Pubkey,
    ata: Pubkey,
    wallet: Pubkey,
    mint: Pubkey,
    token_program: Pubkey,
    associated_token_program: Pubkey,
) -> Instruction {
    let system_program =
        Pubkey::from_str("11111111111111111111111111111111").expect("valid system program id");
    Instruction {
        program_id: associated_token_program,
        accounts: vec![
            AccountMeta::new(funder, true),
            AccountMeta::new(ata, false),
            AccountMeta::new_readonly(wallet, false),
            AccountMeta::new_readonly(mint, false),
            AccountMeta::new_readonly(system_program, false),
            AccountMeta::new_readonly(token_program, false),
        ],
        data: vec![1u8],
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
            decimals: Some(6),
            puller: "5fKb5cF22cFybZB1H4hLDydFhwoQy9JzKzRWaSbMkB6h".into(),
            merchant: Some("5fKb5cF22cFybZB1H4hLDydFhwoQy9JzKzRWaSbMkB6h".into()),
            recipient: Some("5fKb5cF22cFybZB1H4hLDydFhwoQy9JzKzRWaSbMkB6h".into()),
            amount: Some("10000000".into()),
            program_id: None,
            network: Some("mainnet".into()),
            fee_payer,
            fee_payer_key: fee_payer_key.map(str::to_string),
            recent_blockhash: Some("11111111111111111111111111111111".into()),
            plan_id_numeric: Some(1),
            plan_bump: Some(255),
            expected_period_hours: Some(720),
            expected_created_at: Some(1_700_000_000),
        }
    }

    /// Build helper for tests: pins `subscription_authority_init_id` to 0
    /// so the activation builder skips the on-chain SA lookup (the RPC mock
    /// would otherwise try to broadcast an init tx and panic on the second
    /// `getAccountInfo` returning AccountNotFound).
    fn pinned_options(
        extras: BuildSubscriptionActivationOptions,
    ) -> BuildSubscriptionActivationOptions {
        BuildSubscriptionActivationOptions {
            subscription_authority_init_id: Some(0),
            ..extras
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn builds_activation_tx_with_pinned_init_id() {
        let signer = make_signer();
        let rpc = RpcClient::new_mock("succeeds".to_string());
        let md = make_method_details(false, None);
        let payload = build_subscription_activation_transaction_with_options(
            &*signer,
            &rpc,
            &md,
            pinned_options(BuildSubscriptionActivationOptions::default()),
        )
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
            pinned_options(BuildSubscriptionActivationOptions {
                external_id: Some("order-42".into()),
                compute_unit_limit: Some(123_456),
                compute_unit_price: Some(1_000),
                ..Default::default()
            }),
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
                // [compute_price, compute_limit, ata_create_idempotent,
                //  subscribe, transfer, memo] = 6. Init runs as a separate
                // pre-broadcast tx, not bundled into the activation.
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
        let err = build_subscription_activation_transaction_with_options(
            &*signer,
            &rpc,
            &md,
            pinned_options(BuildSubscriptionActivationOptions::default()),
        )
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
        let payload = build_subscription_activation_transaction_with_options(
            &*signer,
            &rpc,
            &md,
            pinned_options(BuildSubscriptionActivationOptions::default()),
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
        let err = build_subscription_activation_transaction_with_options(
            &*signer,
            &rpc,
            &md,
            pinned_options(BuildSubscriptionActivationOptions::default()),
        )
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
        let payload = build_subscription_activation_transaction_with_options(
            &*signer,
            &rpc,
            &md,
            pinned_options(BuildSubscriptionActivationOptions::default()),
        )
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
        let err = build_subscription_activation_transaction_with_options(
            &*signer,
            &rpc,
            &md,
            pinned_options(BuildSubscriptionActivationOptions::default()),
        )
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
}
