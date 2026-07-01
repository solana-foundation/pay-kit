//! End-to-end confidential-charge integration tests against an embedded Surfnet.
//!
//! Exercises the real gateway-paid bundle flow with on-chain execution:
//!   set up a Token-2022 confidential mint + funded sender + recipient (the
//!   gateway) → `build_credential_header` (client builds the partially-signed,
//!   gateway-paid bundle) → settlement (gateway co-signs every tx, runs the
//!   instruction allow-list, submits the bundle, and confirms the transfer).
//!
//! `confidential_charge_full_flow` settles directly via `Mpp::verify`
//! (recipient-key amount enforcement, since the gateway is the recipient).
//! `confidential_charge_via_worker` settles through the worker run-loop
//! (trust-proofs mode), covering `server::confidential_worker`.
//!
//! Run: `cargo test -p solana-mpp --features worker,client --test confidential_integration`
#![cfg(feature = "confidential")]

use std::mem::size_of;
use std::sync::Arc;

use solana_address::Address;
use solana_instruction::Instruction;
use solana_message::Message;
use solana_pay_kit::mpp::client::build_credential_header;
use solana_pay_kit::mpp::protocol::confidential::derive_confidential_keys;
use solana_pay_kit::mpp::protocol::solana::MethodDetails;
use solana_pay_kit::mpp::server::{Config, Mpp};
use solana_pay_kit::mpp::solana_keychain::memory::MemorySigner;
use solana_pay_kit::mpp::solana_keychain::SolanaSigner;
use solana_rpc_client::rpc_client::RpcClient;
use solana_signature::Signature;
use solana_system_interface::instruction as system_instruction;
use solana_transaction::Transaction;
use solana_zk_elgamal_proof_interface::{
    instruction::{ContextStateInfo, ProofInstruction},
    proof_data::PubkeyValidityProofContext,
    state::ProofContextState,
};
use solana_zk_sdk::encryption::elgamal::ElGamalKeypair;
use solana_zk_sdk::zk_elgamal_proof_program::pubkey_validity::build_pubkey_validity_proof_data;
use spl_associated_token_account::{
    get_associated_token_address_with_program_id, instruction::create_associated_token_account,
};
use spl_token_2022::{
    extension::{
        confidential_transfer::{
            instruction::{apply_pending_balance, configure_account, deposit, initialize_mint},
            ConfidentialTransferAccount,
        },
        BaseStateWithExtensions, ExtensionType, StateWithExtensions,
    },
    instruction::{initialize_mint as initialize_mint_base, mint_to, reallocate},
    solana_zk_sdk::encryption::pod::{
        auth_encryption::PodAeCiphertext as PodAeCiphertextLegacy,
        elgamal::PodElGamalCiphertext as PodElGamalCiphertextLegacy,
    },
    state::{Account as TokenAccount, Mint},
};
use spl_token_confidential_transfer_proof_extraction::instruction::ProofLocation;
use surfpool_sdk::{Keypair, Signer, Surfnet};
use tokio::time::{sleep, Duration};

const SURFPOOL_DATASOURCE_RPC_URL_ENV: &str = "SURFPOOL_DATASOURCE_RPC_URL";
const SECRET: &str = "test-secret-key-for-confidential-integration-32b";
const REALM: &str = "confidential.test";

async fn start_surfnet() -> Surfnet {
    let datasource = std::env::var(SURFPOOL_DATASOURCE_RPC_URL_ENV)
        .unwrap_or_else(|_| "https://api.mainnet-beta.solana.com".to_string());
    Surfnet::builder()
        .remote_rpc_url(datasource)
        .start()
        .await
        .unwrap()
}

async fn wait_for_surfnet(rpc: &RpcClient) {
    for _ in 0..300 {
        if rpc.get_latest_blockhash().is_ok() {
            return;
        }
        sleep(Duration::from_millis(100)).await;
    }
    panic!("surfnet rpc did not become ready in time");
}

fn set_sig(tx: &mut Transaction, pk: &solana_pubkey::Pubkey, sig: Signature) {
    let idx = tx
        .message
        .account_keys
        .iter()
        .position(|k| k == pk)
        .unwrap_or_else(|| panic!("signer {pk} not in tx accounts"));
    tx.signatures[idx] = sig;
}

/// Build, sign, and submit a legacy tx via RPC; panic with context on failure.
fn submit(rpc: &RpcClient, payer: &Keypair, ixs: &[Instruction], extra: &[&Keypair], label: &str) {
    let blockhash = rpc.get_latest_blockhash().unwrap();
    let msg = Message::new_with_blockhash(ixs, Some(&payer.pubkey()), &blockhash);
    let mut tx = Transaction::new_unsigned(msg);
    let data = tx.message_data();
    set_sig(&mut tx, &payer.pubkey(), payer.sign_message(&data));
    for kp in extra {
        set_sig(&mut tx, &kp.pubkey(), kp.sign_message(&data));
    }
    rpc.send_and_confirm_transaction(&tx)
        .unwrap_or_else(|e| panic!("{label} failed: {e}"));
}

fn cast_ae_v7_to_legacy(
    v7: &solana_zk_sdk::encryption::auth_encryption::AeCiphertext,
) -> PodAeCiphertextLegacy {
    PodAeCiphertextLegacy::from(v7.to_bytes())
}

/// Configure a confidential account whose ElGamal/AES keys are DERIVED from the
/// owner's signer (so the bundle builder and recipient-key settlement, which
/// both re-derive from the same signer, can decrypt this account's balance).
async fn configure(
    rpc: &RpcClient,
    payer: &Keypair,
    owner_signer: &dyn SolanaSigner,
    owner_kp: &Keypair,
    mint: &solana_pubkey::Pubkey,
) -> solana_pubkey::Pubkey {
    let token_program = spl_token_2022::id();
    let zk_program =
        solana_pubkey::Pubkey::from_str_const("ZkE1Gama1Proof11111111111111111111111111111");
    let ata =
        get_associated_token_address_with_program_id(&owner_kp.pubkey(), mint, &token_program);

    submit(
        rpc,
        payer,
        &[create_associated_token_account(
            &payer.pubkey(),
            &owner_kp.pubkey(),
            mint,
            &token_program,
        )],
        &[],
        "create ATA",
    );

    let keys = derive_confidential_keys(owner_signer, &ata).await.unwrap();
    let elgamal: &ElGamalKeypair = &keys.elgamal;
    let decryptable_zero = cast_ae_v7_to_legacy(&keys.ae.encrypt(0u64));

    let proof_data = build_pubkey_validity_proof_data(elgamal).unwrap();
    let proof_account = Keypair::new();
    let ctx_size = size_of::<ProofContextState<PubkeyValidityProofContext>>();
    let ctx_rent = rpc
        .get_minimum_balance_for_rent_exemption(ctx_size)
        .unwrap();
    let create_ctx = system_instruction::create_account(
        &payer.pubkey(),
        &proof_account.pubkey(),
        ctx_rent,
        ctx_size as u64,
        &zk_program,
    );
    let verify = ProofInstruction::VerifyPubkeyValidity.encode_verify_proof(
        Some(ContextStateInfo {
            context_state_account: &Address::from(proof_account.pubkey().to_bytes()),
            context_state_authority: &Address::from(owner_kp.pubkey().to_bytes()),
        }),
        &proof_data,
    );
    let realloc = reallocate(
        &token_program,
        &ata,
        &payer.pubkey(),
        &owner_kp.pubkey(),
        &[&owner_kp.pubkey()],
        &[ExtensionType::ConfidentialTransferAccount],
    )
    .unwrap();
    let configure_ixs = configure_account(
        &token_program,
        &ata,
        mint,
        &decryptable_zero,
        65536,
        &owner_kp.pubkey(),
        &[],
        ProofLocation::ContextStateAccount(&proof_account.pubkey()),
    )
    .unwrap();
    let mut ixs = vec![create_ctx, verify, realloc];
    ixs.extend(configure_ixs);
    submit(
        rpc,
        payer,
        &ixs,
        &[owner_kp, &proof_account],
        "configure account",
    );
    ata
}

/// Pieces a confidential charge needs, after on-chain setup.
struct Setup {
    surfnet: Surfnet,
    rpc: RpcClient,
    gateway: Keypair,
    gateway_signer: Arc<dyn SolanaSigner>,
    sender_signer: Arc<dyn SolanaSigner>,
    mint: solana_pubkey::Pubkey,
    decimals: u8,
}

/// Start Surfnet, create a confidential mint, configure sender + recipient
/// (=gateway) accounts with signer-derived keys, and fund the sender's
/// available confidential balance.
async fn setup_confidential() -> Setup {
    let surfnet = start_surfnet().await;
    let rpc = RpcClient::new(surfnet.rpc_url().to_string());
    wait_for_surfnet(&rpc).await;

    let token_program = spl_token_2022::id();
    let decimals: u8 = 0;

    let payer = Keypair::new();
    let gateway = Keypair::new();
    let sender = Keypair::new();
    for kp in [&payer, &gateway, &sender] {
        surfnet
            .cheatcodes()
            .fund_sol(&kp.pubkey(), 100_000_000_000)
            .unwrap();
    }
    let gateway_signer: Arc<dyn SolanaSigner> =
        Arc::new(MemorySigner::from_bytes(&gateway.to_bytes()).unwrap());
    let sender_signer: Arc<dyn SolanaSigner> =
        Arc::new(MemorySigner::from_bytes(&sender.to_bytes()).unwrap());

    // Confidential mint (auto-approve, no auditor).
    let mint = Keypair::new();
    let mint_authority = Keypair::new();
    let mint_space = ExtensionType::try_calculate_account_len::<Mint>(&[
        ExtensionType::ConfidentialTransferMint,
    ])
    .unwrap();
    let mint_rent = rpc
        .get_minimum_balance_for_rent_exemption(mint_space)
        .unwrap();
    submit(
        &rpc,
        &payer,
        &[
            system_instruction::create_account(
                &payer.pubkey(),
                &mint.pubkey(),
                mint_rent,
                mint_space as u64,
                &token_program,
            ),
            initialize_mint(&token_program, &mint.pubkey(), None, true, None).unwrap(),
            initialize_mint_base(
                &token_program,
                &mint.pubkey(),
                &mint_authority.pubkey(),
                None,
                decimals,
            )
            .unwrap(),
        ],
        &[&mint],
        "create confidential mint",
    );

    // Configure sender + recipient(=gateway) confidential accounts.
    let sender_ata = configure(
        &rpc,
        &payer,
        sender_signer.as_ref(),
        &sender,
        &mint.pubkey(),
    )
    .await;
    let _gateway_ata = configure(
        &rpc,
        &payer,
        gateway_signer.as_ref(),
        &gateway,
        &mint.pubkey(),
    )
    .await;

    // Fund the sender: mint → deposit → apply_pending_balance.
    let starting: u64 = 50_000;
    submit(
        &rpc,
        &payer,
        &[mint_to(
            &token_program,
            &mint.pubkey(),
            &sender_ata,
            &mint_authority.pubkey(),
            &[],
            starting,
        )
        .unwrap()],
        &[&mint_authority],
        "mint_to sender",
    );
    submit(
        &rpc,
        &payer,
        &[deposit(
            &token_program,
            &sender_ata,
            &mint.pubkey(),
            starting,
            decimals,
            &sender.pubkey(),
            &[&sender.pubkey()],
        )
        .unwrap()],
        &[&sender],
        "deposit",
    );
    {
        let acc = rpc.get_account(&sender_ata).unwrap();
        let state = StateWithExtensions::<TokenAccount>::unpack(&acc.data).unwrap();
        let ext = state
            .get_extension::<ConfidentialTransferAccount>()
            .unwrap();
        let keys = derive_confidential_keys(sender_signer.as_ref(), &sender_ata)
            .await
            .unwrap();
        let decrypt = |ct: &PodElGamalCiphertextLegacy| -> u64 {
            let bytes: [u8; 64] = bytemuck::bytes_of(ct).try_into().unwrap();
            let c =
                solana_zk_sdk::encryption::elgamal::ElGamalCiphertext::from_bytes(&bytes).unwrap();
            keys.elgamal.secret().decrypt_u32(&c).unwrap()
        };
        let pending = decrypt(&ext.pending_balance_lo) + (decrypt(&ext.pending_balance_hi) << 16);
        let counter: u64 = ext.pending_balance_credit_counter.into();
        let new_decryptable = cast_ae_v7_to_legacy(&keys.ae.encrypt(pending));
        submit(
            &rpc,
            &payer,
            &[apply_pending_balance(
                &token_program,
                &sender_ata,
                counter,
                &new_decryptable,
                &sender.pubkey(),
                &[&sender.pubkey()],
            )
            .unwrap()],
            &[&sender],
            "apply_pending_balance",
        );
    }

    Setup {
        surfnet,
        rpc,
        gateway,
        gateway_signer,
        sender_signer,
        mint: mint.pubkey(),
        decimals,
    }
}

/// The confidential `ChargeRequest` the gateway issues (gateway = fee payer +
/// recipient).
fn confidential_request(s: &Setup, amount: u64) -> solana_pay_kit::mpp::ChargeRequest {
    let md = MethodDetails {
        network: Some("localnet".to_string()),
        decimals: Some(s.decimals),
        token_program: Some(spl_token_2022::id().to_string()),
        confidential: Some(true),
        fee_payer: Some(true),
        fee_payer_key: Some(s.gateway.pubkey().to_string()),
        ..Default::default()
    };
    solana_pay_kit::mpp::ChargeRequest {
        amount: amount.to_string(),
        currency: s.mint.to_string(),
        recipient: Some(s.gateway.pubkey().to_string()),
        method_details: Some(serde_json::to_value(&md).unwrap()),
        ..Default::default()
    }
}

/// Gateway `Mpp` that both issues the challenge and (in the direct test)
/// settles with recipient-key amount enforcement.
fn gateway_mpp(s: &Setup) -> Mpp {
    Mpp::new(Config {
        recipient: s.gateway.pubkey().to_string(),
        currency: s.mint.to_string(),
        decimals: s.decimals,
        network: "localnet".to_string(),
        rpc_url: Some(s.surfnet.rpc_url().to_string()),
        challenge_binding_secret: Some(SECRET.to_string()),
        realm: Some(REALM.to_string()),
        fee_payer: true,
        fee_payer_signer: Some(s.gateway_signer.clone()),
        recipient_signer: Some(s.gateway_signer.clone()),
        ..Default::default()
    })
    .unwrap()
}

/// Direct settlement via `Mpp::verify` — recipient-key amount enforcement.
#[tokio::test(flavor = "multi_thread")]
#[serial_test::serial]
async fn confidential_charge_full_flow() {
    let s = setup_confidential().await;
    let request = confidential_request(&s, 1_000);
    let mpp = gateway_mpp(&s);
    let challenge = mpp.charge_challenge(&request).unwrap();

    let auth = build_credential_header(s.sender_signer.as_ref(), &s.rpc, &challenge)
        .await
        .expect("build confidential credential");
    let receipt = mpp
        .verify_credential_with_expected(
            &solana_pay_kit::mpp::parse_authorization(&auth).unwrap(),
            &request,
        )
        .await
        .expect("verify confidential credential");
    assert_eq!(receipt.status.to_string(), "success");
    assert!(!receipt.reference.is_empty());
}

/// Settlement through the confidential worker run-loop (trust-proofs mode).
#[cfg(feature = "worker")]
#[tokio::test(flavor = "multi_thread")]
#[serial_test::serial]
async fn confidential_charge_via_worker() {
    use solana_pay_kit::mpp::server::{spawn_confidential_worker, ConfidentialWorkerConfig};

    let s = setup_confidential().await;
    let request = confidential_request(&s, 1_000);
    // Issue the challenge with the gateway Mpp (shares secret + realm).
    let challenge = gateway_mpp(&s).charge_challenge(&request).unwrap();
    let auth = build_credential_header(s.sender_signer.as_ref(), &s.rpc, &challenge)
        .await
        .expect("build confidential credential");
    let credential = solana_pay_kit::mpp::parse_authorization(&auth).unwrap();
    let charge_request: solana_pay_kit::mpp::ChargeRequest =
        credential.challenge.request.decode().unwrap();

    let handle = spawn_confidential_worker(
        ConfidentialWorkerConfig {
            network: "localnet".to_string(),
            rpc_url: s.surfnet.rpc_url().to_string(),
            challenge_binding_secret: Some(SECRET.to_string()),
            realm: REALM.to_string(),
            sweep_currency: s.mint.to_string(),
            sweep_decimals: s.decimals,
            fee_payer_pubkey: s.gateway.pubkey().to_string(),
            // Gateway is the recipient here ⇒ recipient-key amount enforcement.
            recipient_signer: Some(s.gateway_signer.clone()),
        },
        s.gateway_signer.clone(),
    );
    let receipt = handle
        .settle(credential, charge_request, s.mint.to_string(), s.decimals)
        .await
        .expect("worker settle");
    assert_eq!(receipt.status.to_string(), "success");
    assert!(!receipt.reference.is_empty());
}

/// Orphan sweep: create gateway-owned proof-context + record accounts (as a
/// partially-failed bundle would strand) and confirm the two-pass sweep defers
/// on the first pass and closes them back to the gateway on the second.
#[cfg(feature = "worker")]
#[tokio::test(flavor = "multi_thread")]
#[serial_test::serial]
async fn confidential_orphan_sweep() {
    let s = setup_confidential().await;
    let zk_program =
        solana_pubkey::Pubkey::from_str_const("ZkE1Gama1Proof11111111111111111111111111111");

    // Orphan 1: a gateway-owned spl-record account (authority at offset 1).
    let record = Keypair::new();
    let record_space = spl_record::state::RecordData::WRITABLE_START_INDEX;
    let record_rent = s
        .rpc
        .get_minimum_balance_for_rent_exemption(record_space)
        .unwrap();
    submit(
        &s.rpc,
        &s.gateway,
        &[
            system_instruction::create_account(
                &s.gateway.pubkey(),
                &record.pubkey(),
                record_rent,
                record_space as u64,
                &spl_record::id(),
            ),
            spl_record::instruction::initialize(&record.pubkey(), &s.gateway.pubkey()),
        ],
        &[&record],
        "create orphan record",
    );

    // Orphan 2: a gateway-owned ZK proof context (authority at offset 0).
    let elgamal = ElGamalKeypair::new_rand();
    let proof_data = build_pubkey_validity_proof_data(&elgamal).unwrap();
    let ctx = Keypair::new();
    let ctx_size = size_of::<ProofContextState<PubkeyValidityProofContext>>();
    let ctx_rent = s
        .rpc
        .get_minimum_balance_for_rent_exemption(ctx_size)
        .unwrap();
    submit(
        &s.rpc,
        &s.gateway,
        &[
            system_instruction::create_account(
                &s.gateway.pubkey(),
                &ctx.pubkey(),
                ctx_rent,
                ctx_size as u64,
                &zk_program,
            ),
            ProofInstruction::VerifyPubkeyValidity.encode_verify_proof(
                Some(ContextStateInfo {
                    context_state_account: &Address::from(ctx.pubkey().to_bytes()),
                    context_state_authority: &Address::from(s.gateway.pubkey().to_bytes()),
                }),
                &proof_data,
            ),
        ],
        &[&ctx],
        "create orphan context",
    );

    // One long-lived Mpp so the two-pass guard's store persists across sweeps.
    let mpp = gateway_mpp(&s);

    // First pass: first sighting ⇒ deferred, nothing closed.
    let first = mpp.sweep_confidential_orphans().await.unwrap();
    assert_eq!(first.closed_contexts + first.closed_records, 0);
    assert!(first.deferred >= 2, "expected >=2 deferred, got {first:?}");

    // Second pass: confirmed orphaned ⇒ closed back to the gateway.
    let second = mpp.sweep_confidential_orphans().await.unwrap();
    assert!(second.closed_records >= 1, "record not closed: {second:?}");
    assert!(
        second.closed_contexts >= 1,
        "context not closed: {second:?}"
    );
    assert!(s.rpc.get_account(&record.pubkey()).is_err());
    assert!(s.rpc.get_account(&ctx.pubkey()).is_err());
}
