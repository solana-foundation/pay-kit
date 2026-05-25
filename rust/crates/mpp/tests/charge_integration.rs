//! Integration tests for the charge flow using surfpool-sdk.
//!
//! These tests spin up an embedded Surfnet and exercise the full
//! client build → server verify flow with real Solana transactions.

use solana_mpp::client::build_charge_transaction;
use solana_mpp::client::build_credential_header;
use solana_mpp::protocol::solana::MethodDetails;
use solana_mpp::server::{Config, Mpp};
use solana_mpp::PaymentCredential;
use solana_mpp::{format_authorization, parse_www_authenticate};
use solana_rpc_client::rpc_client::RpcClient;
use std::sync::Arc;
use surfpool_sdk::{Keypair, Signer, Surfnet};
use tokio::time::{sleep, Duration};

const SURFPOOL_DATASOURCE_RPC_URL_ENV: &str = "SURFPOOL_DATASOURCE_RPC_URL";

async fn start_surfnet() -> Surfnet {
    let datasource_rpc_url = std::env::var(SURFPOOL_DATASOURCE_RPC_URL_ENV)
        .unwrap_or_else(|_| "https://api.mainnet-beta.solana.com".to_string());

    Surfnet::builder()
        .remote_rpc_url(datasource_rpc_url)
        .start()
        .await
        .unwrap()
}

/// Create a funded signer using surfpool cheatcodes.
fn fund_signer(surfnet: &Surfnet) -> Arc<dyn solana_mpp::solana_keychain::SolanaSigner> {
    use solana_mpp::solana_keychain::memory::MemorySigner;

    let keypair = Keypair::new();
    surfnet
        .cheatcodes()
        .fund_sol(&keypair.pubkey(), 5_000_000_000)
        .expect("fund signer");

    let signer = MemorySigner::from_bytes(&keypair.to_bytes()).expect("create signer");
    Arc::new(signer)
}

async fn wait_for_surfnet(surfnet: &Surfnet) {
    let rpc = RpcClient::new(surfnet.rpc_url().to_string());
    for _ in 0..300 {
        if rpc.get_latest_blockhash().is_ok() {
            return;
        }
        sleep(Duration::from_millis(100)).await;
    }
    panic!("surfnet rpc did not become ready in time");
}

// ─── SOL charge flow ───────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
#[serial_test::serial]
async fn sol_charge_full_flow() {
    let recipient = Keypair::new();
    let surfnet = start_surfnet().await;
    wait_for_surfnet(&surfnet).await;
    surfnet
        .cheatcodes()
        .fund_sol(&recipient.pubkey(), 1_000_000_000)
        .unwrap();

    let mpp = Mpp::new(Config {
        recipient: recipient.pubkey().to_string(),
        currency: "SOL".to_string(),
        decimals: 9,
        network: "localnet".to_string(),
        rpc_url: Some(surfnet.rpc_url().to_string()),
        secret_key: Some("test-secret".to_string()),
        ..Default::default()
    })
    .unwrap();

    // Generate challenge.
    let challenge = mpp.charge("0.001").unwrap();
    assert_eq!(challenge.method.as_str(), "solana");
    assert_eq!(challenge.intent.as_str(), "charge");

    // Build credential.
    let signer = fund_signer(&surfnet);
    let rpc = RpcClient::new(surfnet.rpc_url().to_string());
    let auth_header = build_credential_header(&*signer, &rpc, &challenge)
        .await
        .expect("build credential");

    assert!(auth_header.starts_with("Payment "));

    // Verify credential.
    let receipt = mpp
        .verify_credential(&solana_mpp::parse_authorization(&auth_header).unwrap())
        .await
        .expect("verify credential");
    assert_eq!(receipt.status.to_string(), "success");
    assert!(!receipt.reference.is_empty());
}

#[tokio::test(flavor = "multi_thread")]
#[serial_test::serial]
async fn sol_charge_wrong_amount_rejected_before_broadcast() {
    let recipient = Keypair::new();
    let surfnet = start_surfnet().await;
    wait_for_surfnet(&surfnet).await;
    surfnet
        .cheatcodes()
        .fund_sol(&recipient.pubkey(), 1_000_000_000)
        .unwrap();

    let mpp = Mpp::new(Config {
        recipient: recipient.pubkey().to_string(),
        currency: "SOL".to_string(),
        decimals: 9,
        network: "localnet".to_string(),
        rpc_url: Some(surfnet.rpc_url().to_string()),
        secret_key: Some("test-secret".to_string()),
        ..Default::default()
    })
    .unwrap();

    let challenge = mpp.charge("0.001").unwrap();
    let signer = fund_signer(&surfnet);
    let rpc = RpcClient::new(surfnet.rpc_url().to_string());

    let request: solana_mpp::ChargeRequest = challenge.request.decode().unwrap();
    let method_details: MethodDetails = request
        .method_details
        .as_ref()
        .map(|v| serde_json::from_value(v.clone()).unwrap())
        .unwrap_or_default();

    // Build tx with WRONG amount.
    let payload = build_charge_transaction(
        &*signer,
        &rpc,
        "1", // 1 lamport instead of 1_000_000
        &request.currency,
        request.recipient.as_deref().unwrap(),
        &method_details,
    )
    .await
    .unwrap();

    let credential = PaymentCredential::new(challenge.to_echo(), payload);
    let auth = format_authorization(&credential).unwrap();

    // Server should reject BEFORE broadcasting.
    let err = mpp
        .verify_credential(&solana_mpp::parse_authorization(&auth).unwrap())
        .await
        .unwrap_err();
    assert!(
        err.message.contains("No matching SOL transfer"),
        "Expected pre-broadcast rejection, got: {}",
        err.message
    );

    // Verify the transaction was NOT broadcast (only the airdrop tx exists).
    let rpc2 = RpcClient::new(surfnet.rpc_url().to_string());
    let signer_balance = rpc2.get_balance(&signer.pubkey()).unwrap();
    // Should still have ~5 SOL (not 5 SOL minus the wrong transfer).
    assert!(
        signer_balance >= 4_900_000_000,
        "Signer should still have ~5 SOL, has {signer_balance}"
    );
}

#[tokio::test(flavor = "multi_thread")]
#[serial_test::serial]
async fn sol_charge_wrong_recipient_rejected_before_broadcast() {
    let real_recipient = Keypair::new();
    let wrong_recipient = Keypair::new();
    let surfnet = start_surfnet().await;
    wait_for_surfnet(&surfnet).await;
    surfnet
        .cheatcodes()
        .fund_sol(&real_recipient.pubkey(), 1_000_000_000)
        .unwrap();
    surfnet
        .cheatcodes()
        .fund_sol(&wrong_recipient.pubkey(), 1_000_000_000)
        .unwrap();

    let mpp = Mpp::new(Config {
        recipient: real_recipient.pubkey().to_string(),
        currency: "SOL".to_string(),
        decimals: 9,
        network: "localnet".to_string(),
        rpc_url: Some(surfnet.rpc_url().to_string()),
        secret_key: Some("test-secret".to_string()),
        ..Default::default()
    })
    .unwrap();

    let challenge = mpp.charge("0.001").unwrap();
    let signer = fund_signer(&surfnet);
    let rpc = RpcClient::new(surfnet.rpc_url().to_string());

    let request: solana_mpp::ChargeRequest = challenge.request.decode().unwrap();
    let method_details: MethodDetails = request
        .method_details
        .as_ref()
        .map(|v| serde_json::from_value(v.clone()).unwrap())
        .unwrap_or_default();

    // Build tx paying WRONG recipient.
    let payload = build_charge_transaction(
        &*signer,
        &rpc,
        &request.amount,
        &request.currency,
        &wrong_recipient.pubkey().to_string(),
        &method_details,
    )
    .await
    .unwrap();

    let credential = PaymentCredential::new(challenge.to_echo(), payload);
    let auth = format_authorization(&credential).unwrap();

    let err = mpp
        .verify_credential(&solana_mpp::parse_authorization(&auth).unwrap())
        .await
        .unwrap_err();
    assert!(
        err.message.contains("No matching SOL transfer"),
        "Expected pre-broadcast rejection, got: {}",
        err.message
    );
}

#[tokio::test(flavor = "multi_thread")]
#[serial_test::serial]
async fn sol_charge_replay_rejected() {
    let recipient = Keypair::new();
    let surfnet = start_surfnet().await;
    wait_for_surfnet(&surfnet).await;
    surfnet
        .cheatcodes()
        .fund_sol(&recipient.pubkey(), 1_000_000_000)
        .unwrap();

    let mpp = Mpp::new(Config {
        recipient: recipient.pubkey().to_string(),
        currency: "SOL".to_string(),
        decimals: 9,
        network: "localnet".to_string(),
        rpc_url: Some(surfnet.rpc_url().to_string()),
        secret_key: Some("test-secret".to_string()),
        ..Default::default()
    })
    .unwrap();

    let challenge = mpp.charge("0.001").unwrap();
    let signer = fund_signer(&surfnet);
    let rpc = RpcClient::new(surfnet.rpc_url().to_string());
    let auth = build_credential_header(&*signer, &rpc, &challenge)
        .await
        .unwrap();

    // First: success.
    let receipt = mpp
        .verify_credential(&solana_mpp::parse_authorization(&auth).unwrap())
        .await
        .unwrap();
    assert_eq!(receipt.status.to_string(), "success");

    // Replay: rejected — either by the replay store (signature-consumed)
    // or by the network itself (duplicate transaction).
    let err = mpp
        .verify_credential(&solana_mpp::parse_authorization(&auth).unwrap())
        .await
        .unwrap_err();
    assert!(
        err.message.contains("consumed")
            || err.message.contains("already been processed")
            || err.code == Some("signature-consumed"),
        "Expected replay rejection, got: {}",
        err.message
    );
}

#[tokio::test(flavor = "multi_thread")]
#[serial_test::serial]
async fn sol_charge_expired_challenge_rejected() {
    let recipient = Keypair::new();
    let surfnet = start_surfnet().await;
    wait_for_surfnet(&surfnet).await;
    surfnet
        .cheatcodes()
        .fund_sol(&recipient.pubkey(), 1_000_000_000)
        .unwrap();

    let mpp = Mpp::new(Config {
        recipient: recipient.pubkey().to_string(),
        currency: "SOL".to_string(),
        decimals: 9,
        network: "localnet".to_string(),
        rpc_url: Some(surfnet.rpc_url().to_string()),
        secret_key: Some("test-secret".to_string()),
        ..Default::default()
    })
    .unwrap();

    // Create an already-expired challenge.
    let challenge = mpp
        .charge_with_options(
            "0.001",
            solana_mpp::server::ChargeOptions {
                expires: Some("1970-01-01T00:00:01Z"),
                ..Default::default()
            },
        )
        .unwrap();

    let signer = fund_signer(&surfnet);
    let rpc = RpcClient::new(surfnet.rpc_url().to_string());
    let auth = build_credential_header(&*signer, &rpc, &challenge)
        .await
        .unwrap();

    let err = mpp
        .verify_credential(&solana_mpp::parse_authorization(&auth).unwrap())
        .await
        .unwrap_err();
    assert!(
        err.code == Some("payment-expired"),
        "Expected expired rejection, got: {} ({:?})",
        err.message,
        err.code
    );
}

#[tokio::test(flavor = "multi_thread")]
#[serial_test::serial]
async fn sol_charge_www_authenticate_roundtrip() {
    let recipient = Keypair::new();
    let surfnet = start_surfnet().await;
    wait_for_surfnet(&surfnet).await;
    surfnet
        .cheatcodes()
        .fund_sol(&recipient.pubkey(), 1_000_000_000)
        .unwrap();

    let mpp = Mpp::new(Config {
        recipient: recipient.pubkey().to_string(),
        currency: "SOL".to_string(),
        decimals: 9,
        network: "localnet".to_string(),
        rpc_url: Some(surfnet.rpc_url().to_string()),
        secret_key: Some("test-secret".to_string()),
        ..Default::default()
    })
    .unwrap();

    let challenge = mpp.charge("0.001").unwrap();

    // Format as WWW-Authenticate header, then parse back.
    let header = challenge.to_header().expect("format header");
    let parsed = parse_www_authenticate(&header).expect("parse header");

    assert_eq!(parsed.id, challenge.id);
    assert_eq!(parsed.method.as_str(), "solana");
    assert_eq!(parsed.intent.as_str(), "charge");

    // Build credential from parsed challenge (should work identically).
    let signer = fund_signer(&surfnet);
    let rpc = RpcClient::new(surfnet.rpc_url().to_string());
    let auth = build_credential_header(&*signer, &rpc, &parsed)
        .await
        .unwrap();

    let receipt = mpp
        .verify_credential(&solana_mpp::parse_authorization(&auth).unwrap())
        .await
        .unwrap();
    assert_eq!(receipt.status.to_string(), "success");
}

// ─── USDC charge flow ──────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
#[serial_test::serial]
async fn usdc_charge_full_flow() {
    let recipient = Keypair::new();
    let surfnet = start_surfnet().await;
    wait_for_surfnet(&surfnet).await;

    surfnet
        .cheatcodes()
        .fund_sol(&recipient.pubkey(), 1_000_000_000)
        .unwrap();

    let usdc_mint: surfpool_sdk::Pubkey = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
        .parse()
        .unwrap();
    let token_program: surfpool_sdk::Pubkey = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
        .parse()
        .unwrap();

    // Fund recipient with 0 USDC (creates ATA).
    surfnet
        .cheatcodes()
        .fund_token(&recipient.pubkey(), &usdc_mint, 0, Some(&token_program))
        .unwrap();

    let mpp = Mpp::new(Config {
        recipient: recipient.pubkey().to_string(),
        currency: "USDC".to_string(),
        decimals: 6,
        network: "localnet".to_string(),
        rpc_url: Some(surfnet.rpc_url().to_string()),
        secret_key: Some("test-secret".to_string()),
        ..Default::default()
    })
    .unwrap();

    let challenge = mpp.charge("1.0").unwrap(); // 1 USDC = 1_000_000 base units

    // Fund signer with SOL + USDC.
    let signer_kp = Keypair::new();
    surfnet
        .cheatcodes()
        .fund_sol(&signer_kp.pubkey(), 5_000_000_000)
        .unwrap();
    surfnet
        .cheatcodes()
        .fund_token(
            &signer_kp.pubkey(),
            &usdc_mint,
            100_000_000, // 100 USDC
            Some(&token_program),
        )
        .unwrap();

    let signer = {
        use solana_mpp::solana_keychain::memory::MemorySigner;
        Arc::new(MemorySigner::from_bytes(&signer_kp.to_bytes()).unwrap())
    };

    let rpc = RpcClient::new(surfnet.rpc_url().to_string());
    let auth = build_credential_header(&*signer, &rpc, &challenge)
        .await
        .expect("build USDC credential");

    let receipt = mpp
        .verify_credential(&solana_mpp::parse_authorization(&auth).unwrap())
        .await
        .expect("verify USDC credential");
    assert_eq!(receipt.status.to_string(), "success");

    // Verify on-chain: recipient got 1 USDC.
    let recipient_ata =
        surfnet
            .cheatcodes()
            .get_ata(&recipient.pubkey(), &usdc_mint, Some(&token_program));
    let balance = rpc.get_token_account_balance(&recipient_ata).unwrap();
    let amount: u64 = balance.amount.parse().unwrap();
    assert_eq!(amount, 1_000_000, "Recipient should have 1 USDC");
}

#[tokio::test(flavor = "multi_thread")]
#[serial_test::serial]
async fn usdc_charge_wrong_amount_no_broadcast() {
    let recipient = Keypair::new();
    let surfnet = start_surfnet().await;
    wait_for_surfnet(&surfnet).await;

    surfnet
        .cheatcodes()
        .fund_sol(&recipient.pubkey(), 1_000_000_000)
        .unwrap();

    let usdc_mint: surfpool_sdk::Pubkey = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
        .parse()
        .unwrap();
    let token_program: surfpool_sdk::Pubkey = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
        .parse()
        .unwrap();

    surfnet
        .cheatcodes()
        .fund_token(&recipient.pubkey(), &usdc_mint, 0, Some(&token_program))
        .unwrap();

    let mpp = Mpp::new(Config {
        recipient: recipient.pubkey().to_string(),
        currency: "USDC".to_string(),
        decimals: 6,
        network: "localnet".to_string(),
        rpc_url: Some(surfnet.rpc_url().to_string()),
        secret_key: Some("test-secret".to_string()),
        ..Default::default()
    })
    .unwrap();

    let challenge = mpp.charge("1.0").unwrap();

    let signer_kp = Keypair::new();
    surfnet
        .cheatcodes()
        .fund_sol(&signer_kp.pubkey(), 5_000_000_000)
        .unwrap();
    surfnet
        .cheatcodes()
        .fund_token(
            &signer_kp.pubkey(),
            &usdc_mint,
            100_000_000,
            Some(&token_program),
        )
        .unwrap();

    let signer = {
        use solana_mpp::solana_keychain::memory::MemorySigner;
        Arc::new(MemorySigner::from_bytes(&signer_kp.to_bytes()).unwrap())
    };

    let rpc = RpcClient::new(surfnet.rpc_url().to_string());

    let request: solana_mpp::ChargeRequest = challenge.request.decode().unwrap();
    let method_details: MethodDetails = request
        .method_details
        .as_ref()
        .map(|v| serde_json::from_value(v.clone()).unwrap())
        .unwrap_or_default();

    // Wrong amount: 1 base unit instead of 1_000_000.
    let payload = build_charge_transaction(
        &*signer,
        &rpc,
        "1",
        &request.currency,
        request.recipient.as_deref().unwrap(),
        &method_details,
    )
    .await
    .unwrap();

    let credential = PaymentCredential::new(challenge.to_echo(), payload);
    let auth = format_authorization(&credential).unwrap();

    let err = mpp
        .verify_credential(&solana_mpp::parse_authorization(&auth).unwrap())
        .await
        .unwrap_err();
    assert!(
        err.message.contains("No matching SPL transferChecked"),
        "Expected pre-broadcast SPL rejection, got: {}",
        err.message
    );

    // Verify signer still has all their USDC.
    let signer_ata =
        surfnet
            .cheatcodes()
            .get_ata(&signer_kp.pubkey(), &usdc_mint, Some(&token_program));
    let balance = rpc.get_token_account_balance(&signer_ata).unwrap();
    let amount: u64 = balance.amount.parse().unwrap();
    assert_eq!(amount, 100_000_000, "Signer should still have all 100 USDC");
}

// ─── Report generation ─────────────────────────────────────────────────

/// Generate an HTML report from all surfpool report data.
/// Run after other tests: cargo test --test charge_integration generate_report
#[test]
fn generate_report() {
    if let Ok(report) =
        surfpool_sdk::report::SurfpoolReport::from_directory("target/surfpool-reports")
    {
        let _ = report.write_html("target/surfpool-report.html");
    }
}
