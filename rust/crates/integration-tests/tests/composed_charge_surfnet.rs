//! Composed charge on a shared surfnet: a merchant server accepts a `charge`
//! paid from a payment channel whose committed payee is the merchant. The
//! transaction's top level is Ed25519 + `settle` + `distribute`; the payment
//! itself is the inner `transferChecked` that `distribute` emits from the
//! channel escrow to the merchant's ATA. Nothing is advertised: both programs
//! are in the spec's default composed set.
//!
//! Run:
//!   SURFNET_RPC=https://402.surfnet.dev:8899 \
//!     cargo test -p paykit-integration-tests --features testkit \
//!       --test composed_charge_surfnet -- --nocapture
//!
//! Skips (does not fail) when the surfnet is unreachable.

#![cfg(feature = "testkit")]

use std::str::FromStr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use solana_pay_kit::mpp::client::{
    build_composed_charge_transaction, BuildChargeTransactionOptions, ChannelFundedCharge,
};
use solana_pay_kit::mpp::program::payment_channels as pc;
use solana_pay_kit::mpp::protocol::solana::MethodDetails;
use solana_pay_kit::mpp::server::{Config, Mpp};
use solana_pay_kit::mpp::settlement::testkit;
use solana_pay_kit::mpp::solana_keychain::SolanaSigner;
use solana_pay_kit::mpp::{ChargeRequest, PaymentCredential};
use solana_pubkey::Pubkey;
use solana_rpc_client::nonblocking::rpc_client::RpcClient as AsyncRpcClient;
use solana_rpc_client::rpc_client::RpcClient;

const DEFAULT_RPC: &str = "https://402.surfnet.dev:8899";
const USDC: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
const TOKEN_PROGRAM: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
/// 0.25 USDC.
const AMOUNT: u64 = 250_000;

fn rpc_url() -> String {
    std::env::var("SURFNET_RPC").unwrap_or_else(|_| DEFAULT_RPC.to_string())
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

async fn token_balance(rpc: &AsyncRpcClient, ata: &Pubkey) -> u64 {
    rpc.get_token_account_balance(ata)
        .await
        .ok()
        .and_then(|b| b.amount.parse().ok())
        .unwrap_or(0)
}

#[tokio::test(flavor = "multi_thread")]
async fn channel_funded_composed_charge_settles_to_merchant() {
    let url = rpc_url();
    let async_rpc = AsyncRpcClient::new(url.clone());
    if async_rpc.get_slot().await.is_err() {
        eprintln!("skipping composed charge test: surfnet unreachable at {url}");
        return;
    }

    let usdc = Pubkey::from_str(USDC).unwrap();
    let token_program = Pubkey::from_str(TOKEN_PROGRAM).unwrap();
    let program_id = pc::default_program_id();

    // Issuer funds and signs for the channel; the customer only pays the
    // transaction fee here (a sponsored variant would need no customer key in
    // the transaction at all). The merchant never touches the chain.
    let (issuer_signer, issuer) = testkit::random_signer();
    let issuer_signer = Arc::new(issuer_signer);
    let (customer_signer, customer) = testkit::random_signer();
    let merchant = Pubkey::new_unique();

    testkit::fund_sol(&url, &issuer, 5_000_000_000).await;
    testkit::fund_sol(&url, &customer, 1_000_000_000).await;
    testkit::fund_token(&url, &issuer, USDC, 10 * AMOUNT, TOKEN_PROGRAM).await;
    // `distribute` requires the payee's and the treasury's ATAs to exist.
    testkit::fund_token(&url, &merchant, USDC, 1, TOKEN_PROGRAM).await;
    let treasury_owner = pc::treasury_owner();
    testkit::fund_token(&url, &treasury_owner, USDC, 1, TOKEN_PROGRAM).await;

    // Open a channel whose payee is the merchant: every distributed delta
    // lands in the merchant's ATA.
    let open_slot = async_rpc.get_slot().await.expect("slot");
    let params = pc::OpenChannelParams {
        payer: issuer,
        rent_payer: issuer,
        payee: merchant,
        mint: usdc,
        authorized_signer: issuer,
        salt: 7,
        open_slot,
        deposit: 4 * AMOUNT,
        grace_period: 3_600,
        recipients: vec![],
        token_program,
        program_id,
    };
    let channel = pc::derive_channel_addresses(&params).channel;
    testkit::open_one(
        url.clone(),
        issuer_signer.clone(),
        pc::build_open_instruction(&params),
    )
    .await;

    let merchant_ata = pc::find_associated_token_address(&merchant, &usdc, &token_program).0;
    let before = token_balance(&async_rpc, &merchant_ata).await;

    // The merchant runs an ordinary USDC charge server. Nothing about
    // composed transactions is configured or advertised.
    let mpp = Mpp::new(Config {
        recipient: merchant.to_string(),
        currency: USDC.to_string(),
        decimals: 6,
        network: "localnet".to_string(),
        rpc_url: Some(url.clone()),
        challenge_binding_secret: Some(
            "test-secret-key-for-integration-tests-32b-padding".to_string(),
        ),
        realm: Some("test".to_string()),
        ..Default::default()
    })
    .expect("server");
    let challenge = mpp.charge("0.25").expect("challenge");
    let request: ChargeRequest = challenge.request.decode().expect("request");
    let method_details: MethodDetails =
        serde_json::from_value(request.method_details.clone().expect("methodDetails"))
            .expect("method details");
    assert!(
        method_details.allowed_programs.is_none(),
        "the default composed set is never advertised"
    );

    // The issuer authorizes exactly the charged amount as the channel's first
    // voucher, so the distributed delta equals the payment leg.
    let expires_at = now() + 3_600;
    let message = pc::voucher_message_bytes(&channel, AMOUNT, expires_at).expect("voucher bytes");
    let voucher_signature: [u8; 64] = issuer_signer
        .sign_message(&message)
        .await
        .expect("sign voucher")
        .into();
    let funded = ChannelFundedCharge {
        channel,
        payer: issuer,
        rent_payer: issuer,
        payee: merchant,
        mint: usdc,
        recipients: vec![],
        token_program,
        program_id,
        treasury_owner,
        authorized_signer: issuer,
        voucher_signature,
        cumulative_amount: AMOUNT,
        expires_at,
    };

    let rpc = RpcClient::new(url.clone());
    let payload = build_composed_charge_transaction(
        &customer_signer,
        &rpc,
        &method_details,
        funded.instructions().expect("instructions"),
        BuildChargeTransactionOptions::default(),
    )
    .await
    .expect("composed payload");
    let credential = PaymentCredential::new(challenge.to_echo(), payload);

    let receipt = mpp
        .verify(&credential, &request)
        .await
        .expect("composed charge verifies by outcome");
    assert_eq!(receipt.status.to_string(), "success");
    assert!(!receipt.reference.is_empty());

    let after = token_balance(&async_rpc, &merchant_ata).await;
    assert_eq!(
        after - before,
        AMOUNT,
        "merchant received the inner transfer"
    );
}
