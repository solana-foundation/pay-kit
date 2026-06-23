//! On-chain proof: open real payment channels and settle them through the
//! shared settlement worker, batched, against a surfnet that has the
//! payment-channels program + USDC deployed.
//!
//! Run against the program-bearing surfnet:
//!   SURFNET_RPC=https://402.surfnet.dev:8899 \
//!     cargo test -p solana-mpp --features settlement --test settlement_onchain -- --nocapture
//!
//! Skips (does not fail) when the surfnet is unreachable.

#![cfg(feature = "settlement")]

use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use solana_mpp::program::payment_channels as pc;
use solana_mpp::settlement::worker::{RpcBroadcaster, SettlementConfig, spawn};
use solana_mpp::solana_keychain::SolanaSigner;
use solana_mpp::solana_keychain::memory::MemorySigner;
use solana_message::Message;
use solana_pubkey::Pubkey;
use solana_rpc_client::rpc_client::RpcClient;
use solana_signature::Signature;
use solana_transaction::Transaction;
use surfpool_sdk::Keypair;

const DEFAULT_RPC: &str = "https://402.surfnet.dev:8899";
const USDC: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
const TOKEN_PROGRAM: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const SYSTEM_PROGRAM: &str = "11111111111111111111111111111111";

const CHANNELS: u64 = 4; // ⌈4/3⌉ = 2 settle transactions ⇒ proves batching
const DEPOSIT: u64 = 100_000; // 0.1 USDC base units
const VOUCHER: u64 = 1_000; // 0.001 USDC settled per channel

fn rpc_url() -> String {
    std::env::var("SURFNET_RPC").unwrap_or_else(|_| DEFAULT_RPC.to_string())
}

fn now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64
}

/// Fresh keypair as a `MemorySigner` (canonical solana pubkey).
fn keypair() -> (MemorySigner, Pubkey) {
    let kp = Keypair::new();
    let signer = MemorySigner::from_bytes(&kp.to_bytes()).expect("signer");
    let pk = signer.pubkey();
    (signer, pk)
}

/// Call a surfnet cheatcode (raw JSON-RPC).
async fn cheat(url: &str, method: &str, params: serde_json::Value) {
    let body = serde_json::json!({"jsonrpc":"2.0","id":1,"method":method,"params":params});
    let resp = reqwest::Client::new()
        .post(url)
        .json(&body)
        .send()
        .await
        .expect("cheat send");
    assert!(resp.status().is_success(), "cheat {method} http {}", resp.status());
}

async fn fund_sol(url: &str, pk: &Pubkey, lamports: u64) {
    cheat(
        url,
        "surfnet_setAccount",
        serde_json::json!([pk.to_string(), {
            "lamports": lamports, "data": "", "executable": false, "owner": SYSTEM_PROGRAM
        }]),
    )
    .await;
}

async fn fund_usdc(url: &str, owner: &Pubkey, amount: u64) {
    cheat(
        url,
        "surfnet_setTokenAccount",
        serde_json::json!([owner.to_string(), USDC, { "amount": amount }, TOKEN_PROGRAM]),
    )
    .await;
}

/// Sign a single-instruction tx with `signer` (fee-payer) and send+confirm it.
async fn send_signed(rpc: &RpcClient, signer: &MemorySigner, payer: &Pubkey, ix: solana_instruction::Instruction) -> Signature {
    let blockhash = rpc.get_latest_blockhash().expect("blockhash");
    let message = Message::new_with_blockhash(&[ix], Some(payer), &blockhash);
    let mut tx = Transaction::new_unsigned(message);
    let sig_bytes = signer.sign_message(&tx.message_data()).await.expect("sign");
    let idx = tx.message.account_keys.iter().position(|k| k == payer).expect("payer key");
    tx.signatures[idx] = Signature::from(<[u8; 64]>::from(sig_bytes));
    rpc.send_and_confirm_transaction(&tx).expect("open tx confirm")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn channels_settle_on_chain_in_batches() {
    let url = rpc_url();
    let rpc = RpcClient::new(url.clone());
    if rpc.get_latest_blockhash().is_err() {
        eprintln!("skipping: surfnet {url} unreachable");
        return;
    }

    let usdc = Pubkey::from_str(USDC).unwrap();
    let token_program = Pubkey::from_str(TOKEN_PROGRAM).unwrap();
    let program_id = pc::default_program_id();

    // Operator: Delegated authority (channel authorized_signer) + fee-payer +
    // settlement signer. Payer funds the deposits.
    let (operator_signer, operator) = keypair();
    let (payer_signer, payer) = keypair();
    // Delegated/upto model: the operator is the payee + settlement authority
    // (the `merchant` in settle_and_finalize must equal the channel's payee).
    let payee = operator;
    fund_sol(&url, &operator, 5_000_000_000).await;
    fund_sol(&url, &payer, 5_000_000_000).await;
    fund_usdc(&url, &payer, DEPOSIT * CHANNELS * 4).await;
    let expires_at = now() + 3_600;

    // ── Open K real channels ────────────────────────────────────────────────
    let mut channels = Vec::new();
    for salt in 0..CHANNELS {
        let params = pc::OpenChannelParams {
            payer,
            payee,
            mint: usdc,
            authorized_signer: operator, // Delegated
            salt,
            deposit: DEPOSIT,
            grace_period: 3_600,
            recipients: vec![],
            token_program,
            program_id,
        };
        let addrs = pc::derive_channel_addresses(&params);
        let ix = pc::build_open_instruction(&params);
        send_signed(&rpc, &payer_signer, &payer, ix).await;
        channels.push(addrs.channel);
    }
    eprintln!("opened {} channels", channels.len());

    // ── Operator signs one voucher per channel (Delegated) ──────────────────
    let mut settle_units = Vec::new();
    for channel in &channels {
        let msg = pc::voucher_message_bytes(channel, VOUCHER, expires_at).unwrap();
        let sig: [u8; 64] = operator_signer.sign_message(&msg).await.unwrap().into();
        let ixs = pc::build_settle_and_finalize_instructions(
            &operator, channel, &operator, Some(&sig), VOUCHER, expires_at, &program_id,
        )
        .unwrap();
        settle_units.push((channel.to_string(), ixs));
    }

    // ── Settle them through the worker ──────────────────────────────────────
    let cfg = SettlementConfig::new(operator, Arc::new(operator_signer));
    let handle = spawn(cfg, Arc::new(RpcBroadcaster::new(url.clone())));

    let mut tasks = Vec::new();
    for (id, ixs) in settle_units {
        let h = handle.clone();
        tasks.push(tokio::spawn(async move { h.settle(id, ixs).await }));
    }
    let mut sigs = Vec::new();
    for t in tasks {
        sigs.push(t.await.unwrap().expect("settle ok"));
    }

    // ⌈4/3⌉ = 2 settlement transactions.
    let mut distinct = sigs.clone();
    distinct.sort();
    distinct.dedup();
    eprintln!("settlement txs: {distinct:?}");
    assert_eq!(distinct.len(), 2, "4 channels should settle in 2 batched txs");

    // Confirm each settlement tx executed on-chain (no program error).
    for sig in &distinct {
        let parsed = Signature::from_str(sig).unwrap();
        let mut ok = false;
        for _ in 0..20 {
            if let Ok(resp) = rpc.get_signature_statuses(&[parsed]) {
                if let Some(Some(st)) = resp.value.into_iter().next() {
                    assert!(st.err.is_none(), "settlement tx {sig} failed on-chain: {:?}", st.err);
                    ok = true;
                    break;
                }
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        assert!(ok, "settlement tx {sig} never confirmed");
    }

    // Each channel is now Finalized on-chain. Channel layout: discriminator(0),
    // version(1), bump(2), status(3); ChannelStatus::Finalized == 1.
    for channel in &channels {
        let acct = rpc.get_account(channel).expect("channel account still present");
        assert!(acct.data.len() > 3, "channel {channel} data too short");
        assert_eq!(acct.data[3], 1, "channel {channel} status should be Finalized (1)");
    }
    eprintln!("✅ {CHANNELS} channels opened + settled on-chain in {} txs", distinct.len());
}
