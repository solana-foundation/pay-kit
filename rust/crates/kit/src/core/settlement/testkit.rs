//! Test/demo harness for the settlement worker (feature `testkit`).
//!
//! Reusable helpers so the x402/mpp tests and the pay bench all drive **one**
//! real open → settle → observe flow against a surfnet, instead of each
//! re-rolling channel opens, cheatcode funding, and worker-driving:
//!
//! - [`random_signer`] — fresh ed25519 keypair as a `MemorySigner`;
//! - [`fund_sol`] / [`fund_token`] — surfnet cheatcode funding;
//! - [`open_one`] — submit + confirm a channel open over async RPC;
//! - [`drive_settlement`] — submit units to the worker concurrently and return
//!   the observed **txid → channel_ids** packing.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use solana_instruction::Instruction;
use solana_keychain::memory::MemorySigner;
use solana_keychain::SolanaSigner;
use solana_message::Message;
use solana_pubkey::Pubkey;
use solana_rpc_client::nonblocking::rpc_client::RpcClient;
use solana_signature::Signature;
use solana_transaction::Transaction;

use super::worker::SettlementHandle;

const SYSTEM_PROGRAM: &str = "11111111111111111111111111111111";

/// Fresh ed25519 keypair as a `MemorySigner` + its pubkey.
pub fn random_signer() -> (MemorySigner, Pubkey) {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).expect("CSPRNG");
    let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
    let mut keypair = [0u8; 64];
    keypair[..32].copy_from_slice(&sk.to_bytes());
    keypair[32..].copy_from_slice(&sk.verifying_key().to_bytes());
    let signer = MemorySigner::from_bytes(&keypair).expect("signer");
    let pubkey = signer.pubkey();
    (signer, pubkey)
}

/// Call a surfnet cheatcode (raw JSON-RPC). Panics on transport/HTTP failure —
/// this is test scaffolding, not production code.
pub async fn cheat(url: &str, method: &str, params: serde_json::Value) {
    let body = serde_json::json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params });
    let resp = reqwest::Client::new()
        .post(url)
        .json(&body)
        .send()
        .await
        .expect("cheat send");
    assert!(
        resp.status().is_success(),
        "cheat {method} http {}",
        resp.status()
    );
}

/// Fund `pk` with `lamports` SOL via `surfnet_setAccount`.
pub async fn fund_sol(url: &str, pk: &Pubkey, lamports: u64) {
    cheat(
        url,
        "surfnet_setAccount",
        serde_json::json!([pk.to_string(), {
            "lamports": lamports, "data": "", "executable": false, "owner": SYSTEM_PROGRAM
        }]),
    )
    .await;
}

/// Fund `owner`'s associated token account for `mint` with `amount` base units
/// via `surfnet_setTokenAccount`.
pub async fn fund_token(url: &str, owner: &Pubkey, mint: &str, amount: u64, token_program: &str) {
    cheat(
        url,
        "surfnet_setTokenAccount",
        serde_json::json!([owner.to_string(), mint, { "amount": amount }, token_program]),
    )
    .await;
}

/// Open one channel: submit the open `ix` (signed by `signer`, the payer) and
/// poll to `confirmed` (no finalized wait). Uses the native async RPC client so
/// K of these run concurrently without parking a worker thread each.
pub async fn open_one(url: String, signer: Arc<MemorySigner>, ix: Instruction) {
    let rpc = RpcClient::new(url);
    let payer = signer.pubkey();
    let blockhash = rpc.get_latest_blockhash().await.expect("blockhash");
    let message = Message::new_with_blockhash(&[ix], Some(&payer), &blockhash);
    let mut tx = Transaction::new_unsigned(message);
    let sig_bytes = signer.sign_message(&tx.message_data()).await.expect("sign");
    let idx = tx
        .message
        .account_keys
        .iter()
        .position(|k| k == &payer)
        .unwrap();
    tx.signatures[idx] = Signature::from(<[u8; 64]>::from(sig_bytes));
    let sig = rpc.send_transaction(&tx).await.expect("open submit");
    for _ in 0..60 {
        if let Ok(r) = rpc.get_signature_statuses(&[sig]).await {
            if let Some(Some(st)) = r.value.into_iter().next() {
                assert!(st.err.is_none(), "open failed: {:?}", st.err);
                return;
            }
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    panic!("open not confirmed");
}

/// Build + sign + send `ixs` as one legacy tx (fee-paid by `signer`), returning
/// the raw RPC result. Unlike [`open_one`], it surfaces the error instead of
/// asserting success — for negative tests that expect an on-chain program error.
pub async fn try_send(
    url: String,
    signer: Arc<MemorySigner>,
    ixs: Vec<Instruction>,
) -> Result<String, String> {
    let rpc = RpcClient::new(url);
    let payer = signer.pubkey();
    let blockhash = rpc
        .get_latest_blockhash()
        .await
        .map_err(|e| e.to_string())?;
    let message = Message::new_with_blockhash(&ixs, Some(&payer), &blockhash);
    let mut tx = Transaction::new_unsigned(message);
    let sig_bytes = signer
        .sign_message(&tx.message_data())
        .await
        .map_err(|e| e.to_string())?;
    let idx = tx
        .message
        .account_keys
        .iter()
        .position(|k| k == &payer)
        .unwrap();
    tx.signatures[idx] = Signature::from(<[u8; 64]>::from(sig_bytes));
    rpc.send_transaction(&tx)
        .await
        .map(|s| s.to_string())
        .map_err(|e| e.to_string())
}

/// Submit each `(channel_id, instructions)` to the worker concurrently; return
/// the resulting **txid → channel_ids** grouping (the observed packing). Panics
/// if any settle fails — the caller wants a clean demo/bench signal.
pub async fn drive_settlement(
    handle: &SettlementHandle,
    units: Vec<(String, Vec<Instruction>)>,
) -> BTreeMap<String, Vec<String>> {
    let mut tasks = Vec::new();
    for (id, ixs) in units {
        let handle = handle.clone();
        tasks.push(tokio::spawn(async move {
            let label = id.clone();
            (label, handle.settle(id, ixs).await)
        }));
    }
    let mut by_tx: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for task in tasks {
        let (id, result) = task.await.expect("join");
        by_tx
            .entry(result.expect("settle ok"))
            .or_default()
            .push(id);
    }
    by_tx
}
