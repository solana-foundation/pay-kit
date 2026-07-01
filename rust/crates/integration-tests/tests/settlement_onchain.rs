//! On-chain proof + bench/demo for the shared settlement worker, driven through
//! the reusable `solana_pay_kit::core::settlement::testkit` harness against a surfnet
//! that has the payment-channels program + USDC deployed.
//!
//! Run:
//!   SURFNET_RPC=https://402.surfnet.dev:8899 \
//!     cargo test -p solana-mpp --features "testkit otel" \
//!       --test settlement_onchain -- --nocapture
//!
//! Skips (does not fail) when the surfnet is unreachable.

#![cfg(feature = "testkit")]

use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use solana_instruction::Instruction;
use solana_pay_kit::mpp::program::payment_channels as pc;
use solana_pay_kit::mpp::settlement::testkit;
use solana_pay_kit::mpp::settlement::worker::{spawn, RpcBroadcaster, SettlementConfig};
use solana_pay_kit::mpp::solana_keychain::memory::MemorySigner;
use solana_pay_kit::mpp::solana_keychain::SolanaSigner;
use solana_pubkey::Pubkey;
use solana_rpc_client::nonblocking::rpc_client::RpcClient;
use solana_signature::Signature;

const DEFAULT_RPC: &str = "https://402.surfnet.dev:8899";
const USDC: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
const TOKEN_PROGRAM: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";

const DEPOSIT: u64 = 100_000; // 0.1 USDC base units
const VOUCHER: u64 = 1_000; // 0.001 USDC settled per channel

fn rpc_url() -> String {
    std::env::var("SURFNET_RPC").unwrap_or_else(|_| DEFAULT_RPC.to_string())
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

/// Fund a Delegated operator (authority + fee-payer + payee) and a payer, then
/// open `count` real channels concurrently. Returns the operator's signer +
/// pubkey and the channel addresses.
async fn open_channels(url: &str, count: u64) -> (Arc<MemorySigner>, Pubkey, Vec<Pubkey>) {
    let usdc = Pubkey::from_str(USDC).unwrap();
    let token_program = Pubkey::from_str(TOKEN_PROGRAM).unwrap();
    let program_id = pc::default_program_id();

    let (operator_signer, operator) = testkit::random_signer();
    let (payer_signer, payer) = testkit::random_signer();
    let operator_signer = Arc::new(operator_signer);
    let payer_signer = Arc::new(payer_signer);

    testkit::fund_sol(url, &operator, 5_000_000_000).await;
    testkit::fund_sol(url, &payer, 5_000_000_000).await;
    testkit::fund_token(url, &payer, USDC, DEPOSIT * count * 4, TOKEN_PROGRAM).await;

    let mut channels = Vec::new();
    let mut opens = Vec::new();
    for salt in 0..count {
        // Delegated/upto model: operator is the payee + authorized_signer (the
        // `merchant` in settle_and_finalize must equal the channel's payee).
        // testkit::open_one fee-pays + signs with `payer`, so rentPayer (a
        // signer) is pinned to `payer` here.
        let params = pc::OpenChannelParams {
            payer,
            rent_payer: payer,
            payee: operator,
            mint: usdc,
            authorized_signer: operator,
            salt,
            deposit: DEPOSIT,
            grace_period: 3_600,
            recipients: vec![],
            token_program,
            program_id,
        };
        channels.push(pc::derive_channel_addresses(&params).channel);
        let ix = pc::build_open_instruction(&params);
        opens.push(tokio::spawn(testkit::open_one(
            url.to_string(),
            payer_signer.clone(),
            ix,
        )));
    }
    for o in opens {
        o.await.unwrap();
    }
    (operator_signer, operator, channels)
}

/// Operator signs one voucher per channel (Delegated) → settle units, keyed by
/// `id_of(index, channel)` for the metrics/report labels.
async fn build_units(
    operator: &Pubkey,
    operator_signer: &MemorySigner,
    channels: &[Pubkey],
    id_of: impl Fn(usize, &Pubkey) -> String,
) -> Vec<(String, Vec<Instruction>)> {
    let program_id = pc::default_program_id();
    let expires_at = now() + 3_600;
    let mut units = Vec::new();
    for (i, channel) in channels.iter().enumerate() {
        let msg = pc::voucher_message_bytes(channel, VOUCHER, expires_at).unwrap();
        let sig: [u8; 64] = operator_signer.sign_message(&msg).await.unwrap().into();
        let ixs = pc::build_settle_and_finalize_instructions(
            operator,
            channel,
            operator,
            Some(&sig),
            VOUCHER,
            expires_at,
            &program_id,
        )
        .unwrap();
        units.push((id_of(i, channel), ixs));
    }
    units
}

/// Assert a settlement signature executed on-chain without a program error.
async fn confirm(rpc: &RpcClient, sig: &str) {
    let parsed = Signature::from_str(sig).unwrap();
    for _ in 0..20 {
        if let Ok(resp) = rpc.get_signature_statuses(&[parsed]).await {
            if let Some(Some(st)) = resp.value.into_iter().next() {
                assert!(
                    st.err.is_none(),
                    "settlement tx {sig} failed on-chain: {:?}",
                    st.err
                );
                return;
            }
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    panic!("settlement tx {sig} never confirmed");
}

/// Parity guard against on-chain-constant drift (program id, distribution hash
/// algorithm/preimage). Opens a real channel **with non-empty splits** and
/// asserts pay-kit's `distribution_hash` equals the hash the program committed
/// on-chain at `open` (it uses `sol_sha256` over the same preimage).
///
/// This is the test that would have caught the blake3→sha256 drift: the program
/// computes its own commitment, so a `distribute` E2E stays self-consistent and
/// never exercises pay-kit's hash — only asserting pay-kit's value **equals the
/// account's** value catches it. The unit golden vector guards the value off
/// chain; this proves the on-chain program agrees.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn distribution_hash_matches_on_chain_commitment() {
    let url = rpc_url();
    let rpc = RpcClient::new(url.clone());
    if rpc.get_latest_blockhash().await.is_err() {
        eprintln!("skipping: surfnet {url} unreachable");
        return;
    }

    let usdc = Pubkey::from_str(USDC).unwrap();
    let token_program = Pubkey::from_str(TOKEN_PROGRAM).unwrap();
    let program_id = pc::default_program_id();

    let (payer_signer, payer) = testkit::random_signer();
    let (_, operator) = testkit::random_signer();
    let payer_signer = Arc::new(payer_signer);
    testkit::fund_sol(&url, &payer, 5_000_000_000).await;
    testkit::fund_token(&url, &payer, USDC, DEPOSIT * 4, TOKEN_PROGRAM).await;

    // Non-empty splits so the committed hash is non-trivial.
    let (_, r1) = testkit::random_signer();
    let (_, r2) = testkit::random_signer();
    let recipients = vec![
        pc::Distribution {
            recipient: r1,
            bps: 7_000,
        },
        pc::Distribution {
            recipient: r2,
            bps: 2_000,
        },
    ];

    // In this single-signer test harness the fee payer / submitter is `payer`
    // itself (see testkit::open_one), so rentPayer is pinned to `payer`.
    let params = pc::OpenChannelParams {
        payer,
        rent_payer: payer,
        payee: operator,
        mint: usdc,
        authorized_signer: operator,
        salt: 0,
        deposit: DEPOSIT,
        grace_period: 3_600,
        recipients: recipients.clone(),
        token_program,
        program_id,
    };
    let channel = pc::derive_channel_addresses(&params).channel;
    testkit::open_one(
        url.clone(),
        payer_signer,
        pc::build_open_instruction(&params),
    )
    .await;

    let data = rpc
        .get_account(&channel)
        .await
        .expect("channel present")
        .data;
    let on_chain =
        pc::generated::accounts::Channel::from_bytes(&data).expect("decode channel account");
    assert_eq!(
        on_chain.distribution_hash,
        pc::distribution_hash(&recipients),
        "pay-kit distribution_hash drifted from the program's on-chain commitment"
    );
    eprintln!("✅ distribution_hash matches the on-chain commitment");
}

/// Negative: an expired voucher must be rejected by the program (`VoucherExpired`
/// = 233 = 0xE9), not settled — proving the on-chain expiry check is enforced.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn expired_voucher_is_rejected_on_chain() {
    let url = rpc_url();
    let rpc = RpcClient::new(url.clone());
    if rpc.get_latest_blockhash().await.is_err() {
        eprintln!("skipping: surfnet {url} unreachable");
        return;
    }

    let (operator_signer, operator, channels) = open_channels(&url, 1).await;
    let channel = channels[0];
    let program_id = pc::default_program_id();
    let expires_at = now() - 3_600; // already expired
    let msg = pc::voucher_message_bytes(&channel, VOUCHER, expires_at).unwrap();
    let sig: [u8; 64] = operator_signer.sign_message(&msg).await.unwrap().into();
    let ixs = pc::build_settle_and_finalize_instructions(
        &operator,
        &channel,
        &operator,
        Some(&sig),
        VOUCHER,
        expires_at,
        &program_id,
    )
    .unwrap();

    let err = testkit::try_send(url.clone(), operator_signer.clone(), ixs)
        .await
        .expect_err("an expired voucher must not settle");
    // VoucherExpired = 233 = 0xE9.
    assert!(
        err.contains("0xe9") || err.to_lowercase().contains("custom program error"),
        "expected VoucherExpired (0xe9), got: {err}"
    );

    // The channel must stay unsettled: status Open (0), not Finalized (1).
    let acct = rpc.get_account(&channel).await.expect("channel present");
    assert_eq!(
        acct.data[3], 0,
        "channel must remain Open after a rejected settle"
    );
    eprintln!("✅ expired voucher rejected on-chain; channel stayed Open");
}

/// Authoritative proof: open 4 real channels, settle through the worker, assert
/// they batch into 2 txs and every channel finalizes on-chain.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn channels_settle_on_chain_in_batches() {
    const CHANNELS: u64 = 4; // ⌈4/3⌉ = 2 settle transactions ⇒ proves batching
    let url = rpc_url();
    let rpc = RpcClient::new(url.clone());
    if rpc.get_latest_blockhash().await.is_err() {
        eprintln!("skipping: surfnet {url} unreachable");
        return;
    }

    let (operator_signer, operator, channels) = open_channels(&url, CHANNELS).await;
    eprintln!("opened {} channels", channels.len());
    let units = build_units(&operator, &operator_signer, &channels, |_, c| c.to_string()).await;

    let cfg = SettlementConfig::new(operator, operator_signer);
    let handle = spawn(cfg, Arc::new(RpcBroadcaster::new(url.clone())));
    let by_tx = testkit::drive_settlement(&handle, units).await;

    eprintln!("settlement txs: {:?}", by_tx.keys().collect::<Vec<_>>());
    assert_eq!(by_tx.len(), 2, "4 channels should settle in 2 batched txs");

    for sig in by_tx.keys() {
        confirm(&rpc, sig).await;
    }
    // Each channel is now Finalized. Channel layout: discriminator(0),
    // version(1), bump(2), status(3); ChannelStatus::Finalized == 1.
    for channel in &channels {
        let acct = rpc
            .get_account(channel)
            .await
            .expect("channel account still present");
        assert!(acct.data.len() > 3, "channel {channel} data too short");
        assert_eq!(
            acct.data[3], 1,
            "channel {channel} status should be Finalized (1)"
        );
    }
    eprintln!(
        "✅ {CHANNELS} channels opened + settled on-chain in {} txs",
        by_tx.len()
    );
}

/// Smoke bench: open K real channels, then measure batched settlement
/// throughput through the worker against the live surfnet.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn settlement_throughput_smoke() {
    const K: u64 = 30; // ⌈30/3⌉ = 10 batched settle txs
    let url = rpc_url();
    if RpcClient::new(url.clone())
        .get_latest_blockhash()
        .await
        .is_err()
    {
        eprintln!("skipping: surfnet {url} unreachable");
        return;
    }

    let t_open = Instant::now();
    let (operator_signer, operator, channels) = open_channels(&url, K).await;
    let open_ms = t_open.elapsed().as_millis();
    let units = build_units(&operator, &operator_signer, &channels, |_, c| c.to_string()).await;

    let cfg = SettlementConfig::new(operator, operator_signer);
    let handle = spawn(cfg, Arc::new(RpcBroadcaster::new(url.clone())));
    let t_settle = Instant::now();
    let by_tx = testkit::drive_settlement(&handle, units).await;
    let settle_ms = t_settle.elapsed().as_millis().max(1);

    eprintln!("\n===== SETTLEMENT SMOKE BENCH (live surfnet) =====");
    eprintln!("channels        {K}");
    eprintln!(
        "open phase      {open_ms} ms  ({} ms/channel)",
        open_ms / K as u128
    );
    eprintln!("settle phase    {settle_ms} ms");
    eprintln!(
        "settle txs      {}  ({} channels/tx)",
        by_tx.len(),
        K as usize / by_tx.len()
    );
    eprintln!(
        "throughput      ~{} channels/sec settled",
        (K as u128 * 1000) / settle_ms
    );
    eprintln!("=================================================\n");

    assert_eq!(
        by_tx.len() as u64,
        K.div_ceil(3),
        "K channels should batch into ⌈K/3⌉ txs"
    );
}

/// Packing run-loop demo: drives the worker, prints the batching decisions
/// (size-trigger vs 350ms-timer + channel_ids per tx) and a packing report, and
/// (feature `otel`) exports the `settlement_flush` spans + metrics to the
/// collector. K=7 → 3 + 3 + 1.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn settlement_packing_runloop_demo() {
    const K: u64 = 7; // 3 (size) + 3 (size) + 1 (timer) → 3 txs

    #[cfg(feature = "otel")]
    let endpoint =
        std::env::var("OTLP_ENDPOINT").unwrap_or_else(|_| "http://localhost:4318".into());
    #[cfg(feature = "otel")]
    let _otel = solana_pay_kit::mpp::otel::init(solana_pay_kit::mpp::otel::OtelOptions {
        service_name: "pay-settlement-bench",
        service_version: env!("CARGO_PKG_VERSION"),
        otlp_endpoint: Some(endpoint.as_str()),
        console_filter: "warn,solana_pay_kit::core::settlement=info",
        trace_filter: "warn,solana_pay_kit::core::settlement=info",
    });

    let url = rpc_url();
    if RpcClient::new(url.clone())
        .get_latest_blockhash()
        .await
        .is_err()
    {
        eprintln!("skipping: surfnet {url} unreachable");
        return;
    }

    let (operator_signer, operator, channels) = open_channels(&url, K).await;
    let units = build_units(&operator, &operator_signer, &channels, |i, _| {
        format!("chan-{i}")
    })
    .await;

    eprintln!("\n>>> submitting {K} channels to the worker (cap 3/tx, 350ms linger) <<<\n");
    let cfg = SettlementConfig::new(operator, operator_signer);
    let handle = spawn(cfg, Arc::new(RpcBroadcaster::new(url.clone())));
    let by_tx = testkit::drive_settlement(&handle, units).await;

    eprintln!(
        "\n===== PACKING REPORT ({K} channels → {} txs) =====",
        by_tx.len()
    );
    for (i, (tx, ids)) in by_tx.iter().enumerate() {
        let mut ids = ids.clone();
        ids.sort();
        eprintln!("tx {}  [{} channels: {}]", i + 1, ids.len(), ids.join(", "));
        eprintln!("      https://pay.sh/receipt/{tx}");
    }
    eprintln!("==================================================\n");

    // ⌈7/3⌉ = 3 txs regardless of how the size/timer triggers split them.
    assert_eq!(
        by_tx.len(),
        3,
        "7 channels should pack into 3 txs (3 + 3 + 1)"
    );

    // `_otel` guard flushes the batch exporter on drop → query the collector
    // for service "pay-settlement-bench".
}
