#![cfg(feature = "testkit")]
//! End-to-end: an MPP session funded by an API-credit provider.
//!
//! A customer holds credits with a provider program (the `credit-provider`
//! example from the payment-channels repository). A merchant API built on the
//! kit's MPP session server offers that provider as a funding option: its 402
//! challenge advertises a V2 hooked channel whose `preFund` and
//! `postDistribute` callbacks are the provider's. The kit's MPP client opens
//! the channel, pays three requests with vouchers and closes. The provider's
//! callbacks debit credits at open, move backing tokens into the deposit, and
//! restore the unused principal as credits when the channel distributes.
//!
//! Everything runs on an in-process offline Surfnet. The two programs are
//! written with `surfnet_writeProgram`; the mint, the customer's ledger and
//! the provider vault are planted with `surfnet_setAccount` /
//! `surfnet_setTokenAccount`, so the customer starts out already holding
//! credits. Only the signed flow is real: provider authorization, the hooked
//! `open`, vouchers, and the sealed `distribute` with callbacks.
//!
//! Run from the payment-channels repository after `just build-v2-localnet`
//! and the credit-provider SBF build:
//!
//! ```sh
//! PAYMENT_CHANNELS_V2_SO=$PC/target/deploy-v2/payment_channels.so \
//! CREDIT_PROVIDER_SO=$PC/target/deploy/credit_provider.so \
//! cargo test -p paykit-integration-tests --features testkit \
//!   --test credit_provider_session_surfnet -- --nocapture
//! ```
//!
//! Without both artifacts the test skips (`HARNESS_REQUIRE=1` turns the skip
//! into a failure).

use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use paykit_integration_tests::skip_or_fail;
use serde_json::{json, Value};
use solana_instruction::{AccountMeta, Instruction};
use solana_pay_kit::core::payment_channel::payer_refund::{
    payer_refund, ObservedAccount, RefundDeadline, SealedRefundTerms,
};
use solana_pay_kit::core::payment_channels as v1;
use solana_pay_kit::core::payment_channels_v2 as v2;
use solana_pay_kit::core::store::MemoryChannelStore;
use solana_pay_kit::core::tx::TxVersion;
use solana_pay_kit::mpp::client::session::{
    create_payment_channel_session_opener, OpenBlockhash, PaymentChannelOpenOptions,
    PaymentChannelSessionOpenOptions, SessionOpenAuthorization,
};
use solana_pay_kit::mpp::protocol::core::challenge::{PaymentChallenge, PaymentCredential};
use solana_pay_kit::mpp::protocol::core::headers::{format_authorization, parse_authorization};
use solana_pay_kit::mpp::protocol::core::types::Base64UrlJson;
use solana_pay_kit::mpp::protocol::intents::session::{
    ClosePayload, SessionAction, SessionRequest,
};
use solana_pay_kit::mpp::server::session::{
    SessionConfig, SessionOpenContext, SessionServer, VoucherSigner,
};
use solana_pay_kit::mpp::settlement::testkit;
use solana_pay_kit::mpp::solana_keychain::memory::MemorySigner;
use solana_pay_kit::mpp::solana_keychain::{SolanaSigner, TransactionSigner};
use solana_pubkey::Pubkey;
use solana_rpc_client::nonblocking::rpc_client::RpcClient;

/// A client reading at `confirmed`: on a live cluster the default
/// (`finalized`) lags the transactions this test just landed.
fn rpc_client(url: &str) -> RpcClient {
    RpcClient::new_with_commitment(
        url.to_string(),
        solana_commitment_config::CommitmentConfig::confirmed(),
    )
}
use surfpool_sdk::{Keypair, Surfnet};

const TOKEN_PROGRAM: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const UPGRADEABLE_LOADER: &str = "BPFLoaderUpgradeab1e11111111111111111111111";
const SECRET: &str = "credit-provider-e2e-challenge-binding-secret";
const REALM: &str = "credit.e2e";

/// The provider program's wire constants (examples/credit-provider).
const LEDGER_SEED: &[u8] = b"credit";
const CALLBACK_ENTRYPOINT: [u8; 8] = *b"credit!!";
const AUTHORIZE: u8 = 2;
const LEDGER_LEN: usize = 331;

/// Base units of a 6-decimal mint. Credits are backed one-for-one.
const CREDITS: u64 = 2_000_000;
/// The funding cap the customer and issuer authorize for one channel.
const CAP: u64 = 1_000_000;
const DEPOSIT: u64 = 1_000_000;
const PRICE: u64 = 10_000;
const REQUESTS: u64 = 3;
const SALT: u64 = 7;

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn token_program() -> Pubkey {
    Pubkey::from_str(TOKEN_PROGRAM).unwrap()
}

fn ata(owner: &Pubkey, mint: &Pubkey) -> Pubkey {
    v1::find_associated_token_address(owner, mint, &token_program()).0
}

fn ledger_address(provider: &Pubkey, owner: &Pubkey, mint: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(&[LEDGER_SEED, owner.as_ref(), mint.as_ref()], provider).0
}

/// A fresh signer and its public key; the same 64 bytes can be rebuilt for a
/// second owner (the session signer is boxed into the client session).
fn signer() -> (MemorySigner, [u8; 64]) {
    let bytes = Keypair::new().to_bytes();
    (MemorySigner::from_bytes(&bytes).unwrap(), bytes)
}

/// The provider's immutable hook policy for one customer and mint: the same
/// descriptor on `preFund` and `postDistribute`, exactly the accounts the
/// callback needs. This is what a reviewed "named provider" resolves to.
fn provider_hooks(provider: &Pubkey, owner: &Pubkey, mint: &Pubkey) -> v2::ChannelHooks {
    let ledger = ledger_address(provider, owner, mint);
    let account = |address: Pubkey, writable: bool| v2::HookAccount {
        address: address.to_string(),
        writable,
    };
    let descriptor = v2::HookDescriptor {
        program_id: provider.to_string(),
        entrypoint: CALLBACK_ENTRYPOINT,
        accounts: vec![
            account(ledger, true),
            account(ata(&ledger, mint), true),
            account(ata(owner, mint), true),
            account(token_program(), false),
        ],
        static_data: vec![],
    };
    v2::ChannelHooks {
        pre_fund: Some(descriptor.clone()),
        post_fund: None,
        pre_distribute: None,
        post_distribute: Some(descriptor),
    }
}

/// `Authorization` as the provider program Borsh-decodes it.
struct Authorization {
    payee: Pubkey,
    authorized_signer: Pubkey,
    distribution_hash: [u8; 32],
    salt: u64,
    open_slot: u64,
    cap: u64,
    nonce: u64,
    expires_at_slot: u64,
}

impl Authorization {
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(136);
        out.extend_from_slice(self.payee.as_ref());
        out.extend_from_slice(self.authorized_signer.as_ref());
        out.extend_from_slice(&self.distribution_hash);
        for value in [
            self.salt,
            self.open_slot,
            self.cap,
            self.nonce,
            self.expires_at_slot,
        ] {
            out.extend_from_slice(&value.to_le_bytes());
        }
        out
    }
}

/// The provider's `Ledger` (Borsh, 331 bytes) as planted for a customer who
/// already deposited: credits available, nothing authorized yet.
fn ledger_bytes(owner: &Pubkey, mint: &Pubkey, issuer: &Pubkey, credits: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(LEDGER_LEN);
    out.push(1); // version
    out.push(0); // busy
    out.push(0); // active
    out.extend_from_slice(owner.as_ref());
    out.extend_from_slice(mint.as_ref());
    out.extend_from_slice(issuer.as_ref());
    out.extend_from_slice(&[0; 32]); // channel
    out.extend_from_slice(&[0; 136]); // authorization
    out.extend_from_slice(&[0; 32]); // configuration
    out.extend_from_slice(&credits.to_le_bytes());
    out.extend_from_slice(&0u64.to_le_bytes()); // funded
    out.extend_from_slice(&0u64.to_le_bytes()); // refunded
    out.extend_from_slice(&0u64.to_le_bytes()); // last_sequence
    assert_eq!(out.len(), LEDGER_LEN);
    out
}

#[derive(Debug, PartialEq, Eq)]
struct LedgerView {
    active: bool,
    credits: u64,
    funded: u64,
    refunded: u64,
    last_sequence: u64,
}

fn decode_ledger(data: &[u8]) -> LedgerView {
    assert_eq!(data.len(), LEDGER_LEN, "ledger length");
    let u64_at = |offset: usize| u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap());
    LedgerView {
        active: data[2] == 1,
        credits: u64_at(299),
        funded: u64_at(307),
        refunded: u64_at(315),
        last_sequence: u64_at(323),
    }
}

/// An SPL `Mint` (82 bytes) with no authorities, so no transaction is needed
/// to create it and nothing can mint more backing.
fn mint_bytes(decimals: u8) -> Vec<u8> {
    let mut out = vec![0u8; 82];
    out[44] = decimals;
    out[45] = 1; // is_initialized
    out
}

fn approve_ix(source: &Pubkey, delegate: &Pubkey, owner: &Pubkey, amount: u64) -> Instruction {
    let mut data = vec![4u8];
    data.extend_from_slice(&amount.to_le_bytes());
    Instruction {
        program_id: token_program(),
        accounts: vec![
            AccountMeta::new(*source, false),
            AccountMeta::new_readonly(*delegate, false),
            AccountMeta::new_readonly(*owner, true),
        ],
        data,
    }
}

fn authorize_ix(
    provider: &Pubkey,
    owner: &Pubkey,
    mint: &Pubkey,
    issuer: &Pubkey,
    authorization: &Authorization,
    channel_program: &Pubkey,
) -> Instruction {
    let ledger = ledger_address(provider, owner, mint);
    let mut data = vec![AUTHORIZE];
    data.extend(authorization.encode());
    let mut accounts = vec![
        AccountMeta::new_readonly(*owner, true),
        AccountMeta::new_readonly(*issuer, true),
        AccountMeta::new(ledger, false),
        AccountMeta::new(ata(&ledger, mint), false),
        AccountMeta::new(ata(owner, mint), false),
        AccountMeta::new_readonly(token_program(), false),
    ];
    // The provider defaults to the canonical deployment; any other (the
    // canary) is named by a trailing account (payment-channels#112).
    if *channel_program != v1::default_program_id() {
        accounts.push(AccountMeta::new_readonly(*channel_program, false));
    }
    Instruction {
        program_id: *provider,
        accounts,
        data,
    }
}

const SYSTEM_PROGRAM: &str = "11111111111111111111111111111111";
const ASSOCIATED_TOKEN_PROGRAM: &str = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL";
/// The `canary` channel deployment (payment-channels `Solex.toml`).
const CANARY_CHANNEL_PROGRAM: &str = "CHNLxBtXw7VPqd5GMcbtVoEbn4ehyaSoiHj56Ao5sWkJ";

fn system_transfer(from: &Pubkey, to: &Pubkey, lamports: u64) -> Instruction {
    let mut data = 2u32.to_le_bytes().to_vec();
    data.extend(lamports.to_le_bytes());
    Instruction {
        program_id: Pubkey::from_str(SYSTEM_PROGRAM).unwrap(),
        accounts: vec![AccountMeta::new(*from, true), AccountMeta::new(*to, false)],
        data,
    }
}

fn create_mint_ixs(
    payer: &Pubkey,
    mint: &Pubkey,
    authority: &Pubkey,
    rent: u64,
) -> [Instruction; 2] {
    let mut create = 0u32.to_le_bytes().to_vec();
    create.extend(rent.to_le_bytes());
    create.extend(82u64.to_le_bytes());
    create.extend(token_program().to_bytes());
    let mut init = vec![20u8, 6];
    init.extend(authority.to_bytes());
    init.push(0);
    [
        Instruction {
            program_id: Pubkey::from_str(SYSTEM_PROGRAM).unwrap(),
            accounts: vec![
                AccountMeta::new(*payer, true),
                AccountMeta::new(*mint, true),
            ],
            data: create,
        },
        Instruction {
            program_id: token_program(),
            accounts: vec![AccountMeta::new(*mint, false)],
            data: init,
        },
    ]
}

fn create_ata_ix(payer: &Pubkey, owner: &Pubkey, mint: &Pubkey) -> Instruction {
    Instruction {
        program_id: Pubkey::from_str(ASSOCIATED_TOKEN_PROGRAM).unwrap(),
        accounts: vec![
            AccountMeta::new(*payer, true),
            AccountMeta::new(ata(owner, mint), false),
            AccountMeta::new_readonly(*owner, false),
            AccountMeta::new_readonly(*mint, false),
            AccountMeta::new_readonly(Pubkey::from_str(SYSTEM_PROGRAM).unwrap(), false),
            AccountMeta::new_readonly(token_program(), false),
        ],
        data: vec![1],
    }
}

fn mint_to_ix(mint: &Pubkey, to: &Pubkey, authority: &Pubkey, amount: u64) -> Instruction {
    let mut data = vec![7u8];
    data.extend(amount.to_le_bytes());
    Instruction {
        program_id: token_program(),
        accounts: vec![
            AccountMeta::new(*mint, false),
            AccountMeta::new(*to, false),
            AccountMeta::new_readonly(*authority, true),
        ],
        data,
    }
}

/// The provider's `initialize`: the issuer must be the provider program's
/// upgrade authority, proven through its ProgramData account.
fn initialize_ix(provider: &Pubkey, owner: &Pubkey, mint: &Pubkey, issuer: &Pubkey) -> Instruction {
    let loader = Pubkey::from_str(UPGRADEABLE_LOADER).unwrap();
    let program_data = Pubkey::find_program_address(&[provider.as_ref()], &loader).0;
    Instruction {
        program_id: *provider,
        accounts: vec![
            AccountMeta::new(*owner, true),
            AccountMeta::new(ledger_address(provider, owner, mint), false),
            AccountMeta::new_readonly(*mint, false),
            AccountMeta::new_readonly(*provider, false),
            AccountMeta::new_readonly(program_data, false),
            AccountMeta::new_readonly(*issuer, true),
            AccountMeta::new_readonly(Pubkey::from_str(SYSTEM_PROGRAM).unwrap(), false),
        ],
        data: vec![0],
    }
}

/// The provider's `deposit`: real tokens into the vault before credits.
fn deposit_ix(provider: &Pubkey, owner: &Pubkey, mint: &Pubkey, amount: u64) -> Instruction {
    let ledger = ledger_address(provider, owner, mint);
    let mut data = vec![1u8];
    data.extend(amount.to_le_bytes());
    Instruction {
        program_id: *provider,
        accounts: vec![
            AccountMeta::new_readonly(*owner, true),
            AccountMeta::new(ledger, false),
            AccountMeta::new(ata(&ledger, mint), false),
            AccountMeta::new(ata(owner, mint), false),
            AccountMeta::new_readonly(token_program(), false),
        ],
        data,
    }
}

struct Chain {
    url: String,
    rpc: RpcClient,
    http: reqwest::Client,
}

impl Chain {
    async fn cheat(&self, method: &str, params: Value) -> Value {
        let body = json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params });
        let response: Value = self
            .http
            .post(&self.url)
            .json(&body)
            .send()
            .await
            .expect("cheatcode transport")
            .json()
            .await
            .expect("cheatcode json");
        assert!(
            response.get("error").is_none(),
            "{method} failed: {}",
            response["error"]
        );
        response["result"].clone()
    }

    async fn set_account(&self, key: &Pubkey, owner: &str, data: &[u8], lamports: u64) {
        self.cheat(
            "surfnet_setAccount",
            json!([key.to_string(), {
                "lamports": lamports,
                "data": hex(data),
                "owner": owner,
                "executable": false,
            }]),
        )
        .await;
    }

    async fn write_program(&self, program: &Pubkey, elf: &[u8]) {
        self.cheat(
            "surfnet_writeProgram",
            json!([program.to_string(), hex(elf), 0]),
        )
        .await;
        let account = self
            .rpc
            .get_account(program)
            .await
            .expect("program account");
        assert!(account.executable, "{program} is not executable");
    }

    async fn token_balance(&self, account: &Pubkey) -> Option<u64> {
        let account = self.rpc.get_account(account).await.ok()?;
        Some(u64::from_le_bytes(account.data[64..72].try_into().unwrap()))
    }

    /// Sign with every signer in order (fee payer first) and land the
    /// transaction at `confirmed`.
    async fn send(&self, signers: &[&MemorySigner], ixs: &[Instruction]) -> String {
        let fee_payer = signers[0].pubkey();
        let blockhash = self.rpc.get_latest_blockhash().await.expect("blockhash");
        let mut tx = solana_pay_kit::core::tx::build_unsigned(
            TxVersion::V0,
            &fee_payer,
            ixs,
            blockhash,
            None,
        )
        .expect("build transaction");
        for signer in signers {
            solana_pay_kit::core::signing::sign_versioned_transaction_slot(*signer, &mut tx)
                .await
                .expect("sign");
        }
        let signature = self
            .rpc
            .send_and_confirm_transaction(&tx)
            .await
            .unwrap_or_else(|error| panic!("transaction failed: {error}"));
        signature.to_string()
    }
}

/// The merchant: a priced route behind the kit's MPP session server, with the
/// credit provider's hooks as the advertised funding profile.
#[derive(Clone)]
struct Merchant {
    session: Arc<SessionServer<MemoryChannelStore>>,
    operator: Arc<MemorySigner>,
    rpc_url: String,
    treasury: Pubkey,
    served: Arc<AtomicU64>,
}

fn bad_request(message: String) -> Response {
    (StatusCode::BAD_REQUEST, Json(json!({ "error": message }))).into_response()
}

fn challenge_response(merchant: &Merchant) -> Response {
    let request = merchant
        .session
        .build_challenge_request()
        .expect("session challenge");
    let challenge = PaymentChallenge::with_challenge_binding_secret(
        SECRET,
        REALM,
        "solana",
        "session",
        Base64UrlJson::from_typed(&request).expect("encode request"),
    );
    let header = challenge.to_header().expect("challenge header");
    (
        StatusCode::PAYMENT_REQUIRED,
        [("www-authenticate", header)],
        Json(json!({ "error": "payment required" })),
    )
        .into_response()
}

async fn quote(State(merchant): State<Merchant>, headers: HeaderMap) -> Response {
    let Some(authorization) = headers.get("authorization") else {
        return challenge_response(&merchant);
    };
    let credential = match parse_authorization(authorization.to_str().unwrap_or_default()) {
        Ok(credential) => credential,
        Err(error) => return bad_request(format!("credential: {error}")),
    };
    let echo = &credential.challenge;
    let challenge = PaymentChallenge {
        id: echo.id.clone(),
        realm: echo.realm.clone(),
        method: echo.method.clone(),
        intent: echo.intent.clone(),
        request: echo.request.clone(),
        expires: echo.expires.clone(),
        description: echo.description.clone(),
        digest: echo.digest.clone(),
        opaque: echo.opaque.clone(),
    };
    if !challenge.verify(SECRET) || challenge.realm != REALM {
        return (StatusCode::UNAUTHORIZED, "challenge binding mismatch").into_response();
    }
    let request: SessionRequest = match challenge.request.decode() {
        Ok(request) => request,
        Err(error) => return bad_request(format!("challenge request: {error}")),
    };
    let action: SessionAction = match serde_json::from_value(credential.payload) {
        Ok(action) => action,
        Err(error) => return bad_request(format!("session action: {error}")),
    };
    match action {
        SessionAction::Open(payload) => {
            let context = SessionOpenContext {
                challenge_id: &challenge.id,
                expires: challenge.expires.as_deref(),
                recent_blockhash: request
                    .method_details
                    .recent_blockhash
                    .as_deref()
                    .unwrap_or_default(),
                recent_slot: request.method_details.recent_slot.unwrap_or_default(),
            };
            match merchant.session.process_open(&payload, context).await {
                Ok(state) => Json(json!({
                    "opened": state.channel_id,
                    "deposit": state.deposit,
                }))
                .into_response(),
                Err(error) => bad_request(format!("open: {error}")),
            }
        }
        SessionAction::Voucher(payload) => match merchant.session.verify_voucher(&payload).await {
            Ok(_) => {
                let served = merchant.served.fetch_add(1, Ordering::SeqCst) + 1;
                Json(json!({ "symbol": "SOL", "quote": 100 + served })).into_response()
            }
            Err(error) => bad_request(format!("voucher: {error}")),
        },
        SessionAction::Close(payload) => match close(&merchant, &payload).await {
            Ok(body) => Json(body).into_response(),
            Err(error) => bad_request(format!("close: {error}")),
        },
        other => bad_request(format!("unsupported action {other:?}")),
    }
}

/// Settle the highest voucher, seal, and distribute with the provider's
/// `postDistribute` callback in one operator-signed transaction.
async fn close(merchant: &Merchant, payload: &ClosePayload) -> Result<Value, String> {
    let params = merchant
        .session
        .process_close(payload)
        .await
        .map_err(|error| error.to_string())?;
    let operator = merchant.operator.pubkey();
    let mut instructions = params
        .settle_instructions(&operator)
        .map_err(|error| error.to_string())?;
    let rpc = rpc_client(&merchant.rpc_url);
    let channel = rpc
        .get_account(&params.channel_id)
        .await
        .map_err(|error| error.to_string())?;
    let state = v2::decode_channel(&channel.data).map_err(|error| error.to_string())?;
    let token = token_program();
    let terms = SealedRefundTerms {
        channel: params.channel_id,
        payer: params.payer.ok_or("missing payer")?,
        mint: params.mint.ok_or("missing mint")?,
        token_program: token,
        deposit: state.channel.deposit,
        settled: params.settled,
        payer_withdrawn_at: state.channel.payer_withdrawn_at,
    };
    let refund_account = rpc.get_account(&terms.payer_token_account()).await.ok();
    let observed = refund_account.as_ref().map(|account| ObservedAccount {
        owner: account.owner,
        data: &account.data,
    });
    let deadline = RefundDeadline {
        sealed_at: now(),
        grace_period: 3_600,
    };
    let clearance = payer_refund(&terms, observed, deadline, now())
        .clearance()
        .ok_or("payer refund account is not payable")?;
    instructions.push(
        params
            .distribute_instruction(&merchant.treasury, &token, &clearance)
            .map_err(|error| error.to_string())?,
    );
    let blockhash = rpc
        .get_latest_blockhash()
        .await
        .map_err(|error| error.to_string())?;
    let mut tx = solana_pay_kit::core::tx::build_unsigned(
        TxVersion::V0,
        &operator,
        &instructions,
        blockhash,
        None,
    )
    .map_err(|error| error.to_string())?;
    solana_pay_kit::core::signing::sign_versioned_transaction_slot(
        merchant.operator.as_ref(),
        &mut tx,
    )
    .await
    .map_err(|error| error.to_string())?;
    let signature = rpc
        .send_and_confirm_transaction(&tx)
        .await
        .map_err(|error| format!("settle + distribute: {error}"))?;
    merchant
        .session
        .mark_sealed(&params.channel_id.to_string())
        .await
        .map_err(|error| error.to_string())?;
    Ok(json!({
        "closed": params.channel_id.to_string(),
        "settled": params.settled,
        "signature": signature.to_string(),
    }))
}

async fn serve(merchant: Merchant) -> String {
    let app = Router::new()
        .route("/api/quote", get(quote))
        .with_state(merchant);
    let listener = tokio::net::TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .expect("bind merchant");
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("merchant server");
    });
    format!("http://{address}/api/quote")
}

fn artifact(variable: &str) -> Option<Vec<u8>> {
    let path = std::env::var_os(variable)?;
    let bytes = std::fs::read(&path)
        .unwrap_or_else(|error| panic!("{variable}={}: {error}", path.to_string_lossy()));
    // SBPF v3 ELFs carry e_flags == 3; the kit's runtime expects that ISA.
    assert_eq!(
        u32::from_le_bytes(bytes[0x30..0x34].try_into().unwrap()),
        3,
        "{variable} is not an SBPF v3 artifact"
    );
    Some(bytes)
}

/// A chain prepared for the flow: programs in place, the customer holding
/// `CREDITS` with the provider and nothing in their own token account.
struct Prepared {
    chain: Chain,
    /// Keeps an in-process Surfnet alive for the test's duration.
    _surfnet: Option<Surfnet>,
    network: &'static str,
    channel_program: Pubkey,
    provider: Pubkey,
    customer: MemorySigner,
    issuer: MemorySigner,
    operator: Arc<MemorySigner>,
    mint: Pubkey,
    treasury_owner: Pubkey,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn credit_provider_funds_an_mpp_session_end_to_end() {
    let (Some(channel_elf), Some(provider_elf)) = (
        artifact("PAYMENT_CHANNELS_V2_SO"),
        artifact("CREDIT_PROVIDER_SO"),
    ) else {
        skip_or_fail(
            "set PAYMENT_CHANNELS_V2_SO and CREDIT_PROVIDER_SO to the SBPF v3 artifacts \
             (payment-channels: `just build-v2-localnet` and the credit-provider build)",
        );
        return;
    };

    // ── Chain ──────────────────────────────────────────────────────────────
    let surfnet = Surfnet::builder()
        .offline(true)
        .start()
        .await
        .expect("start surfnet");
    let chain = Chain {
        url: surfnet.rpc_url().to_string(),
        rpc: rpc_client(surfnet.rpc_url()),
        http: reqwest::Client::new(),
    };
    for _ in 0..100 {
        if chain.rpc.get_latest_blockhash().await.is_ok() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }

    // The hooked channel program at its canonical address (built from the
    // `stable` channel with `--features hooks`), plus the provider program.
    let channel_program = v1::default_program_id();
    let provider = Pubkey::new_unique();
    chain.write_program(&channel_program, &channel_elf).await;
    chain.write_program(&provider, &provider_elf).await;
    let loader = chain.rpc.get_account(&provider).await.unwrap().owner;
    assert_eq!(loader.to_string(), UPGRADEABLE_LOADER);

    // ── Parties ────────────────────────────────────────────────────────────
    let (customer, _) = signer();
    let (issuer, _) = signer();
    let (operator, _) = signer();
    let operator = Arc::new(operator);
    for key in [&customer.pubkey(), &issuer.pubkey(), &operator.pubkey()] {
        testkit::fund_sol(&chain.url, key, 5_000_000_000).await;
    }

    // ── Money: a mint, the customer's credits, the provider's backing ───────
    // Planted with cheatcodes: the customer already holds credits.
    let customer_pk = customer.pubkey();
    let operator_pk = operator.pubkey();
    let mint = Pubkey::new_unique();
    chain
        .set_account(&mint, TOKEN_PROGRAM, &mint_bytes(6), 10_000_000)
        .await;
    let treasury_owner = v1::treasury_owner_for_cluster("localnet");
    assert_eq!(
        treasury_owner.to_string(),
        "Cs2zdfUNonRdRGsiZUQQLdTxzxVvJZmgiX2mpLYKuEqP",
        "the localnet treasury must match the stable channel build"
    );
    let ledger = ledger_address(&provider, &customer_pk, &mint);
    let mint_str = mint.to_string();
    testkit::fund_token(&chain.url, &ledger, &mint_str, CREDITS, TOKEN_PROGRAM).await;
    for owner in [&customer_pk, &operator_pk, &treasury_owner] {
        testkit::fund_token(&chain.url, owner, &mint_str, 0, TOKEN_PROGRAM).await;
    }
    chain
        .set_account(
            &ledger,
            &provider.to_string(),
            &ledger_bytes(&customer_pk, &mint, &issuer.pubkey(), CREDITS),
            10_000_000,
        )
        .await;

    run_flow(Prepared {
        chain,
        _surfnet: Some(surfnet),
        network: "localnet",
        channel_program,
        provider,
        customer,
        issuer,
        operator,
        mint,
        treasury_owner,
    })
    .await;
}

/// The same flow live on devnet, against the deployed canary channel program.
///
/// Every step is a real transaction: the provider program is deployed with a
/// fresh issuer as its upgrade authority, a fresh SPL mint is created, the
/// customer deposits real backing into the provider and receives credits,
/// then the MPP session runs exactly as on Surfnet.
///
/// ```sh
/// CREDIT_E2E_DEVNET_RPC=<https devnet RPC> \
/// CREDIT_E2E_FUNDER=<keypair file with ~2 devnet SOL> \
/// CREDIT_PROVIDER_SO=$PC/target/deploy/credit_provider.so \
/// cargo test -p paykit-integration-tests --features testkit \
///   --test credit_provider_session_surfnet devnet -- --nocapture
/// ```
///
/// `CREDIT_PROVIDER_SO` must be the deployment-aware provider
/// (payment-channels#112). Skips unless all three are set.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn credit_provider_funds_an_mpp_session_on_devnet() {
    let (Ok(url), Ok(funder_path), Some(_)) = (
        std::env::var("CREDIT_E2E_DEVNET_RPC"),
        std::env::var("CREDIT_E2E_FUNDER"),
        artifact("CREDIT_PROVIDER_SO"),
    ) else {
        skip_or_fail("set CREDIT_E2E_DEVNET_RPC, CREDIT_E2E_FUNDER and CREDIT_PROVIDER_SO");
        return;
    };
    assert!(url.starts_with("https://"), "devnet RPC must be https");
    let chain = Chain {
        url: url.clone(),
        rpc: rpc_client(&url),
        http: reqwest::Client::new(),
    };
    let funder_bytes: Vec<u8> =
        serde_json::from_str(&std::fs::read_to_string(&funder_path).unwrap()).unwrap();
    let funder = MemorySigner::from_bytes(&funder_bytes).unwrap();
    let channel_program = Pubkey::from_str(CANARY_CHANNEL_PROGRAM).unwrap();
    let deployed = chain
        .rpc
        .get_account(&channel_program)
        .await
        .expect("canary channel program on devnet");
    assert!(
        deployed.executable,
        "the canary channel program is not executable"
    );

    // ── Parties, funded from the funder ────────────────────────────────────
    let (customer, _) = signer();
    let (issuer, issuer_bytes) = signer();
    let (operator, _) = signer();
    let (provider_signer, provider_bytes) = signer();
    let provider = provider_signer.pubkey();
    let operator = Arc::new(operator);
    chain
        .send(
            &[&funder],
            &[
                system_transfer(&funder.pubkey(), &customer.pubkey(), 100_000_000),
                system_transfer(&funder.pubkey(), &operator.pubkey(), 200_000_000),
                system_transfer(&funder.pubkey(), &issuer.pubkey(), 1_500_000_000),
            ],
        )
        .await;

    // ── The provider program, deployed with the issuer as upgrade authority ──
    let dir = std::env::temp_dir().join(format!("credit-e2e-devnet-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let issuer_path = dir.join("issuer.json");
    let provider_path = dir.join("provider.json");
    std::fs::write(
        &issuer_path,
        serde_json::to_string(&issuer_bytes.to_vec()).unwrap(),
    )
    .unwrap();
    std::fs::write(
        &provider_path,
        serde_json::to_string(&provider_bytes.to_vec()).unwrap(),
    )
    .unwrap();
    let so = std::env::var("CREDIT_PROVIDER_SO").unwrap();
    let out =
        std::process::Command::new(std::env::var("SOLANA_CLI").unwrap_or_else(|_| "solana".into()))
            .args([
                "program",
                "deploy",
                "--url",
                &url,
                "--keypair",
                issuer_path.to_str().unwrap(),
                "--upgrade-authority",
                issuer_path.to_str().unwrap(),
                "--program-id",
                provider_path.to_str().unwrap(),
                "--use-rpc",
                "--skip-feature-verify",
                "--commitment",
                "confirmed",
                "--max-sign-attempts",
                "100",
                "--with-compute-unit-price",
                "10000",
                &so,
            ])
            .output()
            .unwrap();
    // Ephemeral keys never outlive the deployment.
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        out.status.success(),
        "provider deployment failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    println!("provider program {provider} deployed");

    // ── Money: a fresh mint, real backing deposited into the provider ──────
    let customer_pk = customer.pubkey();
    let operator_pk = operator.pubkey();
    let (mint_signer, _) = signer();
    let mint = mint_signer.pubkey();
    let treasury_owner = v1::treasury_owner_for_cluster("devnet");
    assert_eq!(
        treasury_owner.to_string(),
        "4zTeC5mVqWLruDexgU2mV66p9t5vCA9JyiZqdGDUspap",
        "the devnet treasury must match the canary devnet build"
    );
    let mint_rent = chain
        .rpc
        .get_minimum_balance_for_rent_exemption(82)
        .await
        .unwrap();
    let [create_mint, init_mint] = create_mint_ixs(&customer_pk, &mint, &customer_pk, mint_rent);
    chain
        .send(&[&customer, &mint_signer], &[create_mint, init_mint])
        .await;
    let ledger = ledger_address(&provider, &customer_pk, &mint);
    chain
        .send(
            &[&customer],
            &[
                create_ata_ix(&customer_pk, &customer_pk, &mint),
                create_ata_ix(&customer_pk, &operator_pk, &mint),
                create_ata_ix(&customer_pk, &treasury_owner, &mint),
                create_ata_ix(&customer_pk, &ledger, &mint),
                mint_to_ix(&mint, &ata(&customer_pk, &mint), &customer_pk, CREDITS),
            ],
        )
        .await;
    chain
        .send(
            &[&customer, &issuer],
            &[
                initialize_ix(&provider, &customer_pk, &mint, &issuer.pubkey()),
                deposit_ix(&provider, &customer_pk, &mint, CREDITS),
            ],
        )
        .await;
    println!("customer deposited {CREDITS} and holds {CREDITS} credits");

    run_flow(Prepared {
        chain,
        _surfnet: None,
        network: "devnet",
        channel_program,
        provider,
        customer,
        issuer,
        operator,
        mint,
        treasury_owner,
    })
    .await;
}

/// 402 → provider approval → hooked open → voucher-paid requests → close,
/// with on-chain assertions at each step.
async fn run_flow(prepared: Prepared) {
    let Prepared {
        chain,
        _surfnet,
        network,
        channel_program,
        provider,
        customer,
        issuer,
        operator,
        mint,
        treasury_owner,
    } = prepared;
    let customer_pk = customer.pubkey();
    let operator_pk = operator.pubkey();
    let (_, session_key) = signer();
    let session_signer = MemorySigner::from_bytes(&session_key).unwrap();
    let session_pubkey = session_signer.pubkey();
    let mint_str = mint.to_string();
    let ledger = ledger_address(&provider, &customer_pk, &mint);
    let vault = ata(&ledger, &mint);
    let customer_ata = ata(&customer_pk, &mint);
    let merchant_ata = ata(&operator_pk, &mint);
    let treasury_ata = ata(&treasury_owner, &mint);
    assert_eq!(chain.token_balance(&vault).await, Some(CREDITS));
    assert_eq!(chain.token_balance(&customer_ata).await, Some(0));
    let ledger_before = decode_ledger(&chain.rpc.get_account(&ledger).await.unwrap().data);
    assert_eq!(ledger_before.credits, CREDITS);
    assert!(!ledger_before.active);

    // ── Merchant API ───────────────────────────────────────────────────────
    let hooks = provider_hooks(&provider, &customer_pk, &mint);
    let config = SessionConfig {
        operator: operator_pk.to_string(),
        recipient: operator_pk.to_string(),
        splits: vec![],
        amount: PRICE,
        suggested_deposit: Some(DEPOSIT),
        minimum_deposit: Some(DEPOSIT / 2),
        currency: mint_str.clone(),
        decimals: 6,
        network: network.to_string(),
        channel_program: Some(channel_program),
        channel_version: Some(2),
        channel_hooks: Some(hooks.clone()),
        token_program: Some(token_program()),
        voucher_signer: VoucherSigner::Client,
        fee_payer_signer: Some(operator.clone() as Arc<dyn TransactionSigner>),
        rpc_url: Some(chain.url.clone()),
        ..SessionConfig::default()
    };
    let merchant = Merchant {
        session: Arc::new(SessionServer::new(config, MemoryChannelStore::new())),
        operator: operator.clone(),
        rpc_url: chain.url.clone(),
        treasury: treasury_owner,
        served: Arc::new(AtomicU64::new(0)),
    };
    let api = serve(merchant.clone()).await;

    // ── Client: 402 → provider approval → hooked open ──────────────────────
    let http = reqwest::Client::new();
    let response = http.get(&api).send().await.unwrap();
    assert_eq!(response.status(), StatusCode::PAYMENT_REQUIRED);
    let header = response
        .headers()
        .get("www-authenticate")
        .expect("challenge header")
        .to_str()
        .unwrap()
        .to_string();
    let challenge = PaymentChallenge::from_header(&header).expect("parse challenge");
    assert!(challenge.verify(SECRET));
    let request: SessionRequest = challenge.request.decode().expect("session request");
    let details = &request.method_details;
    assert_eq!(details.channel_version, Some(2));
    assert_eq!(details.channel_hooks.as_ref(), Some(&hooks));
    assert_eq!(details.fee_payer, Some(true));
    let open_slot = details.recent_slot.expect("recentSlot");
    println!(
        "402 challenge: channel {} v{} hooks={} recentSlot={open_slot}",
        details.channel_program,
        details.channel_version.unwrap(),
        details.channel_hooks.is_some()
    );

    // The customer asks the provider to back this exact channel. The issuer
    // co-signs: this is the provider approving a bounded amount.
    let payee = Pubkey::from_str(&request.recipient).unwrap();
    let authorization = Authorization {
        payee,
        authorized_signer: session_pubkey,
        distribution_hash: v1::distribution_hash(&[]),
        salt: SALT,
        open_slot,
        cap: CAP,
        nonce: 1,
        expires_at_slot: open_slot + 100_000,
    };
    let approval = chain
        .send(
            &[&customer, &issuer],
            &[
                approve_ix(&customer_ata, &ledger, &customer_pk, CAP),
                authorize_ix(
                    &provider,
                    &customer_pk,
                    &mint,
                    &issuer.pubkey(),
                    &authorization,
                    &channel_program,
                ),
            ],
        )
        .await;
    println!("provider authorization: {approval}");
    assert!(decode_ledger(&chain.rpc.get_account(&ledger).await.unwrap().data).active);

    let blocking_rpc = solana_rpc_client::rpc_client::RpcClient::new_with_commitment(
        chain.url.clone(),
        solana_commitment_config::CommitmentConfig::confirmed(),
    );
    let blockhash = OpenBlockhash::verify(&blocking_rpc, &request)
        .await
        .expect("challenged blockhash is live");
    let mut opened = create_payment_channel_session_opener(
        &request,
        &customer,
        Box::new(session_signer),
        blockhash,
        &SessionOpenAuthorization::client_signed(DEPOSIT),
        PaymentChannelSessionOpenOptions {
            open: PaymentChannelOpenOptions {
                salt: Some(SALT),
                ..Default::default()
            },
            ..Default::default()
        },
    )
    .await
    .expect("build hooked open");
    assert_eq!(opened.open.channel_version, Some(2));
    let channel_id = opened.open.channel_id;

    let pay = |action: &SessionAction| {
        let credential = PaymentCredential::new(challenge.to_echo(), action);
        format_authorization(&credential).expect("credential header")
    };
    let response = http
        .get(&api)
        .header("authorization", pay(&opened.action))
        .send()
        .await
        .unwrap();
    let status = response.status();
    let body: Value = response.json().await.unwrap();
    assert_eq!(status, StatusCode::OK, "open rejected: {body}");
    assert_eq!(body["opened"], channel_id.to_string());
    println!("opened hooked channel {channel_id}: {body}");

    // preFund ran: credits debited, backing moved vault → customer → escrow.
    let ledger_open = decode_ledger(&chain.rpc.get_account(&ledger).await.unwrap().data);
    assert_eq!(ledger_open.credits, CREDITS - DEPOSIT);
    assert_eq!(ledger_open.funded, DEPOSIT);
    assert_eq!(ledger_open.last_sequence, 1);
    assert_eq!(chain.token_balance(&vault).await, Some(CREDITS - DEPOSIT));
    assert_eq!(chain.token_balance(&customer_ata).await, Some(0));
    let escrow = ata(&channel_id, &mint);
    assert_eq!(chain.token_balance(&escrow).await, Some(DEPOSIT));
    let onchain = v2::decode_channel(&chain.rpc.get_account(&channel_id).await.unwrap().data)
        .expect("V2 channel");
    assert_eq!(onchain.hooks, hooks);
    assert_eq!(onchain.channel.deposit, DEPOSIT);

    // ── Metered requests paid by vouchers ──────────────────────────────────
    let mut final_voucher = None;
    for n in 1..=REQUESTS {
        let action = opened
            .session
            .prepare_voucher_action(PRICE)
            .await
            .expect("voucher");
        let response = http
            .get(&api)
            .header("authorization", pay(&action))
            .send()
            .await
            .unwrap();
        let status = response.status();
        let body: Value = response.json().await.unwrap();
        assert_eq!(status, StatusCode::OK, "request {n} rejected: {body}");
        let SessionAction::Voucher(payload) = action else {
            unreachable!()
        };
        opened.session.record_voucher(&payload.voucher).unwrap();
        println!(
            "request {n} served for voucher {}: {body}",
            payload.voucher.data.cumulative_amount
        );
        final_voucher = Some(payload.voucher);
    }
    assert_eq!(merchant.served.load(Ordering::SeqCst), REQUESTS);

    // ── Close: settle, seal, distribute with postDistribute ────────────────
    // A client-signed close carries the final voucher; nothing more is owed,
    // so it is the highest voucher the merchant already accepted.
    let close_action = SessionAction::Close(ClosePayload {
        channel_id: channel_id.to_string(),
        authentication: None,
        voucher: final_voucher,
    });
    let response = http
        .get(&api)
        .header("authorization", pay(&close_action))
        .send()
        .await
        .unwrap();
    let status = response.status();
    let body: Value = response.json().await.unwrap();
    assert_eq!(status, StatusCode::OK, "close rejected: {body}");
    let spent = PRICE * REQUESTS;
    assert_eq!(body["settled"], spent);
    println!("closed: {body}");

    // The merchant was paid, the unused principal went back into provider
    // custody, and the customer's credits were restored for exactly that.
    assert_eq!(chain.token_balance(&merchant_ata).await, Some(spent));
    assert_eq!(chain.token_balance(&vault).await, Some(CREDITS - spent));
    assert_eq!(chain.token_balance(&customer_ata).await, Some(0));
    assert_eq!(chain.token_balance(&treasury_ata).await, Some(0));
    assert_eq!(chain.token_balance(&escrow).await, None, "escrow closed");
    let ledger_after = decode_ledger(&chain.rpc.get_account(&ledger).await.unwrap().data);
    assert_eq!(
        ledger_after,
        LedgerView {
            active: false,
            credits: CREDITS - spent,
            funded: DEPOSIT,
            refunded: DEPOSIT - spent,
            last_sequence: 2,
        }
    );
    println!(
        "credits {CREDITS} → {} (spent {spent}), merchant +{spent}, vault {}",
        ledger_after.credits,
        CREDITS - spent
    );
}
