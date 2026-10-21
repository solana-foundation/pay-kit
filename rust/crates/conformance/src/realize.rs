//! Realize a [`Case`] into a vector by running the Rust kit.
//!
//! Three steps:
//! 1. [`materialize`] produces the vector input (kit-built transactions,
//!    mutations, x402 envelopes);
//! 2. [`run`] drives the kit on that input exactly as an SDK runner would
//!    (client builder, server verifier, canonical encoder) against the
//!    fixture RPC;
//! 3. [`expectation`] turns the observation into the vector's `expect`
//!    block, and refuses when it contradicts the case: a generated case
//!    whose verdict the kit no longer produces, or an authored case the kit
//!    disagrees with without a recorded `kit_divergence` (or agrees with
//!    despite one).
//!
//! Every registry case's `#[test]` calls [`realize_blocking`], so the same
//! check is the positive control and the filler.

use base64::Engine;
use serde::Serialize;
use serde_json::{json, Map, Value};
use solana_pay_kit::core::session::accept_voucher;
use solana_pay_kit::core::store::{
    ChannelState, ChannelStore, MemoryChannelStore, CHANNEL_STATE_SCHEMA_VERSION,
};
use solana_pay_kit::mpp::client::{
    build_charge_transaction_with_options, BuildChargeTransactionOptions, ComputeBudgetOptions,
};
use solana_pay_kit::mpp::protocol::core::{
    base64url_decode, base64url_encode, compute_challenge_id, Base64UrlJson,
};
use solana_pay_kit::mpp::protocol::intents::session::{SessionAction, SessionRequest, VoucherData};
use solana_pay_kit::mpp::protocol::intents::ChargeRequest;
use solana_pay_kit::mpp::protocol::solana::{CredentialPayload, MethodDetails};
use solana_pay_kit::mpp::server::charge::testkit::verify_transaction_pre_broadcast;
use solana_pay_kit::solana_keychain::memory::MemorySigner;
use solana_pay_kit::solana_keychain::SolanaSigner;
use solana_pay_kit::x402::client::exact::{build_payment_header, build_payment_header_v1};
use solana_pay_kit::x402::exact::{
    caip2_network_for_cluster, generate_payment_identifier_id, PaymentExtensions,
    PaymentRequirements,
};
use solana_pay_kit::x402::server::exact::{Config as X402Config, PaymentIdentifierPolicy, X402};
use solana_pay_kit::x402::server::CurrencyConfig;

use crate::case::{Case, Expect, Input, Intent, Mode, Pin, Provenance, RejectCode};
use crate::classify::classify;
use crate::fixture_rpc::{self, Fixtures, HttpFixture};
use crate::keys::{self, ata, TOKEN_2022_PROGRAM, TOKEN_PROGRAM};
use crate::tx::{decode_b64, encode_b64, memo_nonce, x402_static_layout, StaticLayout};

static SEED: std::sync::OnceLock<u64> = std::sync::OnceLock::new();

/// Seeded fills (`pkc fill --seed`) vary memo nonces and mutation
/// magnitudes, never verdicts, so a testee that memorised the committed
/// bytes fails a seeded corpus. Unset for the committed corpus.
pub fn set_seed(seed: u64) {
    let _ = SEED.set(seed);
}

fn seeded_memo(id: &str) -> String {
    match SEED.get() {
        None => memo_nonce(id),
        Some(seed) => {
            use sha2::Digest;
            let digest = sha2::Sha256::digest(format!("{id}:{seed}").as_bytes());
            digest.iter().take(16).map(|b| format!("{b:02x}")).collect()
        }
    }
}

fn seeded(mutation: &crate::mutate::Mutation) -> crate::mutate::Mutation {
    use crate::mutate::Mutation;
    let Some(seed) = SEED.get() else {
        return mutation.clone();
    };
    let scale = 1 + (seed % 50);
    match mutation {
        Mutation::BumpAmount { transfer, delta } => Mutation::BumpAmount {
            transfer: *transfer,
            delta: delta * scale as i64,
        },
        Mutation::OverPay { transfer, delta } => Mutation::OverPay {
            transfer: *transfer,
            delta: delta * scale,
        },
        other => other.clone(),
    }
}

/// What the kit produced for a case input.
#[derive(Debug, Clone, PartialEq)]
pub enum Observed {
    Accept(Output),
    Reject {
        code: Option<RejectCode>,
        message: String,
    },
    /// The kit's public API cannot express the input.
    NotExpressible(String),
}

impl Observed {
    fn reject(message: impl Into<String>) -> Self {
        let message = message.into();
        Observed::Reject {
            code: classify(&message),
            message,
        }
    }

    pub fn summary(&self) -> String {
        match self {
            Observed::Accept(_) => "accept".into(),
            Observed::Reject { code, message } => format!(
                "reject {} ({message})",
                code.map(|c| c.as_str()).unwrap_or("<unclassified>")
            ),
            Observed::NotExpressible(reason) => format!("not expressible: {reason}"),
        }
    }
}

/// The kit's raw accept output.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Output {
    /// Base64 wire transaction (charge build/verify).
    pub transaction: Option<String>,
    /// Base64 x402 payment header (x402 build/verify).
    pub header: Option<String>,
    /// `exactBytes` (canonical-bytes).
    pub exact: Option<Map<String, Value>>,
}

/// A filled case.
#[derive(Debug, Clone)]
pub struct Realized {
    pub input: Value,
    pub expect: Value,
    pub observed: Observed,
}

pub fn realize_blocking(case: &Case) -> Result<Realized, String> {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?
        .block_on(realize(case))
}

pub async fn realize(case: &Case) -> Result<Realized, String> {
    let input = materialize(case)
        .await
        .map_err(|e| format!("{}: materialize input: {e}", case.id))?;
    let observed = run(case.intent, case.mode, &input).await;
    let expect = expectation(case, &input, &observed).map_err(|e| format!("{}: {e}", case.id))?;
    Ok(Realized {
        input,
        expect,
        observed,
    })
}

// ── input ──────────────────────────────────────────────────────────────────

pub async fn materialize(case: &Case) -> Result<Value, String> {
    match &case.input {
        Input::Static(value) => Ok(value.clone()),
        Input::ChargeTransaction {
            base,
            mutation,
            built_from,
        } => {
            let transaction = charge_build(built_from.as_ref().unwrap_or(base)).await?;
            let transaction = match mutation {
                None => transaction,
                Some(mutation) => {
                    check_pairing(case, mutation)?;
                    let tx = decode_b64(&transaction)?;
                    encode_b64(&seeded(mutation).apply(&tx, &[keys::CLIENT_SEED])?)?
                }
            };
            let mut input = base.clone();
            input["transaction"] = json!(transaction);
            Ok(input)
        }
        Input::X402Header(spec) => {
            if let Some(mutation) = &spec.mutation {
                check_pairing(case, mutation)?;
            }
            x402_header_input(case.id.as_str(), spec)
        }
    }
}

/// A generated reject case built from an operator must declare the code the
/// operator table pairs with its suite.
fn check_pairing(case: &Case, mutation: &crate::mutate::Mutation) -> Result<(), String> {
    if let (Provenance::Generated, Expect::Reject { code, .. }) = (&case.provenance, &case.expect) {
        if mutation.expected(case.suite) != Some(*code) {
            return Err(format!(
                "{mutation:?} is paired with {:?} in {}, but the case declares {code}",
                mutation.expected(case.suite).map(|c| c.as_str()),
                case.suite.as_str()
            ));
        }
    }
    Ok(())
}

#[derive(Serialize)]
struct AcceptedExtra {
    #[serde(rename = "feePayer")]
    fee_payer: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    memo: Option<String>,
}

#[derive(Serialize)]
struct Accepted {
    scheme: &'static str,
    network: String,
    amount: String,
    asset: String,
    #[serde(rename = "payTo")]
    pay_to: String,
    #[serde(rename = "maxTimeoutSeconds")]
    max_timeout_seconds: u64,
    extra: AcceptedExtra,
}

#[derive(Serialize)]
struct Envelope {
    #[serde(rename = "x402Version")]
    x402_version: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    scheme: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    network: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    accepted: Option<Accepted>,
    payload: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    extensions: Option<Value>,
}

/// The canonical `accepted` object of a route: what the server advertises
/// and what an honest client echoes.
pub fn route_accepted(
    network: &str,
    recipient: &str,
    currency: &str,
    amount: &str,
    fee_payer: &str,
    memo: Option<&str>,
) -> Value {
    let mut extra = json!({ "feePayer": fee_payer });
    if let Some(memo) = memo {
        extra["memo"] = json!(memo);
    }
    json!({
        "scheme": "exact",
        "network": caip2_network_for_cluster(network),
        "amount": amount,
        "asset": currency,
        "payTo": recipient,
        "maxTimeoutSeconds": 300,
        "extra": extra,
    })
}

fn x402_header_input(id: &str, spec: &crate::case::X402HeaderSpec) -> Result<Value, String> {
    let route = &spec.route;
    let pays = spec.pays.clone().unwrap_or(crate::case::X402Payment {
        recipient: route.recipient,
        mint: route.currency,
        amount: route.amount,
    });
    let memo = spec
        .memo
        .clone()
        .or_else(|| route.memo.map(str::to_string))
        .unwrap_or_else(|| seeded_memo(id));
    let mut tx = x402_static_layout(&StaticLayout {
        fee_payer: keys::X402_SERVER_FEE_PAYER,
        mint: pays.mint,
        pay_to: pays.recipient,
        amount: pays.amount.parse().map_err(|_| "invalid amount")?,
        decimals: 6,
        memo: &memo,
    })?;
    let mut accepted = Accepted {
        scheme: "exact",
        network: caip2_network_for_cluster(route.network).to_string(),
        amount: route.amount.to_string(),
        asset: route.currency.to_string(),
        pay_to: route.recipient.to_string(),
        max_timeout_seconds: 300,
        extra: AcceptedExtra {
            fee_payer: keys::X402_SERVER_FEE_PAYER.to_string(),
            memo: route.memo.map(str::to_string),
        },
    };
    for (key, value) in &spec.accepted_overrides {
        let text = value.as_str().map(str::to_string).unwrap_or_default();
        match *key {
            "network" => accepted.network = text,
            "amount" => accepted.amount = text,
            "asset" => accepted.asset = text,
            "payTo" => accepted.pay_to = text,
            "extra.memo" => accepted.extra.memo = Some(text),
            other => return Err(format!("unsupported accepted override {other}")),
        }
    }
    if let Some(mutation) = &spec.mutation {
        match mutation {
            crate::mutate::Mutation::WrongNetwork { network } => {
                accepted.network = network.to_string();
            }
            other => tx = seeded(other).apply(&tx, &[keys::CLIENT_SEED])?,
        }
    }
    let envelope = Envelope {
        x402_version: spec.version,
        // v1-shaped (top-level scheme + network, no accepted) whenever a v1
        // network slug is given, whatever the version number claims.
        scheme: spec.v1_network.is_some().then_some("exact"),
        network: spec.v1_network,
        accepted: spec.v1_network.is_none().then_some(accepted),
        payload: json!({ "transaction": encode_b64(&tx)? }),
        extensions: spec.extensions.clone(),
    };
    let header = base64::engine::general_purpose::STANDARD
        .encode(serde_json::to_string(&envelope).map_err(|e| e.to_string())?);
    let mut input = json!({
        "x402PaymentHeader": header,
        "x402ServerNetwork": route.network,
        "x402ServerRecipient": route.recipient,
        "x402ServerCurrency": route.currency,
        "x402ServerAmount": route.amount,
        "x402ServerFeePayer": keys::X402_SERVER_FEE_PAYER,
        "x402ServerFeePayerSecretKey": keys::secret_json(keys::X402_SERVER_FEE_PAYER_SEED),
        "rpcFixtures": {
            "recentBlockhash": keys::BLOCKHASH,
            "mints": { route.currency: { "owner": TOKEN_PROGRAM, "decimals": 6 } },
        },
    });
    if let Some(memo) = route.memo {
        input["x402ServerMemo"] = json!(memo);
    }
    for (key, value) in &spec.extra_input {
        input[*key] = value.clone();
    }
    Ok(input)
}

// ── kit drivers ────────────────────────────────────────────────────────────

pub async fn run(intent: Intent, mode: Mode, input: &Value) -> Observed {
    let result = match (intent, mode) {
        (_, Mode::CanonicalBytes) => canonical_bytes(input),
        (Intent::Charge, Mode::BuildTransaction) => match charge_build(input).await {
            Ok(transaction) => Ok(Observed::Accept(Output {
                transaction: Some(transaction),
                ..Default::default()
            })),
            Err(message) => Ok(Observed::reject(message)),
        },
        (Intent::Charge, Mode::VerifyTransaction) => charge_verify(input).await,
        (Intent::X402Exact, Mode::BuildTransaction) => x402_build(input).await,
        (Intent::X402Exact, Mode::VerifyTransaction) => x402_verify(input).await,
        (Intent::Session, Mode::VerifyTransaction) => session_verify(input).await,
        (intent, mode) => Ok(Observed::NotExpressible(format!(
            "no kit path for {} {}",
            intent.as_str(),
            mode.as_str()
        ))),
    };
    result.unwrap_or_else(|setup| Observed::NotExpressible(format!("case setup failed: {setup}")))
}

fn str_field<'a>(value: &'a Value, key: &str) -> &'a str {
    value.get(key).and_then(Value::as_str).unwrap_or("")
}

fn charge_request(input: &Value) -> Result<(ChargeRequest, MethodDetails), String> {
    let request = input.get("request").ok_or("input.request missing")?;
    let charge: ChargeRequest = serde_json::from_value(request.clone())
        .map_err(|e| format!("invalid payload: ChargeRequest: {e}"))?;
    let details: MethodDetails = match &charge.method_details {
        Some(md) => serde_json::from_value(md.clone())
            .map_err(|e| format!("invalid payload: methodDetails: {e}"))?,
        None => MethodDetails::default(),
    };
    Ok((charge, details))
}

fn signer_from(input: &Value, key: &str) -> Result<MemorySigner, String> {
    let bytes: Vec<u8> = input
        .get(key)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("input.{key} missing"))?
        .iter()
        .map(|b| b.as_u64().and_then(|b| u8::try_from(b).ok()))
        .collect::<Option<_>>()
        .ok_or_else(|| format!("input.{key} must be bytes"))?;
    MemorySigner::from_bytes(&bytes).map_err(|e| format!("invalid {key}: {e}"))
}

/// The kit's client builder against the fixture RPC. `Err` is the kit's
/// refusal message.
async fn charge_build(input: &Value) -> Result<String, String> {
    let (charge, details) = charge_request(input)?;
    let signer = signer_from(input, "signerSecretKey")?;
    let request = input.get("request").cloned().unwrap_or(Value::Null);
    let mut budget = ComputeBudgetOptions::default();
    if let Some(limit) = request.get("computeUnitLimit").and_then(Value::as_u64) {
        budget.compute_unit_limit = u32::try_from(limit).map_err(|_| "computeUnitLimit")?;
    }
    if let Some(price) = request.get("computeUnitPrice") {
        let price = price
            .as_str()
            .map(str::to_string)
            .unwrap_or_else(|| price.to_string());
        budget.compute_unit_price_micro_lamports =
            price.parse().map_err(|_| "invalid computeUnitPrice")?;
    }
    let options = BuildChargeTransactionOptions {
        external_id: charge.external_id.clone(),
        compute_budget: budget,
        ..Default::default()
    };
    let recipient = charge
        .recipient
        .clone()
        .ok_or("request.recipient missing")?;
    let fixtures = Fixtures::from_input(input)?;
    let (rpc, _log) = fixture_rpc::rpc_client(&fixtures);
    let payload = build_charge_transaction_with_options(
        &signer,
        &rpc,
        &charge.amount,
        &charge.currency,
        &recipient,
        &details,
        options,
    )
    .await
    .map_err(|e| e.to_string())?;
    match payload {
        CredentialPayload::Transaction { transaction } => Ok(transaction),
        other => Err(format!(
            "builder returned a non-transaction payload: {other:?}"
        )),
    }
}

/// The kit's charge pre-broadcast checks
/// (`mpp::server::charge::testkit::verify_transaction_pre_broadcast`): the
/// offline half of `Mpp::verify` (envelope and compute caps, fee-payer
/// isolation, the exact transfer set), with the server's default accepted
/// message versions.
async fn charge_verify(input: &Value) -> Result<Observed, String> {
    let (charge, details) = charge_request(input)?;
    let Some(transaction) = input.get("transaction").and_then(Value::as_str) else {
        return Ok(Observed::NotExpressible(
            "verify vectors must pin input.transaction".into(),
        ));
    };
    let tx = match decode_b64(transaction) {
        Ok(tx) => tx,
        Err(e) => return Ok(Observed::reject(format!("invalid payload: {e}"))),
    };
    Ok(
        match verify_transaction_pre_broadcast(
            &tx,
            &charge,
            &details,
            solana_pay_kit::core::tx::DEFAULT_ACCEPTED_VERSIONS,
        ) {
            Ok(()) => Observed::Accept(Output {
                transaction: Some(transaction.to_string()),
                ..Default::default()
            }),
            Err(error) => Observed::reject(error.message),
        },
    )
}

async fn x402_build(input: &Value) -> Result<Observed, String> {
    let offer = input.get("x402Offer").ok_or("input.x402Offer missing")?;
    let requirements: PaymentRequirements = serde_json::from_value(offer.clone())
        .map_err(|e| format!("invalid payload: x402Offer: {e}"))?;
    let signer = signer_from(input, "signerSecretKey")?;
    let (rpc, _log) = fixture_rpc::rpc_client(&Fixtures::from_input(input)?);
    let header = if input.get("x402Version").and_then(Value::as_u64) == Some(1) {
        build_payment_header_v1(&signer, &rpc, &requirements, None).await
    } else {
        let mut extensions = match PaymentExtensions::echoing(input.get("x402AdvertisedExtensions"))
        {
            Ok(extensions) => extensions,
            Err(e) => {
                return Ok(Observed::reject(format!(
                    "invalid payload: extensions: {e}"
                )))
            }
        };
        if extensions
            .as_ref()
            .is_some_and(PaymentExtensions::requires_payment_identifier)
        {
            let id = input
                .get("x402PaymentIdentifierId")
                .and_then(Value::as_str)
                .map(str::to_string)
                .unwrap_or_else(generate_payment_identifier_id);
            extensions = extensions.map(|e| e.with_payment_identifier_id(id));
        }
        build_payment_header(&signer, &rpc, &requirements, extensions, None).await
    };
    Ok(match header {
        Ok(header) => Observed::Accept(Output {
            header: Some(header),
            ..Default::default()
        }),
        Err(error) => Observed::reject(error.to_string()),
    })
}

/// The kit's x402 verifier (`X402::verify_payment_signature_for_requirements`)
/// against the route the input configures. The route's requirements are its
/// canonical `accepted` object ([`route_accepted`]) plus the mint's decimals.
async fn x402_verify(input: &Value) -> Result<Observed, String> {
    let payment_identifier = if input
        .get("x402ServerRequiresPaymentIdentifier")
        .and_then(Value::as_bool)
        == Some(true)
    {
        PaymentIdentifierPolicy::Required
    } else {
        PaymentIdentifierPolicy::NotAdvertised
    };
    let header = str_field(input, "x402PaymentHeader");
    let network = str_field(input, "x402ServerNetwork");
    let recipient = str_field(input, "x402ServerRecipient");
    let currency = str_field(input, "x402ServerCurrency");
    let amount = str_field(input, "x402ServerAmount");
    let fee_payer = str_field(input, "x402ServerFeePayer");
    let memo = input.get("x402ServerMemo").and_then(Value::as_str);
    let fixtures = Fixtures::from_input(input)?;
    let decimals = fixtures
        .mints
        .get(currency)
        .map(|m| m.decimals)
        .ok_or_else(|| format!("rpcFixtures has no mint for {currency}"))?;
    let fixture = HttpFixture::start(&fixtures).map_err(|e| e.to_string())?;
    let server = X402::new(X402Config {
        recipient: recipient.to_string(),
        currencies: vec![CurrencyConfig {
            currency: currency.to_string(),
            decimals,
            token_program: None,
        }],
        network: network.to_string(),
        rpc_url: Some(fixture.url().to_string()),
        fee_payer_key: Some(fee_payer.to_string()),
        payment_identifier,
        ..Default::default()
    })
    .map_err(|e| format!("server config: {e}"))?;
    let mut requirements: PaymentRequirements = serde_json::from_value(route_accepted(
        network, recipient, currency, amount, fee_payer, memo,
    ))
    .map_err(|e| format!("route requirements: {e}"))?;
    requirements.decimals = Some(decimals);
    Ok(
        match server
            .verify_payment_signature_for_requirements(header, &requirements)
            .await
        {
            Ok(_) => Observed::Accept(Output {
                header: Some(header.to_string()),
                ..Default::default()
            }),
            Err(error) => {
                let message = error.to_string();
                // A v2 credential names its network inside `accepted`, so a
                // v2 network mismatch is an `accepted` mismatch; v1 carries
                // the network at the top level (`wrong-network`).
                if message.starts_with("Network mismatch") && envelope_version(header) == Some(2) {
                    Observed::Reject {
                        code: Some(RejectCode::AcceptedMismatch),
                        message,
                    }
                } else {
                    Observed::reject(message)
                }
            }
        },
    )
}

fn envelope_version(header: &str) -> Option<u64> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(header)
        .ok()?;
    serde_json::from_slice::<Value>(&bytes)
        .ok()?
        .get("x402Version")?
        .as_u64()
}

async fn session_verify(input: &Value) -> Result<Observed, String> {
    let params = input
        .get("sessionVoucherVerify")
        .ok_or("input.sessionVoucherVerify missing")?;
    let signer = signer_from(input, "signerSecretKey")?;
    let number = |key: &str| -> Result<u64, String> {
        match params.get(key) {
            Some(Value::String(s)) => s.parse().map_err(|_| format!("invalid {key}")),
            Some(v) => v.as_u64().ok_or_else(|| format!("invalid {key}")),
            None => Err(format!("missing {key}")),
        }
    };
    let channel_id = str_field(params, "channelId").to_string();
    let cumulative = number("cumulativeAmount")?;
    let deposit = number("deposit")?;
    let expires_at = params.get("expiresAt").and_then(Value::as_i64).unwrap_or(0);
    let now = params
        .get("nowSeconds")
        .and_then(Value::as_i64)
        .ok_or("missing nowSeconds")?;
    let window = params
        .get("settlementWindowSeconds")
        .and_then(Value::as_i64)
        .unwrap_or(0);
    let voucher = VoucherData {
        channel_id: channel_id.clone(),
        cumulative_amount: cumulative.to_string(),
        expires_at: Some(expires_at),
    };
    let message = voucher.message_bytes().map_err(|e| e.to_string())?;
    let signature = signer
        .sign_message(&message)
        .await
        .map_err(|e| format!("sign voucher: {e}"))?;
    let store = MemoryChannelStore::new();
    store
        .put_channel(
            &channel_id,
            fresh_channel(&channel_id, &signer.pubkey().to_string(), deposit),
        )
        .await
        .map_err(|e| format!("seed channel: {e}"))?;
    Ok(
        match accept_voucher(
            &store,
            &channel_id,
            cumulative,
            expires_at,
            &signature.to_string(),
            now,
            0,
            window,
            0,
        )
        .await
        {
            Ok(_) => Observed::Accept(Output::default()),
            Err(error) => Observed::reject(error.to_string()),
        },
    )
}

fn fresh_channel(channel_id: &str, signer: &str, deposit: u64) -> ChannelState {
    ChannelState {
        channel_id: channel_id.to_string(),
        authorized_signer: signer.to_string(),
        deposit,
        cumulative: 0,
        sealed: false,
        highest_voucher_signature: None,
        highest_voucher_expires_at: None,
        close_requested_at: None,
        final_cumulative: None,
        open_slot: None,
        payer: String::new(),
        rent_payer: String::new(),
        opening_challenge_id: String::new(),
        authentication: None,
        voucher_signer: "client".to_string(),
        idle_timeout_seconds: None,
        last_activity_at: 0,
        spent_amount: 0,
        settled_on_chain: 0,
        distributed_on_chain: 0,
        processed_uses: vec![],
        processed_topup_signatures: vec![],
        next_delivery_sequence: 0,
        pending_deliveries: vec![],
        committed_deliveries: Default::default(),
        pending_setup: None,
        onchain_checked_at: 0,
        lifecycle: None,
        schema_version: CHANNEL_STATE_SCHEMA_VERSION,
        extra: Default::default(),
    }
}

/// JCS canonical JSON through the kit's own encoder (`Base64UrlJson`).
fn canonical_json(value: &Value) -> Result<(String, String), String> {
    let encoded = Base64UrlJson::from_value(value).map_err(|e| e.to_string())?;
    let bytes = base64url_decode(encoded.raw()).map_err(|e| e.to_string())?;
    let json = String::from_utf8(bytes).map_err(|e| e.to_string())?;
    Ok((json, encoded.raw().to_string()))
}

fn canonical_bytes(input: &Value) -> Result<Observed, String> {
    let mut exact = Map::new();
    let set_bytes = |exact: &mut Map<String, Value>, bytes: &[u8]| {
        exact.insert("bytes".into(), json!(bytes));
        exact.insert("base64Url".into(), json!(base64url_encode(bytes)));
    };
    if let Some(value) = input.get("value").filter(|v| !v.is_null()) {
        let (json, b64) = canonical_json(value)?;
        exact.insert("canonicalJson".into(), json!(json));
        exact.insert("base64Url".into(), json!(b64));
    }
    if let Some(enc) = input.get("encodeBase64Url") {
        if let Some(hex) = enc.get("hexBytes").and_then(Value::as_str) {
            let bytes = (0..hex.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&hex[i..i + 2], 16))
                .collect::<Result<Vec<u8>, _>>()
                .map_err(|e| format!("invalid hexBytes: {e}"))?;
            set_bytes(&mut exact, &bytes);
        } else if let Some(utf8) = enc.get("utf8").and_then(Value::as_str) {
            exact.insert("base64Url".into(), json!(base64url_encode(utf8.as_bytes())));
        }
    }
    if let Some(cid) = input.get("challengeId") {
        let opt = |k: &str| cid.get(k).and_then(Value::as_str);
        exact.insert(
            "base64Url".into(),
            json!(compute_challenge_id(
                opt("secretKey").unwrap_or(""),
                opt("realm").unwrap_or(""),
                opt("method").unwrap_or(""),
                opt("intent").unwrap_or(""),
                opt("request").unwrap_or(""),
                opt("expires"),
                opt("digest"),
                opt("opaque"),
            )),
        );
    }
    if let Some(vp) = input.get("voucherPreimage") {
        let voucher = VoucherData {
            channel_id: str_field(vp, "channelId").to_string(),
            cumulative_amount: match vp.get("cumulativeAmount") {
                Some(Value::String(s)) => s.clone(),
                Some(other) => other.to_string(),
                None => String::new(),
            },
            expires_at: vp.get("expiresAt").and_then(Value::as_i64),
        };
        match voucher.message_bytes() {
            Ok(bytes) => set_bytes(&mut exact, &bytes),
            Err(e) => return Ok(Observed::reject(format!("invalid payload: {e}"))),
        }
    }
    if let Some(sw) = input.get("sessionWire") {
        let value = sw.get("value").cloned().unwrap_or(Value::Null);
        let reencoded = match str_field(sw, "shape") {
            "request" => {
                serde_json::from_value::<SessionRequest>(value).and_then(serde_json::to_value)
            }
            "action" => {
                serde_json::from_value::<SessionAction>(value).and_then(serde_json::to_value)
            }
            other => return Err(format!("unknown sessionWire shape {other:?}")),
        };
        match reencoded {
            Ok(reencoded) => {
                let (json, b64) = canonical_json(&reencoded)?;
                exact.insert("canonicalJson".into(), json!(json));
                exact.insert("base64Url".into(), json!(b64));
            }
            Err(e) => {
                return Ok(Observed::Reject {
                    code: Some(RejectCode::InvalidPayload),
                    message: format!("invalid session payload: {e}"),
                })
            }
        }
    }
    Ok(Observed::Accept(Output {
        exact: Some(exact),
        ..Default::default()
    }))
}

// ── expectation ────────────────────────────────────────────────────────────

/// Build the `expect` block, enforcing the case's contract with the kit.
pub fn expectation(case: &Case, input: &Value, observed: &Observed) -> Result<Value, String> {
    match &case.provenance {
        Provenance::Generated => match (&case.expect, observed) {
            (Expect::Accept(pin), Observed::Accept(output)) => {
                let mut expect = json!({ "outcome": "accept" });
                let artifact = project(pin, output, input)?;
                if let Value::Object(fields) = artifact {
                    for (k, v) in fields {
                        expect[k] = v;
                    }
                }
                Ok(expect)
            }
            (Expect::Reject { code, reason }, Observed::Reject { code: got, message }) => {
                if *got != Some(*code) {
                    return Err(format!(
                        "declared reject {code} but the kit rejected as {} ({message})",
                        got.map(|c| c.as_str()).unwrap_or("<unclassified>")
                    ));
                }
                Ok(reject_json(*code, reason.as_deref()))
            }
            (Expect::AcceptAuthored(_), _) => {
                Err("a generated case cannot carry an authored artifact".into())
            }
            (expect, observed) => Err(format!(
                "declared {} but the kit observed {}",
                verdict_name(expect),
                observed.summary()
            )),
        },
        Provenance::Authored { kit_divergence } => {
            let (expect, agrees) = match &case.expect {
                Expect::AcceptAuthored(artifact) => {
                    let mut expect = json!({ "outcome": "accept" });
                    if let Value::Object(fields) = artifact {
                        for (k, v) in fields {
                            expect[k.as_str()] = v.clone();
                        }
                    }
                    let agrees = match observed {
                        Observed::Accept(output) => authored_artifact_agrees(artifact, output),
                        _ => false,
                    };
                    (expect, agrees)
                }
                Expect::Reject { code, reason } => (
                    reject_json(*code, reason.as_deref()),
                    matches!(observed, Observed::Reject { code: Some(got), .. } if got == code),
                ),
                Expect::Accept(_) => {
                    return Err(
                        "an authored accept must carry its artifact (AcceptAuthored)".into(),
                    )
                }
            };
            match (kit_divergence, agrees) {
                (None, true) | (Some(_), false) => Ok(expect),
                (None, false) => Err(format!(
                    "authored expectation {} but the kit observed {}; record a kit_divergence with the reason or fix the kit",
                    expect["outcome"],
                    observed.summary()
                )),
                (Some(reason), true) => Err(format!(
                    "the kit now agrees with the authored expectation; remove kit_divergence ({reason})"
                )),
            }
        }
    }
}

fn verdict_name(expect: &Expect) -> String {
    match expect {
        Expect::Accept(_) | Expect::AcceptAuthored(_) => "accept".into(),
        Expect::Reject { code, .. } => format!("reject {code}"),
    }
}

fn reject_json(code: RejectCode, reason: Option<&str>) -> Value {
    let mut expect = json!({ "outcome": "reject", "rejectCode": code.as_str() });
    if let Some(reason) = reason {
        expect["rejectReason"] = json!(reason);
    }
    expect
}

/// An authored accept agrees when the kit accepts and, for byte artifacts,
/// produces the same bytes.
fn authored_artifact_agrees(artifact: &Value, output: &Output) -> bool {
    match (artifact.get("exactBytes"), &output.exact) {
        (Some(Value::Object(want)), Some(got)) => want.iter().all(|(k, v)| got.get(k) == Some(v)),
        (Some(_), None) => false,
        _ => true,
    }
}

/// Project the kit's output through the case's pin.
pub fn project(pin: &Pin, output: &Output, input: &Value) -> Result<Value, String> {
    match pin {
        Pin::Outcome => Ok(json!({})),
        Pin::ExactBytes(keys) => {
            let exact = output.exact.as_ref().ok_or("kit produced no exactBytes")?;
            let mut out = Map::new();
            for key in keys {
                let value = exact
                    .get(*key)
                    .ok_or_else(|| format!("kit produced no exactBytes.{key}"))?;
                out.insert((*key).to_string(), value.clone());
            }
            Ok(json!({ "exactBytes": out }))
        }
        Pin::Envelope(keys) => {
            let header = output.header.as_ref().ok_or("kit produced no header")?;
            let shape = envelope_shape(header)?;
            let mut out = Map::new();
            for key in keys {
                let value = shape
                    .get(*key)
                    .ok_or_else(|| format!("envelope has no {key}"))?;
                out.insert((*key).to_string(), value.clone());
            }
            Ok(json!({ "x402EnvelopeShape": out }))
        }
        Pin::TransactionShape {
            fee_payer,
            transfers,
            memo,
            max_compute_unit_limit,
            forbidden_programs,
        } => {
            let tx = output
                .transaction
                .as_ref()
                .ok_or("kit produced no transaction")?;
            let shape = transaction_shape(tx, input)?;
            let mut out = Map::new();
            if *fee_payer {
                out.insert("feePayer".into(), shape["feePayer"].clone());
            }
            if !forbidden_programs.is_empty() {
                let programs = shape["programs"].as_array().cloned().unwrap_or_default();
                for forbidden in forbidden_programs {
                    if programs.iter().any(|p| p == forbidden) {
                        return Err(format!(
                            "forbidden program {forbidden} appears in the kit's transaction"
                        ));
                    }
                }
                out.insert("forbiddenPrograms".into(), json!(forbidden_programs));
            }
            if *max_compute_unit_limit {
                out.insert(
                    "maxComputeUnitLimit".into(),
                    shape
                        .get("computeUnitLimit")
                        .cloned()
                        .ok_or("transaction sets no compute unit limit")?,
                );
            }
            if *memo {
                out.insert("memo".into(), shape["memo"].clone());
            }
            if *transfers {
                out.insert("transfers".into(), shape["transfers"].clone());
            }
            Ok(json!({ "transactionShape": out }))
        }
    }
}

/// Decoded charge transaction: fee payer, programs, transfers (SPL
/// destinations resolved to the owner whose ATA they are, among the
/// request's recipient and split recipients), memos, compute budget.
pub fn transaction_shape(transaction: &str, input: &Value) -> Result<Value, String> {
    let tx = decode_b64(transaction)?;
    let keys = tx.message.static_account_keys();
    let request = input.get("request").cloned().unwrap_or(Value::Null);
    let mut owners: Vec<String> = Vec::new();
    if let Some(r) = request.get("recipient").and_then(Value::as_str) {
        owners.push(r.to_string());
    }
    for split in request
        .pointer("/methodDetails/splits")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
    {
        if let Some(r) = split.get("recipient").and_then(Value::as_str) {
            owners.push(r.to_string());
        }
    }
    let mut transfers = Vec::new();
    let mut memos = Vec::new();
    let mut programs = Vec::new();
    let mut limit = None;
    for ix in tx.message.instructions() {
        let program = keys
            .get(ix.program_id_index as usize)
            .map(|k| k.to_string())
            .unwrap_or_default();
        programs.push(json!(program));
        let account = |i: usize| -> String {
            ix.accounts
                .get(i)
                .and_then(|a| keys.get(*a as usize))
                .map(|k| k.to_string())
                .unwrap_or_default()
        };
        let data = ix.data.as_slice();
        match program.as_str() {
            keys::COMPUTE_BUDGET_PROGRAM if data.len() == 5 && data[0] == 2 => {
                limit = Some(u32::from_le_bytes(data[1..5].try_into().unwrap()));
            }
            keys::MEMO_PROGRAM => memos.push(json!(String::from_utf8_lossy(data))),
            keys::SYSTEM_PROGRAM
                if data.len() >= 12
                    && data[..4] == 2u32.to_le_bytes()
                    && ix.accounts.len() >= 2 =>
            {
                transfers.push(json!({
                    "kind": "sol",
                    "destination": account(1),
                    "amount": u64::from_le_bytes(data[4..12].try_into().unwrap()).to_string(),
                }));
            }
            TOKEN_PROGRAM | TOKEN_2022_PROGRAM
                if data.len() == 10 && data[0] == 12 && ix.accounts.len() >= 4 =>
            {
                let mint = account(1);
                let destination = account(2);
                let mut transfer = json!({
                    "kind": "spl",
                    "mint": mint,
                    "amount": u64::from_le_bytes(data[1..9].try_into().unwrap()).to_string(),
                    "decimals": data[9],
                    "tokenProgram": program,
                });
                match owners
                    .iter()
                    .find(|o| ata(o, &mint, &program).to_string() == destination)
                {
                    Some(owner) => transfer["destinationOwner"] = json!(owner),
                    None => transfer["destination"] = json!(destination),
                }
                transfers.push(transfer);
            }
            _ => {}
        }
    }
    let mut shape = json!({
        "feePayer": keys.first().map(|k| k.to_string()).unwrap_or_default(),
        "programs": programs,
        "transfers": transfers,
        "memo": memos,
    });
    if let Some(limit) = limit {
        shape["computeUnitLimit"] = json!(limit);
    }
    Ok(shape)
}

/// Decode a base64(JSON) payment header into the `X402EnvelopeShape`
/// (mirrors `decodeEnvelopeShape` in `harness/src/conformance/x402.ts`).
pub fn envelope_shape(header: &str) -> Result<Map<String, Value>, String> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(header)
        .map_err(|e| format!("header base64: {e}"))?;
    let env: Value = serde_json::from_slice(&bytes).map_err(|e| format!("header json: {e}"))?;
    let accepted = env.get("accepted").filter(|a| a.is_object());
    let transaction = env.pointer("/payload/transaction").and_then(Value::as_str);
    let mut shape = Map::new();
    shape.insert("x402Version".into(), env["x402Version"].clone());
    shape.insert("hasAccepted".into(), json!(accepted.is_some()));
    shape.insert(
        "payloadHasTransaction".into(),
        json!(transaction.is_some_and(|t| !t.is_empty())),
    );
    for key in ["scheme", "network"] {
        if let Some(v) = env.get(key) {
            shape.insert(key.into(), v.clone());
        }
    }
    if let Some(accepted) = accepted {
        for (from, to) in [
            ("scheme", "acceptedScheme"),
            ("network", "acceptedNetwork"),
            ("asset", "acceptedAsset"),
            ("payTo", "acceptedPayTo"),
            ("amount", "acceptedAmount"),
        ] {
            if let Some(v) = accepted.get(from) {
                shape.insert(to.into(), v.clone());
            }
        }
    }
    match env.get("extensions").and_then(Value::as_object) {
        Some(extensions) => {
            let mut keys: Vec<&String> = extensions.keys().collect();
            keys.sort();
            shape.insert("hasExtensions".into(), json!(!keys.is_empty()));
            shape.insert("extensionKeys".into(), json!(keys));
            let pid = extensions
                .get("payment-identifier")
                .filter(|p| p.is_object());
            shape.insert("hasPaymentIdentifier".into(), json!(pid.is_some()));
            if let Some(info) = pid.and_then(|p| p.get("info")).and_then(Value::as_object) {
                if let Some(required) = info.get("required") {
                    shape.insert("paymentIdentifierRequired".into(), required.clone());
                }
                if let Some(id) = info.get("id") {
                    shape.insert("paymentIdentifierId".into(), id.clone());
                }
            }
        }
        None => {
            shape.insert("hasExtensions".into(), json!(false));
            shape.insert("hasPaymentIdentifier".into(), json!(false));
            shape.insert("extensionKeys".into(), json!([]));
        }
    }
    Ok(shape)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::case::Provenance;

    fn base64_case() -> Case {
        crate::cases::canonical::canonical_bytes_utf8_base64url()
    }

    #[test]
    fn planted_generated_verdict_conflict_fails() {
        let mut case = base64_case();
        case.expect = Expect::Reject {
            code: RejectCode::InvalidPayload,
            reason: None,
        };
        let err = realize_blocking(&case).unwrap_err();
        assert!(err.contains("declared reject"), "{err}");
    }

    #[test]
    fn planted_authored_conflict_without_divergence_fails() {
        let mut case = base64_case();
        case.provenance = Provenance::Authored {
            kit_divergence: None,
        };
        case.expect = Expect::AcceptAuthored(
            json!({ "exactBytes": { "base64Url": "not-what-the-kit-says" } }),
        );
        let err = realize_blocking(&case).unwrap_err();
        assert!(err.contains("record a kit_divergence"), "{err}");
    }

    #[test]
    fn stale_divergence_fails_once_the_kit_agrees() {
        let mut case = base64_case();
        case.provenance = Provenance::Authored {
            kit_divergence: Some("planted".into()),
        };
        case.expect = Expect::AcceptAuthored(
            json!({ "exactBytes": { "base64Url": "bXBwLWNvbmZvcm1hbmNl" } }),
        );
        let err = realize_blocking(&case).unwrap_err();
        assert!(err.contains("remove kit_divergence"), "{err}");
    }

    #[test]
    fn operator_pairing_is_enforced() {
        let mut case = crate::cases::x402_exact::x402_exact_verify_zero_transfers_reject();
        case.expect = Expect::Reject {
            code: RejectCode::AmountMismatch,
            reason: None,
        };
        let err = realize_blocking(&case).unwrap_err();
        assert!(err.contains("is paired with"), "{err}");
    }
}
