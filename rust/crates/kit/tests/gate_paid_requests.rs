//! Unified axum gate behavior on paid (credentialed) requests, driven through
//! the public `paid_get` interface with x402 exact credentials settled against
//! a local mock RPC.

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use axum::response::Response;
use axum::routing::post;
use axum::Router;
use solana_pay_kit::core::tx::{TxV1Mode, TxVersion};
use solana_pay_kit::solana_keychain::{MemorySigner, TransactionSigner};
use solana_pay_kit::x402::client::exact::{build_payment_header, parse_x402_challenge};
use solana_pay_kit::x402::solana_rpc_client::rpc_client::RpcClient;
use solana_pay_kit::x402::{PAYMENT_REQUIRED_HEADER, PAYMENT_SIGNATURE_HEADER};
use solana_pay_kit::{paid_get, PayKit, PayKitConfig, Payment};
use std::sync::{Arc, OnceLock};
use tower::ServiceExt;

const RECIPIENT: &str = "11111111111111111111111111111111";
const SECRET: &str = "gate-paid-requests-test-secret-32-bytes";
const ZERO_BLOCKHASH: &str = "11111111111111111111111111111111";

/// JSON-RPC node that confirms every broadcast, so the gate can settle.
fn mock_rpc_url() -> &'static str {
    static URL: OnceLock<String> = OnceLock::new();
    URL.get_or_init(|| {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async move {
                let app = Router::new().route("/", post(mock_rpc));
                let listener = tokio::net::TcpListener::from_std(listener).unwrap();
                axum::serve(listener, app).await.unwrap();
            });
        });
        url
    })
}

async fn mock_rpc(
    axum::Json(body): axum::Json<serde_json::Value>,
) -> axum::Json<serde_json::Value> {
    let result = match body["method"].as_str().unwrap_or_default() {
        "sendTransaction" => {
            let tx = solana_pay_kit::core::tx::decode(body["params"][0].as_str().unwrap()).unwrap();
            serde_json::json!(tx.signatures[0].to_string())
        }
        "getSignatureStatuses" => serde_json::json!({
            "context": {"slot": 1},
            "value": [{
                "slot": 1,
                "confirmations": null,
                "err": null,
                "status": {"Ok": null},
                "confirmationStatus": "confirmed"
            }]
        }),
        "getLatestBlockhash" => serde_json::json!({
            "context": {"slot": 1},
            "value": {"blockhash": ZERO_BLOCKHASH, "lastValidBlockHeight": 100}
        }),
        _ => {
            return axum::Json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": body["id"],
                "error": {"code": -32601, "message": "method not found"}
            }))
        }
    };
    axum::Json(serde_json::json!({"jsonrpc": "2.0", "id": body["id"], "result": result}))
}

fn keypair_signer(seed: u8) -> MemorySigner {
    let signing = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
    let mut keypair = [0u8; 64];
    keypair[..32].copy_from_slice(signing.as_bytes());
    keypair[32..].copy_from_slice(signing.verifying_key().as_bytes());
    MemorySigner::from_bytes(&keypair).unwrap()
}

fn paykit() -> PayKit {
    let fee_payer: Arc<dyn TransactionSigner> = Arc::new(keypair_signer(11));
    PayKit::new(PayKitConfig {
        recipient: RECIPIENT.to_string(),
        network: "localnet".to_string(),
        rpc_url: Some(mock_rpc_url().to_string()),
        fee_payer_signer: Some(fee_payer),
        challenge_binding_secret: Some(SECRET.to_string()),
        realm: Some("gate-paid-requests".to_string()),
        store: Some(Arc::new(solana_pay_kit::mpp::store::MemoryStore::new())),
        tx_v1: TxV1Mode::Off,
        disable_hint: true,
        ..Default::default()
    })
    .expect("valid local-only gate configuration")
}

/// An RPC that only vouches for the pinned blockhash; every other call fails.
fn offline_rpc() -> RpcClient {
    RpcClient::new_mock_with_mocks(
        "fails".to_string(),
        [(
            solana_rpc_client_api::request::RpcRequest::IsBlockhashValid,
            serde_json::json!({ "context": { "slot": 1 }, "value": true }),
        )]
        .into_iter()
        .collect(),
    )
}

fn payer() -> MemorySigner {
    keypair_signer(42)
}

/// The 402 for `uri`, as the x402 base-unit amount it advertises.
async fn advertised_amount(app: &Router, uri: &str) -> (StatusCode, Option<String>) {
    let resp = app
        .clone()
        .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let amount = resp.headers().get(PAYMENT_REQUIRED_HEADER).map(|value| {
        parse_x402_challenge(
            &[(
                PAYMENT_REQUIRED_HEADER.to_string(),
                value.to_str().unwrap().to_string(),
            )],
            None,
        )
        .expect("x402 requirement")
        .amount
    });
    (status, amount)
}

/// Fetch the challenge for `uri`, pay it, and return the paid response.
async fn pay_and_fetch(app: &Router, uri: &str) -> Response {
    let challenge = app
        .clone()
        .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(challenge.status(), StatusCode::PAYMENT_REQUIRED);
    let required = challenge
        .headers()
        .get(PAYMENT_REQUIRED_HEADER)
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    let mut requirements =
        parse_x402_challenge(&[(PAYMENT_REQUIRED_HEADER.to_string(), required)], None).unwrap();
    requirements.recent_blockhash = Some(ZERO_BLOCKHASH.to_string());
    let rpc = offline_rpc();
    let payment = build_payment_header(&payer(), &rpc, &requirements, None, Some(TxVersion::V0))
        .await
        .unwrap();
    app.clone()
        .oneshot(
            Request::builder()
                .uri(uri)
                .header(PAYMENT_SIGNATURE_HEADER, payment)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
}

fn cache_control(resp: &Response) -> Option<String> {
    resp.headers()
        .get(header::CACHE_CONTROL)
        .map(|value| value.to_str().unwrap().to_string())
}

async fn protected(_payment: Payment) -> &'static str {
    "protected"
}

#[tokio::test(flavor = "multi_thread")]
async fn paid_response_is_not_shared_cacheable() {
    let app: Router = Router::new().route("/secret", paid_get(protected, "0.01", &paykit()));
    let resp = pay_and_fetch(&app, "/secret").await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(cache_control(&resp).as_deref(), Some("private, no-store"));
}

#[tokio::test(flavor = "multi_thread")]
async fn paid_response_overrides_a_public_handler_cache_policy() {
    let app: Router = Router::new().route(
        "/secret",
        paid_get(
            |_payment: Payment| async {
                (
                    [(header::CACHE_CONTROL, "public, max-age=600")],
                    "protected",
                )
            },
            "0.01",
            &paykit(),
        ),
    );
    let resp = pay_and_fetch(&app, "/secret").await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(cache_control(&resp).as_deref(), Some("private, no-store"));
}

#[tokio::test(flavor = "multi_thread")]
async fn paid_response_keeps_a_restrictive_handler_cache_policy() {
    let app: Router = Router::new().route(
        "/secret",
        paid_get(
            |_payment: Payment| async {
                (
                    [(header::CACHE_CONTROL, "Private, max-age=60")],
                    "protected",
                )
            },
            "0.01",
            &paykit(),
        ),
    );
    let resp = pay_and_fetch(&app, "/secret").await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(cache_control(&resp).as_deref(), Some("Private, max-age=60"));
}

#[tokio::test(flavor = "multi_thread")]
async fn unpaid_request_advertises_the_route_price() {
    let app: Router = Router::new().route("/secret", paid_get(protected, "0.01", &paykit()));
    assert_eq!(
        advertised_amount(&app, "/secret").await,
        (StatusCode::PAYMENT_REQUIRED, Some("10000".to_string()))
    );
}

fn external_path_price() -> solana_pay_kit::Price {
    solana_pay_kit::Price::dynamic(|ctx| {
        if ctx.uri.path() == "/api/premium" {
            "5.00".to_string()
        } else {
            "0.10".to_string()
        }
    })
}

#[tokio::test(flavor = "multi_thread")]
async fn nested_route_prices_from_the_public_path() {
    let pay = paykit();
    let nested: Router = Router::new().nest(
        "/api",
        Router::new().route("/premium", paid_get(protected, external_path_price(), &pay)),
    );
    let direct: Router = Router::new().route(
        "/api/premium",
        paid_get(protected, external_path_price(), &pay),
    );
    let premium = (StatusCode::PAYMENT_REQUIRED, Some("5000000".to_string()));
    assert_eq!(advertised_amount(&direct, "/api/premium").await, premium);
    assert_eq!(advertised_amount(&nested, "/api/premium").await, premium);
}

#[tokio::test(flavor = "multi_thread")]
async fn nested_route_query_pricing_sees_the_public_query() {
    let pay = paykit();
    let nested: Router = Router::new().nest(
        "/v1",
        Router::new().route(
            "/quote",
            paid_get(
                protected,
                solana_pay_kit::Price::dynamic(|ctx| match ctx.query_param("tier").as_deref() {
                    Some("premium") => "5.00".to_string(),
                    _ => "0.10".to_string(),
                }),
                &pay,
            ),
        ),
    );
    assert_eq!(
        advertised_amount(&nested, "/v1/quote?tier=premium").await,
        (StatusCode::PAYMENT_REQUIRED, Some("5000000".to_string()))
    );
    assert_eq!(
        advertised_amount(&nested, "/v1/quote").await,
        (StatusCode::PAYMENT_REQUIRED, Some("100000".to_string()))
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn nested_paid_request_is_charged_the_public_path_price() {
    let pay = paykit();
    let nested: Router = Router::new().nest(
        "/api",
        Router::new().route(
            "/premium",
            paid_get(
                |payment: Payment| async move { payment.amount },
                external_path_price(),
                &pay,
            ),
        ),
    );
    let resp = pay_and_fetch(&nested, "/api/premium").await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
    assert_eq!(body.as_ref(), b"5.00");
}

fn tier_price() -> solana_pay_kit::Price {
    solana_pay_kit::Price::dynamic(|ctx| match ctx.query_param("tier").as_deref() {
        Some("premium") => "5.00".to_string(),
        _ => "0.10".to_string(),
    })
}

async fn tiered(
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
    payment: Payment,
) -> String {
    format!("{} at {}", params["tier"], payment.amount)
}

#[tokio::test(flavor = "multi_thread")]
async fn duplicate_price_query_key_is_rejected_before_pricing() {
    let app: Router = Router::new().route("/quote", paid_get(tiered, tier_price(), &paykit()));
    for uri in [
        "/quote?tier=basic&tier=premium",
        "/quote?tier=premium&tier=basic",
        "/quote?tier=basic&%74ier=premium",
    ] {
        assert_eq!(
            advertised_amount(&app, uri).await,
            (StatusCode::BAD_REQUEST, None),
            "{uri}"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn duplicate_query_key_with_a_credential_never_reaches_the_handler() {
    let app: Router = Router::new().route("/quote", paid_get(tiered, tier_price(), &paykit()));
    // A credential for the basic price must not unlock a premium-reading handler.
    let basic = pay_and_fetch(&app, "/quote?tier=basic").await;
    assert_eq!(basic.status(), StatusCode::OK);
    let header = {
        let challenge = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/quote?tier=basic")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let required = challenge.headers()[PAYMENT_REQUIRED_HEADER]
            .to_str()
            .unwrap()
            .to_owned();
        let mut requirements =
            parse_x402_challenge(&[(PAYMENT_REQUIRED_HEADER.to_string(), required)], None).unwrap();
        requirements.recent_blockhash = Some(ZERO_BLOCKHASH.to_string());
        build_payment_header(
            &payer(),
            &offline_rpc(),
            &requirements,
            None,
            Some(TxVersion::V0),
        )
        .await
        .unwrap()
    };
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/quote?tier=basic&tier=premium")
                .header(PAYMENT_SIGNATURE_HEADER, header)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test(flavor = "multi_thread")]
async fn single_valued_premium_query_is_charged_the_premium_price() {
    let app: Router = Router::new().route("/quote", paid_get(tiered, tier_price(), &paykit()));
    let resp = pay_and_fetch(&app, "/quote?tier=premium&other=1").await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
    assert_eq!(body.as_ref(), b"premium at 5.00");
}
