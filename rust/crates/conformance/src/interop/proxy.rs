//! The fault proxy: every interop case routes the client adapter through it
//! to the server adapter. Testees stay honest; misbehaviour lives here.
//!
//! - [`Mode::PassThrough`]: forward and record.
//! - [`Mode::Capture`]: also keep the first credential-bearing request the
//!   server accepted, for [`replay`] (idempotent resubmit, cross-server
//!   portability; the generalisation of `harness/src/replay.ts`).
//! - [`Mode::RouteRewrite`]: present the first credential to another route
//!   (cross-route replay).
//! - [`Mode::ServerFault`]: rewrite the first credential's transaction with a
//!   `crate::mutate` operator and re-sign it with the client key the harness
//!   holds (client -> server).
//! - [`Mode::ClientFault`]: tamper with the first challenge (server ->
//!   client) and never forward a credential presented for it.
//!
//! A faulted presentation is answered with the server's response minus its
//! challenge headers and every later credential is refused, so the client
//! cannot re-pay and the proxy's record of the one faulted exchange is what
//! the case asserts.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use axum::body::{to_bytes, Body, Bytes};
use axum::extract::{Request, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use axum::response::Response;
use axum::Router;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use serde_json::{json, Value};

use crate::mutate::Mutation;

use super::claims::Intent;
use super::scenarios::{ClientFault, ServerFault};

const BODY_LIMIT: usize = 4 * 1024 * 1024;
const PAST: &str = "2000-01-01T00:00:00Z";
const DEVNET_CAIP2: &str = "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1";
const MAINNET_CAIP2: &str = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp";

/// What a fault needs to know about the case.
#[derive(Debug, Clone)]
pub struct FaultContext {
    pub intent: Intent,
    /// The client's seed, to re-sign a mutated transaction.
    pub client_seed: [u8; 32],
    pub attacker: String,
    /// The primary transfer amount in base units.
    pub amount: u64,
}

#[derive(Debug, Clone)]
pub enum Mode {
    PassThrough,
    Capture,
    RouteRewrite { from: String, to: String },
    ServerFault(ServerFault, FaultContext),
    ClientFault(ClientFault, FaultContext),
}

/// One request through the proxy.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Exchange {
    pub method: String,
    pub path: String,
    /// The request carried a payment credential.
    pub credential: bool,
    /// The proxy mutated this request or its response.
    pub faulted: bool,
    /// Forwarded to the server (false when the proxy refused it).
    pub forwarded: bool,
    pub status: u16,
    /// The response body, when JSON.
    #[serde(skip_serializing_if = "Value::is_null")]
    pub body: Value,
}

/// A request the server accepted, for [`replay`].
#[derive(Debug, Clone)]
pub struct Captured {
    pub method: Method,
    pub path: String,
    pub headers: HeaderMap,
    pub body: Bytes,
}

#[derive(Debug, Default, Clone)]
pub struct Observed {
    pub exchanges: Vec<Exchange>,
    pub captured: Option<Captured>,
    /// Set once the fault (or rewrite) has been applied.
    pub fault_applied: bool,
    /// Why the fault could not be applied, if it could not.
    pub fault_error: Option<String>,
}

impl Observed {
    pub fn faulted_exchange(&self) -> Option<&Exchange> {
        self.exchanges.iter().find(|e| e.faulted && e.credential)
    }

    /// Credential-bearing requests that arrived after a tampered challenge.
    pub fn credentials_after_fault(&self) -> Vec<&Exchange> {
        let Some(at) = self.exchanges.iter().position(|e| e.faulted) else {
            return Vec::new();
        };
        self.exchanges[at + 1..]
            .iter()
            .filter(|e| e.credential)
            .collect()
    }

    pub fn summary(&self) -> Value {
        json!({
            "faultApplied": self.fault_applied,
            "faultError": self.fault_error,
            "exchanges": self.exchanges,
        })
    }
}

struct Shared {
    upstream: String,
    mode: Mode,
    client: reqwest::Client,
    observed: Mutex<Observed>,
}

pub struct Proxy {
    pub base: String,
    shared: Arc<Shared>,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
}

impl Proxy {
    /// Bind 127.0.0.1:0 and proxy to `upstream` (`http://127.0.0.1:<port>`).
    pub fn start(rt: &tokio::runtime::Runtime, upstream: &str, mode: Mode) -> Result<Self, String> {
        let shared = Arc::new(Shared {
            upstream: upstream.trim_end_matches('/').to_string(),
            mode,
            client: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(std::time::Duration::from_secs(120))
                .build()
                .map_err(|e| e.to_string())?,
            observed: Mutex::new(Observed::default()),
        });
        let listener = rt
            .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
            .map_err(|e| format!("proxy bind: {e}"))?;
        let addr: SocketAddr = listener.local_addr().map_err(|e| e.to_string())?;
        let app = Router::new().fallback(handle).with_state(shared.clone());
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        rt.spawn(async move {
            let _ = axum::serve(listener, app)
                .with_graceful_shutdown(async {
                    let _ = rx.await;
                })
                .await;
        });
        Ok(Self {
            base: format!("http://{addr}"),
            shared,
            shutdown: Some(tx),
        })
    }

    pub fn observed(&self) -> Observed {
        self.shared.observed.lock().expect("observed").clone()
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
    }
}

fn is_credential(headers: &HeaderMap) -> bool {
    let auth = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    auth.len() > 8 && auth[..8].eq_ignore_ascii_case("payment ")
        || headers.contains_key("payment-signature")
        || headers.contains_key("x-payment")
}

fn hop_by_hop(name: &HeaderName) -> bool {
    matches!(
        name.as_str(),
        "host"
            | "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
            | "content-length"
    )
}

const CHALLENGE_HEADERS: [&str; 2] = ["www-authenticate", "payment-required"];

fn refused(reason: &str) -> (StatusCode, HeaderMap, Bytes) {
    let body = json!({"error": "pkc_fault_proxy", "message": reason}).to_string();
    let mut headers = HeaderMap::new();
    headers.insert("content-type", HeaderValue::from_static("application/json"));
    (StatusCode::PAYMENT_REQUIRED, headers, Bytes::from(body))
}

async fn forward(
    shared: &Shared,
    method: &Method,
    path: &str,
    headers: &HeaderMap,
    body: Bytes,
) -> Result<(StatusCode, HeaderMap, Bytes), String> {
    let mut req = shared
        .client
        .request(method.clone(), format!("{}{path}", shared.upstream));
    for (name, value) in headers {
        if !hop_by_hop(name) {
            req = req.header(name, value);
        }
    }
    let resp = req
        .body(body)
        .send()
        .await
        .map_err(|e| format!("upstream {path}: {e}"))?;
    let status = resp.status();
    let mut out = HeaderMap::new();
    for (name, value) in resp.headers() {
        if !hop_by_hop(name) {
            out.append(name.clone(), value.clone());
        }
    }
    let bytes = resp
        .bytes()
        .await
        .map_err(|e| format!("upstream body {path}: {e}"))?;
    Ok((status, out, bytes))
}

async fn handle(State(shared): State<Arc<Shared>>, req: Request) -> Response {
    let method = req.method().clone();
    let path = req
        .uri()
        .path_and_query()
        .map(|p| p.as_str().to_string())
        .unwrap_or_else(|| "/".into());
    let mut headers = req.headers().clone();
    let body = to_bytes(req.into_body(), BODY_LIMIT)
        .await
        .unwrap_or_default();
    let credential = is_credential(&headers);
    let applied = shared.observed.lock().expect("observed").fault_applied;

    let mut faulted = false;
    let mut forwarded = true;
    let mut target = path.clone();
    let mut strip_challenge = false;
    let mut fault_error = None;

    match (&shared.mode, credential) {
        // After a faulted presentation, nothing else is forwarded: the client
        // must not be able to re-pay.
        (Mode::RouteRewrite { .. } | Mode::ServerFault(..), true) if applied => forwarded = false,
        (Mode::ClientFault(..), true) if applied => forwarded = false,
        (Mode::RouteRewrite { from, to }, true)
            if path == *from || path.starts_with(&format!("{from}?")) =>
        {
            target = path.replacen(from.as_str(), to, 1);
            faulted = true;
            strip_challenge = true;
        }
        (Mode::ServerFault(fault, ctx), true) => match mutate_credential(&mut headers, *fault, ctx)
        {
            Ok(()) => {
                faulted = true;
                strip_challenge = true;
            }
            Err(e) => {
                fault_error = Some(e);
                forwarded = false;
            }
        },
        _ => {}
    }

    let result = if forwarded {
        forward(&shared, &method, &target, &headers, body.clone()).await
    } else {
        Ok(refused(
            fault_error
                .as_deref()
                .unwrap_or("credential refused after a faulted exchange"),
        ))
    };
    let (status, mut out_headers, mut out_body) = match result {
        Ok(r) => r,
        Err(e) => {
            let (_, h, b) = refused(&e);
            (StatusCode::BAD_GATEWAY, h, b)
        }
    };

    // Client faults tamper with the first challenge the server emits.
    if let (Mode::ClientFault(fault, ctx), false, false) = (&shared.mode, credential, applied) {
        if status == StatusCode::PAYMENT_REQUIRED {
            match mutate_challenge(&mut out_headers, &mut out_body, *fault, ctx) {
                Ok(true) => faulted = true,
                Ok(false) => {}
                Err(e) => fault_error = Some(e),
            }
        }
    }
    if strip_challenge || (!forwarded && credential) {
        for h in CHALLENGE_HEADERS {
            out_headers.remove(h);
        }
    }

    {
        let mut obs = shared.observed.lock().expect("observed");
        if faulted {
            obs.fault_applied = true;
        }
        if fault_error.is_some() && obs.fault_error.is_none() {
            obs.fault_error = fault_error;
        }
        if matches!(shared.mode, Mode::Capture)
            && credential
            && status == StatusCode::OK
            && obs.captured.is_none()
        {
            obs.captured = Some(Captured {
                method: method.clone(),
                path: path.clone(),
                headers: headers.clone(),
                body: body.clone(),
            });
        }
        obs.exchanges.push(Exchange {
            method: method.to_string(),
            path,
            credential,
            faulted,
            forwarded,
            status: status.as_u16(),
            body: serde_json::from_slice(&out_body).unwrap_or(Value::Null),
        });
    }

    let mut resp = Response::new(Body::from(std::mem::take(&mut out_body)));
    *resp.status_mut() = status;
    *resp.headers_mut() = out_headers;
    resp
}

/// Present a captured request again, to `base` (the same server or another
/// instance). Returns the status and the JSON body (if any).
pub fn replay(
    rt: &tokio::runtime::Runtime,
    captured: &Captured,
    base: &str,
) -> Result<(u16, Value), String> {
    rt.block_on(async {
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_secs(60))
            .build()
            .map_err(|e| e.to_string())?;
        let mut req = client.request(
            captured.method.clone(),
            format!("{}{}", base.trim_end_matches('/'), captured.path),
        );
        for (name, value) in &captured.headers {
            if !hop_by_hop(name) {
                req = req.header(name, value);
            }
        }
        let resp = req
            .body(captured.body.clone())
            .send()
            .await
            .map_err(|e| format!("replay: {e}"))?;
        let status = resp.status().as_u16();
        let bytes = resp.bytes().await.map_err(|e| e.to_string())?;
        Ok((
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        ))
    })
}

// ── credential mutation (client -> server) ──

fn b64url_decode(text: &str) -> Result<Vec<u8>, String> {
    URL_SAFE_NO_PAD
        .decode(text.trim().trim_end_matches('='))
        .map_err(|e| format!("base64url: {e}"))
}

fn mutation_for(fault: ServerFault, ctx: &FaultContext) -> Mutation {
    match fault {
        ServerFault::WrongAmount => Mutation::BumpAmount {
            transfer: 0,
            delta: 1 - ctx.amount as i64,
        },
        // Mutation operators take static addresses (they were written for
        // fixed vector keys); one leaked string per faulted case.
        ServerFault::WrongRecipient => Mutation::SwapRecipient {
            transfer: 0,
            owner: Box::leak(ctx.attacker.clone().into_boxed_str()),
        },
    }
}

fn mutate_transaction(b64: &str, fault: ServerFault, ctx: &FaultContext) -> Result<String, String> {
    let tx = crate::tx::decode_b64(b64)?;
    let mutated = mutation_for(fault, ctx).apply(&tx, &[ctx.client_seed])?;
    crate::tx::encode_b64(&mutated)
}

fn mutate_credential(
    headers: &mut HeaderMap,
    fault: ServerFault,
    ctx: &FaultContext,
) -> Result<(), String> {
    if ctx.intent.is_x402() {
        let name = if headers.contains_key("payment-signature") {
            "payment-signature"
        } else {
            "x-payment"
        };
        let raw = headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .ok_or("x402 payment header is not ASCII")?;
        let mut payload: Value = serde_json::from_slice(
            &STANDARD
                .decode(raw.trim())
                .map_err(|e| format!("x402 header base64: {e}"))?,
        )
        .map_err(|e| format!("x402 header JSON: {e}"))?;
        let tx = payload["payload"]["transaction"]
            .as_str()
            .ok_or("x402 payload carries no transaction")?;
        payload["payload"]["transaction"] = Value::String(mutate_transaction(tx, fault, ctx)?);
        let encoded = STANDARD.encode(payload.to_string());
        headers.insert(
            HeaderName::from_static(name),
            HeaderValue::from_str(&encoded).map_err(|e| e.to_string())?,
        );
        return Ok(());
    }
    let raw = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .ok_or("Authorization is not ASCII")?;
    let token = raw[8..].trim();
    let mut credential: Value = serde_json::from_slice(&b64url_decode(token)?)
        .map_err(|e| format!("credential JSON: {e}"))?;
    let kind = credential["payload"]["type"]
        .as_str()
        .unwrap_or("transaction");
    if kind != "transaction" {
        return Err(format!(
            "credential type {kind:?} carries no transaction to mutate"
        ));
    }
    let tx = credential["payload"]["transaction"]
        .as_str()
        .ok_or("credential carries no payload.transaction")?;
    credential["payload"]["transaction"] = Value::String(mutate_transaction(tx, fault, ctx)?);
    let encoded = format!("Payment {}", URL_SAFE_NO_PAD.encode(credential.to_string()));
    headers.insert(
        "authorization",
        HeaderValue::from_str(&encoded).map_err(|e| e.to_string())?,
    );
    Ok(())
}

// ── challenge mutation (server -> client) ──

/// Rewrite every `name="..."` auth-param in a WWW-Authenticate value.
/// Returns the new value and how many params were rewritten.
fn rewrite_param(
    header: &str,
    name: &str,
    f: &dyn Fn(&str) -> Result<String, String>,
) -> Result<(String, usize), String> {
    let mut out = String::with_capacity(header.len());
    let mut rest = header;
    let mut count = 0;
    let needle = format!("{name}=\"");
    while let Some(at) = rest.find(&needle) {
        let boundary = at == 0
            || rest[..at]
                .chars()
                .last()
                .is_some_and(|c| c == ' ' || c == ',' || c == '\t');
        let value_start = at + needle.len();
        let Some(len) = rest[value_start..].find('"') else {
            return Err(format!("unterminated {name} parameter"));
        };
        out.push_str(&rest[..value_start]);
        let value = &rest[value_start..value_start + len];
        if boundary {
            out.push_str(&f(value)?);
            count += 1;
        } else {
            out.push_str(value);
        }
        out.push('"');
        rest = &rest[value_start + len + 1..];
    }
    out.push_str(rest);
    Ok((out, count))
}

fn mutate_mpp_request(
    value: &str,
    fault: ClientFault,
    ctx: &FaultContext,
) -> Result<String, String> {
    let mut request: Value =
        serde_json::from_slice(&b64url_decode(value)?).map_err(|e| format!("request JSON: {e}"))?;
    match fault {
        ClientFault::WrongNetwork => {
            let current = request["methodDetails"]["network"]
                .as_str()
                .unwrap_or("mainnet")
                .to_string();
            let other = if current == "mainnet" {
                "devnet"
            } else {
                "mainnet"
            };
            if !request["methodDetails"].is_object() {
                request["methodDetails"] = json!({});
            }
            request["methodDetails"]["network"] = Value::String(other.into());
        }
        ClientFault::OverAskingPrice => {
            let amount: u128 = request["amount"]
                .as_str()
                .and_then(|a| a.parse().ok())
                .ok_or("challenge request has no integer amount")?;
            request["amount"] = Value::String((amount * 10_000).to_string());
        }
        ClientFault::MisSignedChallenge => {
            request["recipient"] = Value::String(ctx.attacker.clone());
        }
        ClientFault::ExpiredChallenge => unreachable!("expires is a challenge parameter"),
    }
    Ok(URL_SAFE_NO_PAD.encode(request.to_string()))
}

fn mutate_x402_required(value: &mut Value, fault: ClientFault) -> Result<bool, String> {
    let Some(accepts) = value.get_mut("accepts").and_then(Value::as_array_mut) else {
        return Ok(false);
    };
    for req in accepts {
        match fault {
            ClientFault::WrongNetwork => {
                let other = if req["network"] == MAINNET_CAIP2 {
                    DEVNET_CAIP2
                } else {
                    MAINNET_CAIP2
                };
                req["network"] = Value::String(other.into());
            }
            ClientFault::OverAskingPrice => {
                let amount: u128 = req["amount"]
                    .as_str()
                    .and_then(|a| a.parse().ok())
                    .ok_or("requirement has no integer amount")?;
                req["amount"] = Value::String((amount * 10_000).to_string());
            }
            other => return Err(format!("{other:?} is not an x402 client fault")),
        }
    }
    Ok(true)
}

fn mutate_challenge(
    headers: &mut HeaderMap,
    body: &mut Bytes,
    fault: ClientFault,
    ctx: &FaultContext,
) -> Result<bool, String> {
    if ctx.intent.is_x402() {
        let mut changed = false;
        if let Some(raw) = headers
            .get("payment-required")
            .and_then(|v| v.to_str().ok())
        {
            let mut required: Value = serde_json::from_slice(
                &STANDARD
                    .decode(raw.trim())
                    .map_err(|e| format!("PAYMENT-REQUIRED base64: {e}"))?,
            )
            .map_err(|e| format!("PAYMENT-REQUIRED JSON: {e}"))?;
            if mutate_x402_required(&mut required, fault)? {
                let encoded = STANDARD.encode(required.to_string());
                headers.insert(
                    "payment-required",
                    HeaderValue::from_str(&encoded).map_err(|e| e.to_string())?,
                );
                changed = true;
            }
        }
        if let Ok(mut json) = serde_json::from_slice::<Value>(body) {
            if mutate_x402_required(&mut json, fault)? {
                *body = Bytes::from(json.to_string());
                changed = true;
            }
        }
        return Ok(changed);
    }
    let values: Vec<String> = headers
        .get_all("www-authenticate")
        .iter()
        .filter_map(|v| v.to_str().ok().map(str::to_string))
        .collect();
    if values.is_empty() {
        return Ok(false);
    }
    let mut rewritten = Vec::new();
    let mut total = 0;
    for value in values {
        let (next, n) = match fault {
            ClientFault::ExpiredChallenge => {
                let (next, n) = rewrite_param(&value, "expires", &|_| Ok(PAST.to_string()))?;
                if n == 0 && value.trim_start().starts_with("Payment ") {
                    (format!("{value}, expires=\"{PAST}\""), 1)
                } else {
                    (next, n)
                }
            }
            other => rewrite_param(&value, "request", &|v| mutate_mpp_request(v, other, ctx))?,
        };
        total += n;
        rewritten.push(next);
    }
    headers.remove("www-authenticate");
    for v in rewritten {
        headers.append(
            "www-authenticate",
            HeaderValue::from_str(&v).map_err(|e| e.to_string())?,
        );
    }
    Ok(total > 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx() -> FaultContext {
        FaultContext {
            intent: Intent::Charge,
            client_seed: crate::keys::CLIENT_SEED,
            attacker: crate::keys::X402_OTHER_PAY_TO.into(),
            amount: 1000,
        }
    }

    fn request(json: Value) -> String {
        URL_SAFE_NO_PAD.encode(json.to_string())
    }

    fn decode_request(header: &str) -> Value {
        let at = header.find("request=\"").unwrap() + 9;
        let end = header[at..].find('"').unwrap();
        serde_json::from_slice(&b64url_decode(&header[at..at + end]).unwrap()).unwrap()
    }

    fn challenge() -> String {
        let req = request(
            json!({"amount": "1000", "currency": "sol", "recipient": "R", "methodDetails": {"network": "localnet"}}),
        );
        format!("Payment id=\"abc\", realm=\"r\", method=\"solana\", intent=\"charge\", request=\"{req}\", expires=\"2099-01-01T00:00:00Z\"")
    }

    fn mutated(fault: ClientFault) -> String {
        let mut headers = HeaderMap::new();
        headers.insert(
            "www-authenticate",
            HeaderValue::from_str(&challenge()).unwrap(),
        );
        let mut body = Bytes::new();
        assert!(mutate_challenge(&mut headers, &mut body, fault, &ctx()).unwrap());
        headers["www-authenticate"].to_str().unwrap().to_string()
    }

    #[test]
    fn client_faults_rewrite_only_their_field_and_keep_the_id() {
        let expired = mutated(ClientFault::ExpiredChallenge);
        assert!(
            expired.contains(&format!("expires=\"{PAST}\"")),
            "{expired}"
        );
        assert!(expired.contains("id=\"abc\""));
        assert_eq!(decode_request(&expired)["amount"], "1000");
        let network = mutated(ClientFault::WrongNetwork);
        assert_eq!(
            decode_request(&network)["methodDetails"]["network"],
            "mainnet"
        );
        let price = mutated(ClientFault::OverAskingPrice);
        assert_eq!(decode_request(&price)["amount"], "10000000");
        let signed = mutated(ClientFault::MisSignedChallenge);
        assert_eq!(
            decode_request(&signed)["recipient"],
            crate::keys::X402_OTHER_PAY_TO
        );
        assert!(signed.contains("id=\"abc\""));
    }

    #[test]
    fn rewrite_param_matches_whole_parameter_names_only() {
        let (out, n) = rewrite_param("Payment xrequest=\"a\", request=\"b\"", "request", &|_| {
            Ok("c".into())
        })
        .unwrap();
        assert_eq!(n, 1);
        assert_eq!(out, "Payment xrequest=\"a\", request=\"c\"");
    }

    #[test]
    fn x402_wrong_network_flips_every_requirement() {
        let mut required =
            json!({"x402Version": 2, "accepts": [{"network": DEVNET_CAIP2, "amount": "1000"}]});
        assert!(mutate_x402_required(&mut required, ClientFault::WrongNetwork).unwrap());
        assert_eq!(required["accepts"][0]["network"], MAINNET_CAIP2);
    }

    #[test]
    fn server_fault_rewrites_and_re_signs_the_credential_transaction() {
        let tx = crate::tx::x402_static_layout(&crate::tx::StaticLayout {
            fee_payer: crate::keys::X402_SERVER_FEE_PAYER,
            mint: crate::keys::MINT,
            pay_to: crate::keys::X402_PAY_TO,
            amount: 1000,
            decimals: 6,
            memo: "0123456789abcdef0123456789abcdef",
        })
        .unwrap();
        let b64 = crate::tx::encode_b64(&tx).unwrap();
        let credential = json!({"challenge": {"id": "abc"}, "payload": {"type": "transaction", "transaction": b64}});
        let mut headers = HeaderMap::new();
        headers.insert(
            "authorization",
            HeaderValue::from_str(&format!(
                "Payment {}",
                URL_SAFE_NO_PAD.encode(credential.to_string())
            ))
            .unwrap(),
        );
        mutate_credential(&mut headers, ServerFault::WrongAmount, &ctx()).unwrap();
        let token = headers["authorization"].to_str().unwrap()[8..].to_string();
        let out: Value = serde_json::from_slice(&b64url_decode(&token).unwrap()).unwrap();
        assert_eq!(out["challenge"]["id"], "abc");
        let mutated =
            crate::tx::decode_b64(out["payload"]["transaction"].as_str().unwrap()).unwrap();
        assert_ne!(mutated.message, tx.message);
        // The client slot carries a valid signature over the new message.
        let client = crate::keys::pubkey_of_seed(crate::keys::CLIENT_SEED);
        let index = mutated
            .message
            .static_account_keys()
            .iter()
            .position(|k| *k == client)
            .unwrap();
        assert!(mutated.signatures[index].verify(client.as_ref(), &mutated.message.serialize()));
    }

    /// A fake server: 402 with a challenge without a credential, 200 with
    /// one on `/cheap`, 402 `charge_request_mismatch` with one elsewhere.
    async fn upstream(req: Request) -> Response {
        let paid = is_credential(req.headers());
        let path = req.uri().path().to_string();
        let (status, body) = match (paid, path.as_str()) {
            (false, _) => (
                StatusCode::PAYMENT_REQUIRED,
                json!({"error": "payment_required"}),
            ),
            (true, "/cheap") => (StatusCode::OK, json!({"ok": true, "paid": true})),
            (true, _) => (
                StatusCode::PAYMENT_REQUIRED,
                json!({"code": "charge_request_mismatch"}),
            ),
        };
        let mut resp = Response::new(Body::from(body.to_string()));
        *resp.status_mut() = status;
        if !paid {
            resp.headers_mut().insert(
                "www-authenticate",
                HeaderValue::from_str(&challenge()).unwrap(),
            );
        }
        resp
    }

    fn serve(rt: &tokio::runtime::Runtime) -> String {
        let listener = rt
            .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
            .unwrap();
        let addr = listener.local_addr().unwrap();
        rt.spawn(async move {
            axum::serve(listener, Router::new().fallback(upstream))
                .await
                .unwrap();
        });
        format!("http://{addr}")
    }

    fn get(rt: &tokio::runtime::Runtime, url: &str, credential: bool) -> (u16, bool) {
        rt.block_on(async {
            let mut req = reqwest::Client::new().get(url);
            if credential {
                req = req.header("authorization", "Payment eyJ9");
            }
            let resp = req.send().await.unwrap();
            (
                resp.status().as_u16(),
                resp.headers().contains_key("www-authenticate"),
            )
        })
    }

    #[test]
    fn route_rewrite_presents_one_credential_elsewhere_and_refuses_the_rest() {
        let rt = crate::run::driver::runtime();
        let up = serve(&rt);
        let proxy = Proxy::start(
            &rt,
            &up,
            Mode::RouteRewrite {
                from: "/cheap".into(),
                to: "/expensive".into(),
            },
        )
        .unwrap();
        assert_eq!(
            get(&rt, &format!("{}/cheap", proxy.base), false),
            (402, true)
        );
        // The rewritten presentation reaches /expensive; its challenge is stripped.
        assert_eq!(
            get(&rt, &format!("{}/cheap", proxy.base), true),
            (402, false)
        );
        // A re-payment is not forwarded (control: unproxied it would be 200).
        assert_eq!(
            get(&rt, &format!("{}/cheap", proxy.base), true),
            (402, false)
        );
        assert_eq!(get(&rt, &format!("{up}/cheap"), true).0, 200);
        let obs = proxy.observed();
        let faulted = obs.faulted_exchange().unwrap();
        assert_eq!(faulted.body["code"], "charge_request_mismatch");
        assert!(!obs.exchanges[2].forwarded);
    }

    #[test]
    fn capture_keeps_the_accepted_request_for_replay() {
        let rt = crate::run::driver::runtime();
        let up = serve(&rt);
        let proxy = Proxy::start(&rt, &up, Mode::Capture).unwrap();
        assert_eq!(get(&rt, &format!("{}/cheap", proxy.base), true).0, 200);
        let captured = proxy.observed().captured.unwrap();
        assert_eq!(captured.path, "/cheap");
        assert_eq!(replay(&rt, &captured, &up).unwrap().0, 200);
    }

    #[test]
    fn a_client_fault_never_forwards_a_credential_for_the_tampered_challenge() {
        let rt = crate::run::driver::runtime();
        let up = serve(&rt);
        let proxy = Proxy::start(
            &rt,
            &up,
            Mode::ClientFault(ClientFault::ExpiredChallenge, ctx()),
        )
        .unwrap();
        assert_eq!(
            get(&rt, &format!("{}/cheap", proxy.base), false),
            (402, true)
        );
        assert_eq!(get(&rt, &format!("{}/cheap", proxy.base), true).0, 402);
        let obs = proxy.observed();
        assert!(obs.fault_applied);
        assert_eq!(obs.credentials_after_fault().len(), 1);
        assert!(!obs.exchanges[1].forwarded);
    }
}
