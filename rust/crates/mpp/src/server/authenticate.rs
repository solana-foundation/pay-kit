//! Server-side handler for the `authenticate` intent — a SIWS-style
//! identity proof that binds subsequent HTTP requests to a wallet
//! within a server-defined validity window, without re-signing or
//! re-paying per request.
//!
//! The server emits a 402 challenge carrying the SIWS fields the
//! client must sign. The client signs once, caches the credential,
//! and reuses it on every request until `expirationTime`. The server
//! verifies each request statelessly: ed25519 signature + HMAC nonce
//! integrity + resource-binding match. Cancellation is honoured
//! implicitly because `expirationTime` is pinned to the current
//! billing-period end, matching on-chain cancellation semantics.

use std::sync::Arc;

use crate::error::Error;
use crate::expires;
use crate::program::subscriptions::find_subscription_pda;
use crate::protocol::core::{
    base64url_encode, compute_challenge_id, Base64UrlJson, PaymentChallenge, PaymentCredential,
};
use crate::protocol::intents::{
    AuthenticateMethodDetails, AuthenticatePayload, AuthenticateRequest,
    RESOURCE_SCHEME_SOLANA_SUBSCRIPTION, SIGNATURE_SCHEME_SIWMPP, SIGNATURE_TYPE_ED25519,
    SIWMPP_VERSION,
};
use crate::store::{MemoryStore, Store};
use solana_pubkey::Pubkey;

const METHOD_NAME: &str = "solana";
const INTENT_NAME: &str = "authenticate";

/// Allowance applied to `expirationTime` checks. Servers and clients
/// disagree on the wall clock by up to a minute in practice; a 60s
/// window keeps the common case from spuriously rejecting tokens
/// without unduly extending their lifetime.
const CLOCK_SKEW_TOLERANCE_SECS: i64 = 60;

/// Reasons an authenticate credential can fail verification.
///
/// Servers translate variants into the wire-level 402 / 401 response
/// they prefer; each variant is a distinct failure mode for
/// telemetry / structured logging.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyError {
    /// HMAC over the challenge id (Tier 1) didn't match. Either the
    /// server didn't issue this challenge or the client tampered with
    /// it.
    ChallengeIdMismatch,
    /// `method` / `intent` / `realm` didn't match the configured server.
    PinnedFieldMismatch(&'static str),
    /// `nonce` did not equal the deterministic HMAC the server would
    /// have issued for this `(plan_id, expiration_time)` tuple.
    NonceMismatch,
    /// Token expired (or its `notBefore` hasn't been reached).
    OutsideValidityWindow,
    /// The signed payload was malformed (missing required fields,
    /// non-utf8, etc.).
    MalformedPayload(String),
    /// The `signature` did not verify against the canonical SIWS
    /// message bytes and `address`.
    SignatureInvalid,
    /// The token's `resources` did not include the
    /// `solana-subscription:<pda>` the server expects for the
    /// `(plan, address)` tuple, OR the named PDA does not derive
    /// from `(plan, address)`.
    ResourceMismatch,
    /// Some other internal failure (HMAC setup, base64, etc.).
    Internal(String),
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ChallengeIdMismatch => write!(f, "challenge id HMAC mismatch"),
            Self::PinnedFieldMismatch(name) => {
                write!(f, "credential `{name}` does not match server config")
            }
            Self::NonceMismatch => write!(f, "nonce does not match server-issued HMAC"),
            Self::OutsideValidityWindow => write!(f, "credential outside validity window"),
            Self::MalformedPayload(reason) => write!(f, "malformed credential payload: {reason}"),
            Self::SignatureInvalid => write!(f, "ed25519 signature did not verify"),
            Self::ResourceMismatch => write!(f, "resource binding does not match"),
            Self::Internal(reason) => write!(f, "internal error: {reason}"),
        }
    }
}

impl std::error::Error for VerifyError {}

/// Configuration for the authenticate server handler.
#[derive(Clone)]
pub struct AuthenticateConfig {
    /// Domain the server is gating — pinned in the signed payload.
    pub domain: String,
    /// Canonical origin URI of the gated resource.
    pub uri: String,
    /// Base58 of the plan's PDA. The verifier requires the credential's
    /// `resources` to bind to `find_subscription_pda(plan_id, address)`.
    pub plan_id: String,
    /// Plan anchor (`Plan.created_at` from on-chain). Used to compute
    /// the current billing-period end so the issued `expirationTime`
    /// matches what the on-chain delegation will honour for renewals.
    pub plan_created_at: i64,
    /// Plan's `period_hours` (1..=8760). Combined with `plan_created_at`
    /// to derive the current period's end timestamp.
    pub period_hours: u64,
    /// MPP network slug (`"mainnet"`, `"devnet"`, `"testnet"`,
    /// `"localnet"`). Pinned into the signed message and the
    /// `methodDetails.network` field of the emitted challenge.
    pub network: String,
    /// Subscriptions program ID. Defaults to the canonical mainnet
    /// deployment.
    pub program_id: Option<String>,
    /// HMAC secret. REQUIRED — the SDK refuses to fall back to env-var
    /// lookups so misconfigured deployments fail at boot instead of
    /// silently using whatever happened to be in the process env.
    pub challenge_binding_secret: String,
    /// 402 realm string. REQUIRED — the operator picks an explicit
    /// value rather than inheriting an SDK-side default that's
    /// invisible at config-review time.
    pub realm: String,
    /// Optional human-readable statement embedded in the challenge.
    pub statement: Option<String>,
    /// Optional replay store (currently unused — verify is stateless).
    pub store: Option<Arc<dyn Store>>,
}

/// Server-side handler for the authenticate intent.
#[derive(Clone)]
pub struct AuthenticateServer {
    config: AuthenticateConfig,
    program_id: String,
    challenge_binding_secret: String,
    realm: String,
    #[allow(dead_code)]
    store: Arc<dyn Store>,
}

impl AuthenticateServer {
    /// Build a handler. Validates config eagerly — missing required
    /// fields fail at boot rather than at challenge-emit time.
    pub fn new(config: AuthenticateConfig) -> Result<Self, Error> {
        if config.domain.is_empty() {
            return Err(Error::InvalidConfig("domain is required".into()));
        }
        if config.uri.is_empty() {
            return Err(Error::InvalidConfig("uri is required".into()));
        }
        if config.plan_id.is_empty() {
            return Err(Error::InvalidConfig("plan_id is required".into()));
        }
        if config.challenge_binding_secret.is_empty() {
            return Err(Error::InvalidConfig(
                "challenge_binding_secret is required".into(),
            ));
        }
        if config.realm.is_empty() {
            return Err(Error::InvalidConfig("realm is required".into()));
        }
        if config.network.is_empty() {
            return Err(Error::InvalidConfig("network is required".into()));
        }
        if config.period_hours == 0 || config.period_hours > 8760 {
            return Err(Error::InvalidConfig(
                "period_hours must be in [1, 8760]".into(),
            ));
        }
        let _ = Pubkey::try_from(config.plan_id.as_str())
            .map_err(|e| Error::InvalidConfig(format!("invalid plan_id: {e}")))?;

        let program_id = config
            .program_id
            .clone()
            .unwrap_or_else(|| crate::program::subscriptions::SUBSCRIPTIONS_PROGRAM_ID.to_string());
        let _ = Pubkey::try_from(program_id.as_str())
            .map_err(|e| Error::InvalidConfig(format!("invalid program_id: {e}")))?;

        let challenge_binding_secret = config.challenge_binding_secret.clone();
        let realm = config.realm.clone();
        let store = config
            .store
            .clone()
            .unwrap_or_else(|| Arc::new(MemoryStore::new()));

        Ok(Self {
            config,
            program_id,
            challenge_binding_secret,
            realm,
            store,
        })
    }

    /// Emit a 402 `authenticate` challenge.
    ///
    /// Sets `expirationTime` to the end of the current billing period
    /// derived from `(plan_created_at, period_hours, now)`. The `nonce`
    /// is a deterministic HMAC over `(realm, plan_id, expirationTime)`
    /// so the server can re-derive it at verify time without server-
    /// side state.
    pub fn challenge(&self) -> Result<PaymentChallenge, Error> {
        self.challenge_at(now_unix_secs())
    }

    /// Test-friendly variant of [`Self::challenge`] that takes the
    /// "current time" explicitly. Production code should call
    /// [`Self::challenge`].
    pub fn challenge_at(&self, now_secs: i64) -> Result<PaymentChallenge, Error> {
        let issued_at = format_rfc3339_seconds(now_secs);
        let expiration_secs = current_period_end_secs(
            self.config.plan_created_at,
            self.config.period_hours,
            now_secs,
        );
        let expiration_time = format_rfc3339_seconds(expiration_secs);
        let nonce = self.compute_nonce(&expiration_time);

        let request = AuthenticateRequest {
            domain: self.config.domain.clone(),
            uri: self.config.uri.clone(),
            version: SIWMPP_VERSION.into(),
            nonce,
            issued_at,
            expiration_time,
            not_before: None,
            statement: self.config.statement.clone(),
            request_id: None,
            // resources is intentionally empty — we don't know the
            // signer yet at challenge-emit time. The client fills it in
            // with `solana-subscription:<find_subscription_pda(plan, signer)>`
            // and we verify the derivation at verify time. Anonymous
            // emission is fine because forging the resource binding
            // requires a wallet key that derives to a real PDA.
            resources: Vec::new(),
            method_details: Some(AuthenticateMethodDetails::for_network(&self.config.network)),
        };

        let encoded = Base64UrlJson::from_typed(&request)
            .map_err(|e| Error::Other(format!("encode authenticate request: {e}")))?;
        let default_expires = expires::minutes(5);

        Ok(PaymentChallenge::with_challenge_binding_secret_full(
            &self.challenge_binding_secret,
            &self.realm,
            METHOD_NAME,
            INTENT_NAME,
            encoded,
            Some(&default_expires),
            None,
            self.config.statement.as_deref(),
            None,
        ))
    }

    /// Verify an `authenticate` credential.
    ///
    /// On success returns the proven subscriber `Pubkey`. Servers
    /// route the request upstream after this check; no payment moves.
    pub fn verify(&self, credential: &PaymentCredential) -> Result<Pubkey, VerifyError> {
        self.verify_at(credential, now_unix_secs())
    }

    /// Test-friendly variant of [`Self::verify`].
    pub fn verify_at(
        &self,
        credential: &PaymentCredential,
        now_secs: i64,
    ) -> Result<Pubkey, VerifyError> {
        // Tier 1: HMAC over the challenge id — the server must have
        // issued this exact challenge.
        let expected_id = compute_challenge_id(
            &self.challenge_binding_secret,
            &self.realm,
            credential.challenge.method.as_str(),
            credential.challenge.intent.as_str(),
            credential.challenge.request.raw(),
            credential.challenge.expires.as_deref(),
            credential.challenge.digest.as_deref(),
            credential.challenge.opaque.as_ref().map(|o| o.raw()),
        );
        if credential.challenge.id != expected_id {
            return Err(VerifyError::ChallengeIdMismatch);
        }

        // Tier 2: pinned fields.
        if credential.challenge.method.as_str() != METHOD_NAME {
            return Err(VerifyError::PinnedFieldMismatch("method"));
        }
        if credential.challenge.intent.as_str() != INTENT_NAME {
            return Err(VerifyError::PinnedFieldMismatch("intent"));
        }
        if credential.challenge.realm != self.realm {
            return Err(VerifyError::PinnedFieldMismatch("realm"));
        }

        // Decode the challenge request (server-issued fields).
        let request: AuthenticateRequest = credential
            .challenge
            .request
            .decode()
            .map_err(|e| VerifyError::MalformedPayload(format!("request: {e}")))?;

        // Decode the credential payload (signed by the client).
        let payload: AuthenticatePayload = serde_json::from_value(credential.payload.clone())
            .map_err(|e| VerifyError::MalformedPayload(format!("payload: {e}")))?;

        // Echo checks — payload fields must equal challenge fields where
        // applicable. We don't enforce every field strict-equal (the
        // signer fills in `address`, `network`, `signatureType`,
        // `signatureScheme`, `signature`, and `resources`) but the
        // server-pinned bits must match.
        if payload.domain != request.domain {
            return Err(VerifyError::PinnedFieldMismatch("domain"));
        }
        if payload.uri != request.uri {
            return Err(VerifyError::PinnedFieldMismatch("uri"));
        }
        if payload.version != request.version {
            return Err(VerifyError::PinnedFieldMismatch("version"));
        }
        if payload.nonce != request.nonce {
            return Err(VerifyError::PinnedFieldMismatch("nonce"));
        }
        if payload.issued_at != request.issued_at {
            return Err(VerifyError::PinnedFieldMismatch("issuedAt"));
        }
        if payload.expiration_time != request.expiration_time {
            return Err(VerifyError::PinnedFieldMismatch("expirationTime"));
        }
        // The client picks `network` but it MUST match the network
        // this server is configured for — otherwise the token could be
        // replayed against an authenticate-server on a different chain.
        if payload.network != self.config.network {
            return Err(VerifyError::PinnedFieldMismatch("network"));
        }

        // Validity window check using the credential's
        // expirationTime + the server's known-good period bounds.
        let expiration_secs = parse_rfc3339_seconds(&payload.expiration_time)
            .map_err(|e| VerifyError::MalformedPayload(format!("expirationTime: {e}")))?;
        if now_secs >= expiration_secs + CLOCK_SKEW_TOLERANCE_SECS {
            return Err(VerifyError::OutsideValidityWindow);
        }
        if let Some(nb) = payload.not_before.as_deref() {
            let nb_secs = parse_rfc3339_seconds(nb)
                .map_err(|e| VerifyError::MalformedPayload(format!("notBefore: {e}")))?;
            if now_secs + CLOCK_SKEW_TOLERANCE_SECS < nb_secs {
                return Err(VerifyError::OutsideValidityWindow);
            }
        }

        // expirationTime MUST NOT exceed the current period's end (so
        // a client can't request a token claiming next period's
        // validity).
        let current_period_end = current_period_end_secs(
            self.config.plan_created_at,
            self.config.period_hours,
            now_secs,
        );
        if expiration_secs > current_period_end + CLOCK_SKEW_TOLERANCE_SECS {
            return Err(VerifyError::OutsideValidityWindow);
        }

        // Nonce re-derivation.
        let expected_nonce = self.compute_nonce(&payload.expiration_time);
        if payload.nonce != expected_nonce {
            return Err(VerifyError::NonceMismatch);
        }

        // Resource binding: payload.resources MUST contain a
        // `solana-subscription:<pda>` whose PDA derives from
        // `(plan_id, payload.address)`.
        let address_pubkey = Pubkey::try_from(payload.address.as_str())
            .map_err(|e| VerifyError::MalformedPayload(format!("address: {e}")))?;
        let plan_pubkey = Pubkey::try_from(self.config.plan_id.as_str())
            .map_err(|e| VerifyError::Internal(format!("config.plan_id: {e}")))?;
        let program_pubkey = Pubkey::try_from(self.program_id.as_str())
            .map_err(|e| VerifyError::Internal(format!("config.program_id: {e}")))?;
        let (expected_pda, _) =
            find_subscription_pda(&plan_pubkey, &address_pubkey, &program_pubkey);
        let expected_resource = format!("{RESOURCE_SCHEME_SOLANA_SUBSCRIPTION}:{expected_pda}");
        if !payload.resources.iter().any(|r| r == &expected_resource) {
            return Err(VerifyError::ResourceMismatch);
        }

        // Ed25519 signature over the canonical SIWS message.
        verify_signature(&payload).map_err(|e| match e {
            SignatureError::Invalid => VerifyError::SignatureInvalid,
            SignatureError::Malformed(reason) => VerifyError::MalformedPayload(reason),
        })?;

        Ok(address_pubkey)
    }

    fn compute_nonce(&self, expiration_time: &str) -> String {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        type HmacSha256 = Hmac<Sha256>;
        let mut mac = HmacSha256::new_from_slice(self.challenge_binding_secret.as_bytes())
            .expect("HMAC accepts any key length");
        let input = [
            b"authenticate".as_slice(),
            self.realm.as_bytes(),
            self.config.plan_id.as_bytes(),
            expiration_time.as_bytes(),
        ]
        .join(&b'|');
        mac.update(&input);
        let tag = mac.finalize().into_bytes();
        // 8 bytes ≈ 11 base64url chars — enough randomness for a
        // server-issued nonce, short enough to keep the signed message
        // compact.
        base64url_encode(&tag[..8])
    }
}

enum SignatureError {
    Invalid,
    Malformed(String),
}

fn verify_signature(p: &AuthenticatePayload) -> Result<(), SignatureError> {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    if p.signature_type != SIGNATURE_TYPE_ED25519 {
        return Err(SignatureError::Malformed(format!(
            "expected signature type `{SIGNATURE_TYPE_ED25519}`, got `{}`",
            p.signature_type
        )));
    }
    if p.signature_scheme
        .as_deref()
        .unwrap_or(SIGNATURE_SCHEME_SIWMPP)
        != SIGNATURE_SCHEME_SIWMPP
    {
        return Err(SignatureError::Malformed(format!(
            "unsupported signature scheme `{}`",
            p.signature_scheme.as_deref().unwrap_or("")
        )));
    }

    let address_bytes = bs58::decode(&p.address)
        .into_vec()
        .map_err(|e| SignatureError::Malformed(format!("address base58: {e}")))?;
    let address_arr: [u8; 32] = address_bytes
        .try_into()
        .map_err(|_| SignatureError::Malformed("address must be 32 bytes".into()))?;
    let verifying_key = VerifyingKey::from_bytes(&address_arr)
        .map_err(|e| SignatureError::Malformed(format!("address as pubkey: {e}")))?;

    let sig_bytes = bs58::decode(&p.signature)
        .into_vec()
        .map_err(|e| SignatureError::Malformed(format!("signature base58: {e}")))?;
    let sig_arr: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| SignatureError::Malformed("signature must be 64 bytes".into()))?;
    let signature = Signature::from_bytes(&sig_arr);

    let message = crate::protocol::intents::format_canonical_message(p);
    verifying_key
        .verify(message.as_bytes(), &signature)
        .map_err(|_| SignatureError::Invalid)
}

/// Compute the unix-seconds end of the current billing period for a
/// plan with the given anchor and period length. Mirrors the on-chain
/// program's period bookkeeping (period N = `[anchor + N*Δ, anchor +
/// (N+1)*Δ)`).
fn current_period_end_secs(plan_created_at: i64, period_hours: u64, now: i64) -> i64 {
    let delta = (period_hours as i64) * 3600;
    if delta <= 0 || now < plan_created_at {
        return plan_created_at + delta;
    }
    let elapsed = now - plan_created_at;
    let period_index = elapsed / delta;
    plan_created_at + (period_index + 1) * delta
}

fn now_unix_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Format unix seconds as RFC 3339 in UTC. Reused (duplicated)
/// from subscription.rs so this module stays self-contained.
fn format_rfc3339_seconds(secs: i64) -> String {
    let days = secs.div_euclid(86_400);
    let secs_of_day = secs.rem_euclid(86_400) as u32;
    let h = secs_of_day / 3600;
    let m = (secs_of_day % 3600) / 60;
    let s = secs_of_day % 60;
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mo = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if mo <= 2 { y + 1 } else { y };
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{m:02}:{s:02}Z")
}

/// Parse an RFC 3339 timestamp back to unix seconds. We accept the
/// strict `YYYY-MM-DDTHH:MM:SSZ` form the server emits — anything
/// else is treated as a malformed credential.
fn parse_rfc3339_seconds(s: &str) -> Result<i64, String> {
    // `2026-05-29T22:25:22Z` — 20 chars, fixed-width.
    let bytes = s.as_bytes();
    if bytes.len() != 20 || bytes[19] != b'Z' || bytes[10] != b'T' {
        return Err(format!("not RFC 3339 (YYYY-MM-DDTHH:MM:SSZ): {s}"));
    }
    let parse = |range: std::ops::Range<usize>, name: &str| -> Result<i64, String> {
        std::str::from_utf8(&bytes[range])
            .map_err(|_| format!("{name}: not utf8"))?
            .parse()
            .map_err(|_| format!("{name}: not an integer"))
    };
    let y = parse(0..4, "year")?;
    let mo = parse(5..7, "month")?;
    let d = parse(8..10, "day")?;
    let h = parse(11..13, "hour")?;
    let mi = parse(14..16, "minute")?;
    let s_ = parse(17..19, "second")?;

    // Hinnant's days_from_civil: compute days since unix epoch then
    // add intraday seconds. Months in the formula are remapped so
    // March = 0 and February of the next year = 11; the "y -= m <= 2"
    // step adjusts the year accordingly.
    let y_adj = y - if mo <= 2 { 1 } else { 0 };
    let m_shift = if mo > 2 { mo - 3 } else { mo + 9 };
    let era = if y_adj >= 0 { y_adj } else { y_adj - 399 } / 400;
    let yoe = y_adj - era * 400;
    let doy = (153 * m_shift + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Ok(days * 86_400 + h * 3600 + mi * 60 + s_)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::intents::{
        AuthenticatePayload, SIGNATURE_SCHEME_SIWMPP, SIGNATURE_TYPE_ED25519,
    };
    use ed25519_dalek::{Signer as _, SigningKey};

    const PLAN_ID: &str = "Amp9FrnEX17tVeZ7QnHX1Hh4TynhH4sXLRSde797vdKR";
    const PLAN_CREATED_AT: i64 = 1_780_000_000;
    const PERIOD_HOURS: u64 = 720;
    const TEST_NETWORK: &str = "mainnet";

    fn make_server() -> AuthenticateServer {
        AuthenticateServer::new(AuthenticateConfig {
            domain: "api.example.com".into(),
            uri: "https://api.example.com/v1".into(),
            plan_id: PLAN_ID.into(),
            plan_created_at: PLAN_CREATED_AT,
            period_hours: PERIOD_HOURS,
            network: TEST_NETWORK.into(),
            program_id: None,
            challenge_binding_secret: "test-secret".into(),
            realm: "api.example.com".into(),
            statement: Some("Sign in to use your active subscription.".into()),
            store: None,
        })
        .expect("valid config")
    }

    fn make_signer() -> SigningKey {
        // Deterministic key so the derived pubkey is stable across runs.
        SigningKey::from_bytes(&[7u8; 32])
    }

    fn sign_payload_for_challenge(
        challenge: &PaymentChallenge,
        key: &SigningKey,
        now: i64,
    ) -> PaymentCredential {
        let _ = now;
        let request: AuthenticateRequest = challenge.request.decode().expect("decode request");
        let address = bs58::encode(key.verifying_key().as_bytes()).into_string();
        let address_pubkey = Pubkey::try_from(address.as_str()).expect("valid address");
        let plan_pubkey = Pubkey::try_from(PLAN_ID).expect("valid plan");
        let program_pubkey =
            Pubkey::try_from(crate::program::subscriptions::SUBSCRIPTIONS_PROGRAM_ID)
                .expect("valid program");
        let (pda, _) = find_subscription_pda(&plan_pubkey, &address_pubkey, &program_pubkey);

        let mut payload = AuthenticatePayload {
            domain: request.domain.clone(),
            uri: request.uri.clone(),
            address,
            version: request.version.clone(),
            network: TEST_NETWORK.into(),
            nonce: request.nonce.clone(),
            issued_at: request.issued_at.clone(),
            expiration_time: request.expiration_time.clone(),
            not_before: request.not_before.clone(),
            statement: request.statement.clone(),
            request_id: request.request_id.clone(),
            resources: vec![format!("{RESOURCE_SCHEME_SOLANA_SUBSCRIPTION}:{pda}")],
            signature_type: SIGNATURE_TYPE_ED25519.into(),
            signature_scheme: Some(SIGNATURE_SCHEME_SIWMPP.into()),
            signature: String::new(),
        };
        let message = crate::protocol::intents::format_canonical_message(&payload);
        let sig = key.sign(message.as_bytes());
        payload.signature = bs58::encode(sig.to_bytes()).into_string();
        PaymentCredential::new(
            challenge.to_echo(),
            serde_json::to_value(&payload).expect("payload serializable"),
        )
    }

    #[test]
    fn happy_path_round_trip() {
        let server = make_server();
        let now = PLAN_CREATED_AT + 60; // 1 minute into period 0
        let challenge = server.challenge_at(now).expect("challenge");
        let key = make_signer();
        let credential = sign_payload_for_challenge(&challenge, &key, now);
        let proven = server.verify_at(&credential, now).expect("verify");
        let expected_pubkey = Pubkey::try_from(
            bs58::encode(key.verifying_key().as_bytes())
                .into_string()
                .as_str(),
        )
        .expect("valid");
        assert_eq!(proven, expected_pubkey);
    }

    #[test]
    fn verify_rejects_expired_token() {
        let server = make_server();
        let challenge = server.challenge_at(PLAN_CREATED_AT).expect("challenge");
        let credential = sign_payload_for_challenge(&challenge, &make_signer(), PLAN_CREATED_AT);
        // Set "now" well past the period end + skew tolerance.
        let way_later = PLAN_CREATED_AT + (PERIOD_HOURS as i64) * 3600 + 3600;
        assert_eq!(
            server.verify_at(&credential, way_later),
            Err(VerifyError::OutsideValidityWindow)
        );
    }

    #[test]
    fn verify_rejects_tampered_nonce() {
        let server = make_server();
        let now = PLAN_CREATED_AT + 60;
        let challenge = server.challenge_at(now).expect("challenge");
        let credential = sign_payload_for_challenge(&challenge, &make_signer(), now);
        // Tamper with the nonce post-sign — the Tier-1 challenge id HMAC
        // (computed over the unchanged request bytes) still passes, but
        // the payload echo check should catch the mismatch.
        let mut tampered_payload: AuthenticatePayload =
            serde_json::from_value(credential.payload.clone()).expect("decode");
        tampered_payload.nonce = "different-nonce".into();
        let tampered_credential = PaymentCredential::new(
            credential.challenge.clone(),
            serde_json::to_value(&tampered_payload).expect("encode"),
        );
        assert_eq!(
            server.verify_at(&tampered_credential, now),
            Err(VerifyError::PinnedFieldMismatch("nonce"))
        );
    }

    #[test]
    fn verify_rejects_resource_for_other_wallet() {
        let server = make_server();
        let now = PLAN_CREATED_AT + 60;
        let challenge = server.challenge_at(now).expect("challenge");
        let credential = sign_payload_for_challenge(&challenge, &make_signer(), now);
        // Rewrite the resource to claim a PDA for a different wallet.
        let other_pda = Pubkey::new_unique();
        let mut tampered_payload: AuthenticatePayload =
            serde_json::from_value(credential.payload.clone()).expect("decode");
        tampered_payload.resources =
            vec![format!("{RESOURCE_SCHEME_SOLANA_SUBSCRIPTION}:{other_pda}")];
        let tampered = PaymentCredential::new(
            credential.challenge.clone(),
            serde_json::to_value(&tampered_payload).expect("encode"),
        );
        assert_eq!(
            server.verify_at(&tampered, now),
            Err(VerifyError::ResourceMismatch)
        );
    }

    #[test]
    fn verify_rejects_bogus_signature() {
        let server = make_server();
        let now = PLAN_CREATED_AT + 60;
        let challenge = server.challenge_at(now).expect("challenge");
        let credential = sign_payload_for_challenge(&challenge, &make_signer(), now);
        let mut tampered_payload: AuthenticatePayload =
            serde_json::from_value(credential.payload.clone()).expect("decode");
        // Replace the signature with one signed by a DIFFERENT key.
        let other_key = SigningKey::from_bytes(&[42u8; 32]);
        let message = crate::protocol::intents::format_canonical_message(&tampered_payload);
        let sig = other_key.sign(message.as_bytes());
        tampered_payload.signature = bs58::encode(sig.to_bytes()).into_string();
        let tampered = PaymentCredential::new(
            credential.challenge.clone(),
            serde_json::to_value(&tampered_payload).expect("encode"),
        );
        assert_eq!(
            server.verify_at(&tampered, now),
            Err(VerifyError::SignatureInvalid)
        );
    }

    #[test]
    fn challenge_emits_expected_method_details() {
        let server = make_server();
        let challenge = server
            .challenge_at(PLAN_CREATED_AT + 60)
            .expect("challenge");
        let request: AuthenticateRequest = challenge.request.decode().expect("decode");
        let md = request.method_details.expect("method details");
        assert_eq!(md.network.as_deref(), Some(TEST_NETWORK));
        assert_eq!(md.signature_type.as_deref(), Some(SIGNATURE_TYPE_ED25519));
        assert_eq!(
            md.signature_scheme.as_deref(),
            Some(SIGNATURE_SCHEME_SIWMPP)
        );
    }

    #[test]
    fn current_period_end_rolls_at_period_boundary() {
        // Anchor at PLAN_CREATED_AT, 30-day period. One second before the
        // period boundary should still be inside period 0; one second
        // after should be in period 1.
        let delta = (PERIOD_HOURS as i64) * 3600;
        let just_before = PLAN_CREATED_AT + delta - 1;
        let just_after = PLAN_CREATED_AT + delta + 1;
        assert_eq!(
            current_period_end_secs(PLAN_CREATED_AT, PERIOD_HOURS, just_before),
            PLAN_CREATED_AT + delta
        );
        assert_eq!(
            current_period_end_secs(PLAN_CREATED_AT, PERIOD_HOURS, just_after),
            PLAN_CREATED_AT + 2 * delta
        );
    }

    #[test]
    fn parse_rfc3339_round_trip() {
        let secs = 1_780_090_739;
        let s = format_rfc3339_seconds(secs);
        assert_eq!(parse_rfc3339_seconds(&s).unwrap(), secs);
    }

    #[test]
    fn parse_rfc3339_rejects_malformed() {
        assert!(parse_rfc3339_seconds("not a date").is_err());
        assert!(parse_rfc3339_seconds("2026-05-29 22:25:22Z").is_err()); // space instead of T
        assert!(parse_rfc3339_seconds("2026-05-29T22:25:22").is_err()); // missing Z
    }
}
