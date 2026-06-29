//! Client-side builder for the `authenticate` intent.
//!
//! Given a server-issued challenge and a Solana signer, produce an
//! `Authorization: Payment …` header value the client can attach to
//! every request inside the challenge's validity window.

use solana_keychain::SolanaSigner;

use crate::mpp::error::Error;
use crate::mpp::protocol::core::{format_authorization, PaymentChallenge, PaymentCredential};
use crate::mpp::protocol::intents::{
    format_canonical_message, AuthenticatePayload, AuthenticateRequest,
    RESOURCE_SCHEME_SOLANA_SUBSCRIPTION, SIGNATURE_SCHEME_SIWMPP, SIGNATURE_TYPE_ED25519,
};

/// Build a signed `authenticate` credential ready for the
/// `Authorization` header.
///
/// `subscription_pda` is the base58 SubscriptionDelegation PDA the
/// signer's wallet is bound to. The server's verifier expects to find
/// `solana-subscription:<pda>` in `payload.resources`, and that the
/// PDA derives from `(plan_id, signer_pubkey)` — caller supplies the
/// PDA directly to avoid re-deriving on the client.
///
/// The MPP `network` slug is pulled from
/// `methodDetails.network`; the builder errors loudly when missing
/// rather than silently signing for the wrong chain.
pub async fn build_credential_header(
    signer: &dyn SolanaSigner,
    challenge: &PaymentChallenge,
    subscription_pda: &str,
) -> Result<String, Error> {
    let credential = build_credential(signer, challenge, subscription_pda).await?;
    format_authorization(&credential)
}

/// Like [`build_credential_header`] but returns the structured
/// [`PaymentCredential`] for callers that want to inspect or store
/// the parsed shape (e.g. accounts.yml persistence). Use this when
/// you need both the signed payload and the matching header value.
pub async fn build_credential(
    signer: &dyn SolanaSigner,
    challenge: &PaymentChallenge,
    subscription_pda: &str,
) -> Result<PaymentCredential, Error> {
    if challenge.intent.as_str() != "authenticate" {
        return Err(Error::Other(format!(
            "build_credential expects intent=`authenticate`, got `{}`",
            challenge.intent
        )));
    }

    let request: AuthenticateRequest = challenge
        .request
        .decode()
        .map_err(|e| Error::Other(format!("decode authenticate request: {e}")))?;

    let address = signer.pubkey().to_string();
    // The signer commits to the network the server advertised. If the
    // server didn't include `methodDetails.network`, fail loudly — the
    // alternative is silently signing a token for a different network
    // than the user intended.
    let network = request
        .method_details
        .as_ref()
        .and_then(|m| m.network.clone())
        .ok_or_else(|| {
            Error::Other(
                "authenticate challenge missing `methodDetails.network` — server is misconfigured"
                    .into(),
            )
        })?;

    let mut resources = request.resources.clone();
    let binding = format!("{RESOURCE_SCHEME_SOLANA_SUBSCRIPTION}:{subscription_pda}");
    if !resources.iter().any(|r| r == &binding) {
        resources.push(binding);
    }

    let mut payload = AuthenticatePayload {
        domain: request.domain.clone(),
        uri: request.uri.clone(),
        address,
        version: request.version.clone(),
        network,
        nonce: request.nonce.clone(),
        issued_at: request.issued_at.clone(),
        expiration_time: request.expiration_time.clone(),
        not_before: request.not_before.clone(),
        statement: request.statement.clone(),
        request_id: request.request_id.clone(),
        resources,
        signature_type: SIGNATURE_TYPE_ED25519.into(),
        signature_scheme: Some(SIGNATURE_SCHEME_SIWMPP.into()),
        signature: String::new(),
    };

    let message = format_canonical_message(&payload);
    let sig_bytes = signer
        .sign_message(message.as_bytes())
        .await
        .map_err(|e| Error::Other(format!("Subscriber signing failed: {e}")))?;
    payload.signature = bs58::encode(<[u8; 64]>::from(sig_bytes)).into_string();

    let payload_value = serde_json::to_value(&payload)
        .map_err(|e| Error::Other(format!("encode authenticate payload: {e}")))?;
    Ok(PaymentCredential::new(challenge.to_echo(), payload_value))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mpp::program::subscriptions::{find_subscription_pda, SUBSCRIPTIONS_PROGRAM_ID};
    use crate::mpp::server::authenticate::{AuthenticateConfig, AuthenticateServer};
    use solana_keychain::MemorySigner;
    use solana_pubkey::Pubkey;

    const PLAN_ID: &str = "Amp9FrnEX17tVeZ7QnHX1Hh4TynhH4sXLRSde797vdKR";
    const PLAN_CREATED_AT: i64 = 1_780_000_000;
    const PERIOD_HOURS: u64 = 720;

    fn make_signer() -> Box<dyn SolanaSigner> {
        // Deterministic 64-byte keypair (32-byte secret seed + 32-byte
        // pubkey) so the derived address is stable across runs.
        let sk = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let mut kp = [0u8; 64];
        kp[..32].copy_from_slice(sk.as_bytes());
        kp[32..].copy_from_slice(sk.verifying_key().as_bytes());
        Box::new(MemorySigner::from_bytes(&kp).expect("valid keypair"))
    }

    fn make_server() -> AuthenticateServer {
        AuthenticateServer::new(AuthenticateConfig {
            domain: "api.example.com".into(),
            uri: "https://api.example.com/v1".into(),
            plan_id: PLAN_ID.into(),
            plan_created_at: PLAN_CREATED_AT,
            period_hours: PERIOD_HOURS,
            network: "mainnet".into(),
            program_id: None,
            challenge_binding_secret: "test-secret".into(),
            realm: "api.example.com".into(),
            statement: None,
            store: None,
        })
        .expect("valid config")
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn round_trip_signs_and_verifies() {
        let signer = make_signer();
        let server = make_server();
        let now = PLAN_CREATED_AT + 60;
        let challenge = server.challenge_at(now).expect("challenge");

        let plan = Pubkey::try_from(PLAN_ID).unwrap();
        let program = Pubkey::try_from(SUBSCRIPTIONS_PROGRAM_ID).unwrap();
        let (pda, _) = find_subscription_pda(&plan, &signer.pubkey(), &program);

        let credential = build_credential(&*signer, &challenge, &pda.to_string())
            .await
            .expect("build credential");

        let proven = server.verify_at(&credential, now).expect("verify");
        assert_eq!(proven, signer.pubkey());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn header_includes_payment_scheme() {
        let signer = make_signer();
        let server = make_server();
        let challenge = server
            .challenge_at(PLAN_CREATED_AT + 60)
            .expect("challenge");

        let plan = Pubkey::try_from(PLAN_ID).unwrap();
        let program = Pubkey::try_from(SUBSCRIPTIONS_PROGRAM_ID).unwrap();
        let (pda, _) = find_subscription_pda(&plan, &signer.pubkey(), &program);

        let header = build_credential_header(&*signer, &challenge, &pda.to_string())
            .await
            .expect("build header");
        assert!(header.starts_with("Payment "));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn rejects_non_authenticate_intent() {
        let signer = make_signer();
        // Build a charge challenge instead of authenticate — should fail
        // at the intent check before any signing happens.
        let challenge = crate::mpp::server::Mpp::new(crate::mpp::server::Config {
            recipient: signer.pubkey().to_string(),
            currency: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v".into(),
            decimals: 6,
            network: "mainnet".into(),
            // ≥32 bytes to satisfy the audit #24 secret-length check at Mpp::new.
            challenge_binding_secret: Some("test-secret-key-for-authenticate-32b-pad".into()),
            ..Default::default()
        })
        .expect("mpp")
        .charge_challenge(&crate::mpp::ChargeRequest {
            amount: "1000".into(),
            currency: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v".into(),
            recipient: Some(signer.pubkey().to_string()),
            ..Default::default()
        })
        .expect("charge challenge");

        let err = build_credential(&*signer, &challenge, "dummy-pda")
            .await
            .expect_err("intent mismatch");
        assert!(format!("{err}").contains("authenticate"));
    }
}
