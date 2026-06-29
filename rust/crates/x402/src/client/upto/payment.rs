//! Client-side payment building for the x402 `upto` scheme (payment-channel).
//!
//! The client opens a channel whose `deposit` is the authorized maximum, with
//! `authorized_signer = operator` so the operator can settle the actual amount
//! with a single voucher. The client signs only the `open` transaction; the
//! operator broadcasts it and settles after metering.

use std::str::FromStr;

use solana_hash::Hash;
use solana_keychain::SolanaSigner;
use solana_pubkey::Pubkey;

use solana_pay_core::payment_channels as pc;

use crate::error::Error;
use crate::protocol::schemes::upto::{
    UptoPayload, UptoRequiredEnvelope, UptoRequirements, UptoSignatureEnvelope,
    PROFILE_PAYMENT_CHANNEL, UPTO_SCHEME,
};
use crate::{PAYMENT_REQUIRED_HEADER, X402_VERSION_V2};

/// Build an `upto` payload for a `payment-channel` requirement.
///
/// `expires_at` is the voucher/authorization deadline (Unix seconds); `nonce`
/// uniquely identifies this authorization. The requirement MUST carry
/// `extra.recentBlockhash` (the operator provides it in the 402 challenge).
pub async fn build_upto_payload(
    payer_signer: &dyn SolanaSigner,
    requirements: &UptoRequirements,
    expires_at: i64,
    nonce: impl Into<String>,
) -> Result<UptoPayload, Error> {
    if !requirements
        .extra
        .profiles
        .iter()
        .any(|p| p == PROFILE_PAYMENT_CHANNEL)
    {
        return Err(Error::Other(
            "requirement does not advertise the payment-channel profile".to_string(),
        ));
    }

    let max = requirements.max_amount()?;
    let payee = Pubkey::from_str(&requirements.pay_to)
        .map_err(|e| Error::Other(format!("invalid payTo: {e}")))?;
    let mint = Pubkey::from_str(&requirements.asset)
        .map_err(|e| Error::Other(format!("invalid asset mint: {e}")))?;
    let operator = Pubkey::from_str(&requirements.extra.fee_payer)
        .map_err(|e| Error::Other(format!("invalid feePayer: {e}")))?;
    let program_id = match &requirements.extra.channel_program {
        Some(value) => {
            Pubkey::from_str(value).map_err(|e| Error::Other(format!("invalid programId: {e}")))?
        }
        None => pc::default_program_id(),
    };
    let token_program = match &requirements.extra.token_program {
        Some(value) => Pubkey::from_str(value)
            .map_err(|e| Error::Other(format!("invalid tokenProgram: {e}")))?,
        None => Pubkey::from_str("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")
            .expect("valid token program"),
    };
    let recent_blockhash = requirements
        .extra
        .recent_blockhash
        .as_deref()
        .ok_or_else(|| Error::Other("requirement missing extra.recentBlockhash".to_string()))?;
    let blockhash = Hash::from_str(recent_blockhash)
        .map_err(|e| Error::Other(format!("invalid recentBlockhash: {e}")))?;

    let salt = pc::random_salt();
    // operator is both the voucher signer (authorized_signer) and the fee payer.
    let open = pc::build_open_payment_channel_tx(
        payer_signer,
        &payee,
        &mint,
        &operator,
        salt,
        max,
        pc::DEFAULT_GRACE_PERIOD_SECONDS,
        vec![],
        &token_program,
        &program_id,
        &operator,
        blockhash,
    )
    .await?;

    Ok(UptoPayload {
        profile: PROFILE_PAYMENT_CHANNEL.to_string(),
        from: pc::pubkey_string(&payer_signer.pubkey()),
        max_amount: max.to_string(),
        expires_at,
        valid_after: requirements.extra.valid_after.unwrap_or(0),
        nonce: nonce.into(),
        channel_id: pc::pubkey_string(&open.channel_id),
        deposit: max.to_string(),
        authorized_signer: pc::pubkey_string(&operator),
        open_transaction: Some(open.transaction),
        signature: None,
    })
}

/// Wrap a payload in a `PAYMENT-SIGNATURE` envelope and base64-encode it.
pub fn encode_upto_header(
    requirements: &UptoRequirements,
    payload: UptoPayload,
) -> Result<String, Error> {
    // Emit the canonical x402 v2 shape: `{ x402Version, accepted, payload }`.
    // Per spec §5.2 the scheme/network live inside `accepted`, not at the
    // envelope level.
    let envelope = UptoSignatureEnvelope {
        x402_version: X402_VERSION_V2,
        accepted: serde_json::to_value(requirements)
            .map_err(|e| Error::Other(format!("upto accepted serialization failed: {e}")))?,
        payload,
    };
    let json = serde_json::to_string(&envelope)
        .map_err(|e| Error::Other(format!("upto envelope serialization failed: {e}")))?;
    Ok(base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        json.as_bytes(),
    ))
}

/// Build the full `PAYMENT-SIGNATURE` header value for an `upto` payment.
pub async fn build_upto_header(
    payer_signer: &dyn SolanaSigner,
    requirements: &UptoRequirements,
    expires_at: i64,
    nonce: impl Into<String>,
) -> Result<String, Error> {
    let payload = build_upto_payload(payer_signer, requirements, expires_at, nonce).await?;
    encode_upto_header(requirements, payload)
}

/// Parse a 402 `upto` challenge from a `PAYMENT-REQUIRED` header value or body.
pub fn parse_upto_challenge(
    headers: &[(String, String)],
    body: Option<&str>,
) -> Option<UptoRequirements> {
    let from_header = headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(PAYMENT_REQUIRED_HEADER))
        .and_then(|(_, value)| {
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, value).ok()
        })
        .and_then(|bytes| serde_json::from_slice::<UptoRequiredEnvelope>(&bytes).ok());

    let envelope = from_header
        .or_else(|| body.and_then(|b| serde_json::from_str::<UptoRequiredEnvelope>(b).ok()))?;

    envelope
        .accepts
        .into_iter()
        .find(|req| req.scheme == UPTO_SCHEME)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::schemes::upto::UptoExtra;

    const OPERATOR: &str = "9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin";

    fn requirements() -> UptoRequirements {
        UptoRequirements {
            scheme: UPTO_SCHEME.to_string(),
            network: "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1".to_string(),
            amount: "1000000".to_string(),
            asset: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v".to_string(),
            pay_to: "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY".to_string(),
            max_timeout_seconds: 300,
            extra: UptoExtra {
                profiles: vec![PROFILE_PAYMENT_CHANNEL.to_string()],
                decimals: Some(6),
                token_program: None,
                fee_payer: OPERATOR.to_string(),
                channel_program: None,
                recent_blockhash: Some(Hash::default().to_string()),
                last_valid_block_height: None,
                valid_after: None,
            },
        }
    }

    fn sample_payload() -> UptoPayload {
        UptoPayload {
            profile: PROFILE_PAYMENT_CHANNEL.to_string(),
            from: "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY".to_string(),
            max_amount: "1000000".to_string(),
            expires_at: 4_102_444_800,
            valid_after: 0,
            nonce: "n-1".to_string(),
            channel_id: "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY".to_string(),
            deposit: "1000000".to_string(),
            authorized_signer: OPERATOR.to_string(),
            open_transaction: Some("tx".to_string()),
            signature: None,
        }
    }

    #[test]
    fn encode_header_produces_upto_envelope() {
        let header = encode_upto_header(&requirements(), sample_payload()).unwrap();
        let bytes =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &header).unwrap();
        let envelope: UptoSignatureEnvelope = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            envelope.accepted.get("scheme").and_then(|s| s.as_str()),
            Some(UPTO_SCHEME)
        );
        assert_eq!(envelope.payload.max_amount, "1000000");
        assert_eq!(envelope.x402_version, X402_VERSION_V2);
        assert!(envelope.accepted.is_object());
    }

    #[test]
    fn parse_challenge_reads_payment_required_header() {
        let envelope = UptoRequiredEnvelope {
            x402_version: X402_VERSION_V2,
            resource: None,
            accepts: vec![requirements()],
            error: None,
        };
        let json = serde_json::to_string(&envelope).unwrap();
        let value =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, json.as_bytes());
        let headers = vec![(PAYMENT_REQUIRED_HEADER.to_string(), value)];

        let parsed = parse_upto_challenge(&headers, None).unwrap();
        assert_eq!(parsed.amount, "1000000");
        assert_eq!(parsed.extra.fee_payer, OPERATOR);
    }

    #[test]
    fn parse_challenge_returns_none_without_upto_offer() {
        assert!(parse_upto_challenge(&[], None).is_none());
    }
}
