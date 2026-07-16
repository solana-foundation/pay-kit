//! Client-side payment building for the x402 `upto` scheme (payment-channel).
//!
//! The client opens a channel whose `deposit` is the authorized maximum, with
//! `authorized_signer = receiverAuthorizer` (the voucher signer) and
//! `payee = feePayer` — the facilitator's zero-share lifecycle seat, which also
//! sponsors the fee and rent. The client signs only the `open` transaction; the
//! fee payer broadcasts it and later submits the settlement carrying the
//! receiver authorizer's voucher for the metered amount.

use std::str::FromStr;

use solana_hash::Hash;
use solana_keychain::SolanaSigner;
use solana_pubkey::Pubkey;

use crate::core::payment_channels as pc;

use crate::x402::error::Error;
use crate::x402::protocol::schemes::upto::{
    UptoPayload, UptoRequiredEnvelope, UptoRequirements, UptoSignatureEnvelope, UPTO_SCHEME,
};
use crate::x402::{PAYMENT_REQUIRED_HEADER, X402_VERSION_V2};

/// Build an `upto` payload for a `payment-channel` requirement.
///
/// `expires_at` is the voucher/authorization deadline (Unix seconds); `nonce`
/// uniquely identifies this authorization. The requirement MUST carry
/// `extra.recentBlockhash` AND `extra.recentSlot` (the operator provides both
/// in the 402 challenge): the slot feeds the program's `openSlot`, a
/// channel-PDA seed the program only accepts within a recent window, and it
/// comes from the challenge — never from a client-side RPC fetch.
pub async fn build_upto_payload(
    payer_signer: &dyn SolanaSigner,
    requirements: &UptoRequirements,
    expires_at: i64,
    _nonce: impl Into<String>,
) -> Result<UptoPayload, Error> {
    let max = requirements.max_amount()?;
    let mint = Pubkey::from_str(&requirements.asset)
        .map_err(|e| Error::Other(format!("invalid asset mint: {e}")))?;
    let fee_payer = Pubkey::from_str(&requirements.extra.fee_payer)
        .map_err(|e| Error::Other(format!("invalid feePayer: {e}")))?;
    let receiver_authorizer = Pubkey::from_str(&requirements.extra.receiver_authorizer)
        .map_err(|e| Error::Other(format!("invalid receiverAuthorizer: {e}")))?;
    if requirements.extra.withdraw_delay == 0 {
        return Err(Error::Other(
            "requirement missing extra.withdrawDelay".to_string(),
        ));
    }
    let beneficiary = Pubkey::from_str(&requirements.pay_to)
        .map_err(|e| Error::Other(format!("invalid payTo: {e}")))?;
    // Always explicit: the payee seat is held by the facilitator (fee payer)
    // with a zero implicit remainder, so 100% of settled funds must be
    // assigned to `payTo` through the recipients list.
    let recipients = vec![pc::Distribution {
        recipient: beneficiary,
        bps: 10_000,
    }];
    let program_id = pc::default_program_id();
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
    let open_slot: u64 = requirements
        .extra
        .recent_slot
        .as_deref()
        .ok_or_else(|| Error::Other("requirement missing extra.recentSlot".to_string()))?
        .parse()
        .map_err(|e| Error::Other(format!("invalid recentSlot: {e}")))?;

    let salt = pc::random_salt();
    let open = pc::build_open_payment_channel_tx(
        payer_signer,
        // Channel payee: the fee payer's zero-share lifecycle seat.
        &fee_payer,
        &mint,
        &receiver_authorizer,
        salt,
        open_slot,
        max,
        requirements.extra.withdraw_delay,
        recipients,
        &token_program,
        &program_id,
        &fee_payer,
        blockhash,
    )
    .await?;

    Ok(UptoPayload {
        from: pc::pubkey_string(&payer_signer.pubkey()),
        max_amount: max.to_string(),
        expires_at,
        valid_after: requirements.extra.valid_after.unwrap_or(0),
        nonce: salt.to_string(),
        channel_id: pc::pubkey_string(&open.channel_id),
        deposit: max.to_string(),
        authorized_signer: pc::pubkey_string(&receiver_authorizer),
        open_slot: open_slot.to_string(),
        open_transaction: Some(open.transaction),
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

/// Parse a 402 `upto` challenge from a `PAYMENT-REQUIRED` header value or body,
/// returning the first advertised `upto` requirement. Use [`parse_upto_accepts`]
/// to consider every advertised currency.
pub fn parse_upto_challenge(
    headers: &[(String, String)],
    body: Option<&str>,
) -> Option<UptoRequirements> {
    parse_upto_accepts(headers, body).into_iter().next()
}

/// Parse *all* `upto` requirements advertised on a 402 (every `scheme == "upto"`
/// `accepts` entry), so a balance- and cost-aware selector can choose among the
/// offered currencies — not just the first. Empty when none are present.
pub fn parse_upto_accepts(
    headers: &[(String, String)],
    body: Option<&str>,
) -> Vec<UptoRequirements> {
    let from_header = headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(PAYMENT_REQUIRED_HEADER))
        .and_then(|(_, value)| {
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, value).ok()
        })
        .and_then(|bytes| serde_json::from_slice::<UptoRequiredEnvelope>(&bytes).ok());

    let Some(envelope) = from_header
        .or_else(|| body.and_then(|b| serde_json::from_str::<UptoRequiredEnvelope>(b).ok()))
    else {
        return Vec::new();
    };

    envelope
        .accepts
        .into_iter()
        .filter(|req| req.scheme == UPTO_SCHEME)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::x402::protocol::schemes::upto::UptoExtra;

    const RECEIVER_AUTHORIZER: &str = "9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin";

    fn requirements() -> UptoRequirements {
        UptoRequirements {
            scheme: UPTO_SCHEME.to_string(),
            network: "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1".to_string(),
            amount: "1000000".to_string(),
            asset: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v".to_string(),
            pay_to: "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY".to_string(),
            max_timeout_seconds: 300,
            extra: UptoExtra {
                token_program: None,
                fee_payer: RECEIVER_AUTHORIZER.to_string(),
                receiver_authorizer: RECEIVER_AUTHORIZER.to_string(),
                withdraw_delay: 900,
                recent_blockhash: Some(Hash::default().to_string()),
                last_valid_block_height: None,
                recent_slot: Some("314".to_string()),
                valid_after: None,
            },
        }
    }

    fn sample_payload() -> UptoPayload {
        UptoPayload {
            from: "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY".to_string(),
            max_amount: "1000000".to_string(),
            expires_at: 4_102_444_800,
            valid_after: 0,
            nonce: "n-1".to_string(),
            channel_id: "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY".to_string(),
            deposit: "1000000".to_string(),
            authorized_signer: RECEIVER_AUTHORIZER.to_string(),
            open_slot: "314".to_string(),
            open_transaction: Some("tx".to_string()),
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
        assert_eq!(parsed.extra.fee_payer, RECEIVER_AUTHORIZER);
        assert_eq!(parsed.extra.receiver_authorizer, RECEIVER_AUTHORIZER);
        assert_eq!(parsed.extra.withdraw_delay, 900);
    }

    #[test]
    fn parse_challenge_returns_none_without_upto_offer() {
        assert!(parse_upto_challenge(&[], None).is_none());
    }
}
