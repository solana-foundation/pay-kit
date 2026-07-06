//! Client-side payment building for the x402 `batch-settlement` scheme.
//!
//! The client opens a channel depositing more than one request's worth, then
//! signs cumulative vouchers per request. By default the payer key also signs
//! vouchers (`authorizedSigner == payer`); a delegated session signer is a
//! follow-up.

use std::str::FromStr;

use solana_hash::Hash;
use solana_keychain::SolanaSigner;
use solana_pubkey::Pubkey;

use crate::core::payment_channels as pc;

use crate::x402::error::Error;
use crate::x402::protocol::schemes::batch_settlement::{
    BatchChannelConfig, BatchPayload, BatchRequiredEnvelope, BatchRequirements,
    BatchSignatureEnvelope, BatchSplit, BatchVoucher, BATCH_SETTLEMENT_SCHEME,
    PROFILE_PAYMENT_CHANNEL,
};
use crate::x402::{PAYMENT_REQUIRED_HEADER, X402_VERSION_V2};

fn random_salt() -> u64 {
    let mut bytes = [0u8; 8];
    getrandom::fill(&mut bytes).expect("getrandom CSPRNG failure");
    u64::from_le_bytes(bytes)
}

/// Sign a cumulative voucher over the 48-byte payload with `signer`.
pub async fn sign_voucher(
    signer: &dyn SolanaSigner,
    channel_id: &Pubkey,
    cumulative: u64,
    expires_at: i64,
) -> Result<BatchVoucher, Error> {
    let message = pc::voucher_message_bytes(channel_id, cumulative, expires_at)?;
    let sig: [u8; 64] = signer
        .sign_message(&message)
        .await
        .map_err(|e| Error::Other(format!("voucher signing failed: {e}")))?
        .into();
    Ok(BatchVoucher {
        channel_id: pc::pubkey_string(channel_id),
        cumulative_amount: cumulative.to_string(),
        expires_at,
        signer: pc::pubkey_string(&signer.pubkey()),
        signature: bs58::encode(sig).into_string(),
    })
}

fn resolve_pubkey(value: &str, label: &str) -> Result<Pubkey, Error> {
    Pubkey::from_str(value).map_err(|e| Error::Other(format!("invalid {label}: {e}")))
}

/// Build a `deposit` payload: a channel `open` transaction (payer-signed,
/// operator-fee-payer) plus the first cumulative voucher.
///
/// `expires_at` is the voucher deadline (Unix seconds, must be future). The
/// payer key is also the `authorizedSigner`.
pub async fn build_deposit(
    payer_signer: &dyn SolanaSigner,
    requirements: &BatchRequirements,
    deposit_amount: u64,
    first_charge: u64,
    expires_at: i64,
) -> Result<(Pubkey, BatchPayload), Error> {
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
    let payer = payer_signer.pubkey();
    let payee = resolve_pubkey(&requirements.pay_to, "payTo")?;
    let mint = resolve_pubkey(&requirements.asset, "asset mint")?;
    let operator = resolve_pubkey(&requirements.extra.fee_payer, "feePayer")?;
    let program_id = resolve_pubkey(&requirements.extra.channel_program, "channelProgram")?;
    let token_program = match &requirements.extra.token_program {
        Some(tp) => resolve_pubkey(tp, "tokenProgram")?,
        None => Pubkey::from_str("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")
            .expect("valid token program"),
    };
    let blockhash = Hash::from_str(
        requirements
            .extra
            .recent_blockhash
            .as_deref()
            .ok_or_else(|| Error::Other("requirement missing extra.recentBlockhash".to_string()))?,
    )
    .map_err(|e| Error::Other(format!("invalid recentBlockhash: {e}")))?;

    let recipients: Vec<pc::Distribution> = requirements
        .extra
        .distribution_splits
        .iter()
        .map(|s| {
            Ok(pc::Distribution {
                recipient: resolve_pubkey(&s.recipient, "split recipient")?,
                bps: s.share_bps,
            })
        })
        .collect::<Result<_, Error>>()?;

    let salt = random_salt();
    let grace = requirements.extra.grace_period_seconds;
    // authorized_signer == payer (the payer signs vouchers).
    let open = pc::build_open_payment_channel_tx(
        payer_signer,
        &payee,
        &mint,
        &payer,
        salt,
        deposit_amount,
        grace,
        recipients,
        &token_program,
        &program_id,
        &operator,
        blockhash,
    )
    .await?;

    let voucher = if first_charge > 0 {
        Some(sign_voucher(payer_signer, &open.channel_id, first_charge, expires_at).await?)
    } else {
        None
    };

    let config = BatchChannelConfig {
        payer: pc::pubkey_string(&payer),
        payee: requirements.pay_to.clone(),
        mint: requirements.asset.clone(),
        authorized_signer: pc::pubkey_string(&payer),
        salt: salt.to_string(),
        deposit_amount: deposit_amount.to_string(),
        grace_period_seconds: grace,
        distribution_splits: requirements
            .extra
            .distribution_splits
            .iter()
            .map(|s| BatchSplit {
                recipient: s.recipient.clone(),
                share_bps: s.share_bps,
            })
            .collect(),
    };

    Ok((
        open.channel_id,
        BatchPayload::Deposit {
            channel_config: config,
            transaction: open.transaction,
            voucher,
        },
    ))
}

/// Client-side cumulative tracker for a channel's vouchers.
pub struct BatchChannel {
    channel_id: Pubkey,
    cumulative: u64,
    expires_at: i64,
}

impl BatchChannel {
    /// Track a channel starting at `initial_cumulative` (e.g. the first
    /// voucher's amount from [`build_deposit`], or the on-chain `settled` on
    /// recovery).
    pub fn new(channel_id: Pubkey, initial_cumulative: u64, expires_at: i64) -> Self {
        Self {
            channel_id,
            cumulative: initial_cumulative,
            expires_at,
        }
    }

    pub fn cumulative(&self) -> u64 {
        self.cumulative
    }

    /// Advance by `charge` and sign the next cumulative voucher.
    pub async fn voucher(
        &mut self,
        signer: &dyn SolanaSigner,
        charge: u64,
    ) -> Result<BatchVoucher, Error> {
        self.cumulative = self
            .cumulative
            .checked_add(charge)
            .ok_or_else(|| Error::Other("cumulative overflow".to_string()))?;
        sign_voucher(signer, &self.channel_id, self.cumulative, self.expires_at).await
    }

    /// Wrap a voucher in a steady-state `voucher` payload.
    pub fn voucher_payload(&self, voucher: BatchVoucher) -> BatchPayload {
        BatchPayload::Voucher {
            channel_id: pc::pubkey_string(&self.channel_id),
            voucher,
        }
    }

    /// Build a cooperative-close `refund` payload, signing a voucher at the
    /// current cumulative as proof of channel ownership. The server requires
    /// this voucher to authorize the close; the watermark is not advanced.
    pub async fn refund_payload(&self, signer: &dyn SolanaSigner) -> Result<BatchPayload, Error> {
        let voucher =
            sign_voucher(signer, &self.channel_id, self.cumulative, self.expires_at).await?;
        Ok(BatchPayload::Refund {
            channel_id: pc::pubkey_string(&self.channel_id),
            voucher: Some(voucher),
        })
    }
}

/// Wrap a payload in a `PAYMENT-SIGNATURE` envelope and base64-encode it.
pub fn encode_batch_header(
    requirements: &BatchRequirements,
    payload: BatchPayload,
) -> Result<String, Error> {
    let envelope = BatchSignatureEnvelope {
        x402_version: X402_VERSION_V2,
        scheme: BATCH_SETTLEMENT_SCHEME.to_string(),
        network: Some(requirements.network.clone()),
        accepted: Some(requirements.to_accepted_value()?),
        payload,
    };
    let json = serde_json::to_string(&envelope)
        .map_err(|e| Error::Other(format!("batch envelope serialization failed: {e}")))?;
    Ok(base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        json.as_bytes(),
    ))
}

/// Parse a 402 `batch-settlement` challenge from a `PAYMENT-REQUIRED` header or body.
pub fn parse_batch_challenge(
    headers: &[(String, String)],
    body: Option<&str>,
) -> Option<BatchRequirements> {
    let from_header = headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(PAYMENT_REQUIRED_HEADER))
        .and_then(|(_, value)| {
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, value).ok()
        })
        .and_then(|bytes| serde_json::from_slice::<BatchRequiredEnvelope>(&bytes).ok());
    let envelope = from_header
        .or_else(|| body.and_then(|b| serde_json::from_str::<BatchRequiredEnvelope>(b).ok()))?;
    envelope
        .accepts
        .into_iter()
        .find(|r| r.scheme == BATCH_SETTLEMENT_SCHEME)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::x402::protocol::schemes::batch_settlement::{BatchExtra, BatchSplit};
    use solana_keychain::memory::MemorySigner;

    /// A real in-memory ed25519 signer that produces valid signatures for both
    /// `sign_message` (vouchers) and `sign_transaction` (channel `open`). Built
    /// from a fixed seed so tests stay deterministic.
    fn signer_from_seed(seed: u8) -> MemorySigner {
        let sk = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
        let mut keypair = [0u8; 64];
        keypair[..32].copy_from_slice(sk.as_bytes());
        keypair[32..].copy_from_slice(&sk.verifying_key().to_bytes());
        MemorySigner::from_bytes(&keypair).expect("valid keypair")
    }

    fn signer() -> MemorySigner {
        signer_from_seed(7)
    }

    /// A future voucher expiry.
    const EXPIRES_AT: i64 = 4_102_444_800;

    fn requirements() -> BatchRequirements {
        BatchRequirements {
            scheme: BATCH_SETTLEMENT_SCHEME.to_string(),
            network: "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1".to_string(),
            amount: "10000".to_string(),
            asset: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v".to_string(),
            pay_to: "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY".to_string(),
            max_timeout_seconds: 3600,
            extra: BatchExtra {
                profiles: vec![PROFILE_PAYMENT_CHANNEL.to_string()],
                channel_program: "CHNLxYvVA28MJP9PrFuDXccuoGXAx7jBacfLEkahyGsX".to_string(),
                grace_period_seconds: 900,
                decimals: Some(6),
                token_program: None,
                fee_payer: "9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin".to_string(),
                recent_blockhash: Some(Hash::default().to_string()),
                suggested_deposit: None,
                minimum_deposit: None,
                min_voucher_delta: None,
                distribution_splits: vec![],
            },
        }
    }

    #[test]
    fn encode_header_round_trips() {
        let payload = BatchPayload::Refund {
            channel_id: "Chan11111111111111111111111111111111111111".to_string(),
            voucher: None,
        };
        let header = encode_batch_header(&requirements(), payload).unwrap();
        let bytes =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &header).unwrap();
        let env: BatchSignatureEnvelope = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(env.scheme, BATCH_SETTLEMENT_SCHEME);
        assert!(env.accepted.is_some());
    }

    #[test]
    fn parse_challenge_reads_header() {
        let env = BatchRequiredEnvelope {
            x402_version: X402_VERSION_V2,
            resource: None,
            accepts: vec![requirements()],
            error: None,
        };
        let json = serde_json::to_string(&env).unwrap();
        let value =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, json.as_bytes());
        let headers = vec![(PAYMENT_REQUIRED_HEADER.to_string(), value)];
        let parsed = parse_batch_challenge(&headers, None).unwrap();
        assert_eq!(parsed.amount, "10000");
        assert!(parse_batch_challenge(&[], None).is_none());
    }

    #[tokio::test]
    async fn sign_voucher_populates_all_fields() {
        let s = signer();
        let channel = Pubkey::new_unique();
        let voucher = sign_voucher(&s, &channel, 12345, EXPIRES_AT).await.unwrap();
        assert_eq!(voucher.channel_id, pc::pubkey_string(&channel));
        assert_eq!(voucher.cumulative_amount, "12345");
        assert_eq!(voucher.expires_at, EXPIRES_AT);
        assert_eq!(voucher.signer, pc::pubkey_string(&s.pubkey()));
        // A base58 ed25519 signature decodes to 64 bytes.
        assert_eq!(
            bs58::decode(&voucher.signature).into_vec().unwrap().len(),
            64
        );
    }

    #[tokio::test]
    async fn build_deposit_happy_path_with_first_charge() {
        let s = signer();
        let (channel_id, payload) = build_deposit(&s, &requirements(), 500_000, 10_000, EXPIRES_AT)
            .await
            .unwrap();
        match payload {
            BatchPayload::Deposit {
                channel_config,
                transaction,
                voucher,
            } => {
                assert_eq!(channel_config.payer, pc::pubkey_string(&s.pubkey()));
                assert_eq!(
                    channel_config.authorized_signer,
                    pc::pubkey_string(&s.pubkey())
                );
                assert_eq!(channel_config.deposit_amount, "500000");
                assert_eq!(channel_config.grace_period_seconds, 900);
                assert!(!transaction.is_empty());
                let voucher = voucher.expect("first_charge > 0 signs a voucher");
                assert_eq!(voucher.cumulative_amount, "10000");
                assert_eq!(voucher.channel_id, pc::pubkey_string(&channel_id));
            }
            other => panic!("expected Deposit, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn build_deposit_omits_voucher_on_zero_charge() {
        let s = signer();
        let (_, payload) = build_deposit(&s, &requirements(), 500_000, 0, EXPIRES_AT)
            .await
            .unwrap();
        match payload {
            BatchPayload::Deposit { voucher, .. } => assert!(voucher.is_none()),
            other => panic!("expected Deposit, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn build_deposit_carries_distribution_splits() {
        let s = signer();
        let mut req = requirements();
        let split_recipient = Pubkey::new_unique().to_string();
        req.extra.distribution_splits = vec![BatchSplit {
            recipient: split_recipient.clone(),
            share_bps: 2500,
        }];
        // Also exercise the explicit tokenProgram branch.
        req.extra.token_program = Some("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA".to_string());
        let (_, payload) = build_deposit(&s, &req, 500_000, 0, EXPIRES_AT)
            .await
            .unwrap();
        match payload {
            BatchPayload::Deposit { channel_config, .. } => {
                assert_eq!(channel_config.distribution_splits.len(), 1);
                assert_eq!(
                    channel_config.distribution_splits[0].recipient,
                    split_recipient
                );
                assert_eq!(channel_config.distribution_splits[0].share_bps, 2500);
            }
            other => panic!("expected Deposit, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn build_deposit_rejects_missing_profile() {
        let s = signer();
        let mut req = requirements();
        req.extra.profiles = vec![];
        let err = build_deposit(&s, &req, 500_000, 0, EXPIRES_AT)
            .await
            .unwrap_err();
        assert!(matches!(err, Error::Other(reason) if reason.contains("payment-channel profile")));
    }

    #[tokio::test]
    async fn build_deposit_rejects_missing_blockhash() {
        let s = signer();
        let mut req = requirements();
        req.extra.recent_blockhash = None;
        let err = build_deposit(&s, &req, 500_000, 0, EXPIRES_AT)
            .await
            .unwrap_err();
        assert!(matches!(err, Error::Other(reason) if reason.contains("recentBlockhash")));
    }

    #[tokio::test]
    async fn build_deposit_rejects_invalid_blockhash() {
        let s = signer();
        let mut req = requirements();
        req.extra.recent_blockhash = Some("not-a-hash".to_string());
        let err = build_deposit(&s, &req, 500_000, 0, EXPIRES_AT)
            .await
            .unwrap_err();
        assert!(matches!(err, Error::Other(reason) if reason.contains("invalid recentBlockhash")));
    }

    #[tokio::test]
    async fn build_deposit_rejects_invalid_pay_to() {
        let s = signer();
        let mut req = requirements();
        req.pay_to = "@@@".to_string();
        let err = build_deposit(&s, &req, 500_000, 0, EXPIRES_AT)
            .await
            .unwrap_err();
        assert!(matches!(err, Error::Other(reason) if reason.contains("invalid payTo")));
    }

    #[tokio::test]
    async fn build_deposit_rejects_invalid_asset_mint() {
        let s = signer();
        let mut req = requirements();
        req.asset = "not-base58!".to_string();
        let err = build_deposit(&s, &req, 500_000, 0, EXPIRES_AT)
            .await
            .unwrap_err();
        assert!(matches!(err, Error::Other(reason) if reason.contains("invalid asset mint")));
    }

    #[tokio::test]
    async fn build_deposit_rejects_invalid_fee_payer() {
        let s = signer();
        let mut req = requirements();
        req.extra.fee_payer = "bad".to_string();
        let err = build_deposit(&s, &req, 500_000, 0, EXPIRES_AT)
            .await
            .unwrap_err();
        assert!(matches!(err, Error::Other(reason) if reason.contains("invalid feePayer")));
    }

    #[tokio::test]
    async fn build_deposit_rejects_invalid_channel_program() {
        let s = signer();
        let mut req = requirements();
        req.extra.channel_program = "bad".to_string();
        let err = build_deposit(&s, &req, 500_000, 0, EXPIRES_AT)
            .await
            .unwrap_err();
        assert!(matches!(err, Error::Other(reason) if reason.contains("invalid channelProgram")));
    }

    #[tokio::test]
    async fn build_deposit_rejects_invalid_token_program() {
        let s = signer();
        let mut req = requirements();
        req.extra.token_program = Some("bad".to_string());
        let err = build_deposit(&s, &req, 500_000, 0, EXPIRES_AT)
            .await
            .unwrap_err();
        assert!(matches!(err, Error::Other(reason) if reason.contains("invalid tokenProgram")));
    }

    #[tokio::test]
    async fn build_deposit_rejects_invalid_split_recipient() {
        let s = signer();
        let mut req = requirements();
        req.extra.distribution_splits = vec![BatchSplit {
            recipient: "not-valid".to_string(),
            share_bps: 100,
        }];
        let err = build_deposit(&s, &req, 500_000, 0, EXPIRES_AT)
            .await
            .unwrap_err();
        assert!(matches!(err, Error::Other(reason) if reason.contains("invalid split recipient")));
    }

    #[tokio::test]
    async fn batch_channel_tracks_cumulative_and_wraps_payload() {
        let s = signer();
        let channel = Pubkey::new_unique();
        let mut ch = BatchChannel::new(channel, 100, EXPIRES_AT);
        assert_eq!(ch.cumulative(), 100);

        let v1 = ch.voucher(&s, 50).await.unwrap();
        assert_eq!(ch.cumulative(), 150);
        assert_eq!(v1.cumulative_amount, "150");

        let v2 = ch.voucher(&s, 25).await.unwrap();
        assert_eq!(ch.cumulative(), 175);
        assert_eq!(v2.cumulative_amount, "175");

        // Steady-state voucher payload.
        let payload = ch.voucher_payload(v2.clone());
        match payload {
            BatchPayload::Voucher {
                channel_id,
                voucher,
            } => {
                assert_eq!(channel_id, pc::pubkey_string(&channel));
                assert_eq!(voucher.cumulative_amount, "175");
            }
            other => panic!("expected Voucher, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn batch_channel_voucher_rejects_overflow() {
        let s = signer();
        let channel = Pubkey::new_unique();
        let mut ch = BatchChannel::new(channel, u64::MAX, EXPIRES_AT);
        let err = ch.voucher(&s, 1).await.unwrap_err();
        assert!(matches!(err, Error::Other(reason) if reason.contains("cumulative overflow")));
    }

    #[tokio::test]
    async fn batch_channel_refund_payload_signs_at_current_watermark() {
        let s = signer();
        let channel = Pubkey::new_unique();
        let ch = BatchChannel::new(channel, 777, EXPIRES_AT);
        let payload = ch.refund_payload(&s).await.unwrap();
        match payload {
            BatchPayload::Refund {
                channel_id,
                voucher,
            } => {
                assert_eq!(channel_id, pc::pubkey_string(&channel));
                let voucher = voucher.expect("refund carries a proof voucher");
                assert_eq!(voucher.cumulative_amount, "777");
            }
            other => panic!("expected Refund, got {other:?}"),
        }
    }

    #[test]
    fn parse_challenge_reads_body_when_no_header() {
        let env = BatchRequiredEnvelope {
            x402_version: X402_VERSION_V2,
            resource: None,
            accepts: vec![requirements()],
            error: None,
        };
        let json = serde_json::to_string(&env).unwrap();
        let parsed = parse_batch_challenge(&[], Some(&json)).unwrap();
        assert_eq!(parsed.amount, "10000");
    }
}
