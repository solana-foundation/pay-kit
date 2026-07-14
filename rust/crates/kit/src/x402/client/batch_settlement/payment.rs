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

/// Sign a cumulative voucher over the 50-byte payload with `signer`.
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
/// payer key is also the `authorizedSigner`. The requirement MUST carry
/// `extra.recentBlockhash` and `extra.recentSlot` (server-prefetched in the
/// 402 challenge): the slot feeds the program's `openSlot`, a channel-PDA seed
/// the program only accepts within a recent window, and it comes from the
/// challenge — never from a client-side RPC fetch.
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
    let open_slot: u64 = requirements
        .extra
        .recent_slot
        .as_deref()
        .ok_or_else(|| Error::Other("requirement missing extra.recentSlot".to_string()))?
        .parse()
        .map_err(|e| Error::Other(format!("invalid recentSlot: {e}")))?;

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
        open_slot,
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
        recent_slot: open_slot.to_string(),
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
        let cumulative = self
            .cumulative
            .checked_add(charge)
            .ok_or_else(|| Error::Other("cumulative overflow".to_string()))?;
        let voucher = sign_voucher(signer, &self.channel_id, cumulative, self.expires_at).await?;
        self.cumulative = cumulative;
        Ok(voucher)
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
    use crate::x402::protocol::schemes::batch_settlement::BatchExtra;
    use ed25519_dalek::SigningKey;
    use solana_keychain::memory::MemorySigner;
    use solana_keychain::{SignTransactionResult, SignerError};
    use solana_signature::Signature;
    use solana_transaction::Transaction;

    const FAR_FUTURE: i64 = 4_102_444_800;

    fn memory_signer(seed: u8) -> MemorySigner {
        let key = SigningKey::from_bytes(&[seed; 32]);
        MemorySigner::from_bytes(&key.to_keypair_bytes()).unwrap()
    }

    struct RejectingSigner(Pubkey);

    #[async_trait::async_trait]
    impl SolanaSigner for RejectingSigner {
        fn pubkey(&self) -> Pubkey {
            self.0
        }

        async fn sign_transaction(
            &self,
            _transaction: &mut Transaction,
        ) -> Result<SignTransactionResult, SignerError> {
            Err(SignerError::Other(
                "test signer rejects transactions".to_string(),
            ))
        }

        async fn sign_message(&self, _message: &[u8]) -> Result<Signature, SignerError> {
            Err(SignerError::SigningFailed(
                "test signer rejects messages".to_string(),
            ))
        }

        async fn is_available(&self) -> bool {
            true
        }
    }

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
                recent_slot: Some("314".to_string()),
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

    #[test]
    fn parse_challenge_falls_back_to_body_and_filters_other_schemes() {
        let mut other = requirements();
        other.scheme = "exact".to_string();
        let envelope = BatchRequiredEnvelope {
            x402_version: X402_VERSION_V2,
            resource: None,
            accepts: vec![other, requirements()],
            error: None,
        };
        let body = serde_json::to_string(&envelope).unwrap();
        let headers = vec![(
            PAYMENT_REQUIRED_HEADER.to_string(),
            "not-base64".to_string(),
        )];

        let parsed = parse_batch_challenge(&headers, Some(&body)).unwrap();
        assert_eq!(parsed.scheme, BATCH_SETTLEMENT_SCHEME);
        assert_eq!(parsed.amount, "10000");
    }

    #[tokio::test]
    async fn build_deposit_creates_first_voucher_without_rpc() {
        let signer = memory_signer(7);
        let (channel_id, payload) = build_deposit(&signer, &requirements(), 500, 100, FAR_FUTURE)
            .await
            .unwrap();

        let BatchPayload::Deposit {
            channel_config,
            transaction,
            voucher,
        } = payload
        else {
            panic!("expected deposit payload");
        };
        assert_eq!(channel_config.payer, pc::pubkey_string(&signer.pubkey()));
        assert_eq!(channel_config.authorized_signer, channel_config.payer);
        assert_eq!(channel_config.deposit_amount, "500");
        assert_eq!(channel_config.recent_slot, "314");
        assert!(!transaction.is_empty());
        let voucher = voucher.expect("first charge must create a voucher");
        assert_eq!(voucher.channel_id, pc::pubkey_string(&channel_id));
        assert_eq!(voucher.cumulative_amount, "100");
        assert_eq!(voucher.signer, pc::pubkey_string(&signer.pubkey()));
    }

    #[tokio::test]
    async fn build_deposit_rejects_unusable_challenges_before_signing() {
        let signer = memory_signer(8);

        let mut no_profile = requirements();
        no_profile.extra.profiles.clear();
        assert!(build_deposit(&signer, &no_profile, 100, 0, FAR_FUTURE)
            .await
            .is_err());

        let mut no_blockhash = requirements();
        no_blockhash.extra.recent_blockhash = None;
        assert!(build_deposit(&signer, &no_blockhash, 100, 0, FAR_FUTURE)
            .await
            .is_err());

        let mut invalid_slot = requirements();
        invalid_slot.extra.recent_slot = Some("not-a-slot".to_string());
        assert!(build_deposit(&signer, &invalid_slot, 100, 0, FAR_FUTURE)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn channel_does_not_advance_when_voucher_signing_fails() {
        let channel_id = Pubkey::new_unique();
        let mut channel = BatchChannel::new(channel_id, 50, FAR_FUTURE);
        let rejecting = RejectingSigner(Pubkey::new_unique());

        assert!(channel.voucher(&rejecting, 25).await.is_err());
        assert_eq!(channel.cumulative(), 50);

        let signer = memory_signer(9);
        let voucher = channel.voucher(&signer, 25).await.unwrap();
        assert_eq!(voucher.cumulative_amount, "75");
        assert_eq!(channel.cumulative(), 75);

        let payload = channel.voucher_payload(voucher);
        assert_eq!(
            payload.channel_id(),
            Some(pc::pubkey_string(&channel_id).as_str())
        );
        let refund = channel.refund_payload(&signer).await.unwrap();
        assert!(matches!(
            refund,
            BatchPayload::Refund {
                voucher: Some(_),
                ..
            }
        ));
    }
}
