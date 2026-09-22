//! Stateless checks for the SVM `batch-settlement` scheme.
//!
//! Everything here is pure: no RPC, no store. It covers the wire-level
//! obligations of spec §4 and the first three steps of the Phase 3 voucher
//! acceptance in §5 — the channel-config bindings, the PDA derivation, and the
//! Ed25519 voucher signature.
//!
//! The stateful half lives elsewhere: the watermark, deposit cap, and
//! idempotent-replay rules are enforced against stored channel state by
//! [`crate::core::session::accept_voucher`], and the onchain channel bindings
//! by the server after it reads the confirmed account.

use solana_pubkey::Pubkey;

use crate::core::payment_channels as pc;
use crate::x402::protocol::schemes::exact::programs;

use super::errors::{self, BatchError};
use super::types::{
    BatchChannelConfig, BatchPayload, BatchRequirements, BatchVoucher, VoucherState,
    MAX_WITHDRAW_DELAY_SECONDS, MIN_WITHDRAW_DELAY_SECONDS, PAYMENT_FLOW_AUTHORIZATION,
    VOUCHER_EXPIRES_AT,
};

type Result<T> = std::result::Result<T, BatchError>;

fn parse_key(value: &str, field: &str) -> Result<Pubkey> {
    pc::parse_pubkey(value)
        .map_err(|e| BatchError::new(errors::INVALID_CHANNEL_STATE, format!("{field}: {e}")))
}

/// Confirm `extra.paymentFlow`, when present, is the protocol-default
/// `authorization` flow this scheme resolves to.
pub fn check_payment_flow(payment_flow: Option<&str>) -> Result<()> {
    match payment_flow {
        None | Some(PAYMENT_FLOW_AUTHORIZATION) => Ok(()),
        Some(other) => Err(BatchError::new(
            errors::INVALID_PAYMENT_FLOW,
            format!("extra.paymentFlow must be \"authorization\", got {other:?}"),
        )),
    }
}

/// Enforce the x402 conformance bound on the forced-close grace period.
///
/// The payment-channels program accepts any positive `grace_period`, so this
/// range is the scheme's own: long enough that a server can always redeem an
/// accepted voucher before the payer's forced close lands, short enough that a
/// client's escape hatch stays usable. It must also outlast the HTTP completion
/// window, or a request could still be in flight when the channel can close.
pub fn check_withdraw_delay(withdraw_delay: u32, max_timeout_seconds: u64) -> Result<()> {
    if !(MIN_WITHDRAW_DELAY_SECONDS..=MAX_WITHDRAW_DELAY_SECONDS).contains(&withdraw_delay) {
        return Err(BatchError::new(
            errors::INVALID_WITHDRAW_DELAY_OUT_OF_RANGE,
            format!(
                "withdrawDelay {withdraw_delay} is outside \
                 {MIN_WITHDRAW_DELAY_SECONDS}..={MAX_WITHDRAW_DELAY_SECONDS} seconds"
            ),
        ));
    }
    if u64::from(withdraw_delay) < max_timeout_seconds {
        return Err(BatchError::new(
            errors::INVALID_WITHDRAW_DELAY_OUT_OF_RANGE,
            format!(
                "withdrawDelay {withdraw_delay} is shorter than \
                 maxTimeoutSeconds {max_timeout_seconds}"
            ),
        ));
    }
    Ok(())
}

/// Confirm `extra.tokenProgram` names a supported SPL token program.
///
/// This is only the shape check. Both the client and the sponsor MUST also
/// confirm the value equals the onchain owner of the mint — a server-declared
/// token program is otherwise free to disagree with reality, and the ATA
/// derivations that follow would silently target the wrong accounts.
pub fn check_token_program(token_program: &str) -> Result<Pubkey> {
    if token_program != programs::TOKEN_PROGRAM && token_program != programs::TOKEN_2022_PROGRAM {
        return Err(BatchError::new(
            errors::INVALID_TOKEN_PROGRAM,
            format!("unsupported tokenProgram {token_program}"),
        ));
    }
    parse_key(token_program, "extra.tokenProgram")
        .map_err(|e| BatchError::new(errors::INVALID_TOKEN_PROGRAM, e.detail))
}

/// Derive the canonical channel PDA from the channel configuration.
///
/// The seeds are `["channel", payer, feePayer, token, payerAuthorizer,
/// u64(salt).le, u64(openSlot).le]`. `feePayer` occupies the program's `payee`
/// seed because this scheme seats the sponsor there with a zero share.
pub fn derive_channel_id(
    config: &BatchChannelConfig,
    fee_payer: &str,
    program_id: &Pubkey,
) -> Result<Pubkey> {
    let payer = parse_key(&config.payer, "channelConfig.payer")?;
    let payee = parse_key(fee_payer, "extra.feePayer")?;
    let token = parse_key(&config.token, "channelConfig.token")?;
    let authorized_signer = parse_key(&config.payer_authorizer, "channelConfig.payerAuthorizer")?;
    let salt = config
        .salt()
        .map_err(|e| BatchError::new(errors::INVALID_CHANNEL_STATE, e.to_string()))?;
    Ok(pc::find_channel_pda(
        &payer,
        &payee,
        &token,
        &authorized_signer,
        salt,
        config.open_slot,
        program_id,
    )
    .0)
}

/// Bind the client's channel configuration to the requirements it answers.
///
/// Every field here is either a PDA seed or an immutable channel property, so a
/// mismatch means the client is describing a different channel than the one the
/// server priced — the PDA derivation alone would not catch a divergent
/// `receiver`, whose only onchain trace is the committed distribution hash.
pub fn check_channel_config(
    config: &BatchChannelConfig,
    requirements: &BatchRequirements,
) -> Result<()> {
    let extra = &requirements.extra;
    check_payment_flow(extra.payment_flow.as_deref())?;
    check_withdraw_delay(extra.withdraw_delay, requirements.max_timeout_seconds)?;
    check_token_program(&extra.token_program)?;

    // The program requires distinct payer and payee accounts, and a sponsor
    // that could also sign vouchers would be able to create its own claim.
    if config.payer == extra.fee_payer || config.payer_authorizer == extra.fee_payer {
        return Err(BatchError::new(
            errors::INVALID_FEE_PAYER_MISMATCH,
            "channelConfig.payer and payerAuthorizer must not equal extra.feePayer",
        ));
    }
    if config.receiver != requirements.pay_to {
        return Err(BatchError::new(
            errors::INVALID_CHANNEL_STATE,
            format!(
                "channelConfig.receiver {} does not match payTo {}",
                config.receiver, requirements.pay_to
            ),
        ));
    }
    if config.token != requirements.asset {
        return Err(BatchError::new(
            errors::INVALID_CHANNEL_STATE,
            format!(
                "channelConfig.token {} does not match asset {}",
                config.token, requirements.asset
            ),
        ));
    }
    if config.withdraw_delay != extra.withdraw_delay {
        return Err(BatchError::new(
            errors::INVALID_WITHDRAW_DELAY_MISMATCH,
            format!(
                "channelConfig.withdrawDelay {} does not match extra.withdrawDelay {}",
                config.withdraw_delay, extra.withdraw_delay
            ),
        ));
    }
    // Either both sides name the receiver authorizer or neither does: a config
    // that supplies one the requirements never advertised is not bound to any
    // key the server actually controls.
    if config.receiver_authorizer != extra.receiver_authorizer {
        return Err(BatchError::new(
            errors::INVALID_RECEIVER_AUTHORIZER_MISMATCH,
            "channelConfig.receiverAuthorizer must match extra.receiverAuthorizer",
        ));
    }
    // The voucher-signing mode is part of the channel's terms and MUST agree on
    // both sides (spec §4.2). This implementation offers client-signed vouchers
    // only: a server-mode channel would record the operator as the onchain
    // `authorized_signer`, able to claim up to the full deposit without any
    // further client signature — never something this server advertises.
    let config_mode = config.voucher_signer.as_deref().unwrap_or("client");
    let extra_mode = extra.voucher_signer.as_deref().unwrap_or("client");
    if config_mode != extra_mode {
        return Err(BatchError::new(
            errors::INVALID_CHANNEL_STATE,
            format!(
                "channelConfig.voucherSigner {config_mode:?} does not match                  extra.voucherSigner {extra_mode:?}"
            ),
        ));
    }
    if extra_mode != "client" || extra.operator.is_some() {
        return Err(BatchError::new(
            errors::INVALID_CHANNEL_STATE,
            "server-signed channels (extra.voucherSigner \"server\" / extra.operator) \
             are not supported by this implementation; use client-signed vouchers",
        ));
    }
    Ok(())
}

/// Refuse the server-mode payload variants this implementation does not serve.
///
/// An `authorization` payload, or a `deposit` carrying a payer proof, asks the
/// operator to sign vouchers on the client's behalf. This server signs nothing
/// on a client's behalf, so the request is refused by type rather than failing
/// deeper in with a misleading channel-state code.
pub fn check_client_signed_payload(payload: &BatchPayload) -> Result<()> {
    let refused = match payload {
        BatchPayload::Authorization { .. } => true,
        // A deposit either carries the client's voucher (client mode) or a
        // payer proof (server mode); one with no voucher has nothing this
        // server can charge against, whichever field it carries.
        BatchPayload::Deposit {
            authorization,
            voucher,
            ..
        } => authorization.is_some() || voucher.is_none(),
        BatchPayload::Voucher { .. } | BatchPayload::Refund { .. } => false,
    };
    if refused {
        return Err(BatchError::new(
            errors::INVALID_PAYLOAD_TYPE,
            format!(
                "{} payloads belong to server-signed channels, which this \
                 implementation does not offer; send a client-signed voucher",
                payload.type_name()
            ),
        ));
    }
    Ok(())
}

/// Refuse a `refund` that names an amount.
///
/// The payment-channels program returns all unused escrow or nothing, so a
/// partial refund cannot be honored; the request is refused with the dedicated
/// code rather than silently returning the full remainder (spec §4.3).
pub fn check_no_refund_amount(payload: &BatchPayload) -> Result<()> {
    if let BatchPayload::Refund {
        amount: Some(amount),
        ..
    } = payload
    {
        return Err(BatchError::new(
            errors::INVALID_CLOSE_AMOUNT_UNSUPPORTED,
            format!("refund carries amount {amount:?}; this scheme returns the full unused escrow"),
        ));
    }
    Ok(())
}

/// Verify a paid-request voucher against its channel and return the cumulative
/// amount it authorizes.
///
/// Checks the three stateless obligations: the voucher names the derived
/// channel, it never expires, and its Ed25519 signature verifies against
/// `channelConfig.payerAuthorizer` over the canonical 50-byte message.
pub fn check_voucher(
    voucher: &BatchVoucher,
    config: &BatchChannelConfig,
    channel_id: &Pubkey,
) -> Result<u64> {
    let expected = pc::pubkey_string(channel_id);
    if voucher.channel_id != expected {
        return Err(BatchError::new(
            errors::INVALID_CHANNEL_ID_MISMATCH,
            format!(
                "voucher.channelId {} does not match the derived PDA {expected}",
                voucher.channel_id
            ),
        ));
    }
    check_voucher_expiry(voucher.expires_at)?;
    let max_claimable = voucher
        .max_claimable()
        .map_err(|e| BatchError::new(errors::INVALID_VOUCHER_SIGNATURE, e.to_string()))?;
    verify_voucher_signature(
        &voucher.channel_id,
        max_claimable,
        voucher.expires_at,
        &voucher.signature,
        &config.payer_authorizer,
    )?;
    Ok(max_claimable)
}

/// Async counterpart to [`check_voucher`] that reuses the shared secure
/// micro-batch verifier when `PAY_VERIFY_BATCH=1`.
///
/// Batch settlement and MPP sessions carry the same canonical payment-channel
/// voucher signature. Keeping batch settlement on the synchronous verifier
/// left every gateway worker doing an independent curve operation even though
/// the shared verifier already coalesces concurrent vouchers, rejects
/// degenerate inputs before the batch equation, and strictly re-verifies an
/// individually failing batch.
pub async fn check_voucher_batched(
    voucher: &BatchVoucher,
    config: &BatchChannelConfig,
    channel_id: &Pubkey,
) -> Result<u64> {
    let expected = pc::pubkey_string(channel_id);
    if voucher.channel_id != expected {
        return Err(BatchError::new(
            errors::INVALID_CHANNEL_ID_MISMATCH,
            format!(
                "voucher.channelId {} does not match the derived PDA {expected}",
                voucher.channel_id
            ),
        ));
    }
    check_voucher_expiry(voucher.expires_at)?;
    let max_claimable = voucher
        .max_claimable()
        .map_err(|e| BatchError::new(errors::INVALID_VOUCHER_SIGNATURE, e.to_string()))?;

    let Some(verifier) = crate::core::batch_verify::batch_verifier() else {
        verify_voucher_signature(
            &voucher.channel_id,
            max_claimable,
            voucher.expires_at,
            &voucher.signature,
            &config.payer_authorizer,
        )?;
        return Ok(max_claimable);
    };

    let parts = crate::core::voucher::voucher_verify_parts(
        &voucher.channel_id,
        max_claimable,
        voucher.expires_at,
        &voucher.signature,
        &config.payer_authorizer,
        0,
        0,
    )
    .map_err(|e| BatchError::new(errors::INVALID_VOUCHER_SIGNATURE, e.to_string()))?;
    if !verifier
        .verify(parts.message, parts.verifying_key, parts.signature)
        .await
    {
        return Err(BatchError::new(
            errors::INVALID_VOUCHER_SIGNATURE,
            "Voucher signature verification failed",
        ));
    }
    Ok(max_claimable)
}

/// Reject any voucher expiry other than zero.
///
/// A nonzero expiry would add a second clock the server has to beat, on top of
/// the forced-close grace period, and could leave an accepted voucher
/// unredeemable while the channel is still open — after the resource has
/// already been served.
pub fn check_voucher_expiry(expires_at: i64) -> Result<()> {
    if expires_at != VOUCHER_EXPIRES_AT {
        return Err(BatchError::new(
            errors::INVALID_VOUCHER_EXPIRY,
            format!("voucher expiresAt must be 0, got {expires_at}"),
        ));
    }
    Ok(())
}

/// Verify an Ed25519 voucher signature over the canonical 50-byte message.
fn verify_voucher_signature(
    channel_id: &str,
    max_claimable: u64,
    expires_at: i64,
    signature: &str,
    payer_authorizer: &str,
) -> Result<()> {
    crate::core::voucher::verify_voucher_signature(
        channel_id,
        max_claimable,
        expires_at,
        signature,
        payer_authorizer,
        // Expiry is pinned to zero by `check_voucher_expiry`, so the clock and
        // settlement window this helper takes are inert here.
        0,
        0,
    )
    .map_err(|e| BatchError::new(errors::INVALID_VOUCHER_SIGNATURE, e.to_string()))
}

/// Reject the immediate cooperative-close shortcut.
///
/// The shortcut is optional in the spec, and honoring it safely requires a
/// facilitator-local trusted binding between a receiver-authorizer key and the
/// server that owns `payTo` — established out of band, no later than the
/// channel's first deposit. This SDK has no such registry, and a key that
/// merely appears in a request is not a trust anchor, so a supplied voucher or
/// authorization is refused rather than silently ignored. The interoperable
/// path is the payer-signed `request_close` below.
pub fn check_no_cooperative_close(payload: &BatchPayload) -> Result<()> {
    let BatchPayload::Refund {
        voucher,
        close_authorization,
        ..
    } = payload
    else {
        return Ok(());
    };
    if voucher.is_some() || close_authorization.is_some() {
        return Err(BatchError::new(
            errors::INVALID_CLOSE_AUTHORIZATION,
            "immediate cooperative close requires a trusted server binding, \
             which this implementation does not provide; omit voucher and \
             closeAuthorization and use the payer-signed request_close path",
        ));
    }
    Ok(())
}

/// Client-side check before adopting a corrective 402's channel snapshot.
///
/// A resource server that has lost sync can tell the client where its watermark
/// actually is, but the client must not take that on faith: adopting an
/// inflated `chargedCumulativeAmount` would make it sign away funds it never
/// spent. So the server must prove it holds a voucher the client itself signed
/// at that amount, and the snapshot may not claim more charged than proven.
///
/// Returns the cumulative base the client may adopt.
pub fn check_corrective_voucher_state(
    voucher_state: &VoucherState,
    channel_id: &str,
    payer_authorizer: &str,
    charged_cumulative_amount: u64,
) -> Result<u64> {
    check_voucher_expiry(voucher_state.expires_at)?;
    let signed = voucher_state
        .signed_max_claimable()
        .map_err(|e| BatchError::new(errors::INVALID_CUMULATIVE_AMOUNT_MISMATCH, e.to_string()))?;
    verify_voucher_signature(
        channel_id,
        signed,
        voucher_state.expires_at,
        &voucher_state.signature,
        payer_authorizer,
    )?;
    if charged_cumulative_amount > signed {
        return Err(BatchError::new(
            errors::INVALID_CUMULATIVE_AMOUNT_MISMATCH,
            format!(
                "corrective chargedCumulativeAmount {charged_cumulative_amount} \
                 exceeds the proven signedMaxClaimable {signed}"
            ),
        ));
    }
    Ok(charged_cumulative_amount)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::x402::protocol::schemes::batch_settlement::types::{
        BatchAuthorization, BatchDeposit, BatchExtra,
    };
    use ed25519_dalek::{Signer, SigningKey};

    const PAY_TO: &str = "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY";
    const MINT: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
    const FEE_PAYER: &str = "9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin";

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn key_b58(sk: &SigningKey) -> String {
        bs58::encode(sk.verifying_key().as_bytes()).into_string()
    }

    fn requirements(config_authorizer: &str) -> (BatchRequirements, BatchChannelConfig) {
        let requirements = BatchRequirements {
            scheme: super::super::BATCH_SETTLEMENT_SCHEME.to_string(),
            network: "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp".to_string(),
            amount: "1000".to_string(),
            asset: MINT.to_string(),
            pay_to: PAY_TO.to_string(),
            max_timeout_seconds: 300,
            extra: BatchExtra {
                payment_flow: None,
                fee_payer: FEE_PAYER.to_string(),
                receiver_authorizer: None,
                withdraw_delay: 3600,
                token_program: programs::TOKEN_PROGRAM.to_string(),
                memo: None,
                recent_blockhash: None,
                recent_slot: None,
                channel_state: None,
                voucher_state: None,
                transaction_versions: None,
                voucher_signer: None,
                operator: None,
                max_idle_secs: None,
            },
        };
        let config = BatchChannelConfig {
            payer: key_b58(&key(1)),
            payer_authorizer: config_authorizer.to_string(),
            receiver: PAY_TO.to_string(),
            receiver_authorizer: None,
            token: MINT.to_string(),
            withdraw_delay: 3600,
            salt: "42".to_string(),
            open_slot: 341_000_000,
            voucher_signer: None,
        };
        (requirements, config)
    }

    fn sign(sk: &SigningKey, channel: &Pubkey, cumulative: u64, expires_at: i64) -> String {
        let msg = pc::voucher_message_bytes(channel, cumulative, expires_at).unwrap();
        bs58::encode(sk.sign(&msg).to_bytes()).into_string()
    }

    #[test]
    fn payment_flow_accepts_only_the_authorization_default() {
        assert!(check_payment_flow(None).is_ok());
        assert!(check_payment_flow(Some("authorization")).is_ok());
        let err = check_payment_flow(Some("upfront")).unwrap_err();
        assert_eq!(err.code, errors::INVALID_PAYMENT_FLOW);
    }

    #[test]
    fn withdraw_delay_enforces_the_conformance_range_and_the_http_window() {
        assert!(check_withdraw_delay(900, 300).is_ok());
        assert!(check_withdraw_delay(2_592_000, 300).is_ok());
        // Below the floor, above the ceiling, and shorter than the completion
        // window all fail with the same out-of-range code.
        for (delay, timeout) in [(899u32, 300u64), (2_592_001, 300), (900, 901)] {
            let err = check_withdraw_delay(delay, timeout).unwrap_err();
            assert_eq!(
                err.code,
                errors::INVALID_WITHDRAW_DELAY_OUT_OF_RANGE,
                "delay={delay} timeout={timeout}"
            );
        }
        // Exactly equal to the completion window is fine.
        assert!(check_withdraw_delay(900, 900).is_ok());
    }

    #[test]
    fn token_program_accepts_both_spl_programs_and_nothing_else() {
        assert!(check_token_program(programs::TOKEN_PROGRAM).is_ok());
        assert!(check_token_program(programs::TOKEN_2022_PROGRAM).is_ok());
        let err = check_token_program(programs::SYSTEM_PROGRAM).unwrap_err();
        assert_eq!(err.code, errors::INVALID_TOKEN_PROGRAM);
    }

    #[test]
    fn channel_id_derivation_matches_the_program_seeds() {
        let (requirements, config) = requirements(&key_b58(&key(1)));
        let program_id = pc::default_program_id();
        let derived = derive_channel_id(&config, &requirements.extra.fee_payer, &program_id)
            .expect("derivable");
        let expected = pc::find_channel_pda(
            &pc::parse_pubkey(&config.payer).unwrap(),
            &pc::parse_pubkey(FEE_PAYER).unwrap(),
            &pc::parse_pubkey(MINT).unwrap(),
            &pc::parse_pubkey(&config.payer_authorizer).unwrap(),
            42,
            341_000_000,
            &program_id,
        )
        .0;
        assert_eq!(derived, expected);

        // The salt and open slot are seeds: changing either moves the channel.
        let mut moved = config.clone();
        moved.salt = "43".to_string();
        assert_ne!(
            derive_channel_id(&moved, FEE_PAYER, &program_id).unwrap(),
            derived
        );
        let mut moved = config;
        moved.open_slot += 1;
        assert_ne!(
            derive_channel_id(&moved, FEE_PAYER, &program_id).unwrap(),
            derived
        );
    }

    #[test]
    fn channel_config_binds_every_field_to_the_requirements() {
        let (requirements, config) = requirements(&key_b58(&key(1)));
        assert!(check_channel_config(&config, &requirements).is_ok());

        /// One way to break a channel config, and the code it must produce.
        type BreakCase = (&'static str, Box<dyn Fn(&mut BatchChannelConfig)>);

        let cases: Vec<BreakCase> = vec![
            (
                errors::INVALID_CHANNEL_STATE,
                Box::new(|c: &mut BatchChannelConfig| c.receiver = FEE_PAYER.to_string()),
            ),
            (
                errors::INVALID_CHANNEL_STATE,
                Box::new(|c: &mut BatchChannelConfig| c.token = PAY_TO.to_string()),
            ),
            (
                errors::INVALID_WITHDRAW_DELAY_MISMATCH,
                Box::new(|c: &mut BatchChannelConfig| c.withdraw_delay = 1800),
            ),
            (
                errors::INVALID_RECEIVER_AUTHORIZER_MISMATCH,
                Box::new(|c: &mut BatchChannelConfig| {
                    c.receiver_authorizer = Some(PAY_TO.to_string())
                }),
            ),
            (
                errors::INVALID_FEE_PAYER_MISMATCH,
                Box::new(|c: &mut BatchChannelConfig| c.payer = FEE_PAYER.to_string()),
            ),
            (
                errors::INVALID_FEE_PAYER_MISMATCH,
                Box::new(|c: &mut BatchChannelConfig| c.payer_authorizer = FEE_PAYER.to_string()),
            ),
        ];
        for (code, mutate) in cases {
            let mut broken = config.clone();
            mutate(&mut broken);
            let err = check_channel_config(&broken, &requirements).unwrap_err();
            assert_eq!(err.code, code, "detail: {}", err.detail);
        }

        // Explicit client mode is the default spelled out.
        let mut explicit = config.clone();
        explicit.voucher_signer = Some("client".to_string());
        assert!(check_channel_config(&explicit, &requirements).is_ok());
    }

    #[test]
    fn server_signed_channels_are_refused_on_either_side() {
        let (requirements, config) = requirements(&key_b58(&key(1)));
        // The client asks for server mode against a client-mode requirement.
        let mut delegated = config.clone();
        delegated.voucher_signer = Some("server".to_string());
        let err = check_channel_config(&delegated, &requirements).unwrap_err();
        assert_eq!(err.code, errors::INVALID_CHANNEL_STATE);
        assert!(err.detail.contains("voucherSigner"));
        // A requirement advertising server mode (or an operator) is never one
        // this implementation produced, and is refused even when echoed back
        // consistently.
        let mut server_terms = requirements.clone();
        server_terms.extra.voucher_signer = Some("server".to_string());
        server_terms.extra.operator = Some(key_b58(&key(2)));
        let err = check_channel_config(&delegated, &server_terms).unwrap_err();
        assert_eq!(err.code, errors::INVALID_CHANNEL_STATE);
        assert!(err.detail.contains("not supported"));
        let mut operator_only = requirements;
        operator_only.extra.operator = Some(key_b58(&key(2)));
        assert_eq!(
            check_channel_config(&config, &operator_only)
                .unwrap_err()
                .code,
            errors::INVALID_CHANNEL_STATE
        );
    }

    #[test]
    fn server_mode_payloads_and_partial_refunds_are_refused_by_code() {
        let (_, config) = requirements(&key_b58(&key(1)));
        let proof = BatchAuthorization {
            kind: "proof".to_string(),
            channel_id: PAY_TO.to_string(),
            payer: config.payer.clone(),
            request_id: "req-1".to_string(),
            authorized_amount: "1000".to_string(),
            expires_at: 1_758_215_100,
            signature: "sig".to_string(),
        };
        let authorization = BatchPayload::Authorization {
            channel_config: config.clone(),
            authorization: proof.clone(),
        };
        assert_eq!(
            check_client_signed_payload(&authorization)
                .unwrap_err()
                .code,
            errors::INVALID_PAYLOAD_TYPE
        );
        let delegated_deposit = BatchPayload::Deposit {
            channel_config: config.clone(),
            voucher: None,
            deposit: BatchDeposit {
                amount: "1".to_string(),
                transaction: "b64".to_string(),
            },
            authorization: Some(proof.clone()),
        };
        assert_eq!(
            check_client_signed_payload(&delegated_deposit)
                .unwrap_err()
                .code,
            errors::INVALID_PAYLOAD_TYPE
        );
        // Both fields at once, or neither, are equally not a client-signed deposit.
        let both = BatchPayload::Deposit {
            channel_config: config.clone(),
            voucher: Some(BatchVoucher {
                channel_id: PAY_TO.to_string(),
                max_claimable_amount: "1".to_string(),
                expires_at: 0,
                signature: "sig".to_string(),
            }),
            deposit: BatchDeposit {
                amount: "1".to_string(),
                transaction: "b64".to_string(),
            },
            authorization: Some(proof),
        };
        assert_eq!(
            check_client_signed_payload(&both).unwrap_err().code,
            errors::INVALID_PAYLOAD_TYPE
        );
        let neither = BatchPayload::Deposit {
            channel_config: config.clone(),
            voucher: None,
            deposit: BatchDeposit {
                amount: "1".to_string(),
                transaction: "b64".to_string(),
            },
            authorization: None,
        };
        assert_eq!(
            check_client_signed_payload(&neither).unwrap_err().code,
            errors::INVALID_PAYLOAD_TYPE
        );
        let voucher = BatchPayload::Voucher {
            channel_config: config.clone(),
            voucher: BatchVoucher {
                channel_id: PAY_TO.to_string(),
                max_claimable_amount: "1".to_string(),
                expires_at: 0,
                signature: "sig".to_string(),
            },
        };
        assert!(check_client_signed_payload(&voucher).is_ok());

        let partial = BatchPayload::Refund {
            channel_config: config.clone(),
            transaction: "b64".to_string(),
            voucher: None,
            close_authorization: None,
            amount: Some("1500".to_string()),
        };
        assert_eq!(
            check_no_refund_amount(&partial).unwrap_err().code,
            errors::INVALID_CLOSE_AMOUNT_UNSUPPORTED
        );
        let full = BatchPayload::Refund {
            channel_config: config,
            transaction: "b64".to_string(),
            voucher: None,
            close_authorization: None,
            amount: None,
        };
        assert!(check_no_refund_amount(&full).is_ok());
    }

    #[test]
    fn voucher_check_binds_channel_expiry_and_signer() {
        let sk = key(7);
        let (requirements, config) = requirements(&key_b58(&sk));
        let program_id = pc::default_program_id();
        let channel = derive_channel_id(&config, &requirements.extra.fee_payer, &program_id)
            .expect("derivable");
        let channel_b58 = pc::pubkey_string(&channel);

        let good = BatchVoucher {
            channel_id: channel_b58.clone(),
            max_claimable_amount: "5000".to_string(),
            expires_at: 0,
            signature: sign(&sk, &channel, 5000, 0),
        };
        assert_eq!(check_voucher(&good, &config, &channel).unwrap(), 5000);

        // Wrong channel id.
        let mut wrong_channel = good.clone();
        wrong_channel.channel_id = PAY_TO.to_string();
        assert_eq!(
            check_voucher(&wrong_channel, &config, &channel)
                .unwrap_err()
                .code,
            errors::INVALID_CHANNEL_ID_MISMATCH
        );

        // Nonzero expiry, even with a signature that verifies over it.
        let expiring = BatchVoucher {
            channel_id: channel_b58.clone(),
            max_claimable_amount: "5000".to_string(),
            expires_at: 4_102_444_800,
            signature: sign(&sk, &channel, 5000, 4_102_444_800),
        };
        assert_eq!(
            check_voucher(&expiring, &config, &channel)
                .unwrap_err()
                .code,
            errors::INVALID_VOUCHER_EXPIRY
        );

        // Tampered amount: the signature covers it, so it no longer verifies.
        let mut tampered = good.clone();
        tampered.max_claimable_amount = "6000".to_string();
        assert_eq!(
            check_voucher(&tampered, &config, &channel)
                .unwrap_err()
                .code,
            errors::INVALID_VOUCHER_SIGNATURE
        );

        // Signed by a key the channel config does not name.
        let mut other = config.clone();
        other.payer_authorizer = key_b58(&key(8));
        assert_eq!(
            check_voucher(&good, &other, &channel).unwrap_err().code,
            errors::INVALID_VOUCHER_SIGNATURE
        );
    }

    #[test]
    fn cooperative_close_hints_are_refused_but_plain_refunds_pass() {
        let (_, config) = requirements(&key_b58(&key(1)));
        let plain = BatchPayload::Refund {
            channel_config: config.clone(),
            transaction: "b64".to_string(),
            voucher: None,
            close_authorization: None,
            amount: None,
        };
        assert!(check_no_cooperative_close(&plain).is_ok());

        let with_voucher = BatchPayload::Refund {
            channel_config: config.clone(),
            transaction: "b64".to_string(),
            voucher: Some(BatchVoucher {
                channel_id: PAY_TO.to_string(),
                max_claimable_amount: "1".to_string(),
                expires_at: 0,
                signature: "sig".to_string(),
            }),
            close_authorization: None,
            amount: None,
        };
        assert_eq!(
            check_no_cooperative_close(&with_voucher).unwrap_err().code,
            errors::INVALID_CLOSE_AUTHORIZATION
        );

        // Paid-request payloads are unaffected.
        let deposit = BatchPayload::Deposit {
            channel_config: config,
            voucher: Some(BatchVoucher {
                channel_id: PAY_TO.to_string(),
                max_claimable_amount: "1".to_string(),
                expires_at: 0,
                signature: "sig".to_string(),
            }),
            deposit: BatchDeposit {
                amount: "1".to_string(),
                transaction: "b64".to_string(),
            },
            authorization: None,
        };
        assert!(check_no_cooperative_close(&deposit).is_ok());
        assert!(check_client_signed_payload(&deposit).is_ok());
    }

    #[test]
    fn corrective_state_is_adopted_only_against_a_client_signed_proof() {
        let sk = key(9);
        let (requirements, config) = requirements(&key_b58(&sk));
        let program_id = pc::default_program_id();
        let channel = derive_channel_id(&config, &requirements.extra.fee_payer, &program_id)
            .expect("derivable");
        let channel_b58 = pc::pubkey_string(&channel);

        let proof = VoucherState {
            signed_max_claimable: "3000".to_string(),
            expires_at: 0,
            signature: sign(&sk, &channel, 3000, 0),
        };
        assert_eq!(
            check_corrective_voucher_state(&proof, &channel_b58, &config.payer_authorizer, 3000)
                .unwrap(),
            3000
        );

        // A server claiming more charged than it can prove is rejected: this is
        // the check that stops a corrective 402 from inflating what the client
        // will sign next.
        let err =
            check_corrective_voucher_state(&proof, &channel_b58, &config.payer_authorizer, 3001)
                .unwrap_err();
        assert_eq!(err.code, errors::INVALID_CUMULATIVE_AMOUNT_MISMATCH);

        // A proof signed by someone other than the client's own authorizer.
        let forged = VoucherState {
            signed_max_claimable: "3000".to_string(),
            expires_at: 0,
            signature: sign(&key(10), &channel, 3000, 0),
        };
        assert_eq!(
            check_corrective_voucher_state(&forged, &channel_b58, &config.payer_authorizer, 3000)
                .unwrap_err()
                .code,
            errors::INVALID_VOUCHER_SIGNATURE
        );
    }
}
