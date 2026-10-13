//! Explicit opt-in client for the atomic V2 channel-charge profile.

use solana_keychain::{SolanaSigner, TransactionSigner};

use crate::core::{payment_channel::v1, payment_channel::v2::ChannelHooks, signing, tx};
use crate::mpp::{
    error::Error,
    protocol::{
        channel_charge::{compile, terms, verify_transaction},
        core::{PaymentChallenge, PaymentCredential},
        intents::ChargeRequest,
        solana::{CredentialPayload, MethodDetails},
    },
};

/// Sign the exact voucher and the funding payer's transaction slot, leaving the
/// payee/sponsor slots for server co-signing. No client identity round-trip.
///
/// `expected_hooks` is a caller-owned allowlist, never copied from an untrusted
/// challenge. Use empty hooks to opt into the non-hook profile only. Callers must
/// approve the challenge amount/network/recipient before calling this low-level API.
pub async fn build_channel_charge_credential(
    payer: &dyn TransactionSigner,
    voucher_signer: &dyn SolanaSigner,
    challenge: &PaymentChallenge,
    expected_hooks: &ChannelHooks,
    salt: u64,
) -> Result<PaymentCredential, Error> {
    build_channel_charge_credential_with_options(
        payer,
        voucher_signer,
        challenge,
        expected_hooks,
        salt,
        None,
    )
    .await
}

/// As [`build_channel_charge_credential`], capped to the wallet's supported
/// transaction version. A packet that cannot fit fails before wallet signing.
pub async fn build_channel_charge_credential_with_options(
    payer: &dyn TransactionSigner,
    voucher_signer: &dyn SolanaSigner,
    challenge: &PaymentChallenge,
    expected_hooks: &ChannelHooks,
    salt: u64,
    max_tx_version: Option<tx::TxVersion>,
) -> Result<PaymentCredential, Error> {
    if challenge.method.as_str() != "solana" || !challenge.intent.is_charge() {
        return Err(Error::InvalidConfig("not a Solana charge challenge".into()));
    }
    let request: ChargeRequest = challenge.request.decode()?;
    let details: MethodDetails = serde_json::from_value(
        request
            .method_details
            .clone()
            .ok_or_else(|| Error::InvalidConfig("missing methodDetails".into()))?,
    )
    .map_err(|e| Error::InvalidConfig(e.to_string()))?;
    let mut terms = terms(
        &request,
        &details,
        challenge
            .expires
            .as_deref()
            .ok_or_else(|| Error::InvalidConfig("missing expiry".into()))?,
        payer.pubkey(),
        voucher_signer.pubkey(),
        salt,
    )?;
    if &terms.hooks != expected_hooks {
        return Err(Error::InvalidConfig(
            "channel charge hook policy mismatch".into(),
        ));
    }
    if terms.expires_at <= time::OffsetDateTime::now_utc().unix_timestamp() {
        return Err(Error::InvalidConfig(
            "channel charge challenge expired".into(),
        ));
    }
    let convert = |e: crate::core::Error| Error::InvalidConfig(e.to_string());
    terms.version =
        tx::negotiate(details.transaction_versions.as_deref(), max_tx_version).map_err(convert)?;
    // Size-check before asking either wallet to sign.
    compile(&terms, &challenge.id, &[0; 64])?;
    let voucher = v1::voucher_message_bytes(
        &v1::derive_channel_addresses(&terms.params).channel,
        terms.params.deposit,
        terms.expires_at,
    )
    .map_err(convert)?;
    let signature = voucher_signer
        .sign_message(&voucher)
        .await
        .map_err(|e| Error::InvalidConfig(format!("voucher signing failed: {e}")))?;
    let bytes: [u8; 64] = signature
        .as_ref()
        .try_into()
        .map_err(|_| Error::InvalidConfig("invalid voucher signature length".into()))?;
    let mut transaction = compile(&terms, &challenge.id, &bytes)?;
    signing::sign_versioned_transaction_slot(payer, &mut transaction)
        .await
        .map_err(convert)?;
    verify_transaction(&transaction, &challenge.to_echo(), expected_hooks)?;
    Ok(PaymentCredential {
        challenge: challenge.to_echo(),
        payload: serde_json::to_value(CredentialPayload::Transaction {
            transaction: tx::encode(&transaction).map_err(convert)?,
        })
        .map_err(|e| Error::InvalidConfig(e.to_string()))?,
        source: None,
    })
}
