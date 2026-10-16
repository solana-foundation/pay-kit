//! Exact, atomic V2 channel-backed charges. This grammar is deliberately separate
//! from the direct-transfer instruction allowlist.

use serde::{Deserialize, Serialize};
use solana_hash::Hash;
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use solana_transaction::versioned::VersionedTransaction;
use std::str::FromStr;

use crate::core::{
    payment_channel::{v1, v2},
    tx,
};
use crate::mpp::{
    error::Error,
    protocol::{core::ChallengeEcho, intents::ChargeRequest, solana::MethodDetails},
};

/// Server-advertised policy. Payer, voucher key and salt are client-selected,
/// authenticated by the funding payer's transaction signature, not by a preflight.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChannelChargeProfile {
    pub channel_program: String,
    pub channel_version: u8,
    pub channel_hooks: v2::ChannelHooks,
    pub recent_slot: u64,
}

fn invalid(message: impl Into<String>) -> Error {
    Error::InvalidConfig(format!("channel charge: {}", message.into()))
}

fn key(value: &str) -> Result<Pubkey, Error> {
    Pubkey::from_str(value).map_err(|_| invalid("invalid public key"))
}

fn core_error(error: crate::core::Error) -> Error {
    invalid(error.to_string())
}

/// Validated economic and deployment policy, shared by builder and verifier.
pub(crate) struct Terms {
    pub params: v1::OpenChannelParams,
    pub hooks: v2::ChannelHooks,
    pub blockhash: Hash,
    pub expires_at: i64,
    pub treasury: Pubkey,
    pub version: tx::TxVersion,
}

/// Validate without signing or accessing RPC. SPL Token only: Token-2022 transfer
/// fees and mint-controlled callbacks cannot promise this profile's exact credit.
pub(crate) fn terms(
    request: &ChargeRequest,
    details: &MethodDetails,
    expires: &str,
    payer: Pubkey,
    voucher_signer: Pubkey,
    salt: u64,
) -> Result<Terms, Error> {
    let profile = details
        .channel_charge
        .as_ref()
        .ok_or_else(|| invalid("missing profile"))?;
    let program_id = key(&profile.channel_program)?;
    if profile.channel_version != 2 {
        return Err(invalid("requires V2"));
    }
    let network = details
        .network
        .as_deref()
        .ok_or_else(|| invalid("missing network"))?;
    crate::mpp::program::channel_deployment::resolve_for_network(
        program_id,
        Some(profile.channel_version),
        Some(&profile.channel_hooks),
        network,
    )?;
    if details.confidential.unwrap_or(false) {
        return Err(invalid("confidential channel charges are unsupported"));
    }
    let version =
        tx::negotiate(details.transaction_versions.as_deref(), None).map_err(core_error)?;
    let token_program = key(details
        .token_program
        .as_deref()
        .ok_or_else(|| invalid("missing tokenProgram"))?)?;
    if token_program != key(super::solana::programs::TOKEN_PROGRAM)? {
        return Err(invalid("requires SPL Token"));
    }
    let mint = key(&request.currency)?;
    let recipient = key(request
        .recipient
        .as_deref()
        .ok_or_else(|| invalid("missing recipient"))?)?;
    let fee_payer = match (details.fee_payer, details.fee_payer_key.as_deref()) {
        (Some(true), Some(sponsor)) => key(sponsor)?,
        (None | Some(false), None) => payer,
        _ => return Err(invalid("inconsistent fee payer policy")),
    };
    let payee = if details.fee_payer == Some(true) {
        fee_payer
    } else {
        recipient
    };
    let deposit = request.parse_amount()?;
    if deposit == 0 {
        return Err(invalid("amount must be positive"));
    }
    let splits = details.splits.as_deref().unwrap_or_default();
    super::solana::validate_splits(splits)?;
    let mut primary = deposit;
    let mut amounts = Vec::new();
    let mut seen = std::collections::HashSet::from([recipient, payee]);
    for split in splits {
        let recipient = key(&split.recipient)?;
        let amount = split
            .amount
            .parse::<u64>()
            .map_err(|_| invalid("invalid split amount"))?;
        if amount == 0
            || !seen.insert(recipient)
            || split.memo.is_some()
            || split.ata_creation_required.unwrap_or(false)
        {
            return Err(invalid(
                "unsupported split (zero, duplicate, memo or ATA creation)",
            ));
        }
        primary = primary
            .checked_sub(amount)
            .ok_or_else(|| invalid("splits exceed total amount"))?;
        amounts.push((recipient, amount));
    }
    if primary == 0 {
        return Err(invalid("primary recipient amount must be positive"));
    }
    if recipient != payee {
        amounts.insert(0, (recipient, primary));
    }
    let mut recipients = Vec::new();
    for (recipient, amount) in amounts {
        let numerator = u128::from(amount) * 10_000;
        if numerator % u128::from(deposit) != 0 {
            return Err(invalid(
                "split cannot be represented exactly in basis points",
            ));
        }
        recipients.push(v1::Distribution {
            recipient,
            bps: (numerator / u128::from(deposit)) as u16,
        });
    }
    // Distinct roles keep the server from authorizing its own assets as payer.
    if payer == payee || (details.fee_payer == Some(true) && payer == fee_payer) {
        return Err(invalid("funding payer aliases a server signer"));
    }
    let blockhash = Hash::from_str(
        details
            .recent_blockhash
            .as_deref()
            .ok_or_else(|| invalid("missing recentBlockhash"))?,
    )
    .map_err(|_| invalid("invalid recentBlockhash"))?;
    let expires_at =
        time::OffsetDateTime::parse(expires, &time::format_description::well_known::Rfc3339)
            .map_err(|_| invalid("invalid challenge expiry"))?
            .unix_timestamp();
    Ok(Terms {
        params: v1::OpenChannelParams {
            payer,
            rent_payer: fee_payer,
            payee,
            mint,
            authorized_signer: voucher_signer,
            salt,
            open_slot: profile.recent_slot,
            deposit,
            grace_period: 1,
            recipients,
            token_program,
            program_id,
        },
        hooks: profile.channel_hooks.clone(),
        blockhash,
        expires_at,
        treasury: v1::treasury_owner_for_cluster(network),
        version,
    })
}

pub(crate) fn compile(
    terms: &Terms,
    challenge_id: &str,
    voucher_signature: &[u8; 64],
) -> Result<VersionedTransaction, Error> {
    let p = &terms.params;
    let channel = v1::derive_channel_addresses(p).channel;
    let mut instructions = vec![v2::build_open_instruction(p, &terms.hooks).map_err(core_error)?];
    instructions.extend(
        v1::build_settle_and_seal_instructions(
            &p.payee,
            &channel,
            &p.authorized_signer,
            Some(voucher_signature),
            p.deposit,
            terms.expires_at,
            &p.program_id,
        )
        .map_err(core_error)?,
    );
    instructions.push(
        v2::build_distribute_instruction(
            &channel,
            &p.payer,
            &p.rent_payer,
            &p.payee,
            &terms.treasury,
            &p.mint,
            &p.recipients,
            &p.token_program,
            &p.program_id,
            &terms.hooks,
        )
        .map_err(core_error)?,
    );
    instructions.push(solana_instruction::Instruction {
        program_id: v1::to_address(&v1::memo_program_id()),
        accounts: vec![],
        data: format!("mpp-charge:{challenge_id}").into_bytes(),
    });
    tx::build_unsigned(
        terms.version,
        &p.rent_payer,
        &instructions,
        terms.blockhash,
        None,
    )
    .map_err(core_error)
}

/// Verify the exact compiled grammar before any server signature. Only the
/// client-owned payer, voucher key, salt and voucher signature are extracted;
/// every other byte is reconstructed from authenticated challenge policy.
pub fn verify_transaction(
    transaction: &VersionedTransaction,
    challenge: &ChallengeEcho,
    expected_hooks: &v2::ChannelHooks,
) -> Result<(), Error> {
    let request: ChargeRequest = challenge.request.decode()?;
    let details: MethodDetails = serde_json::from_value(
        request
            .method_details
            .clone()
            .ok_or_else(|| invalid("missing methodDetails"))?,
    )
    .map_err(|_| invalid("invalid methodDetails"))?;
    let profile = details
        .channel_charge
        .as_ref()
        .ok_or_else(|| invalid("missing profile"))?;
    if &profile.channel_hooks != expected_hooks {
        return Err(invalid("hook policy mismatch"));
    }
    let instructions = transaction.message.instructions();
    if instructions.len() != 5 {
        return Err(invalid(
            "expected open, Ed25519, settleAndSeal, distribute, memo",
        ));
    }
    let open = &instructions[0];
    let keys = transaction.message.static_account_keys();
    let account = |index: usize| -> Result<Pubkey, Error> {
        open.accounts
            .get(index)
            .and_then(|i| keys.get(*i as usize))
            .copied()
            .ok_or_else(|| invalid("invalid open account index"))
    };
    let payer = account(0)?;
    let voucher_signer = account(4)?;
    let salt = u64::from_le_bytes(
        open.data
            .get(1..9)
            .ok_or_else(|| invalid("truncated open"))?
            .try_into()
            .map_err(|_| invalid("invalid salt"))?,
    );
    let signature: [u8; 64] = instructions[1]
        .data
        .get(48..112)
        .ok_or_else(|| invalid("truncated voucher"))?
        .try_into()
        .map_err(|_| invalid("invalid voucher signature"))?;
    let mut terms = terms(
        &request,
        &details,
        challenge
            .expires
            .as_deref()
            .ok_or_else(|| invalid("missing expiry"))?,
        payer,
        voucher_signer,
        salt,
    )?;
    let actual_version = tx::TxVersion::of(&transaction.message).map_err(core_error)?;
    if !tx::accepted_versions(details.transaction_versions.as_deref()).contains(&actual_version) {
        return Err(invalid("transaction version not advertised"));
    }
    terms.version = actual_version;
    let expected = compile(&terms, &challenge.id, &signature)?;
    if transaction.message != expected.message
        || transaction.signatures.len() != expected.signatures.len()
    {
        return Err(invalid(
            "transaction differs from exact channel-charge grammar",
        ));
    }
    let voucher = v1::voucher_message_bytes(
        &v1::derive_channel_addresses(&terms.params).channel,
        terms.params.deposit,
        terms.expires_at,
    )
    .map_err(core_error)?;
    if !Signature::from(signature).verify(voucher_signer.as_ref(), &voucher) {
        return Err(invalid("invalid voucher signature"));
    }
    let message = transaction.message.serialize();
    for (index, signature) in transaction.signatures.iter().enumerate() {
        let signer = keys[index];
        // Only server-owned slots may remain unsigned.
        let server_owned = signer == terms.params.payee
            || (details.fee_payer == Some(true) && signer == terms.params.rent_payer);
        if (!server_owned || *signature != Signature::default())
            && !signature.verify(signer.as_ref(), &message)
        {
            return Err(invalid("invalid or missing transaction signature"));
        }
    }
    Ok(())
}

#[cfg(all(test, feature = "client", feature = "server"))]
#[path = "channel_charge_tests.rs"]
mod tests;
