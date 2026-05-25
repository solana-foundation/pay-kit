//! Typed helpers for the payment-channels program.
//!
//! The generated Codama client is kept as a path dependency and re-exported
//! through this module.  Everything here is hand-written adapter code: PDA
//! derivation, associated token derivation, distribution hashing, voucher bytes,
//! and convenience instruction builders.

use std::str::FromStr;

use solana_address::Address;
use solana_instruction::AccountMeta;
use solana_instruction::Instruction;
use solana_pubkey::Pubkey;

use crate::error::{Error, Result};

pub use payment_channels_client as generated;
use payment_channels_client::generated::instructions::{
    DistributeBuilder, FinalizeBuilder, OpenBuilder, RequestCloseBuilder, SettleAndFinalizeBuilder,
    SettleBuilder, TopUpBuilder,
};
use payment_channels_client::generated::types::{
    DistributeArgs, DistributionEntry, OpenArgs, SettleAndFinalizeArgs, SettleArgs, TopUpArgs,
    VoucherArgs,
};

/// Canonical payment-channels program ID deployed to Surfnet.
pub const PAYMENT_CHANNELS_PROGRAM_ID: &str = "GuoKrzaBiZnW5DvJ3yZVE7xHqbcBvaX9SH6P6Cn9gNvc";

/// Channel PDA seed prefix.
pub const CHANNEL_SEED: &[u8] = b"channel";

/// Event authority PDA seed prefix.
pub const EVENT_AUTHORITY_SEED: &[u8] = b"event_authority";

/// Ed25519 precompile program ID.
pub const ED25519_PROGRAM_ID: &str = "Ed25519SigVerify111111111111111111111111111";

/// Instructions sysvar ID.
pub const INSTRUCTIONS_SYSVAR_ID: &str = "Sysvar1nstructions1111111111111111111111111";

/// Rent sysvar ID.
pub const RENT_SYSVAR_ID: &str = "SysvarRent111111111111111111111111111111111";

/// Treasury owner used by the current payment-channels program deployment.
pub const TREASURY_OWNER: [u8; 32] = [
    0xBE, 0xEF, 0xBE, 0xEF, 0xBE, 0xEF, 0xBE, 0xEF, 0xBE, 0xEF, 0xBE, 0xEF, 0xBE, 0xEF, 0xBE, 0xEF,
    0xBE, 0xEF, 0xBE, 0xEF, 0xBE, 0xEF, 0xBE, 0xEF, 0xBE, 0xEF, 0xBE, 0xEF, 0xBE, 0xEF, 0xBE, 0xEF,
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Distribution {
    pub recipient: Pubkey,
    pub bps: u16,
}

#[derive(Debug, Clone)]
pub struct OpenChannelParams {
    pub payer: Pubkey,
    pub payee: Pubkey,
    pub mint: Pubkey,
    pub authorized_signer: Pubkey,
    pub salt: u64,
    pub deposit: u64,
    pub grace_period: u32,
    pub recipients: Vec<Distribution>,
    pub token_program: Pubkey,
    pub program_id: Pubkey,
}

#[derive(Debug, Clone)]
pub struct ChannelAddresses {
    pub channel: Pubkey,
    pub payer_token_account: Pubkey,
    pub channel_token_account: Pubkey,
    pub event_authority: Pubkey,
}

pub fn default_program_id() -> Pubkey {
    Pubkey::from_str(PAYMENT_CHANNELS_PROGRAM_ID).expect("valid payment-channels program id")
}

pub fn instructions_sysvar_id() -> Pubkey {
    Pubkey::from_str(INSTRUCTIONS_SYSVAR_ID).expect("valid instructions sysvar id")
}

pub fn rent_sysvar_id() -> Pubkey {
    Pubkey::from_str(RENT_SYSVAR_ID).expect("valid rent sysvar id")
}

pub fn treasury_owner() -> Pubkey {
    Pubkey::from(TREASURY_OWNER)
}

pub fn parse_pubkey(value: &str) -> Result<Pubkey> {
    Pubkey::from_str(value).map_err(|e| Error::Other(format!("invalid pubkey {value}: {e}")))
}

pub fn pubkey_string(pubkey: &Pubkey) -> String {
    bs58::encode(pubkey.as_ref()).into_string()
}

pub fn to_address(pubkey: &Pubkey) -> Address {
    Address::from(pubkey.to_bytes())
}

pub fn from_address(address: &Address) -> Pubkey {
    Pubkey::from(address.to_bytes())
}

pub fn find_channel_pda(
    payer: &Pubkey,
    payee: &Pubkey,
    mint: &Pubkey,
    authorized_signer: &Pubkey,
    salt: u64,
    program_id: &Pubkey,
) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[
            CHANNEL_SEED,
            payer.as_ref(),
            payee.as_ref(),
            mint.as_ref(),
            authorized_signer.as_ref(),
            &salt.to_le_bytes(),
        ],
        program_id,
    )
}

pub fn find_event_authority_pda(program_id: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[EVENT_AUTHORITY_SEED], program_id)
}

pub fn find_associated_token_address(
    owner: &Pubkey,
    mint: &Pubkey,
    token_program: &Pubkey,
) -> (Pubkey, u8) {
    let ata_program = Pubkey::from_str(crate::protocol::solana::programs::ASSOCIATED_TOKEN_PROGRAM)
        .expect("valid associated token program id");
    Pubkey::find_program_address(
        &[owner.as_ref(), token_program.as_ref(), mint.as_ref()],
        &ata_program,
    )
}

pub fn derive_channel_addresses(params: &OpenChannelParams) -> ChannelAddresses {
    let (channel, _) = find_channel_pda(
        &params.payer,
        &params.payee,
        &params.mint,
        &params.authorized_signer,
        params.salt,
        &params.program_id,
    );
    let (payer_token_account, _) =
        find_associated_token_address(&params.payer, &params.mint, &params.token_program);
    let (channel_token_account, _) =
        find_associated_token_address(&channel, &params.mint, &params.token_program);
    let (event_authority, _) = find_event_authority_pda(&params.program_id);

    ChannelAddresses {
        channel,
        payer_token_account,
        channel_token_account,
        event_authority,
    }
}

pub fn distribution_hash(recipients: &[Distribution]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&(recipients.len() as u32).to_le_bytes());
    for recipient in recipients {
        hasher.update(recipient.recipient.as_ref());
        hasher.update(&recipient.bps.to_le_bytes());
    }
    *hasher.finalize().as_bytes()
}

pub fn voucher_message_bytes(
    channel_id: &Pubkey,
    cumulative_amount: u64,
    expires_at: i64,
) -> Result<Vec<u8>> {
    let voucher = VoucherArgs {
        channel_id: to_address(channel_id),
        cumulative_amount,
        expires_at,
    };
    borsh::to_vec(&voucher)
        .map_err(|e| Error::Other(format!("voucher Borsh serialization failed: {e}")))
}

pub fn build_open_instruction(params: &OpenChannelParams) -> Instruction {
    let addresses = derive_channel_addresses(params);
    let recipients = params
        .recipients
        .iter()
        .map(|entry| DistributionEntry {
            recipient: to_address(&entry.recipient),
            bps: entry.bps,
        })
        .collect();

    let mut ix = OpenBuilder::new()
        .payer(to_address(&params.payer))
        .payee(to_address(&params.payee))
        .mint(to_address(&params.mint))
        .authorized_signer(to_address(&params.authorized_signer))
        .channel(to_address(&addresses.channel))
        .payer_token_account(to_address(&addresses.payer_token_account))
        .channel_token_account(to_address(&addresses.channel_token_account))
        .token_program(to_address(&params.token_program))
        .rent(to_address(&rent_sysvar_id()))
        .associated_token_program(to_address(
            &Pubkey::from_str(crate::protocol::solana::programs::ASSOCIATED_TOKEN_PROGRAM)
                .expect("valid associated token program id"),
        ))
        .event_authority(to_address(&addresses.event_authority))
        .self_program(to_address(&params.program_id))
        .open_args(OpenArgs {
            salt: params.salt,
            deposit: params.deposit,
            grace_period: params.grace_period,
            recipients,
        })
        .instruction();
    ix.program_id = to_address(&params.program_id);
    ix
}

pub fn build_top_up_instruction(
    payer: &Pubkey,
    channel: &Pubkey,
    mint: &Pubkey,
    amount: u64,
    token_program: &Pubkey,
    program_id: &Pubkey,
) -> Instruction {
    let (payer_token_account, _) = find_associated_token_address(payer, mint, token_program);
    let (channel_token_account, _) = find_associated_token_address(channel, mint, token_program);
    let mut ix = TopUpBuilder::new()
        .payer(to_address(payer))
        .channel(to_address(channel))
        .payer_token_account(to_address(&payer_token_account))
        .channel_token_account(to_address(&channel_token_account))
        .mint(to_address(mint))
        .token_program(to_address(token_program))
        .top_up_args(TopUpArgs { amount })
        .instruction();
    ix.program_id = to_address(program_id);
    ix
}

pub fn build_ed25519_verify_instruction(
    authorized_signer: &Pubkey,
    signature: &[u8; 64],
    message: &[u8],
) -> Instruction {
    let public_key_offset: u16 = 16;
    let signature_offset: u16 = public_key_offset + 32;
    let message_data_offset: u16 = signature_offset + 64;
    let message_data_size: u16 = message
        .len()
        .try_into()
        .expect("voucher message fits in ed25519 instruction");
    let current_instruction: u16 = u16::MAX;

    let mut data = Vec::with_capacity(message_data_offset as usize + message.len());
    data.push(1);
    data.push(0);
    data.extend_from_slice(&signature_offset.to_le_bytes());
    data.extend_from_slice(&current_instruction.to_le_bytes());
    data.extend_from_slice(&public_key_offset.to_le_bytes());
    data.extend_from_slice(&current_instruction.to_le_bytes());
    data.extend_from_slice(&message_data_offset.to_le_bytes());
    data.extend_from_slice(&message_data_size.to_le_bytes());
    data.extend_from_slice(&current_instruction.to_le_bytes());
    data.extend_from_slice(authorized_signer.as_ref());
    data.extend_from_slice(signature);
    data.extend_from_slice(message);

    Instruction {
        program_id: to_address(
            &Pubkey::from_str(ED25519_PROGRAM_ID).expect("valid ed25519 program id"),
        ),
        accounts: vec![],
        data,
    }
}

pub fn build_settle_instructions(
    channel: &Pubkey,
    authorized_signer: &Pubkey,
    signature: &[u8; 64],
    cumulative_amount: u64,
    expires_at: i64,
    program_id: &Pubkey,
) -> Result<Vec<Instruction>> {
    let message = voucher_message_bytes(channel, cumulative_amount, expires_at)?;
    let verify = build_ed25519_verify_instruction(authorized_signer, signature, &message);
    let mut settle = SettleBuilder::new()
        .channel(to_address(channel))
        .instructions_sysvar(to_address(&instructions_sysvar_id()))
        .settle_args(SettleArgs {
            voucher: VoucherArgs {
                channel_id: to_address(channel),
                cumulative_amount,
                expires_at,
            },
        })
        .instruction();
    settle.program_id = to_address(program_id);
    Ok(vec![verify, settle])
}

pub fn build_settle_and_finalize_instructions(
    merchant: &Pubkey,
    channel: &Pubkey,
    authorized_signer: &Pubkey,
    signature: Option<&[u8; 64]>,
    cumulative_amount: u64,
    expires_at: i64,
    program_id: &Pubkey,
) -> Result<Vec<Instruction>> {
    let mut instructions = Vec::with_capacity(if signature.is_some() { 2 } else { 1 });
    let has_voucher = if let Some(signature) = signature {
        let message = voucher_message_bytes(channel, cumulative_amount, expires_at)?;
        instructions.push(build_ed25519_verify_instruction(
            authorized_signer,
            signature,
            &message,
        ));
        1
    } else {
        0
    };
    let mut settle_and_finalize = SettleAndFinalizeBuilder::new()
        .merchant(to_address(merchant))
        .channel(to_address(channel))
        .instructions_sysvar(to_address(&instructions_sysvar_id()))
        .settle_and_finalize_args(SettleAndFinalizeArgs {
            voucher: VoucherArgs {
                channel_id: to_address(channel),
                cumulative_amount,
                expires_at,
            },
            has_voucher,
        })
        .instruction();
    settle_and_finalize.program_id = to_address(program_id);
    instructions.push(settle_and_finalize);
    Ok(instructions)
}

pub fn build_request_close_instruction(
    payer: &Pubkey,
    channel: &Pubkey,
    program_id: &Pubkey,
) -> Instruction {
    let mut ix = RequestCloseBuilder::new()
        .payer(to_address(payer))
        .channel(to_address(channel))
        .instruction();
    ix.program_id = to_address(program_id);
    ix
}

pub fn build_finalize_instruction(channel: &Pubkey, program_id: &Pubkey) -> Instruction {
    let mut ix = FinalizeBuilder::new()
        .channel(to_address(channel))
        .instruction();
    ix.program_id = to_address(program_id);
    ix
}

#[allow(clippy::too_many_arguments)]
pub fn build_distribute_instruction(
    channel: &Pubkey,
    payer: &Pubkey,
    payee: &Pubkey,
    treasury: &Pubkey,
    mint: &Pubkey,
    recipients: &[Distribution],
    token_program: &Pubkey,
    program_id: &Pubkey,
) -> Instruction {
    let (channel_token_account, _) = find_associated_token_address(channel, mint, token_program);
    let (payer_token_account, _) = find_associated_token_address(payer, mint, token_program);
    let (payee_token_account, _) = find_associated_token_address(payee, mint, token_program);
    let (treasury_token_account, _) = find_associated_token_address(treasury, mint, token_program);
    let recipient_token_accounts = recipients
        .iter()
        .map(|entry| {
            let (token_account, _) =
                find_associated_token_address(&entry.recipient, mint, token_program);
            AccountMeta::new(to_address(&token_account), false)
        })
        .collect::<Vec<_>>();
    let recipients = recipients
        .iter()
        .map(|entry| DistributionEntry {
            recipient: to_address(&entry.recipient),
            bps: entry.bps,
        })
        .collect();

    let mut ix = DistributeBuilder::new()
        .channel(to_address(channel))
        .payer(to_address(payer))
        .channel_token_account(to_address(&channel_token_account))
        .payer_token_account(to_address(&payer_token_account))
        .payee_token_account(to_address(&payee_token_account))
        .treasury_token_account(to_address(&treasury_token_account))
        .mint(to_address(mint))
        .token_program(to_address(token_program))
        .add_remaining_accounts(&recipient_token_accounts)
        .distribute_args(DistributeArgs { recipients })
        .instruction();
    ix.program_id = to_address(program_id);
    ix
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pk(byte: u8) -> Pubkey {
        Pubkey::from([byte; 32])
    }

    #[test]
    fn distribution_hash_matches_program_preimage_shape() {
        let recipients = vec![
            Distribution {
                recipient: pk(1),
                bps: 7_500,
            },
            Distribution {
                recipient: pk(2),
                bps: 2_500,
            },
        ];

        let mut hasher = blake3::Hasher::new();
        hasher.update(&2u32.to_le_bytes());
        hasher.update(pk(1).as_ref());
        hasher.update(&7_500u16.to_le_bytes());
        hasher.update(pk(2).as_ref());
        hasher.update(&2_500u16.to_le_bytes());

        assert_eq!(
            distribution_hash(&recipients),
            *hasher.finalize().as_bytes()
        );
    }

    #[test]
    fn voucher_message_is_program_borsh_layout() {
        let bytes = voucher_message_bytes(&pk(9), 42, 1234).unwrap();
        assert_eq!(bytes.len(), 48);
        assert_eq!(&bytes[..32], pk(9).as_ref());
        assert_eq!(&bytes[32..40], &42u64.to_le_bytes());
        assert_eq!(&bytes[40..48], &1234i64.to_le_bytes());
    }

    #[test]
    fn channel_pda_is_stable() {
        let program_id = default_program_id();
        let (channel, bump) = find_channel_pda(&pk(1), &pk(2), &pk(3), &pk(4), 99, &program_id);
        let expected = Pubkey::create_program_address(
            &[
                CHANNEL_SEED,
                pk(1).as_ref(),
                pk(2).as_ref(),
                pk(3).as_ref(),
                pk(4).as_ref(),
                &99u64.to_le_bytes(),
                &[bump],
            ],
            &program_id,
        )
        .unwrap();
        assert_eq!(channel, expected);
    }
}
