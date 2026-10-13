//! Explicit V2 payment-channel ABI. Hooks execute inside the channel instruction;
//! they are never emitted as independent transaction instructions.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

use super::v1;
use crate::core::{Error, Result};
use crate::generated::payment_channels::generated::accounts::Channel;

pub const PAYMENT_CHANNELS_PROGRAM_ID: &str = "CHNLxBtXw7VPqd5GMcbtVoEbn4ehyaSoiHj56Ao5sWkJ";
pub const CHANNEL_ACCOUNT_SIZE: usize = 1121;
pub const HOOK_DESCRIPTOR_SIZE: usize = 206;
pub const MAX_HOOK_ACCOUNTS: usize = 4;
pub const MAX_STATIC_DATA: usize = 32;

/// Additional callback accounts never acquire signer privileges.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HookAccount {
    pub address: String,
    pub writable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HookDescriptor {
    pub program_id: String,
    pub entrypoint: [u8; 8],
    #[serde(default)]
    pub accounts: Vec<HookAccount>,
    #[serde(default)]
    pub static_data: Vec<u8>,
}

/// Slot order is part of the ABI, independent of JSON object key order.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChannelHooks {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pre_fund: Option<HookDescriptor>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub post_fund: Option<HookDescriptor>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pre_distribute: Option<HookDescriptor>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub post_distribute: Option<HookDescriptor>,
}

fn invalid(message: &str) -> Error {
    Error::Other(format!("payment-channel ABI: {message}"))
}

impl ChannelHooks {
    pub fn slots(&self) -> [Option<&HookDescriptor>; 4] {
        [
            self.pre_fund.as_ref(),
            self.post_fund.as_ref(),
            self.pre_distribute.as_ref(),
            self.post_distribute.as_ref(),
        ]
    }

    pub fn is_empty(&self) -> bool {
        self.slots().iter().all(Option::is_none)
    }

    pub fn validate(&self) -> Result<()> {
        for hook in self.slots().into_iter().flatten() {
            let program = v1::parse_pubkey(&hook.program_id)?;
            if program == Pubkey::default()
                || program == v1::parse_pubkey(PAYMENT_CHANNELS_PROGRAM_ID)?
            {
                return Err(invalid("enabled hook has zero or self target program"));
            }
            if hook.accounts.len() > MAX_HOOK_ACCOUNTS || hook.static_data.len() > MAX_STATIC_DATA {
                return Err(invalid("hook exceeds account or static-data bounds"));
            }
            let mut seen = std::collections::HashSet::new();
            for account in &hook.accounts {
                let address = v1::parse_pubkey(&account.address)?;
                if !seen.insert(address) || address == program {
                    return Err(invalid("duplicate or target-aliasing hook account"));
                }
            }
        }
        Ok(())
    }

    /// Compact `open` suffix: enabled byte followed by only used data/accounts.
    pub fn encode_open_suffix(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut bytes = Vec::new();
        for slot in self.slots() {
            bytes.push(u8::from(slot.is_some()));
            if let Some(hook) = slot {
                bytes.extend_from_slice(v1::parse_pubkey(&hook.program_id)?.as_ref());
                bytes.extend_from_slice(&hook.entrypoint);
                bytes.push(hook.accounts.len() as u8);
                bytes.push(hook.static_data.len() as u8);
                bytes.extend_from_slice(&hook.static_data);
                for account in &hook.accounts {
                    bytes.extend_from_slice(v1::parse_pubkey(&account.address)?.as_ref());
                    bytes.push(u8::from(account.writable));
                }
            }
        }
        Ok(bytes)
    }

    /// Canonical fixed account representation; unused bytes are always zero.
    pub fn encode_fixed(&self) -> Result<[u8; 4 * HOOK_DESCRIPTOR_SIZE]> {
        self.validate()?;
        let mut bytes = [0; 4 * HOOK_DESCRIPTOR_SIZE];
        for (index, hook) in self.slots().into_iter().enumerate() {
            if let Some(hook) = hook {
                let out = &mut bytes[index * HOOK_DESCRIPTOR_SIZE..][..HOOK_DESCRIPTOR_SIZE];
                out[..32].copy_from_slice(v1::parse_pubkey(&hook.program_id)?.as_ref());
                out[32..40].copy_from_slice(&hook.entrypoint);
                out[40] = hook.accounts.len() as u8;
                out[41] = hook.static_data.len() as u8;
                out[42..42 + hook.static_data.len()].copy_from_slice(&hook.static_data);
                for (index, account) in hook.accounts.iter().enumerate() {
                    let offset = 74 + index * 33;
                    out[offset..offset + 32]
                        .copy_from_slice(v1::parse_pubkey(&account.address)?.as_ref());
                    out[offset + 32] = u8::from(account.writable);
                }
            }
        }
        Ok(bytes)
    }
}

/// A known program and its matching ABI; unknown programs fail closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Deployment {
    pub program_id: Pubkey,
    pub version: u8,
}

impl Default for Deployment {
    fn default() -> Self {
        Self {
            program_id: v1::default_program_id(),
            version: 1,
        }
    }
}

pub fn resolve_deployment(program: Pubkey, version: Option<u8>) -> Result<Deployment> {
    Deployment::resolve(program, version)
}

impl Deployment {
    /// Decode RPC data only after verifying its owner against the selected deployment.
    pub fn decode_account(&self, owner: &Pubkey, data: &[u8]) -> Result<ChannelState> {
        if owner != &self.program_id {
            return Err(invalid("channel account owner mismatch"));
        }
        self.decode_channel(data)
    }

    pub fn resolve(program_id: Pubkey, version: Option<u8>) -> Result<Self> {
        let actual = if program_id == v1::default_program_id() {
            1
        } else if program_id == v1::parse_pubkey(PAYMENT_CHANNELS_PROGRAM_ID)? {
            2
        } else {
            return Err(invalid("unknown channel program"));
        };
        if version.unwrap_or(1) != actual {
            return Err(invalid("program and ABI version mismatch"));
        }
        Ok(Self {
            program_id,
            version: actual,
        })
    }

    pub fn decode_channel(&self, data: &[u8]) -> Result<ChannelState> {
        // Revalidate because the public fields are useful to callers but mutable.
        Self::resolve(self.program_id, Some(self.version))?;
        if self.version == 2 {
            return decode_channel(data);
        }
        Ok(ChannelState {
            channel: decode_base(data, 1)?,
            hooks: ChannelHooks::default(),
            guard: 0,
            operation_sequence: 0,
            config_hash: [0; 32],
        })
    }
}

#[derive(Debug, Clone)]
pub struct ChannelState {
    pub channel: Channel,
    pub hooks: ChannelHooks,
    pub guard: u8,
    pub operation_sequence: u64,
    pub config_hash: [u8; 32],
}

fn decode_base(data: &[u8], version: u8) -> Result<Channel> {
    if data.len() != 256 || data[0] != 1 || data[1] != version || data[3] > 3 {
        return Err(invalid("invalid channel length, version, or status"));
    }
    Channel::from_bytes(data).map_err(|_| invalid("invalid channel account"))
}

pub fn decode_channel(data: &[u8]) -> Result<ChannelState> {
    if data.len() != CHANNEL_ACCOUNT_SIZE {
        return Err(invalid("invalid V2 channel length"));
    }
    let channel = decode_base(&data[..256], 2)?;
    if data[256] != 0 {
        return Err(invalid("channel callback guard is active"));
    }
    let mut slots: [Option<HookDescriptor>; 4] = Default::default();
    for (index, slot) in slots.iter_mut().enumerate() {
        let raw = &data[297 + index * HOOK_DESCRIPTOR_SIZE..][..HOOK_DESCRIPTOR_SIZE];
        if raw[..32] == [0; 32] {
            if raw.iter().any(|byte| *byte != 0) {
                return Err(invalid("disabled hook has nonzero payload"));
            }
            continue;
        }
        let count = usize::from(raw[40]);
        let len = usize::from(raw[41]);
        if count > MAX_HOOK_ACCOUNTS || len > MAX_STATIC_DATA {
            return Err(invalid("invalid hook bounds"));
        }
        if raw[42 + len..74].iter().any(|byte| *byte != 0)
            || raw[74 + count * 33..].iter().any(|byte| *byte != 0)
        {
            return Err(invalid("noncanonical hook padding"));
        }
        let mut accounts = Vec::with_capacity(count);
        for index in 0..count {
            let offset = 74 + index * 33;
            if raw[offset + 32] > 1 {
                return Err(invalid("invalid hook writable flag"));
            }
            accounts.push(HookAccount {
                address: Pubkey::new_from_array(raw[offset..offset + 32].try_into().unwrap())
                    .to_string(),
                writable: raw[offset + 32] == 1,
            });
        }
        *slot = Some(HookDescriptor {
            program_id: Pubkey::new_from_array(raw[..32].try_into().unwrap()).to_string(),
            entrypoint: raw[32..40].try_into().unwrap(),
            accounts,
            static_data: raw[42..42 + len].to_vec(),
        });
    }
    let [pre_fund, post_fund, pre_distribute, post_distribute] = slots;
    let hooks = ChannelHooks {
        pre_fund,
        post_fund,
        pre_distribute,
        post_distribute,
    };
    hooks.validate()?;
    if hooks.config_hash()? != data[265..297] {
        return Err(invalid("hook configuration hash mismatch"));
    }
    Ok(ChannelState {
        channel,
        hooks,
        guard: 0,
        operation_sequence: u64::from_le_bytes(data[257..265].try_into().unwrap()),
        config_hash: data[265..297].try_into().unwrap(),
    })
}

impl ChannelHooks {
    pub fn config_hash(&self) -> Result<[u8; 32]> {
        Ok(Sha256::digest(self.encode_fixed()?).into())
    }
}

/// Capability PDA: the program signs only this dedicated callback authority.
pub fn find_callback_authority(
    channel: &Pubkey,
    config_hash: &[u8; 32],
    phase: u8,
    target: &Pubkey,
    program_id: &Pubkey,
) -> Result<(Pubkey, u8)> {
    Deployment::resolve(*program_id, Some(2))?;
    if phase > 3 {
        return Err(invalid("invalid callback phase"));
    }
    Ok(Pubkey::find_program_address(
        &[
            b"channel_hook",
            channel.as_ref(),
            config_hash,
            &[phase],
            target.as_ref(),
        ],
        program_id,
    ))
}

fn append_hooks(
    instruction: &mut Instruction,
    channel: &Pubkey,
    hooks: &ChannelHooks,
    phases: std::ops::Range<usize>,
) -> Result<()> {
    let program = v1::from_address(&instruction.program_id);
    Deployment::resolve(program, Some(2))?;
    let hash = hooks.config_hash()?;
    for phase in phases {
        if let Some(hook) = hooks.slots()[phase] {
            let target = v1::parse_pubkey(&hook.program_id)?;
            let authority =
                find_callback_authority(channel, &hash, phase as u8, &target, &program)?.0;
            instruction
                .accounts
                .push(AccountMeta::new_readonly(v1::to_address(&target), false));
            instruction
                .accounts
                .push(AccountMeta::new_readonly(v1::to_address(&authority), false));
            for account in &hook.accounts {
                let address = v1::parse_pubkey(&account.address)?;
                if address == *channel || address == authority {
                    return Err(invalid("hook extra aliases channel or callback authority"));
                }
                instruction.accounts.push(if account.writable {
                    AccountMeta::new(v1::to_address(&address), false)
                } else {
                    AccountMeta::new_readonly(v1::to_address(&address), false)
                });
            }
        }
    }
    Ok(())
}

pub fn build_open_instruction(
    params: &v1::OpenChannelParams,
    hooks: &ChannelHooks,
) -> Result<Instruction> {
    let mut instruction = v1::build_open_instruction(params);
    instruction.data.extend(hooks.encode_open_suffix()?);
    append_hooks(
        &mut instruction,
        &v1::derive_channel_addresses(params).channel,
        hooks,
        0..2,
    )?;
    Ok(instruction)
}

#[allow(clippy::too_many_arguments)]
pub fn build_top_up_instruction(
    payer: &Pubkey,
    channel: &Pubkey,
    mint: &Pubkey,
    amount: u64,
    token_program: &Pubkey,
    program_id: &Pubkey,
    hooks: &ChannelHooks,
) -> Result<Instruction> {
    let mut instruction =
        v1::build_top_up_instruction(payer, channel, mint, amount, token_program, program_id);
    append_hooks(&mut instruction, channel, hooks, 0..2)?;
    Ok(instruction)
}

#[allow(clippy::too_many_arguments)]
pub fn build_distribute_instruction(
    channel: &Pubkey,
    payer: &Pubkey,
    rent_payer: &Pubkey,
    payee: &Pubkey,
    treasury: &Pubkey,
    mint: &Pubkey,
    recipients: &[v1::Distribution],
    token_program: &Pubkey,
    program_id: &Pubkey,
    hooks: &ChannelHooks,
) -> Result<Instruction> {
    let mut instruction = v1::build_distribute_instruction(
        channel,
        payer,
        rent_payer,
        payee,
        treasury,
        mint,
        recipients,
        token_program,
        program_id,
    );
    append_hooks(&mut instruction, channel, hooks, 2..4)?;
    Ok(instruction)
}

/// Return sealed unused principal through the same mandatory distribution hooks.
pub fn build_withdraw_payer_instruction(
    payer: &Pubkey,
    channel: &Pubkey,
    mint: &Pubkey,
    token_program: &Pubkey,
    program_id: &Pubkey,
    hooks: &ChannelHooks,
) -> Result<Instruction> {
    use crate::generated::payment_channels::generated::instructions::WithdrawPayer;

    let mut instruction = WithdrawPayer {
        payer: v1::to_address(payer),
        channel: v1::to_address(channel),
        channel_token_account: v1::to_address(
            &v1::find_associated_token_address(channel, mint, token_program).0,
        ),
        payer_token_account: v1::to_address(
            &v1::find_associated_token_address(payer, mint, token_program).0,
        ),
        mint: v1::to_address(mint),
        token_program: v1::to_address(token_program),
    }
    .instruction();
    instruction.program_id = v1::to_address(program_id);
    append_hooks(&mut instruction, channel, hooks, 2..4)?;
    Ok(instruction)
}

#[allow(clippy::too_many_arguments)]
pub async fn build_open_payment_channel_tx_with_options(
    signer: &dyn solana_keychain::TransactionSigner,
    payee: &Pubkey,
    mint: &Pubkey,
    authorized_signer: &Pubkey,
    salt: u64,
    open_slot: u64,
    deposit: u64,
    grace_period: u32,
    recipients: Vec<v1::Distribution>,
    token_program: &Pubkey,
    program_id: &Pubkey,
    fee_payer: &Pubkey,
    recent_blockhash: solana_hash::Hash,
    options: &v1::OpenTxOptions,
    hooks: &ChannelHooks,
) -> Result<v1::PaymentChannelOpenTransaction> {
    let params = v1::OpenChannelParams {
        payer: signer.pubkey(),
        rent_payer: *fee_payer,
        payee: *payee,
        mint: *mint,
        authorized_signer: *authorized_signer,
        salt,
        open_slot,
        deposit,
        grace_period,
        recipients,
        token_program: *token_program,
        program_id: *program_id,
    };
    let channel_id = v1::derive_channel_addresses(&params).channel;
    let mut instructions = vec![build_open_instruction(&params, hooks)?];
    if let Some(memo) = options.memo.as_deref() {
        if memo.len() > v1::OPEN_MAX_MEMO_BYTES {
            return Err(invalid("open memo exceeds maximum length"));
        }
        instructions.push(Instruction {
            program_id: v1::memo_program_id(),
            accounts: vec![],
            data: memo.as_bytes().to_vec(),
        });
    }
    let mut tx = crate::core::tx::build_unsigned(
        options.version,
        fee_payer,
        &instructions,
        recent_blockhash,
        options.compute_budget.as_ref(),
    )?;
    crate::core::signing::sign_versioned_transaction_slot(signer, &mut tx)
        .await
        .map_err(|error| Error::Other(format!("payment-channel open signing failed: {error}")))?;
    Ok(v1::PaymentChannelOpenTransaction {
        channel_id,
        transaction: crate::core::tx::encode(&tx)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hooks() -> ChannelHooks {
        ChannelHooks {
            pre_fund: Some(HookDescriptor {
                program_id: Pubkey::new_from_array([8; 32]).to_string(),
                entrypoint: *b"prefund!",
                accounts: vec![HookAccount {
                    address: Pubkey::new_from_array([9; 32]).to_string(),
                    writable: true,
                }],
                static_data: vec![4, 5],
            }),
            ..Default::default()
        }
    }

    fn state(hooks: &ChannelHooks) -> Vec<u8> {
        let mut bytes = vec![0; CHANNEL_ACCOUNT_SIZE];
        bytes[0] = 1;
        bytes[1] = 2;
        bytes[265..297].copy_from_slice(&hooks.config_hash().unwrap());
        bytes[297..].copy_from_slice(&hooks.encode_fixed().unwrap());
        bytes
    }

    #[test]
    fn fixed_and_compact_layouts() {
        let hooks = hooks();
        let bytes = hooks.encode_fixed().unwrap();
        assert_eq!(bytes.len(), 824);
        // Independent golden digest of the existing hooks fixture.
        assert_eq!(
            hooks.config_hash().unwrap(),
            [
                0x2d, 0x8e, 0xbd, 0x54, 0xef, 0xcc, 0xdc, 0xf0, 0xde, 0xce, 0xea, 0x66, 0xa2, 0x70,
                0xba, 0x45, 0xba, 0xb8, 0xd6, 0xc0, 0xa6, 0xd8, 0xea, 0xb1, 0xf2, 0x1a, 0x0d, 0x81,
                0xf4, 0xc9, 0xcf, 0x4d,
            ]
        );
        assert_eq!(&bytes[32..42], b"prefund!\x01\x02");
        assert_eq!(&bytes[42..44], &[4, 5]);
        assert_eq!(bytes[106], 1);
        assert!(bytes[107..].iter().all(|byte| *byte == 0));
        let compact = hooks.encode_open_suffix().unwrap();
        assert_eq!(compact.len(), 1 + 42 + 2 + 33 + 3);
        assert_eq!(compact[0], 1);
        assert_eq!(&compact[43..45], &[4, 5]);
        assert_eq!(decode_channel(&state(&hooks)).unwrap().hooks, hooks);
    }

    #[test]
    fn strict_decoder_rejects_corruption_and_trailing_data() {
        let valid = state(&hooks());
        for offset in [
            0,
            1,
            3,
            256,
            265,
            297 + 40,
            297 + 41,
            297 + 106,
            297 + 44,
            297 + 206 + 32,
        ] {
            let mut bad = valid.clone();
            bad[offset] = 255;
            assert!(decode_channel(&bad).is_err(), "offset {offset}");
        }
        for len in [0, 255, 256, 1120] {
            assert!(decode_channel(&valid[..len]).is_err());
        }
        let mut bad = valid;
        bad.push(0);
        assert!(decode_channel(&bad).is_err());
    }

    #[test]
    fn deployment_resolution_is_explicit_and_fail_closed() {
        assert_eq!(
            Deployment::resolve(v1::default_program_id(), None)
                .unwrap()
                .version,
            1
        );
        let v2 = v1::parse_pubkey(PAYMENT_CHANNELS_PROGRAM_ID).unwrap();
        assert_eq!(Deployment::resolve(v2, Some(2)).unwrap().version, 2);
        assert!(Deployment::resolve(v2, None).is_err());
        assert!(Deployment::resolve(v2, Some(1)).is_err());
        assert!(Deployment::resolve(Pubkey::new_from_array([5; 32]), None).is_err());
        assert!(Deployment::resolve(v1::default_program_id(), Some(3)).is_err());
    }

    #[test]
    fn top_up_keeps_data_and_appends_only_active_pair_without_signers() {
        let program = v1::parse_pubkey(PAYMENT_CHANNELS_PROGRAM_ID).unwrap();
        let payer = Pubkey::new_from_array([1; 32]);
        let channel = Pubkey::new_from_array([2; 32]);
        let mint = Pubkey::new_from_array([3; 32]);
        let token = Pubkey::new_from_array([4; 32]);
        let hooks = hooks();
        let base = v1::build_top_up_instruction(&payer, &channel, &mint, 99, &token, &program);
        let ix = build_top_up_instruction(&payer, &channel, &mint, 99, &token, &program, &hooks)
            .unwrap();
        assert_eq!(ix.data, base.data);
        assert_eq!(ix.accounts.len(), base.accounts.len() + 3);
        assert!(ix.accounts[base.accounts.len()..]
            .iter()
            .all(|account| !account.is_signer));
        assert!(ix.accounts.last().unwrap().is_writable);
        let mut duplicate = hooks.clone();
        let account = duplicate.pre_fund.as_ref().unwrap().accounts[0].clone();
        duplicate.pre_fund.as_mut().unwrap().accounts.push(account);
        assert!(duplicate.validate().is_err());
    }

    #[test]
    fn withdrawal_uses_distribution_hooks_and_preserves_payer_authority() {
        let payer = Pubkey::new_unique();
        let channel = Pubkey::new_unique();
        let mint = Pubkey::new_unique();
        let token = v1::parse_pubkey("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA").unwrap();
        let program = v1::parse_pubkey(PAYMENT_CHANNELS_PROGRAM_ID).unwrap();
        let mut config = hooks();
        config.post_distribute = config.pre_fund.clone();
        let ix =
            build_withdraw_payer_instruction(&payer, &channel, &mint, &token, &program, &config)
                .unwrap();
        assert_eq!(ix.data, [8]);
        assert_eq!(ix.program_id, v1::to_address(&program));
        assert_eq!(ix.accounts.len(), 9);
        assert!(ix.accounts[0].is_signer);
        assert!(ix.accounts[1..].iter().all(|account| !account.is_signer));
        assert_eq!(
            ix.accounts[3].pubkey,
            v1::to_address(&v1::find_associated_token_address(&payer, &mint, &token).0)
        );
        let target =
            v1::parse_pubkey(&config.post_distribute.as_ref().unwrap().program_id).unwrap();
        let authority = find_callback_authority(
            &channel,
            &config.config_hash().unwrap(),
            3,
            &target,
            &program,
        )
        .unwrap()
        .0;
        assert_eq!(ix.accounts[7].pubkey, v1::to_address(&authority));
        assert!(build_withdraw_payer_instruction(
            &payer,
            &channel,
            &mint,
            &token,
            &v1::default_program_id(),
            &config,
        )
        .is_err());
    }

    #[test]
    fn serde_rejects_signer_privileges() {
        let json = serde_json::to_value(hooks()).unwrap();
        assert!(json.get("preFund").is_some());
        assert_eq!(
            serde_json::from_value::<ChannelHooks>(json.clone()).unwrap(),
            hooks()
        );
        let mut invalid = json;
        invalid["preFund"]["accounts"][0]["signer"] = true.into();
        assert!(serde_json::from_value::<ChannelHooks>(invalid).is_err());
    }

    #[test]
    fn open_and_distribute_use_distinct_pairs_and_preserve_base_accounts() {
        let program = v1::parse_pubkey(PAYMENT_CHANNELS_PROGRAM_ID).unwrap();
        let params = v1::OpenChannelParams {
            payer: Pubkey::new_from_array([1; 32]),
            rent_payer: Pubkey::new_from_array([2; 32]),
            payee: Pubkey::new_from_array([3; 32]),
            mint: Pubkey::new_from_array([4; 32]),
            authorized_signer: Pubkey::new_from_array([5; 32]),
            salt: 6,
            open_slot: 7,
            deposit: 100,
            grace_period: 60,
            recipients: vec![],
            token_program: Pubkey::new_from_array([6; 32]),
            program_id: program,
        };
        let mut hooks = hooks();
        hooks.post_fund = hooks.pre_fund.clone();
        hooks.pre_distribute = hooks.pre_fund.clone();
        hooks.post_distribute = hooks.pre_fund.clone();
        let base_open = v1::build_open_instruction(&params);
        let open = build_open_instruction(&params, &hooks).unwrap();
        assert_eq!(&open.data[..base_open.data.len()], &base_open.data);
        assert_eq!(
            &open.data[base_open.data.len()..],
            &hooks.encode_open_suffix().unwrap()
        );
        assert_eq!(
            &open.accounts[..base_open.accounts.len()],
            &base_open.accounts
        );
        assert_eq!(open.accounts.len(), base_open.accounts.len() + 6);
        let channel = v1::derive_channel_addresses(&params).channel;
        let treasury = Pubkey::new_from_array([10; 32]);
        let base_distribute = v1::build_distribute_instruction(
            &channel,
            &params.payer,
            &params.rent_payer,
            &params.payee,
            &treasury,
            &params.mint,
            &params.recipients,
            &params.token_program,
            &program,
        );
        let distribute = build_distribute_instruction(
            &channel,
            &params.payer,
            &params.rent_payer,
            &params.payee,
            &treasury,
            &params.mint,
            &params.recipients,
            &params.token_program,
            &program,
            &hooks,
        )
        .unwrap();
        assert_eq!(distribute.data, base_distribute.data);
        assert_eq!(distribute.accounts[10].pubkey, v1::to_address(&program));
        assert_eq!(open.accounts[13].pubkey, v1::to_address(&program));
        assert_eq!(
            &distribute.accounts[..base_distribute.accounts.len()],
            &base_distribute.accounts
        );
        assert_eq!(
            distribute.accounts.len(),
            base_distribute.accounts.len() + 6
        );
        let fund_authority = open.accounts[base_open.accounts.len() + 1].pubkey;
        let distribute_authority = distribute.accounts[base_distribute.accounts.len() + 1].pubkey;
        assert_ne!(fund_authority, distribute_authority);
        assert!(distribute.accounts[base_distribute.accounts.len()..]
            .iter()
            .all(|account| !account.is_signer));

        let mut wrong_program = params;
        wrong_program.program_id = v1::default_program_id();
        assert!(build_open_instruction(&wrong_program, &hooks).is_err());
    }

    #[test]
    fn bounded_descriptors_and_account_owner_are_checked() {
        let mut configured = hooks();
        configured.pre_fund.as_mut().unwrap().static_data = vec![0; 33];
        assert!(configured.encode_open_suffix().is_err());
        configured.pre_fund.as_mut().unwrap().static_data = vec![0; 32];
        assert!(configured.encode_open_suffix().is_ok());
        configured.pre_fund.as_mut().unwrap().accounts = (20..25)
            .map(|byte| HookAccount {
                address: Pubkey::new_from_array([byte; 32]).to_string(),
                writable: false,
            })
            .collect();
        assert!(configured.encode_fixed().is_err());
        configured.pre_fund.as_mut().unwrap().accounts.pop();
        let data = state(&configured);
        assert_eq!(decode_channel(&data).unwrap().hooks, configured);
        let deployment = Deployment::resolve(
            v1::parse_pubkey(PAYMENT_CHANNELS_PROGRAM_ID).unwrap(),
            Some(2),
        )
        .unwrap();
        assert!(deployment
            .decode_account(&v1::default_program_id(), &data)
            .is_err());
        assert!(deployment
            .decode_account(&deployment.program_id, &data)
            .is_ok());
        assert!(Deployment::default().decode_channel(&data).is_err());
        let mut v1_data = vec![0; 256];
        v1_data[0] = 1;
        v1_data[1] = 1;
        assert!(Deployment::default().decode_channel(&v1_data).is_ok());
        assert!(deployment.decode_channel(&v1_data).is_err());
    }
}
