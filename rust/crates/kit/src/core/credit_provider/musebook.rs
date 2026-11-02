//! Musebook credit provider: token-backed API credits spent through V2
//! payment-channel hooks (`themusebook/musebook-credit-provider`).
//!
//! Everything here is pinned per cluster. A merchant only selects the name;
//! program IDs, entrypoint, seeds and hook accounts are never caller-supplied.
//! Only devnet has a deployment. Every other network is unavailable.
//!
//! Hook layout (the same descriptor in the `pre_fund` and `post_distribute` slots;
//! no `post_fund` / `pre_distribute`):
//! `[ledger (w), ledger vault ATA (w), owner ATA (w), SPL Token (ro)]`, entrypoint
//! `b"musebook"`, no static data. The provider's *config* PDA is not a hook
//! account (all four descriptor slots are used). It is passed to the provider's
//! own `initialize`, `deposit` and `authorize` instructions built here.

use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

use crate::core::payment_channel::{v1, v2};

/// Callback entrypoint discriminator checked by the provider program.
pub const ENTRYPOINT: [u8; 8] = *b"musebook";
pub const LEDGER_SEED: &[u8] = b"musebook-credit";
pub const CONFIG_SEED: &[u8] = b"musebook-config";
/// Hooked channel instructions run the provider callback inside the channel
/// instruction. Observed peaks reach about 200k CU depending on PDA bumps, so
/// always request an explicit limit.
pub const COMPUTE_UNIT_LIMIT: u32 = 400_000;
/// The provider custodies classic SPL Token mints only.
pub const TOKEN_PROGRAM_ID: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";

/// Longest authorization window (slots past `open_slot`) an issuer co-signs.
pub const MAX_AUTHORIZATION_SLOTS: u64 = 9_000;
/// Byte offset of `authorization.nonce` in the provider's 332-byte ledger.
const LEDGER_NONCE_OFFSET: usize = 4 + 32 * 4 + 32 * 3 + 8 * 3;
const LEDGER_LEN: usize = 332;

const INITIALIZE: u8 = 0;
const DEPOSIT: u8 = 1;
const AUTHORIZE: u8 = 2;
const CANCEL_UNFUNDED: u8 = 3;
const LOADER: &str = "BPFLoaderUpgradeab1e11111111111111111111111";

/// A reviewed, pinned deployment of the provider and the channel program it trusts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Deployment {
    pub cluster: &'static str,
    pub program_id: &'static str,
    /// Payment-channels program whose callbacks the provider accepts.
    pub channel_program_id: &'static str,
}

/// Devnet: provider `97F68uhs…` (Squads 2-of-3 governed) trusting the devnet
/// V2-hooks channel deployment `CHNLxBt…`.
pub const DEVNET: Deployment = Deployment {
    cluster: "devnet",
    program_id: "97F68uhs5fmvddJxH1LrKytbBXrhx6ZBZwuZAdUdP7QA",
    channel_program_id: v2::PAYMENT_CHANNELS_PROGRAM_ID,
};

/// Resolve the pinned deployment for a PayKit network name or CAIP-2-ish
/// `solana:<cluster>` string. Unknown or undeployed networks yield `None`.
pub fn deployment(network: &str) -> Option<Deployment> {
    match network.strip_prefix("solana:").unwrap_or(network) {
        "devnet" => Some(DEVNET),
        _ => None,
    }
}

impl Deployment {
    pub fn program(&self) -> Pubkey {
        v1::parse_pubkey(self.program_id).expect("pinned program id")
    }

    pub fn channel_program(&self) -> Pubkey {
        v1::parse_pubkey(self.channel_program_id).expect("pinned channel program id")
    }

    pub fn ledger_address(&self, owner: &Pubkey, mint: &Pubkey) -> Pubkey {
        Pubkey::find_program_address(
            &[LEDGER_SEED, owner.as_ref(), mint.as_ref()],
            &self.program(),
        )
        .0
    }

    pub fn config_address(&self) -> Pubkey {
        Pubkey::find_program_address(&[CONFIG_SEED], &self.program()).0
    }

    /// The exact, immutable hook policy for `owner`'s credits in `mint`.
    pub fn hooks(&self, owner: &Pubkey, mint: &Pubkey) -> v2::ChannelHooks {
        let token = token_program();
        let ledger = self.ledger_address(owner, mint);
        let account = |key: Pubkey, writable| v2::HookAccount {
            address: v1::pubkey_string(&key),
            writable,
        };
        let descriptor = v2::HookDescriptor {
            program_id: self.program_id.to_string(),
            entrypoint: ENTRYPOINT,
            accounts: vec![
                account(ledger, true),
                account(ata(&ledger, mint), true),
                account(ata(owner, mint), true),
                account(token, false),
            ],
            static_data: vec![],
        };
        v2::ChannelHooks {
            pre_fund: Some(descriptor.clone()),
            post_fund: None,
            pre_distribute: None,
            post_distribute: Some(descriptor),
        }
    }

    /// Detection: is this hook configuration a Musebook credit-backed channel
    /// for `owner`/`mint` on this deployment? Exact match only. A look-alike
    /// with a different program, entrypoint, slot set or account list is not.
    pub fn is_credit_channel(
        &self,
        hooks: &v2::ChannelHooks,
        owner: &Pubkey,
        mint: &Pubkey,
    ) -> bool {
        *hooks == self.hooks(owner, mint)
    }

    /// Provider ledger creation. The issuer must equal the provider config's
    /// issuer, or the upgrade authority when none is set.
    pub fn initialize_ledger_instruction(
        &self,
        owner: &Pubkey,
        mint: &Pubkey,
        issuer: &Pubkey,
    ) -> Instruction {
        let program = self.program();
        let loader = v1::parse_pubkey(LOADER).expect("loader id");
        let program_data = Pubkey::find_program_address(&[program.as_ref()], &loader).0;
        self.instruction(
            vec![
                w(owner, true),
                w(&self.ledger_address(owner, mint), false),
                r(mint, false),
                r(&program, false),
                r(&program_data, false),
                r(issuer, true),
                r(&v1::system_program_id(), false),
                r(&self.config_address(), false),
            ],
            vec![INITIALIZE],
        )
    }

    /// Owner deposits backing tokens; credits are issued 1:1 in base units.
    pub fn deposit_instruction(&self, owner: &Pubkey, mint: &Pubkey, amount: u64) -> Instruction {
        let ledger = self.ledger_address(owner, mint);
        let mut data = vec![DEPOSIT];
        data.extend(amount.to_le_bytes());
        self.instruction(
            vec![
                r(owner, true),
                w(&ledger, false),
                w(&ata(&ledger, mint), false),
                w(&ata(owner, mint), false),
                r(&token_program(), false),
                r(&self.config_address(), false),
            ],
            data,
        )
    }

    /// Owner + issuer bind one channel incarnation (payee, signer,
    /// distribution, salt, open slot), with a cap, nonce and expiry slot.
    pub fn authorize_instruction(
        &self,
        owner: &Pubkey,
        mint: &Pubkey,
        issuer: &Pubkey,
        authorization: &Authorization,
    ) -> Instruction {
        let ledger = self.ledger_address(owner, mint);
        let mut data = vec![AUTHORIZE];
        data.extend(authorization.encode());
        self.instruction(
            vec![
                r(owner, true),
                r(issuer, true),
                w(&ledger, false),
                w(&ata(&ledger, mint), false),
                w(&ata(owner, mint), false),
                r(&token_program(), false),
                r(&self.config_address(), false),
            ],
            data,
        )
    }

    pub fn cancel_unfunded_instruction(
        &self,
        owner: &Pubkey,
        mint: &Pubkey,
        issuer: &Pubkey,
    ) -> Instruction {
        self.instruction(
            vec![
                r(owner, true),
                r(issuer, true),
                w(&self.ledger_address(owner, mint), false),
            ],
            vec![CANCEL_UNFUNDED],
        )
    }

    /// Owner/issuer authorization fields for a channel about to be opened.
    #[allow(clippy::too_many_arguments)]
    pub fn authorization_for_channel(
        &self,
        payee: &Pubkey,
        authorized_signer: &Pubkey,
        recipients: &[v1::Distribution],
        salt: u64,
        open_slot: u64,
        cap: u64,
        nonce: u64,
        expires_at_slot: u64,
    ) -> Authorization {
        Authorization {
            payee: payee.to_bytes(),
            authorized_signer: authorized_signer.to_bytes(),
            distribution_hash: v1::distribution_hash(recipients),
            salt,
            open_slot,
            cap,
            nonce,
            expires_at_slot,
        }
    }

    /// SPL Token `Approve` making the ledger PDA the owner ATA's delegate for
    /// exactly `cap`, which the provider's `authorize` requires.
    pub fn approve_instruction(&self, owner: &Pubkey, mint: &Pubkey, cap: u64) -> Instruction {
        let mut data = vec![4u8];
        data.extend(cap.to_le_bytes());
        Instruction {
            program_id: v1::to_address(&token_program()),
            accounts: vec![
                w(&ata(owner, mint), false),
                r(&self.ledger_address(owner, mint), false),
                r(owner, true),
            ],
            data,
        }
    }

    /// The two instructions an issuer co-signs ahead of a credit `open`:
    /// `[Approve(cap), authorize(authorization)]`.
    pub fn authorization_instructions(
        &self,
        owner: &Pubkey,
        mint: &Pubkey,
        issuer: &Pubkey,
        authorization: &Authorization,
    ) -> Vec<Instruction> {
        vec![
            self.approve_instruction(owner, mint, authorization.cap),
            self.authorize_instruction(owner, mint, issuer, authorization),
        ]
    }

    /// Hooked `open` (`OpenWithHooks`) preceded by the 400k CU request. The
    /// owner is both channel payer and rent payer, because the provider
    /// requires the refund destination to be the owner ATA.
    pub fn open_channel_instructions(
        &self,
        params: &v1::OpenChannelParams,
    ) -> crate::core::Result<Vec<Instruction>> {
        self.check_channel(&params.program_id, &params.token_program)?;
        let hooks = self.hooks(&params.payer, &params.mint);
        Ok(vec![
            compute_budget_instruction(),
            v2::build_open_instruction(params, &hooks)?,
        ])
    }

    pub fn top_up_instructions(
        &self,
        owner: &Pubkey,
        channel: &Pubkey,
        mint: &Pubkey,
        amount: u64,
    ) -> crate::core::Result<Vec<Instruction>> {
        let (program, token) = (self.channel_program(), token_program());
        let hooks = self.hooks(owner, mint);
        Ok(vec![
            compute_budget_instruction(),
            v2::build_top_up_instruction(owner, channel, mint, amount, &token, &program, &hooks)?,
        ])
    }

    #[allow(clippy::too_many_arguments)]
    pub fn distribute_instructions(
        &self,
        channel: &Pubkey,
        owner: &Pubkey,
        rent_payer: &Pubkey,
        payee: &Pubkey,
        treasury: &Pubkey,
        mint: &Pubkey,
        recipients: &[v1::Distribution],
    ) -> crate::core::Result<Vec<Instruction>> {
        let (program, token) = (self.channel_program(), token_program());
        let hooks = self.hooks(owner, mint);
        Ok(vec![
            compute_budget_instruction(),
            v2::build_distribute_instruction(
                channel, owner, rent_payer, payee, treasury, mint, recipients, &token, &program,
                &hooks,
            )?,
        ])
    }

    pub fn withdraw_payer_instructions(
        &self,
        owner: &Pubkey,
        channel: &Pubkey,
        mint: &Pubkey,
    ) -> crate::core::Result<Vec<Instruction>> {
        let (program, token) = (self.channel_program(), token_program());
        let hooks = self.hooks(owner, mint);
        Ok(vec![
            compute_budget_instruction(),
            v2::build_withdraw_payer_instruction(owner, channel, mint, &token, &program, &hooks)?,
        ])
    }

    fn check_channel(&self, program: &Pubkey, token: &Pubkey) -> crate::core::Result<()> {
        if *program != self.channel_program() || *token != token_program() {
            return Err(crate::core::Error::Other(format!(
                "musebook credits on {} require channel program {} and SPL Token",
                self.cluster, self.channel_program_id
            )));
        }
        Ok(())
    }

    fn instruction(&self, accounts: Vec<AccountMeta>, data: Vec<u8>) -> Instruction {
        Instruction {
            program_id: v1::to_address(&self.program()),
            accounts,
            data,
        }
    }
}

/// Mirrors the provider's Borsh `Authorization` (fixed 136 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Authorization {
    pub payee: [u8; 32],
    pub authorized_signer: [u8; 32],
    pub distribution_hash: [u8; 32],
    pub salt: u64,
    pub open_slot: u64,
    pub cap: u64,
    pub nonce: u64,
    pub expires_at_slot: u64,
}

/// Issuer-side terms a client proposes for one credit channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthorizationTerms {
    /// Must be the ledger's consumed nonce + 1 ([`ledger_next_nonce`]).
    pub nonce: u64,
    /// Total the channel may ever fund (deposit plus top-ups).
    pub cap: u64,
    /// Last slot at which the authorization may fund the channel.
    pub expires_at_slot: u64,
}

/// Next authorization nonce for a ledger account's data, or `None` when the
/// data is not a provider ledger.
pub fn ledger_next_nonce(data: &[u8]) -> Option<u64> {
    if data.len() != LEDGER_LEN {
        return None;
    }
    let bytes = data[LEDGER_NONCE_OFFSET..LEDGER_NONCE_OFFSET + 8]
        .try_into()
        .ok()?;
    u64::from_le_bytes(bytes).checked_add(1)
}

impl Authorization {
    /// Decode the provider `authorize` instruction data (tag + 136 bytes).
    pub fn decode_instruction_data(data: &[u8]) -> Option<Self> {
        let (&tag, rest) = data.split_first()?;
        if tag != AUTHORIZE || rest.len() != 136 {
            return None;
        }
        let key = |i: usize| -> [u8; 32] { rest[i..i + 32].try_into().unwrap() };
        let num = |i: usize| u64::from_le_bytes(rest[96 + i * 8..104 + i * 8].try_into().unwrap());
        Some(Self {
            payee: key(0),
            authorized_signer: key(32),
            distribution_hash: key(64),
            salt: num(0),
            open_slot: num(1),
            cap: num(2),
            nonce: num(3),
            expires_at_slot: num(4),
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(136);
        out.extend(self.payee);
        out.extend(self.authorized_signer);
        out.extend(self.distribution_hash);
        for v in [
            self.salt,
            self.open_slot,
            self.cap,
            self.nonce,
            self.expires_at_slot,
        ] {
            out.extend(v.to_le_bytes());
        }
        out
    }
}

/// `SetComputeUnitLimit(COMPUTE_UNIT_LIMIT)`.
pub fn compute_budget_instruction() -> Instruction {
    let mut data = vec![2u8];
    data.extend(COMPUTE_UNIT_LIMIT.to_le_bytes());
    Instruction {
        program_id: v1::to_address(&v1::compute_budget_program_id()),
        accounts: vec![],
        data,
    }
}

fn token_program() -> Pubkey {
    v1::parse_pubkey(TOKEN_PROGRAM_ID).expect("token program id")
}

fn ata(owner: &Pubkey, mint: &Pubkey) -> Pubkey {
    v1::find_associated_token_address(owner, mint, &token_program()).0
}

fn w(key: &Pubkey, signer: bool) -> AccountMeta {
    AccountMeta::new(v1::to_address(key), signer)
}

fn r(key: &Pubkey, signer: bool) -> AccountMeta {
    AccountMeta::new_readonly(v1::to_address(key), signer)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(n: u8) -> Pubkey {
        Pubkey::new_from_array([n; 32])
    }

    #[test]
    fn only_devnet_is_deployed() {
        assert_eq!(deployment("devnet"), Some(DEVNET));
        assert_eq!(deployment("solana:devnet"), Some(DEVNET));
        for n in [
            "mainnet",
            "mainnet-beta",
            "solana:mainnet",
            "localnet",
            "testnet",
            "",
            "Devnet",
        ] {
            assert_eq!(deployment(n), None, "{n}");
        }
    }

    #[test]
    fn hooks_use_prefund_and_postdistribute_with_pinned_accounts() {
        let (owner, mint) = (key(1), key(2));
        let hooks = DEVNET.hooks(&owner, &mint);
        hooks.validate().unwrap();
        assert!(hooks.post_fund.is_none() && hooks.pre_distribute.is_none());
        let d = hooks.pre_fund.as_ref().unwrap();
        assert_eq!(Some(d), hooks.post_distribute.as_ref());
        assert_eq!(d.program_id, DEVNET.program_id);
        assert_eq!(d.entrypoint, *b"musebook");
        assert!(d.static_data.is_empty());
        let ledger = DEVNET.ledger_address(&owner, &mint);
        let want = [
            (ledger, true),
            (ata(&ledger, &mint), true),
            (ata(&owner, &mint), true),
            (token_program(), false),
        ];
        assert_eq!(d.accounts.len(), v2::MAX_HOOK_ACCOUNTS);
        for (got, (k, wr)) in d.accounts.iter().zip(want) {
            assert_eq!(
                (got.address.as_str(), got.writable),
                (v1::pubkey_string(&k).as_str(), wr)
            );
        }
    }

    #[test]
    fn detection_is_exact() {
        let (owner, mint) = (key(1), key(2));
        let hooks = DEVNET.hooks(&owner, &mint);
        assert!(DEVNET.is_credit_channel(&hooks, &owner, &mint));
        assert!(
            !DEVNET.is_credit_channel(&hooks, &key(3), &mint),
            "other owner"
        );
        let mut wrong = hooks.clone();
        wrong.pre_fund.as_mut().unwrap().entrypoint = *b"credit!!";
        assert!(!DEVNET.is_credit_channel(&wrong, &owner, &mint));
        let mut wrong = hooks.clone();
        wrong.post_distribute = None;
        assert!(!DEVNET.is_credit_channel(&wrong, &owner, &mint));
        let mut wrong = hooks;
        wrong.pre_fund.as_mut().unwrap().accounts[3].writable = true;
        assert!(!DEVNET.is_credit_channel(&wrong, &owner, &mint));
        assert!(!DEVNET.is_credit_channel(&v2::ChannelHooks::default(), &owner, &mint));
    }

    #[test]
    fn provider_instructions_carry_config_account_last() {
        let (owner, mint, issuer) = (key(1), key(2), key(3));
        let config = v1::to_address(&DEVNET.config_address());
        let init = DEVNET.initialize_ledger_instruction(&owner, &mint, &issuer);
        assert_eq!((init.data.clone(), init.accounts.len()), (vec![0], 8));
        assert_eq!(init.accounts[7].pubkey, config);
        assert!(init.accounts[0].is_signer && init.accounts[5].is_signer);
        let dep = DEVNET.deposit_instruction(&owner, &mint, 7);
        assert_eq!(dep.accounts.len(), 6);
        assert_eq!(dep.accounts[5].pubkey, config);
        assert_eq!(dep.data, [vec![1], 7u64.to_le_bytes().to_vec()].concat());
        let auth = Authorization {
            cap: 5,
            nonce: 1,
            ..Default::default()
        };
        let ix = DEVNET.authorize_instruction(&owner, &mint, &issuer, &auth);
        assert_eq!(ix.accounts.len(), 7);
        assert_eq!(ix.accounts[6].pubkey, config);
        assert_eq!(ix.data.len(), 1 + 136);
        assert!(ix.accounts[0].is_signer && ix.accounts[1].is_signer);
        assert!(ix.accounts.iter().skip(2).all(|a| !a.is_signer));
    }

    #[test]
    fn channel_instructions_request_400k_cu_and_use_with_hooks_tags() {
        let (owner, mint, payee) = (key(1), key(2), key(4));
        let budget = compute_budget_instruction();
        assert_eq!(
            budget.data,
            [vec![2], 400_000u32.to_le_bytes().to_vec()].concat()
        );
        let params = v1::OpenChannelParams {
            payer: owner,
            rent_payer: owner,
            payee,
            mint,
            authorized_signer: owner,
            salt: 1,
            open_slot: 2,
            deposit: 3,
            grace_period: 60,
            recipients: v1::sole_recipient(&payee),
            token_program: token_program(),
            program_id: DEVNET.channel_program(),
        };
        let open = DEVNET.open_channel_instructions(&params).unwrap();
        assert_eq!(open[0], budget);
        assert_eq!(open[1].data[0], v2::OPEN_WITH_HOOKS_DISCRIMINATOR);
        // base 14 accounts + (callback program, authority, 4 extras) for pre_fund.
        assert_eq!(open[1].accounts.len(), 14 + 6);
        let channel = v1::derive_channel_addresses(&params).channel;
        let top = DEVNET
            .top_up_instructions(&owner, &channel, &mint, 1)
            .unwrap();
        assert_eq!(top[1].data[0], v2::TOP_UP_WITH_HOOKS_DISCRIMINATOR);
        let dist = DEVNET
            .distribute_instructions(
                &channel,
                &owner,
                &owner,
                &payee,
                &key(9),
                &mint,
                &params.recipients,
            )
            .unwrap();
        assert_eq!(dist[1].data[0], v2::DISTRIBUTE_WITH_HOOKS_DISCRIMINATOR);
        let wd = DEVNET
            .withdraw_payer_instructions(&owner, &channel, &mint)
            .unwrap();
        assert_eq!(
            wd[1].data,
            vec![v2::WITHDRAW_PAYER_WITH_HOOKS_DISCRIMINATOR]
        );
        for ixs in [&open, &top, &dist, &wd] {
            assert_eq!(ixs[0], budget);
        }
        // Wrong channel program or token program fails closed.
        let mut bad = params.clone();
        bad.program_id = v1::default_program_id();
        assert!(DEVNET.open_channel_instructions(&bad).is_err());
    }
}
