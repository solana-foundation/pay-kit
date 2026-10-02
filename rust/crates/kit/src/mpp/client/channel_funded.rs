//! Pay a `charge` from a payment channel whose committed payee is the
//! merchant.
//!
//! This is the first concrete *composed* funding source (see
//! [`build_composed_charge_transaction`](super::build_composed_charge_transaction)
//! and the spec's "Composed Transactions" section). The client never holds the
//! stablecoin: a channel funded by someone else — typically a credit issuer —
//! names the merchant as payee at `open`, and each charge is paid with three
//! instructions:
//!
//! 1. an Ed25519 signature-verification instruction carrying the channel
//!    voucher signed by the channel's `authorized_signer`;
//! 2. the channel program's `settle`, which advances the cumulative
//!    watermark; and
//! 3. the channel program's `distribute`, which pays the newly settled delta
//!    to the payee (and any committed split recipients) as an inner
//!    `transferChecked`.
//!
//! Both programs are in the spec's default composed set, so a server that
//! implements composed verification accepts this without advertising
//! anything. The charged `amount` must equal the newly settled delta
//! (`cumulative_amount - settled`) so the payee's inner transfer matches the
//! challenged payment leg exactly; vouchers on one channel are therefore
//! issued strictly one at a time.

use solana_instruction::Instruction;
use solana_pubkey::Pubkey;
use std::str::FromStr;

use crate::core::payment_channels::{
    build_distribute_instruction, build_settle_instructions, Distribution,
};
use crate::mpp::error::Error;
use crate::mpp::protocol::solana::programs;

/// One charge paid by settling and distributing a payment channel.
#[derive(Debug, Clone)]
pub struct ChannelFundedCharge {
    /// Channel PDA.
    pub channel: Pubkey,
    /// Channel payer (the depositor, e.g. the credit issuer).
    pub payer: Pubkey,
    /// Channel rent payer, as recorded at `open`.
    pub rent_payer: Pubkey,
    /// Channel payee. Must equal the challenged `recipient` (or the
    /// recipient must be one of `recipients`) for the payment leg to match.
    pub payee: Pubkey,
    /// Channel mint; must equal the challenged `currency`.
    pub mint: Pubkey,
    /// Distribution preimage committed at `open` (empty for a two-party
    /// channel where the payee receives everything).
    pub recipients: Vec<Distribution>,
    /// Token program governing `mint`.
    pub token_program: Pubkey,
    /// Payment-channel program ID.
    pub program_id: Pubkey,
    /// Treasury owner for the cluster (see
    /// [`treasury_owner_for_cluster`](crate::core::payment_channels::treasury_owner_for_cluster)).
    pub treasury_owner: Pubkey,
    /// The channel's authorized voucher signer.
    pub authorized_signer: Pubkey,
    /// Ed25519 signature over the canonical voucher bytes.
    pub voucher_signature: [u8; 64],
    /// Cumulative amount the voucher authorizes.
    pub cumulative_amount: u64,
    /// Voucher expiry (unix seconds; `0` = never).
    pub expires_at: i64,
}

impl ChannelFundedCharge {
    /// The three instructions that pay the charge: Ed25519 verify, `settle`,
    /// `distribute`. Prepend compute-budget instructions and sign with
    /// [`build_composed_charge_transaction`](super::build_composed_charge_transaction).
    pub fn instructions(&self) -> Result<Vec<Instruction>, Error> {
        let mut instructions = build_settle_instructions(
            &self.channel,
            &self.authorized_signer,
            &self.voucher_signature,
            self.cumulative_amount,
            self.expires_at,
            &self.program_id,
        )
        .map_err(|e| Error::Other(format!("settle instructions: {e}")))?;
        instructions.push(build_distribute_instruction(
            &self.channel,
            &self.payer,
            &self.rent_payer,
            &self.payee,
            &self.treasury_owner,
            &self.mint,
            &self.recipients,
            &self.token_program,
            &self.program_id,
        ));
        Ok(instructions)
    }

    /// The non-base programs these instructions invoke at the top level: the
    /// Ed25519 program and the channel program. Both are in the default
    /// composed set, so
    /// [`composed_programs_accepted`](super::composed_programs_accepted)
    /// returns `true` for any challenge unless the server disabled composed
    /// transactions.
    pub fn programs(&self) -> [Pubkey; 2] {
        [
            Pubkey::from_str(programs::ED25519_PROGRAM).expect("valid ed25519 program id"),
            self.program_id,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::payment_channels::default_program_id;

    fn sample() -> ChannelFundedCharge {
        ChannelFundedCharge {
            channel: Pubkey::new_unique(),
            payer: Pubkey::new_unique(),
            rent_payer: Pubkey::new_unique(),
            payee: Pubkey::new_unique(),
            mint: Pubkey::new_unique(),
            recipients: vec![],
            token_program: Pubkey::from_str(programs::TOKEN_PROGRAM).unwrap(),
            program_id: default_program_id(),
            treasury_owner: Pubkey::new_unique(),
            authorized_signer: Pubkey::new_unique(),
            voucher_signature: [7u8; 64],
            cumulative_amount: 250_000,
            expires_at: 0,
        }
    }

    #[test]
    fn instructions_are_ed25519_settle_distribute() {
        let charge = sample();
        let ixs = charge.instructions().unwrap();
        assert_eq!(ixs.len(), 3);
        assert_eq!(
            ixs[0].program_id,
            Pubkey::from_str(programs::ED25519_PROGRAM).unwrap()
        );
        assert_eq!(ixs[1].program_id, charge.program_id);
        assert_eq!(ixs[2].program_id, charge.program_id);
        // The ed25519 instruction carries the 50-byte voucher: 16-byte header,
        // 32-byte pubkey, 64-byte signature, 50-byte message.
        assert_eq!(ixs[0].data.len(), 16 + 32 + 64 + 50);
    }

    #[test]
    fn programs_are_the_default_composed_set() {
        let charge = sample();
        let defaults = crate::mpp::protocol::solana::default_composed_programs();
        for program in charge.programs() {
            assert!(defaults.contains(&program), "{program} not in default set");
        }
    }
}
