//! The payer-refund check a sealed session `distribute` requires.

use solana_pubkey::Pubkey;

use super::session::SealParams;
use crate::core::payment_channel::payer_refund::{
    payer_refund, ObservedAccount, PayerRefund, RefundDeadline, SealedRefundTerms,
};
use crate::mpp::error::{Error, Result};

impl SealParams {
    /// The account [`Self::payer_refund`] needs fetched next to the channel:
    /// the payer's refund token account.
    pub fn payer_refund_account(&self, token_program: &Pubkey) -> Result<Pubkey> {
        Ok(self
            .refund_terms(token_program, 0, 0)?
            .payer_token_account())
    }

    /// What the sealed `distribute` may do at `now` (unix seconds), from the
    /// fetched channel account and the account at
    /// [`Self::payer_refund_account`] (`None` when it does not exist).
    ///
    /// `sealed_at` is when the channel was sealed, as recorded by
    /// [`SessionServer::mark_sealed`](super::session::SessionServer::mark_sealed)
    /// and read back with
    /// [`SessionServer::sealed_at`](super::session::SessionServer::sealed_at);
    /// it is ignored for a channel this close seals, and `None` for an
    /// already-sealed one starts the deadline at `now`.
    ///
    /// [`PayerRefund::Clear`] and [`PayerRefund::Forfeit`] carry the
    /// clearance [`Self::distribute_instruction`] takes. On
    /// [`PayerRefund::Deferred`] land only the settle-and-seal and retry the
    /// distribute by `until`: the program would forfeit the refund to the
    /// treasury, while the payer can still repair its account or
    /// `withdraw_payer`. From `until` on the distribute runs anyway
    /// ([`PayerRefund::Forfeit`]), so the payout is never held hostage.
    pub fn payer_refund(
        &self,
        channel_account: &[u8],
        token_program: &Pubkey,
        payer_token_account: Option<ObservedAccount<'_>>,
        sealed_at: Option<i64>,
        now: i64,
    ) -> Result<PayerRefund> {
        let deployment = crate::mpp::program::channel_deployment::resolve(
            self.program_id,
            self.channel_version,
            self.channel_hooks.as_ref(),
        )?;
        let channel = deployment.decode_channel(channel_account)?.channel;
        let terms =
            self.refund_terms(token_program, channel.deposit, channel.payer_withdrawn_at)?;
        let sealed = channel.status
            == crate::generated::payment_channels::generated::types::ChannelStatus::Sealed as u8;
        let terms = SealedRefundTerms {
            // An already-sealed channel refunds from its onchain watermark;
            // otherwise the seal this close lands commits at least the one it
            // settles.
            settled: if sealed {
                channel.settlement.settled
            } else {
                channel.settlement.settled.max(self.settled)
            },
            ..terms
        };
        if crate::core::payment_channels::from_address(&channel.payer) != terms.payer {
            return Err(Error::Other(
                "channel account payer does not match the seal parameters".into(),
            ));
        }
        let deadline = RefundDeadline {
            sealed_at: if sealed {
                sealed_at.unwrap_or(now)
            } else {
                now
            },
            grace_period: channel.grace_period,
        };
        Ok(payer_refund(&terms, payer_token_account, deadline, now))
    }

    fn refund_terms(
        &self,
        token_program: &Pubkey,
        deposit: u64,
        payer_withdrawn_at: i64,
    ) -> Result<SealedRefundTerms> {
        Ok(SealedRefundTerms {
            channel: self.channel_id,
            payer: self
                .payer
                .ok_or_else(|| Error::Other("distribution missing payer".into()))?,
            mint: self
                .mint
                .ok_or_else(|| Error::Other("distribution missing mint".into()))?,
            token_program: *token_program,
            deposit,
            settled: self.settled,
            payer_withdrawn_at,
        })
    }
}
