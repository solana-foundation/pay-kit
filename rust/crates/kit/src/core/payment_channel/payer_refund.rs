//! Whether a sealed `distribute` refunds the payer or forfeits the refund.
//!
//! On a sealed channel the payment-channels program pays `deposit - settled`
//! back to the payer's associated token account, unless the payer already
//! withdrew it. It never fails on an unusable refund account: a missing,
//! uninitialized, frozen, reassigned or extension-bearing one has the refund
//! redirected to the protocol treasury, and the channel closes in the same
//! instruction. A server cranking that `distribute` checks the account first
//! and, when it cannot be paid, lands only the seal and defers the
//! distribute: the payer can still `withdraw_payer` or repair the account,
//! and a later pass distributes once it can be paid.
//!
//! The deferral is bounded. A payer must not hold the merchant's settled
//! revenue and the sponsor's rent in escrow by keeping its account unusable,
//! so once the channel has been sealed for its grace period the distribute
//! runs anyway and the program's redirect to the treasury is accepted.

use solana_pubkey::Pubkey;

use super::token_account::{decode_token_account, TOKEN_ACCOUNT_FROZEN, TOKEN_ACCOUNT_INITIALIZED};
use super::v1::find_associated_token_address;

/// Evidence that a sealed `distribute` of [`Self::channel`] may run: no
/// refund is due, the payer's token account can take it, or the deferral
/// deadline passed. Only [`payer_refund`] issues one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DistributeClearance {
    channel: Pubkey,
}

impl DistributeClearance {
    /// The channel this clearance was issued for.
    pub fn channel(&self) -> &Pubkey {
        &self.channel
    }
}

/// What to do with a sealed channel's `distribute`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PayerRefund {
    /// Distribute: the payer's refund, if any, is paid.
    Clear(DistributeClearance),
    /// A refund is due and `payer_token_account` cannot receive it: land only
    /// the seal and distribute on a later pass, at the latest at `until`
    /// (unix seconds).
    Deferred {
        refund: u64,
        payer_token_account: Pubkey,
        reason: String,
        until: i64,
    },
    /// The deferral deadline passed with the account still unusable:
    /// distribute anyway, and the program redirects `refund` to the treasury.
    Forfeit {
        clearance: DistributeClearance,
        refund: u64,
        payer_token_account: Pubkey,
        reason: String,
    },
}

impl PayerRefund {
    /// The clearance to distribute now, `None` while deferred.
    pub fn clearance(self) -> Option<DistributeClearance> {
        match self {
            Self::Clear(clearance) | Self::Forfeit { clearance, .. } => Some(clearance),
            Self::Deferred { .. } => None,
        }
    }
}

/// When a deferred distribute stops waiting for the payer's account.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RefundDeadline {
    /// When the channel was sealed (unix seconds); the time of this close for
    /// a channel it seals. The program records no seal time, so a server
    /// keeps the one it observed first.
    pub sealed_at: i64,
    /// The channel's grace period, in seconds.
    pub grace_period: u32,
}

impl RefundDeadline {
    /// The first time the distribute runs whatever the account's state.
    pub fn until(&self) -> i64 {
        self.sealed_at.saturating_add(i64::from(self.grace_period))
    }
}

/// An account as fetched from the cluster.
#[derive(Debug, Clone, Copy)]
pub struct ObservedAccount<'a> {
    /// The program that owns the account.
    pub owner: Pubkey,
    pub data: &'a [u8],
}

/// The channel fields a sealed `distribute` decides the refund from.
#[derive(Debug, Clone, Copy)]
pub struct SealedRefundTerms {
    pub channel: Pubkey,
    pub payer: Pubkey,
    pub mint: Pubkey,
    pub token_program: Pubkey,
    pub deposit: u64,
    /// The watermark the channel is sealed at.
    pub settled: u64,
    pub payer_withdrawn_at: i64,
}

impl SealedRefundTerms {
    /// The payer's refund account, which `payer_token_account` must be the
    /// fetch of.
    pub fn payer_token_account(&self) -> Pubkey {
        find_associated_token_address(&self.payer, &self.mint, &self.token_program).0
    }

    /// The refund a sealed `distribute` pays the payer: zero once the payer
    /// withdrew it or the deposit is fully settled.
    pub fn refund_due(&self) -> u64 {
        if self.payer_withdrawn_at != 0 {
            return 0;
        }
        self.deposit.saturating_sub(self.settled)
    }
}

/// Decide what a sealed `distribute` under `terms` may do at `now` (unix
/// seconds). `payer_token_account` is the account at
/// [`SealedRefundTerms::payer_token_account`], `None` when it does not exist.
pub fn payer_refund(
    terms: &SealedRefundTerms,
    payer_token_account: Option<ObservedAccount<'_>>,
    deadline: RefundDeadline,
    now: i64,
) -> PayerRefund {
    let clearance = DistributeClearance {
        channel: terms.channel,
    };
    let refund = terms.refund_due();
    let Some(reason) = (refund > 0)
        .then(|| unpayable_reason(terms, payer_token_account))
        .flatten()
    else {
        return PayerRefund::Clear(clearance);
    };
    let payer_token_account = terms.payer_token_account();
    let until = deadline.until();
    if now >= until {
        return PayerRefund::Forfeit {
            clearance,
            refund,
            payer_token_account,
            reason: reason.to_string(),
        };
    }
    PayerRefund::Deferred {
        refund,
        payer_token_account,
        reason: reason.to_string(),
        until,
    }
}

/// Why the payer's refund account cannot take a refund, `None` when it can.
fn unpayable_reason(
    terms: &SealedRefundTerms,
    payer_token_account: Option<ObservedAccount<'_>>,
) -> Option<&'static str> {
    let blocked = Some;
    let Some(account) = payer_token_account else {
        return blocked("does not exist");
    };
    if account.owner != terms.token_program {
        return blocked("is not owned by the channel's token program");
    }
    let Some(decoded) = decode_token_account(account.data) else {
        return blocked("is not an initialized token account");
    };
    if decoded.state == TOKEN_ACCOUNT_FROZEN {
        return blocked("is frozen");
    }
    if decoded.state != TOKEN_ACCOUNT_INITIALIZED {
        return blocked("is not initialized");
    }
    if decoded.mint != terms.mint || decoded.owner != terms.payer {
        return blocked("is not held by the payer for the channel's mint");
    }
    if decoded.unsupported_extension.is_some() {
        return blocked("carries a token account extension the program will not pay into");
    }
    None
}

#[cfg(test)]
mod tests {
    use super::super::token_account::TOKEN_ACCOUNT_LEN;
    use super::*;

    fn terms() -> SealedRefundTerms {
        SealedRefundTerms {
            channel: Pubkey::new_unique(),
            payer: Pubkey::new_unique(),
            mint: Pubkey::new_unique(),
            token_program: Pubkey::new_unique(),
            deposit: 1_000,
            settled: 400,
            payer_withdrawn_at: 0,
        }
    }

    fn token_account(mint: &Pubkey, owner: &Pubkey, state: u8) -> Vec<u8> {
        let mut data = vec![0u8; TOKEN_ACCOUNT_LEN];
        data[..32].copy_from_slice(mint.as_ref());
        data[32..64].copy_from_slice(owner.as_ref());
        data[108] = state;
        data
    }

    const SEALED_AT: i64 = 1_000_000;
    const GRACE: u32 = 900;
    const DEADLINE: RefundDeadline = RefundDeadline {
        sealed_at: SEALED_AT,
        grace_period: GRACE,
    };

    fn decide(terms: &SealedRefundTerms, account: Option<ObservedAccount<'_>>) -> PayerRefund {
        payer_refund(terms, account, DEADLINE, SEALED_AT)
    }

    fn observed(terms: &SealedRefundTerms, data: &[u8]) -> PayerRefund {
        decide(
            terms,
            Some(ObservedAccount {
                owner: terms.token_program,
                data,
            }),
        )
    }

    #[test]
    fn an_unusable_refund_account_defers_a_due_refund() {
        let terms = terms();
        let blocked = |outcome: PayerRefund| {
            assert!(
                matches!(
                    outcome,
                    PayerRefund::Deferred { refund: 600, until, .. }
                        if until == SEALED_AT + i64::from(GRACE)
                ),
                "{outcome:?}"
            )
        };
        blocked(decide(&terms, None));
        blocked(observed(
            &terms,
            &token_account(&terms.mint, &terms.payer, TOKEN_ACCOUNT_FROZEN),
        ));
        blocked(observed(
            &terms,
            &token_account(&terms.mint, &terms.payer, 0),
        ));
        blocked(observed(
            &terms,
            &token_account(
                &terms.mint,
                &Pubkey::new_unique(),
                TOKEN_ACCOUNT_INITIALIZED,
            ),
        ));
        blocked(observed(&terms, &[]));
        blocked(decide(
            &terms,
            Some(ObservedAccount {
                owner: Pubkey::new_unique(),
                data: &token_account(&terms.mint, &terms.payer, TOKEN_ACCOUNT_INITIALIZED),
            }),
        ));
    }

    #[test]
    fn a_live_account_or_no_refund_clears_the_distribute() {
        let terms = terms();
        let live = token_account(&terms.mint, &terms.payer, TOKEN_ACCOUNT_INITIALIZED);
        assert!(
            matches!(observed(&terms, &live), PayerRefund::Clear(c) if c.channel == terms.channel)
        );
        for terms in [
            SealedRefundTerms {
                settled: 1_000,
                ..terms
            },
            SealedRefundTerms {
                payer_withdrawn_at: 1,
                ..terms
            },
        ] {
            assert!(matches!(decide(&terms, None), PayerRefund::Clear(_)));
        }
    }

    /// The deferral is bounded: from the deadline on, an account still
    /// unusable no longer holds the payout, and the refund is forfeited.
    #[test]
    fn a_deferral_ends_at_the_grace_deadline() {
        let terms = terms();
        let until = DEADLINE.until();
        let at = |now: i64| payer_refund(&terms, None, DEADLINE, now);
        assert!(matches!(at(until - 1), PayerRefund::Deferred { .. }));
        assert!(at(until - 1).clearance().is_none());
        match at(until) {
            PayerRefund::Forfeit {
                clearance, refund, ..
            } => {
                assert_eq!(clearance.channel, terms.channel);
                assert_eq!(refund, 600);
            }
            other => panic!("expected forfeit, got {other:?}"),
        }
        assert!(at(until + 10).clearance().is_some());
        // A payable account clears at any time, before or after the deadline.
        let live = token_account(&terms.mint, &terms.payer, TOKEN_ACCOUNT_INITIALIZED);
        let account = Some(ObservedAccount {
            owner: terms.token_program,
            data: &live,
        });
        for now in [SEALED_AT, until + 10] {
            assert!(matches!(
                payer_refund(&terms, account, DEADLINE, now),
                PayerRefund::Clear(_)
            ));
        }
    }
}
