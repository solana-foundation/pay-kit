//! Mutation operators: one valid transaction or credential in, one invalid
//! one out.
//!
//! Each operator is paired, per suite, with the reject code the verifier must
//! produce ([`Mutation::expected`]). Reject cases built from an operator take
//! their expectation from that table, so an operator cannot be attached to a
//! case with a code it does not produce. The vector carries the mutated
//! bytes, never the operator name: other SDKs see only the result.
//!
//! Transaction operators decompile the message (`tx.rs`), edit instructions,
//! recompile as version 0 and re-sign every slot whose key the filler holds,
//! so a mutation never fails for an unrelated reason such as a stale
//! signature (except [`Mutation::DropSignature`], whose point that is).

use solana_instruction::AccountMeta;
use solana_transaction::versioned::VersionedTransaction;

use crate::case::{RejectCode, Suite};
use crate::keys::{
    self, ata, pubkey, MEMO_PROGRAM, SYSTEM_PROGRAM, TOKEN_2022_PROGRAM, TOKEN_PROGRAM,
};
use crate::tx::{compile_v0, decompile, sign_slots};

/// Selects the n-th (0-based) value transfer: System `Transfer` or SPL
/// `TransferChecked`, in instruction order.
pub type TransferIndex = usize;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mutation {
    /// Add `delta` base units to the transfer amount (negative underpays).
    BumpAmount { transfer: TransferIndex, delta: i64 },
    /// Pay more than required. Separate from `BumpAmount` because the spec
    /// treats it differently (x402 §1.4 tolerates overpayment).
    OverPay { transfer: TransferIndex, delta: u64 },
    /// Send the transfer to `owner` (its ATA for SPL) instead.
    SwapRecipient {
        transfer: TransferIndex,
        owner: &'static str,
    },
    /// Pay in `mint` instead (source and destination ATAs re-derived for
    /// the transfer's original owners).
    WrongMint {
        transfer: TransferIndex,
        mint: &'static str,
        source_owner: &'static str,
        destination_owner: &'static str,
    },
    /// Rewrite `TransferChecked.decimals`.
    SetDecimals {
        transfer: TransferIndex,
        decimals: u8,
    },
    /// Rewrite the ComputeBudget unit price.
    SetComputeUnitPrice { micro_lamports: u64 },
    /// Zero the client's signature and do not re-sign.
    DropSignature,
    /// Remove the n-th transfer (zero matching transfers).
    DropTransfer { transfer: TransferIndex },
    /// Duplicate the n-th transfer right after itself.
    ExtraTransfer { transfer: TransferIndex },
    /// Remove one transfer of a pair that pays two identical legs, so one
    /// instruction would have to satisfy both.
    DuplicateLegReuse { transfer: TransferIndex },
    /// Remove the n-th Memo instruction.
    DropMemo { memo: usize },
    /// Replace the n-th Memo instruction's text.
    ReplaceMemo { memo: usize, text: &'static str },
    /// List the fee payer as a signer account of the n-th Memo instruction
    /// (x402 §2.1.1: the fee payer appears in no instruction's accounts).
    FeePayerAsAccount { memo: usize },
    /// Make the fee payer the transfer authority.
    FeePayerAsAuthority { transfer: TransferIndex },
    /// Envelope: claim another network in `accepted.network` (x402 v2).
    WrongNetwork { network: &'static str },
    /// Challenge expiry in the past. Not expressible offline in the vector
    /// ABI: charge verify vectors carry no challenge (each runner mints its
    /// own) and x402 `exact` has no challenge expiry. Kept so the operator
    /// table states it; `expected` returns `None` for every suite.
    ExpireChallenge,
}

impl Mutation {
    /// The reject code this operator must produce in `suite`, or `None` when
    /// the operator does not apply there or the spec does not make it a
    /// reject (callers then author the case by hand).
    pub fn expected(&self, suite: Suite) -> Option<RejectCode> {
        use Mutation::*;
        use RejectCode::*;
        match (self, suite) {
            (BumpAmount { .. }, Suite::Charge) => Some(NoMatchingTransfer),
            (BumpAmount { .. }, Suite::X402Exact) => Some(AmountMismatch),
            (OverPay { .. }, _) => None,
            (SwapRecipient { .. }, Suite::Charge | Suite::X402Exact) => Some(NoMatchingTransfer),
            (WrongMint { .. }, Suite::Charge | Suite::X402Exact) => Some(NoMatchingTransfer),
            (SetDecimals { .. }, Suite::Charge) => Some(NoMatchingTransfer),
            (SetDecimals { .. }, Suite::X402Exact) => Some(DecimalsMismatch),
            (SetComputeUnitPrice { .. }, Suite::Charge | Suite::X402Exact) => {
                Some(ComputePriceOverCap)
            }
            (DropSignature, Suite::Charge | Suite::X402Exact) => Some(InvalidPayload),
            (DropTransfer { .. }, Suite::Charge | Suite::X402Exact) => Some(NoMatchingTransfer),
            (ExtraTransfer { .. }, Suite::Charge | Suite::X402Exact) => Some(UnexpectedInstruction),
            (DuplicateLegReuse { .. }, Suite::Charge) => Some(NoMatchingTransfer),
            (DropMemo { .. } | ReplaceMemo { .. }, Suite::Charge | Suite::X402Exact) => {
                Some(InvalidPayload)
            }
            (FeePayerAsAccount { .. }, Suite::X402Exact) => Some(FeePayerNotAuthority),
            (FeePayerAsAuthority { .. }, Suite::Charge | Suite::X402Exact) => {
                Some(FeePayerNotAuthority)
            }
            (Mutation::WrongNetwork { .. }, Suite::X402Exact) => Some(RejectCode::WrongNetwork),
            _ => None,
        }
    }

    /// True for operators that edit the envelope rather than the transaction.
    pub fn is_envelope(&self) -> bool {
        matches!(
            self,
            Mutation::WrongNetwork { .. } | Mutation::ExpireChallenge
        )
    }

    /// Short human description recorded in the case description.
    pub fn describe(&self) -> String {
        match self {
            Mutation::BumpAmount { transfer, delta } => {
                format!("transfer #{transfer} amount changed by {delta} base units")
            }
            Mutation::OverPay { transfer, delta } => {
                format!("transfer #{transfer} pays {delta} base units more than required")
            }
            Mutation::SwapRecipient { transfer, owner } => {
                format!("transfer #{transfer} redirected to {owner}")
            }
            Mutation::WrongMint { transfer, mint, .. } => {
                format!("transfer #{transfer} paid in mint {mint}")
            }
            Mutation::SetDecimals { transfer, decimals } => {
                format!("transfer #{transfer} TransferChecked decimals set to {decimals}")
            }
            Mutation::SetComputeUnitPrice { micro_lamports } => {
                format!("compute unit price set to {micro_lamports} micro-lamports")
            }
            Mutation::DropSignature => "client signature zeroed".into(),
            Mutation::DropTransfer { transfer } => format!("transfer #{transfer} removed"),
            Mutation::ExtraTransfer { transfer } => format!("transfer #{transfer} duplicated"),
            Mutation::DuplicateLegReuse { transfer } => {
                format!(
                    "transfer #{transfer} removed so one instruction must cover two identical legs"
                )
            }
            Mutation::DropMemo { memo } => format!("memo #{memo} removed"),
            Mutation::ReplaceMemo { memo, text } => format!("memo #{memo} replaced with {text:?}"),
            Mutation::FeePayerAsAccount { memo } => {
                format!("fee payer added as a signer account of memo #{memo}")
            }
            Mutation::FeePayerAsAuthority { transfer } => {
                format!("fee payer made the authority of transfer #{transfer}")
            }
            Mutation::WrongNetwork { network } => format!("accepted.network set to {network}"),
            Mutation::ExpireChallenge => "challenge expiry moved into the past".into(),
        }
    }

    /// Apply a transaction operator. `signers` are the seeds the filler may
    /// re-sign with (the client; never the sponsor, whose slot stays empty
    /// on x402).
    pub fn apply(
        &self,
        tx: &VersionedTransaction,
        signers: &[[u8; 32]],
    ) -> Result<VersionedTransaction, String> {
        if self.is_envelope() {
            return Err(format!(
                "{self:?} mutates the envelope, not the transaction"
            ));
        }
        if let Mutation::DropSignature = self {
            let mut out = tx.clone();
            let client = keys::pubkey_of_seed(keys::CLIENT_SEED);
            let index = out
                .message
                .static_account_keys()
                .iter()
                .position(|k| *k == client)
                .ok_or("client is not a signer of the transaction")?;
            out.signatures[index] = Default::default();
            return Ok(out);
        }
        let mut d = decompile(&tx.message)?;
        let transfers: Vec<usize> = d
            .instructions
            .iter()
            .enumerate()
            .filter(|(_, ix)| is_transfer(ix))
            .map(|(i, _)| i)
            .collect();
        let memos: Vec<usize> = d
            .instructions
            .iter()
            .enumerate()
            .filter(|(_, ix)| ix.program_id == pubkey(MEMO_PROGRAM))
            .map(|(i, _)| i)
            .collect();
        let transfer_at = |n: usize| {
            transfers
                .get(n)
                .copied()
                .ok_or_else(|| format!("transaction has no transfer #{n}"))
        };
        let memo_at = |n: usize| {
            memos
                .get(n)
                .copied()
                .ok_or_else(|| format!("transaction has no memo #{n}"))
        };
        match self {
            Mutation::BumpAmount { transfer, delta } => {
                let ix = &mut d.instructions[transfer_at(*transfer)?];
                let range = amount_range(ix)?;
                let amount = u64::from_le_bytes(ix.data[range.clone()].try_into().unwrap());
                let bumped = amount
                    .checked_add_signed(*delta)
                    .ok_or("amount bump overflows")?;
                ix.data[range].copy_from_slice(&bumped.to_le_bytes());
            }
            Mutation::OverPay { transfer, delta } => {
                let ix = &mut d.instructions[transfer_at(*transfer)?];
                let range = amount_range(ix)?;
                let amount = u64::from_le_bytes(ix.data[range.clone()].try_into().unwrap());
                ix.data[range].copy_from_slice(&(amount + delta).to_le_bytes());
            }
            Mutation::SwapRecipient { transfer, owner } => {
                let ix = &mut d.instructions[transfer_at(*transfer)?];
                if ix.program_id == pubkey(SYSTEM_PROGRAM) {
                    ix.accounts[1].pubkey = pubkey(owner);
                } else {
                    let mint = ix.accounts[1].pubkey.to_string();
                    let program = ix.program_id.to_string();
                    ix.accounts[2].pubkey = ata(owner, &mint, &program);
                }
            }
            Mutation::WrongMint {
                transfer,
                mint,
                source_owner,
                destination_owner,
            } => {
                let ix = &mut d.instructions[transfer_at(*transfer)?];
                if ix.program_id == pubkey(SYSTEM_PROGRAM) {
                    return Err("WrongMint needs an SPL transfer".into());
                }
                let program = ix.program_id.to_string();
                ix.accounts[0].pubkey = ata(source_owner, mint, &program);
                ix.accounts[1].pubkey = pubkey(mint);
                ix.accounts[2].pubkey = ata(destination_owner, mint, &program);
            }
            Mutation::SetDecimals { transfer, decimals } => {
                let ix = &mut d.instructions[transfer_at(*transfer)?];
                if ix.program_id == pubkey(SYSTEM_PROGRAM) || ix.data.len() != 10 {
                    return Err("SetDecimals needs a TransferChecked".into());
                }
                ix.data[9] = *decimals;
            }
            Mutation::SetComputeUnitPrice { micro_lamports } => {
                let ix = d
                    .instructions
                    .iter_mut()
                    .find(|ix| {
                        ix.program_id == pubkey(keys::COMPUTE_BUDGET_PROGRAM)
                            && ix.data.first() == Some(&3)
                    })
                    .ok_or("transaction has no SetComputeUnitPrice")?;
                ix.data[1..9].copy_from_slice(&micro_lamports.to_le_bytes());
            }
            Mutation::DropTransfer { transfer } | Mutation::DuplicateLegReuse { transfer } => {
                d.instructions.remove(transfer_at(*transfer)?);
            }
            Mutation::ExtraTransfer { transfer } => {
                let at = transfer_at(*transfer)?;
                let copy = d.instructions[at].clone();
                d.instructions.insert(at + 1, copy);
            }
            Mutation::DropMemo { memo } => {
                d.instructions.remove(memo_at(*memo)?);
            }
            Mutation::ReplaceMemo { memo, text } => {
                let at = memo_at(*memo)?;
                d.instructions[at].data = text.as_bytes().to_vec();
            }
            Mutation::FeePayerAsAccount { memo } => {
                let at = memo_at(*memo)?;
                let fee_payer = d.fee_payer;
                d.instructions[at]
                    .accounts
                    .push(AccountMeta::new_readonly(fee_payer, true));
            }
            Mutation::FeePayerAsAuthority { transfer } => {
                let at = transfer_at(*transfer)?;
                let fee_payer = d.fee_payer;
                let ix = &mut d.instructions[at];
                if ix.program_id == pubkey(SYSTEM_PROGRAM) {
                    ix.accounts[0] = AccountMeta::new(fee_payer, true);
                } else {
                    ix.accounts[3] = AccountMeta::new_readonly(fee_payer, true);
                }
            }
            Mutation::WrongNetwork { .. } | Mutation::ExpireChallenge | Mutation::DropSignature => {
                unreachable!("handled above")
            }
        }
        let mut out = compile_v0(&d)?;
        sign_slots(&mut out, signers);
        Ok(out)
    }
}

fn is_transfer(ix: &solana_instruction::Instruction) -> bool {
    let program = ix.program_id.to_string();
    (program == SYSTEM_PROGRAM && ix.data.len() >= 12 && ix.data[..4] == 2u32.to_le_bytes())
        || ((program == TOKEN_PROGRAM || program == TOKEN_2022_PROGRAM)
            && ix.data.len() == 10
            && ix.data[0] == 12)
}

fn amount_range(ix: &solana_instruction::Instruction) -> Result<std::ops::Range<usize>, String> {
    if ix.program_id == pubkey(SYSTEM_PROGRAM) {
        Ok(4..12)
    } else if ix.data.len() == 10 && ix.data[0] == 12 {
        Ok(1..9)
    } else {
        Err("not a value transfer".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tx::{x402_static_layout, StaticLayout};

    fn layout() -> VersionedTransaction {
        x402_static_layout(&StaticLayout {
            fee_payer: keys::X402_SERVER_FEE_PAYER,
            mint: keys::MINT,
            pay_to: keys::X402_PAY_TO,
            amount: 1000,
            decimals: 6,
            memo: "0123456789abcdef0123456789abcdef",
        })
        .unwrap()
    }

    #[test]
    fn every_transaction_operator_changes_the_message() {
        let tx = layout();
        let ops = [
            Mutation::BumpAmount {
                transfer: 0,
                delta: -1,
            },
            Mutation::OverPay {
                transfer: 0,
                delta: 1,
            },
            Mutation::SwapRecipient {
                transfer: 0,
                owner: keys::X402_OTHER_PAY_TO,
            },
            Mutation::WrongMint {
                transfer: 0,
                mint: keys::OTHER_MINT,
                source_owner: keys::CLIENT,
                destination_owner: keys::X402_PAY_TO,
            },
            Mutation::SetDecimals {
                transfer: 0,
                decimals: 9,
            },
            Mutation::SetComputeUnitPrice {
                micro_lamports: 5_000_001,
            },
            Mutation::DropTransfer { transfer: 0 },
            Mutation::ExtraTransfer { transfer: 0 },
            Mutation::DropMemo { memo: 0 },
            Mutation::ReplaceMemo {
                memo: 0,
                text: "other",
            },
            Mutation::FeePayerAsAccount { memo: 0 },
            Mutation::FeePayerAsAuthority { transfer: 0 },
        ];
        for op in ops {
            let out = op.apply(&tx, &[keys::CLIENT_SEED]).unwrap();
            assert_ne!(out.message, tx.message, "{op:?} left the message unchanged");
        }
        let dropped = Mutation::DropSignature.apply(&tx, &[]).unwrap();
        assert_eq!(dropped.message, tx.message);
        assert_ne!(dropped.signatures, tx.signatures);
    }

    #[test]
    fn expire_challenge_is_not_expressible_offline() {
        for suite in [Suite::Charge, Suite::X402Exact, Suite::Session] {
            assert_eq!(Mutation::ExpireChallenge.expected(suite), None);
        }
    }

    #[test]
    fn codes_are_paired_per_suite_not_per_operator() {
        let bump = Mutation::BumpAmount {
            transfer: 0,
            delta: -1,
        };
        assert_eq!(
            bump.expected(Suite::Charge),
            Some(RejectCode::NoMatchingTransfer)
        );
        assert_eq!(
            bump.expected(Suite::X402Exact),
            Some(RejectCode::AmountMismatch)
        );
    }
}
