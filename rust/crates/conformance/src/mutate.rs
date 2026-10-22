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
//! recompile in the message's own format (legacy, version 0 or version 1
//! with its header compute config) and re-sign every slot whose key the
//! filler holds, so a mutation never fails for an unrelated reason such as a
//! stale signature (except [`Mutation::DropSignature`], whose point that
//! is). Only [`Mutation::ToFormat`] changes the format.

use ed25519_dalek::Signer;
use solana_instruction::{AccountMeta, Instruction};
use solana_message::{v1::TransactionConfig, VersionedMessage};
use solana_signature::Signature;
use solana_transaction::versioned::VersionedTransaction;

use crate::case::{RejectCode, Suite};
use crate::keys::{
    self, ata, pubkey, ATA_PROGRAM, MEMO_PROGRAM, SYSTEM_PROGRAM, TOKEN_2022_PROGRAM, TOKEN_PROGRAM,
};
use crate::tx::{
    compile_as, compile_v0, decompile, recompile, sign_slots, v1_config, MessageFormat,
};

/// Selects the n-th (0-based) value transfer: System `Transfer` or SPL
/// `TransferChecked`, in instruction order.
pub type TransferIndex = usize;

/// One field of an Associated Token Account creation instruction, changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AtaEdit {
    /// The account that funds the rent (account 0).
    Payer(&'static str),
    /// The mint (account 3); the ATA address is re-derived to match.
    Mint(&'static str),
    /// The token program (account 5); the ATA address is re-derived.
    TokenProgram(&'static str),
    /// The ATA address (account 1) set to `owner`'s ATA instead.
    Address { owner: &'static str },
    /// Non-idempotent `Create` (empty data) instead of `CreateIdempotent`.
    NonIdempotent,
}

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
    /// Replace the client's signature with its valid signature over another
    /// message, as a server sees a landed transaction's signature copied in:
    /// well-formed bytes that do not verify over this message.
    ForgeSignature,
    /// Keep only the first `keep` signatures; the message still requires
    /// all of them.
    TruncateSignatures { keep: usize },
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
    /// Make the fee payer the funding source of the n-th SOL transfer (its
    /// `from`, which on a System transfer is also the authority).
    FeePayerAsSolSource { transfer: TransferIndex },
    /// Append a System transfer of `lamports` from the fee payer to `to`: a
    /// sponsor drain that is not a payment leg.
    FeePayerSystemTransfer { to: &'static str, lamports: u64 },
    /// Insert an idempotent Associated Token Account creation for `owner`
    /// (mint and token program of transfer #0, payer = fee payer) before
    /// transfer #0.
    AddCreateAta { owner: &'static str },
    /// Edit the n-th Associated Token Program instruction the kit built.
    EditCreateAta { index: usize, edit: AtaEdit },
    /// Remove the n-th Associated Token Program instruction.
    DropCreateAta { index: usize },
    /// Insert a ComputeBudget instruction with raw `data` at the front.
    AddComputeBudget { data: &'static [u8] },
    /// Replace the data of the n-th ComputeBudget instruction.
    SetComputeBudgetData { index: usize, data: &'static [u8] },
    /// Insert an instruction of `program` (no accounts, `data`) after the
    /// last value transfer.
    AddProgramInstruction {
        program: &'static str,
        data: &'static [u8],
    },
    /// Duplicate the n-th Memo instruction right after itself.
    DuplicateMemo { memo: usize },
    /// Make the key of `seed` a required signer (a read-only signer account
    /// of the n-th Memo instruction) and sign with it.
    ExtraSigner { memo: usize, seed: [u8; 32] },
    /// Fund transfer #n from the key of `seed` instead of the client, which
    /// then signs as that leg's authority (SOL: the System transfer's source;
    /// SPL: the owner of its own token account).
    SecondAuthority {
        transfer: TransferIndex,
        seed: [u8; 32],
    },
    /// Make the key of `seed` a required signer that no instruction names,
    /// and sign with it.
    UnusedSigner { seed: [u8; 32] },
    /// Envelope: claim another network in `accepted.network` (x402 v2).
    WrongNetwork { network: &'static str },
    /// Challenge expiry in the past. Not expressible offline in the vector
    /// ABI: charge verify vectors carry no challenge (each runner mints its
    /// own) and x402 `exact` has no challenge expiry. Kept so the operator
    /// table states it; `expected` returns `None` for every suite.
    ExpireChallenge,
    /// Recompile the same instructions in another message format, moving the
    /// compute budget between the ComputeBudget instructions (legacy,
    /// version 0) and the version-1 header `TransactionConfig` (the kit's
    /// encoding: total priority fee rounded up, maximum loaded-data limit).
    /// Whether that is a reject depends on what the server accepts, so
    /// `expected` is `None`: cases using it are authored.
    ToFormat { format: MessageFormat },
    /// Version 1: set the header `computeUnitLimit`.
    V1ComputeUnitLimit { limit: u32 },
    /// Version 1: set the header `priorityFee` (total lamports).
    V1PriorityFee { lamports: u64 },
    /// Version 1: set the header `computeUnitLimit` and `priorityFee`
    /// together, so a per-unit price boundary can sit below a sponsor's cap
    /// on the total fee.
    V1Budget { limit: u32, lamports: u64 },
    /// Version 1: remove the header `computeUnitLimit` (budgeted zero).
    V1DropComputeUnitLimit,
    /// Version 1: remove the header `loadedAccountsDataSizeLimit` (budgeted
    /// zero bytes).
    V1DropLoadedAccountsDataSizeLimit,
    /// Replace the n-th Memo instruction's text with `len` hex characters,
    /// to move the serialized size across a version's limit. Whether that is
    /// a reject depends on the format, so `expected` is `None`.
    PadMemo { memo: usize, len: usize },
    /// Version 0: resolve transfer #0's destination through an address
    /// lookup table instead of the static account keys.
    AddLookupTable,
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
            (
                DropSignature | ForgeSignature | TruncateSignatures { .. },
                Suite::Charge | Suite::X402Exact | Suite::Session,
            ) => Some(InvalidPayload),
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
            (FeePayerAsSolSource { .. }, Suite::Charge) => Some(FeePayerIsFundsSource),
            (FeePayerSystemTransfer { .. }, Suite::Charge | Suite::Session) => {
                Some(UnexpectedInstruction)
            }
            (FeePayerSystemTransfer { .. }, Suite::X402Exact) => Some(FeePayerNotAuthority),
            (AddCreateAta { .. }, Suite::Charge) => Some(UnexpectedInstruction),
            (EditCreateAta { .. } | DropCreateAta { .. }, Suite::Charge) => Some(InvalidPayload),
            (AddComputeBudget { .. }, Suite::X402Exact) => Some(InvalidPayload),
            (AddComputeBudget { .. }, Suite::Charge) => Some(UnexpectedInstruction),
            (SetComputeBudgetData { .. }, Suite::X402Exact) => Some(InvalidPayload),
            (AddProgramInstruction { .. }, Suite::Charge | Suite::X402Exact | Suite::Session) => {
                Some(UnexpectedInstruction)
            }
            (ExtraSigner { .. }, Suite::X402Exact) => Some(UnexpectedInstruction),
            (SecondAuthority { .. }, Suite::Charge) => Some(MixedFundingAuthority),
            (UnusedSigner { .. }, Suite::Charge) => Some(UnexpectedSigner),
            (DuplicateMemo { .. }, Suite::X402Exact) => Some(InvalidPayload),
            (Mutation::WrongNetwork { .. }, Suite::X402Exact) => Some(RejectCode::AcceptedMismatch),
            (V1ComputeUnitLimit { .. }, Suite::Charge | Suite::X402Exact | Suite::Session) => {
                Some(ComputeLimitOverCap)
            }
            (
                V1PriorityFee { .. } | V1Budget { .. },
                Suite::Charge | Suite::X402Exact | Suite::Session,
            ) => Some(ComputePriceOverCap),
            (
                V1DropComputeUnitLimit | V1DropLoadedAccountsDataSizeLimit,
                Suite::Charge | Suite::X402Exact | Suite::Session,
            ) => Some(InvalidPayload),
            (AddLookupTable, Suite::Charge | Suite::X402Exact | Suite::Session) => {
                Some(InvalidPayload)
            }
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
            Mutation::ForgeSignature => {
                "client signature replaced with its signature over another message".into()
            }
            Mutation::TruncateSignatures { keep } => {
                format!("signatures cut to the first {keep}")
            }
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
            Mutation::FeePayerAsSolSource { transfer } => {
                format!("fee payer made the funding source of SOL transfer #{transfer}")
            }
            Mutation::FeePayerSystemTransfer { to, lamports } => {
                format!("System transfer of {lamports} lamports from the fee payer to {to} added")
            }
            Mutation::AddCreateAta { owner } => {
                format!("idempotent ATA creation for {owner}, paid by the fee payer, added")
            }
            Mutation::EditCreateAta { index, edit } => {
                let what = match edit {
                    AtaEdit::Payer(p) => format!("payer set to {p}"),
                    AtaEdit::Mint(m) => format!("mint set to {m} (address re-derived)"),
                    AtaEdit::TokenProgram(p) => {
                        format!("token program set to {p} (address re-derived)")
                    }
                    AtaEdit::Address { owner } => format!("address set to {owner}'s ATA"),
                    AtaEdit::NonIdempotent => "made a non-idempotent Create".into(),
                };
                format!("ATA creation #{index} {what}")
            }
            Mutation::DropCreateAta { index } => format!("ATA creation #{index} removed"),
            Mutation::AddComputeBudget { data } => {
                format!("ComputeBudget instruction with data {data:?} added")
            }
            Mutation::SetComputeBudgetData { index, data } => {
                format!("ComputeBudget instruction #{index} data set to {data:?}")
            }
            Mutation::AddProgramInstruction { program, data } => {
                format!("instruction of program {program} with data {data:?} added")
            }
            Mutation::DuplicateMemo { memo } => format!("memo #{memo} duplicated"),
            Mutation::ExtraSigner { memo, seed } => format!(
                "{} added as a required signer of memo #{memo}",
                keys::pubkey_of_seed(*seed)
            ),
            Mutation::SecondAuthority { transfer, seed } => format!(
                "transfer #{transfer} funded and signed by {}",
                keys::pubkey_of_seed(*seed)
            ),
            Mutation::UnusedSigner { seed } => format!(
                "{} added as a required signer no instruction names",
                keys::pubkey_of_seed(*seed)
            ),
            Mutation::WrongNetwork { network } => format!("accepted.network set to {network}"),
            Mutation::ExpireChallenge => "challenge expiry moved into the past".into(),
            Mutation::ToFormat { format } => match format {
                MessageFormat::Legacy => {
                    "recompiled as a legacy message (compute budget as instructions)".into()
                }
                MessageFormat::V0 => {
                    "recompiled as a version-0 message (compute budget as instructions)".into()
                }
                MessageFormat::V1 => {
                    "recompiled as a version-1 message (compute budget in the header)".into()
                }
            },
            Mutation::V1ComputeUnitLimit { limit } => {
                format!("version-1 header computeUnitLimit set to {limit}")
            }
            Mutation::V1PriorityFee { lamports } => {
                format!("version-1 header priorityFee set to {lamports} lamports")
            }
            Mutation::V1Budget { limit, lamports } => format!(
                "version-1 header computeUnitLimit set to {limit} and priorityFee to {lamports} lamports"
            ),
            Mutation::V1DropComputeUnitLimit => "version-1 header computeUnitLimit removed".into(),
            Mutation::V1DropLoadedAccountsDataSizeLimit => {
                "version-1 header loadedAccountsDataSizeLimit removed".into()
            }
            Mutation::PadMemo { memo, len } => {
                format!("memo #{memo} replaced with {len} hex characters")
            }
            Mutation::AddLookupTable => {
                "transfer #0 destination resolved through an address lookup table".into()
            }
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
        if let Mutation::ForgeSignature = self {
            let mut out = tx.clone();
            let client = keys::pubkey_of_seed(keys::CLIENT_SEED);
            let index = out
                .message
                .static_account_keys()
                .iter()
                .position(|k| *k == client)
                .ok_or("client is not a signer of the transaction")?;
            let other =
                keys::signing_key(keys::CLIENT_SEED).sign(b"a transaction that already landed");
            out.signatures[index] = Signature::from(other.to_bytes());
            return Ok(out);
        }
        if let Mutation::TruncateSignatures { keep } = self {
            let mut out = tx.clone();
            if *keep >= out.signatures.len() {
                return Err(format!("{self:?} keeps every signature"));
            }
            out.signatures.truncate(*keep);
            return Ok(out);
        }
        match self {
            Mutation::ToFormat { format } => return to_format(tx, *format, signers),
            Mutation::AddLookupTable => return add_lookup_table(tx, signers),
            Mutation::V1ComputeUnitLimit { .. }
            | Mutation::V1PriorityFee { .. }
            | Mutation::V1Budget { .. }
            | Mutation::V1DropComputeUnitLimit
            | Mutation::V1DropLoadedAccountsDataSizeLimit => {
                let mut config = v1_config(&tx.message)
                    .ok_or_else(|| format!("{self:?} needs a version-1 message"))?;
                match self {
                    Mutation::V1ComputeUnitLimit { limit } => {
                        config.compute_unit_limit = Some(*limit)
                    }
                    Mutation::V1PriorityFee { lamports } => config.priority_fee = Some(*lamports),
                    Mutation::V1Budget { limit, lamports } => {
                        config.compute_unit_limit = Some(*limit);
                        config.priority_fee = Some(*lamports);
                    }
                    Mutation::V1DropComputeUnitLimit => config.compute_unit_limit = None,
                    _ => config.loaded_accounts_data_size_limit = None,
                }
                let mut out = compile_as(MessageFormat::V1, &decompile(&tx.message)?, config)?;
                sign_slots(&mut out, signers);
                return Ok(out);
            }
            _ => {}
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
        let atas: Vec<usize> = d
            .instructions
            .iter()
            .enumerate()
            .filter(|(_, ix)| ix.program_id == pubkey(ATA_PROGRAM))
            .map(|(i, _)| i)
            .collect();
        let ata_at = |n: usize| {
            atas.get(n)
                .copied()
                .ok_or_else(|| format!("transaction has no ATA creation #{n}"))
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
            Mutation::FeePayerAsSolSource { transfer } => {
                let at = transfer_at(*transfer)?;
                let fee_payer = d.fee_payer;
                let ix = &mut d.instructions[at];
                if ix.program_id != pubkey(SYSTEM_PROGRAM) {
                    return Err("FeePayerAsSolSource needs a System transfer".into());
                }
                ix.accounts[0] = AccountMeta::new(fee_payer, true);
            }
            Mutation::FeePayerSystemTransfer { to, lamports } => {
                let mut data = 2u32.to_le_bytes().to_vec();
                data.extend_from_slice(&lamports.to_le_bytes());
                let ix = Instruction {
                    program_id: pubkey(SYSTEM_PROGRAM),
                    accounts: vec![
                        AccountMeta::new(d.fee_payer, true),
                        AccountMeta::new(pubkey(to), false),
                    ],
                    data,
                };
                let after = transfers
                    .last()
                    .map(|t| t + 1)
                    .unwrap_or(d.instructions.len());
                d.instructions.insert(after, ix);
            }
            Mutation::AddCreateAta { owner } => {
                let at = transfer_at(0)?;
                let transfer = &d.instructions[at];
                if transfer.program_id == pubkey(SYSTEM_PROGRAM) {
                    return Err("AddCreateAta needs an SPL transfer".into());
                }
                let mint = transfer.accounts[1].pubkey.to_string();
                let program = transfer.program_id.to_string();
                let ix = create_ata(d.fee_payer, owner, &mint, &program, owner);
                d.instructions.insert(at, ix);
            }
            Mutation::EditCreateAta { index, edit } => {
                let at = ata_at(*index)?;
                let ix = &mut d.instructions[at];
                let owner = ix.accounts[2].pubkey.to_string();
                let mut mint = ix.accounts[3].pubkey.to_string();
                let mut program = ix.accounts[5].pubkey.to_string();
                match edit {
                    AtaEdit::Payer(payer) => {
                        let payer = pubkey(payer);
                        ix.accounts[0] = AccountMeta::new(payer, true);
                    }
                    AtaEdit::Mint(m) => {
                        mint = m.to_string();
                        ix.accounts[3].pubkey = pubkey(m);
                        ix.accounts[1].pubkey = ata(&owner, &mint, &program);
                    }
                    AtaEdit::TokenProgram(p) => {
                        program = p.to_string();
                        ix.accounts[5].pubkey = pubkey(p);
                        ix.accounts[1].pubkey = ata(&owner, &mint, &program);
                    }
                    AtaEdit::Address { owner } => {
                        ix.accounts[1].pubkey = ata(owner, &mint, &program);
                    }
                    AtaEdit::NonIdempotent => ix.data = Vec::new(),
                }
            }
            Mutation::DropCreateAta { index } => {
                d.instructions.remove(ata_at(*index)?);
            }
            Mutation::AddComputeBudget { data } => {
                d.instructions.insert(
                    0,
                    Instruction {
                        program_id: pubkey(keys::COMPUTE_BUDGET_PROGRAM),
                        accounts: vec![],
                        data: data.to_vec(),
                    },
                );
            }
            Mutation::SetComputeBudgetData { index, data } => {
                let at = d
                    .instructions
                    .iter()
                    .enumerate()
                    .filter(|(_, ix)| ix.program_id == pubkey(keys::COMPUTE_BUDGET_PROGRAM))
                    .map(|(i, _)| i)
                    .nth(*index)
                    .ok_or_else(|| format!("transaction has no ComputeBudget #{index}"))?;
                d.instructions[at].data = data.to_vec();
            }
            Mutation::AddProgramInstruction { program, data } => {
                let after = transfers
                    .last()
                    .map(|t| t + 1)
                    .unwrap_or(d.instructions.len());
                d.instructions.insert(
                    after,
                    Instruction {
                        program_id: pubkey(program),
                        accounts: vec![],
                        data: data.to_vec(),
                    },
                );
            }
            Mutation::DuplicateMemo { memo } => {
                let at = memo_at(*memo)?;
                let copy = d.instructions[at].clone();
                d.instructions.insert(at + 1, copy);
            }
            Mutation::ExtraSigner { memo, seed } => {
                let at = memo_at(*memo)?;
                d.instructions[at]
                    .accounts
                    .push(AccountMeta::new_readonly(keys::pubkey_of_seed(*seed), true));
                let mut out = recompile(&tx.message, &d)?;
                let mut seeds = signers.to_vec();
                seeds.push(*seed);
                sign_slots(&mut out, &seeds);
                return Ok(out);
            }
            Mutation::PadMemo { memo, len } => {
                let at = memo_at(*memo)?;
                d.instructions[at].data = b"0123456789abcdef"
                    .iter()
                    .cycle()
                    .take(*len)
                    .copied()
                    .collect();
            }
            Mutation::SecondAuthority { transfer, seed } => {
                let at = transfer_at(*transfer)?;
                let authority = keys::pubkey_of_seed(*seed);
                let ix = &mut d.instructions[at];
                if ix.program_id == pubkey(SYSTEM_PROGRAM) {
                    ix.accounts[0] = AccountMeta::new(authority, true);
                } else {
                    let mint = ix.accounts[1].pubkey.to_string();
                    let program = ix.program_id.to_string();
                    ix.accounts[0] =
                        AccountMeta::new(ata(&authority.to_string(), &mint, &program), false);
                    ix.accounts[3] = AccountMeta::new_readonly(authority, true);
                }
                let mut out = recompile(&tx.message, &d)?;
                let mut seeds = signers.to_vec();
                seeds.push(*seed);
                sign_slots(&mut out, &seeds);
                return Ok(out);
            }
            Mutation::UnusedSigner { seed } => {
                let mut out = compile_v0(&d)?;
                let VersionedMessage::V0(message) = &mut out.message else {
                    unreachable!("compile_v0 builds a version-0 message")
                };
                // The new key joins the end of the signer block as a
                // read-only signer; every later index shifts by one.
                let at = message.header.num_required_signatures;
                message
                    .account_keys
                    .insert(at as usize, keys::pubkey_of_seed(*seed));
                message.header.num_required_signatures += 1;
                message.header.num_readonly_signed_accounts += 1;
                for ix in &mut message.instructions {
                    if ix.program_id_index >= at {
                        ix.program_id_index += 1;
                    }
                    for account in &mut ix.accounts {
                        if *account >= at {
                            *account += 1;
                        }
                    }
                }
                out.signatures =
                    vec![Signature::default(); message.header.num_required_signatures as usize];
                let mut seeds = signers.to_vec();
                seeds.push(*seed);
                sign_slots(&mut out, &seeds);
                return Ok(out);
            }
            Mutation::WrongNetwork { .. }
            | Mutation::ExpireChallenge
            | Mutation::DropSignature
            | Mutation::ForgeSignature
            | Mutation::TruncateSignatures { .. }
            | Mutation::ToFormat { .. }
            | Mutation::AddLookupTable
            | Mutation::V1ComputeUnitLimit { .. }
            | Mutation::V1PriorityFee { .. }
            | Mutation::V1Budget { .. }
            | Mutation::V1DropComputeUnitLimit
            | Mutation::V1DropLoadedAccountsDataSizeLimit => {
                unreachable!("handled above")
            }
        }
        let mut out = recompile(&tx.message, &d)?;
        sign_slots(&mut out, signers);
        Ok(out)
    }
}

/// [`Mutation::ToFormat`]: the same instructions in `format`. Leaving
/// version 1, the header budget becomes `SetComputeUnitLimit` +
/// `SetComputeUnitPrice` (price = priority fee per unit, rounded down);
/// entering it, the ComputeBudget instructions become the header config the
/// kit would write for them (an absent limit takes the runtime default).
fn to_format(
    tx: &VersionedTransaction,
    format: MessageFormat,
    signers: &[[u8; 32]],
) -> Result<VersionedTransaction, String> {
    use solana_pay_kit::core::tx::{unit_limit_instruction, unit_price_instruction, ComputeBudget};
    let from = MessageFormat::of(&tx.message);
    if from == format {
        return Err(format!(
            "the message is already in format {}",
            format.as_str()
        ));
    }
    let mut d = decompile(&tx.message)?;
    let mut config = TransactionConfig::default();
    if from == MessageFormat::V1 {
        let header = v1_config(&tx.message).unwrap_or_default();
        if let Some(limit) = header.compute_unit_limit {
            let price = match header.priority_fee {
                Some(fee) if limit > 0 => (fee as u128 * 1_000_000 / limit as u128) as u64,
                _ => 0,
            };
            d.instructions.insert(0, unit_price_instruction(price));
            d.instructions.insert(0, unit_limit_instruction(limit));
        }
    } else if format == MessageFormat::V1 {
        let (mut limit, mut price) = (None, None);
        d.instructions.retain(|ix| {
            if ix.program_id != pubkey(keys::COMPUTE_BUDGET_PROGRAM) {
                return true;
            }
            match (ix.data.first(), ix.data.len()) {
                (Some(2), 5) => limit = Some(u32::from_le_bytes(ix.data[1..5].try_into().unwrap())),
                (Some(3), 9) => price = Some(u64::from_le_bytes(ix.data[1..9].try_into().unwrap())),
                _ => {}
            }
            false
        });
        let limit = limit
            .unwrap_or_else(|| ComputeBudget::runtime_default(d.instructions.len()).unit_limit);
        config = ComputeBudget::new(limit, price.unwrap_or(0)).v1_config();
    }
    let mut out = compile_as(format, &d, config)?;
    sign_slots(&mut out, signers);
    Ok(out)
}

/// [`Mutation::AddLookupTable`]: recompile a version-0 message with transfer
/// #0's destination moved out of the static keys into a lookup table.
fn add_lookup_table(
    tx: &VersionedTransaction,
    signers: &[[u8; 32]],
) -> Result<VersionedTransaction, String> {
    if MessageFormat::of(&tx.message) != MessageFormat::V0 {
        return Err("AddLookupTable needs a version-0 message".into());
    }
    let d = decompile(&tx.message)?;
    let transfer = d
        .instructions
        .iter()
        .find(|ix| is_transfer(ix))
        .ok_or("transaction has no transfer #0")?;
    let index = if transfer.program_id == pubkey(SYSTEM_PROGRAM) {
        1
    } else {
        2
    };
    let table = solana_message::AddressLookupTableAccount {
        key: solana_pubkey::Pubkey::new_from_array([0x41; 32]),
        addresses: vec![transfer.accounts[index].pubkey],
    };
    let message = solana_message::v0::Message::try_compile(
        &d.fee_payer,
        &d.instructions,
        std::slice::from_ref(&table),
        d.blockhash,
    )
    .map_err(|e| format!("compile v0 message with a lookup table: {e}"))?;
    if message.address_table_lookups.is_empty() {
        return Err("the destination did not move into the lookup table".into());
    }
    let message = VersionedMessage::V0(message);
    let mut out = VersionedTransaction {
        signatures: vec![Default::default(); message.header().num_required_signatures as usize],
        message,
    };
    sign_slots(&mut out, signers);
    Ok(out)
}

/// `CreateIdempotent` for `owner`'s ATA of `mint` under `program`, with the
/// address derived for `address_owner` (normally `owner`).
fn create_ata(
    payer: solana_pubkey::Pubkey,
    owner: &str,
    mint: &str,
    program: &str,
    address_owner: &str,
) -> Instruction {
    Instruction {
        program_id: pubkey(ATA_PROGRAM),
        accounts: vec![
            AccountMeta::new(payer, true),
            AccountMeta::new(ata(address_owner, mint, program), false),
            AccountMeta::new_readonly(pubkey(owner), false),
            AccountMeta::new_readonly(pubkey(mint), false),
            AccountMeta::new_readonly(pubkey(SYSTEM_PROGRAM), false),
            AccountMeta::new_readonly(pubkey(program), false),
        ],
        data: vec![1],
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
        let forged = Mutation::ForgeSignature.apply(&tx, &[]).unwrap();
        assert_eq!(forged.message, tx.message);
        assert!(forged
            .signatures
            .iter()
            .all(|s| *s != Signature::default() || tx.signatures.contains(s)));
        assert_ne!(forged.signatures, tx.signatures);
        let cut = Mutation::TruncateSignatures { keep: 1 }
            .apply(&tx, &[])
            .unwrap();
        assert_eq!(cut.signatures.len(), 1);
    }

    #[test]
    fn version_operators_change_the_message_and_keep_the_format() {
        let v0 = layout();
        let v1 = crate::tx::x402_static_layout_v1(
            &StaticLayout {
                fee_payer: keys::X402_SERVER_FEE_PAYER,
                mint: keys::MINT,
                pay_to: keys::X402_PAY_TO,
                amount: 1000,
                decimals: 6,
                memo: "0123456789abcdef0123456789abcdef",
            },
            crate::tx::x402_static_layout_v1_config(),
        )
        .unwrap();
        assert_eq!(MessageFormat::of(&v1.message), MessageFormat::V1);
        let cases = [
            (
                &v0,
                Mutation::ToFormat {
                    format: MessageFormat::V1,
                },
                MessageFormat::V1,
            ),
            (
                &v0,
                Mutation::ToFormat {
                    format: MessageFormat::Legacy,
                },
                MessageFormat::Legacy,
            ),
            (
                &v1,
                Mutation::ToFormat {
                    format: MessageFormat::V0,
                },
                MessageFormat::V0,
            ),
            (
                &v0,
                Mutation::PadMemo { memo: 0, len: 1300 },
                MessageFormat::V0,
            ),
            (
                &v1,
                Mutation::PadMemo { memo: 0, len: 1300 },
                MessageFormat::V1,
            ),
            (&v0, Mutation::AddLookupTable, MessageFormat::V0),
            (
                &v1,
                Mutation::V1ComputeUnitLimit { limit: 1 },
                MessageFormat::V1,
            ),
            (
                &v1,
                Mutation::V1PriorityFee { lamports: 7 },
                MessageFormat::V1,
            ),
            (
                &v1,
                Mutation::V1Budget {
                    limit: 300,
                    lamports: 7,
                },
                MessageFormat::V1,
            ),
            (&v1, Mutation::V1DropComputeUnitLimit, MessageFormat::V1),
            (
                &v1,
                Mutation::V1DropLoadedAccountsDataSizeLimit,
                MessageFormat::V1,
            ),
            // Instruction operators recompile in the message's own format.
            (
                &v1,
                Mutation::BumpAmount {
                    transfer: 0,
                    delta: -1,
                },
                MessageFormat::V1,
            ),
            (
                &v1,
                Mutation::ExtraSigner {
                    memo: 0,
                    seed: [21; 32],
                },
                MessageFormat::V1,
            ),
        ];
        for (tx, op, format) in cases {
            let out = op.apply(tx, &[keys::CLIENT_SEED]).unwrap();
            assert_ne!(out.message, tx.message, "{op:?} left the message unchanged");
            assert_eq!(MessageFormat::of(&out.message), format, "{op:?}");
            // Every slot the filler holds is re-signed.
            assert!(crate::tx::signature_slots(&out)
                .iter()
                .all(|(_, slot)| *slot != crate::tx::Slot::Invalid));
        }
        // v0 -> v1 -> v0: the limit survives; the 1 micro-lamport price
        // becomes the kit's 1-lamport total (rounded up), i.e. 5
        // micro-lamports per unit over 200_000 units on the way back.
        let there = Mutation::ToFormat {
            format: MessageFormat::V1,
        }
        .apply(&v0, &[keys::CLIENT_SEED])
        .unwrap();
        let header = crate::tx::v1_config(&there.message).unwrap();
        assert_eq!(header.compute_unit_limit, Some(200_000));
        assert_eq!(header.priority_fee, Some(1));
        let back = Mutation::ToFormat {
            format: MessageFormat::V0,
        }
        .apply(&there, &[keys::CLIENT_SEED])
        .unwrap();
        let price = Mutation::SetComputeUnitPrice { micro_lamports: 5 }
            .apply(&v0, &[keys::CLIENT_SEED])
            .unwrap();
        assert_eq!(back.message, price.message);
        // A v1-only operator refuses other formats.
        assert!(Mutation::V1DropComputeUnitLimit
            .apply(&v0, &[keys::CLIENT_SEED])
            .is_err());
        assert!(Mutation::AddLookupTable
            .apply(&v1, &[keys::CLIENT_SEED])
            .is_err());
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
