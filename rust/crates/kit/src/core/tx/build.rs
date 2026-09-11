//! Compile instructions into an unsigned transaction of a given version, with
//! the compute budget encoded the way that version carries it, and the
//! version's wire limits enforced before any signer is involved.

use solana_hash::Hash;
use solana_instruction::Instruction;
use solana_message::{v0, v1, VersionedMessage};
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use solana_transaction::versioned::VersionedTransaction;

use super::budget::ComputeBudget;
use super::version::TxVersion;
use super::wire::serialized_size;
use crate::core::{Error, Result};

/// Compile `instructions` with `fee_payer` as account key zero into an
/// unsigned transaction of `version`, all signature slots zeroed.
///
/// `budget` is prepended as ComputeBudget instructions for version 0 and
/// written into the header for version 1. A version-1 transaction without a
/// compute unit limit is budgeted zero compute units, so `None` on version 1
/// uses [`ComputeBudget::runtime_default`], which mirrors what an unbudgeted
/// version-0 transaction gets.
///
/// Fails when the result exceeds the version's limits. Address lookup tables
/// are never used; every account is a static key.
pub fn build_unsigned(
    version: TxVersion,
    fee_payer: &Pubkey,
    instructions: &[Instruction],
    recent_blockhash: Hash,
    budget: Option<&ComputeBudget>,
) -> Result<VersionedTransaction> {
    let message = match version {
        TxVersion::V0 => {
            let with_budget: Vec<Instruction> = match budget {
                Some(budget) => budget
                    .instructions()
                    .into_iter()
                    .chain(instructions.iter().cloned())
                    .collect(),
                None => instructions.to_vec(),
            };
            VersionedMessage::V0(
                v0::Message::try_compile(fee_payer, &with_budget, &[], recent_blockhash)
                    .map_err(|e| Error::Other(format!("failed to compile v0 message: {e}")))?,
            )
        }
        TxVersion::V1 => {
            let default_budget = ComputeBudget::runtime_default(instructions.len());
            let budget = budget.unwrap_or(&default_budget);
            VersionedMessage::V1(
                v1::Message::try_compile_with_config(
                    fee_payer,
                    instructions,
                    recent_blockhash,
                    budget.v1_config(),
                )
                .map_err(|e| Error::Other(format!("failed to compile v1 message: {e}")))?,
            )
        }
    };
    let tx = VersionedTransaction {
        signatures: vec![Signature::default(); message.header().num_required_signatures as usize],
        message,
    };
    check_limits(&tx, version)?;
    Ok(tx)
}

/// Enforce `version`'s wire limits on a built transaction: serialized size,
/// static account count, and, where the format bounds them, instruction and
/// signature counts.
pub fn check_limits(tx: &VersionedTransaction, version: TxVersion) -> Result<usize> {
    let limits = version.limits();
    let size = serialized_size(tx)?;
    if size > limits.max_bytes {
        return Err(Error::Other(format!(
            "version {version} transaction is {size} bytes, over the {}-byte limit",
            limits.max_bytes
        )));
    }
    let accounts = tx.message.static_account_keys().len();
    if accounts > limits.max_static_accounts {
        return Err(Error::Other(format!(
            "version {version} transaction has {accounts} accounts, over the limit of {}",
            limits.max_static_accounts
        )));
    }
    if let Some(max) = limits.max_instructions {
        let count = tx.message.instructions().len();
        if count > max {
            return Err(Error::Other(format!(
                "version {version} transaction has {count} instructions, over the limit of {max}"
            )));
        }
    }
    if let Some(max) = limits.max_signatures {
        let count = tx.message.header().num_required_signatures as usize;
        if count > max {
            return Err(Error::Other(format!(
                "version {version} transaction requires {count} signatures, over the limit of {max}"
            )));
        }
    }
    Ok(size)
}

/// Serialized size the transaction would have once built and signed. The
/// blockhash does not affect size, so this is exact for packing decisions.
/// Errors only when the instructions cannot be compiled into `version` at all;
/// an over-limit size is returned, not rejected, so packers can probe.
pub fn measure(
    version: TxVersion,
    fee_payer: &Pubkey,
    instructions: &[Instruction],
    budget: Option<&ComputeBudget>,
) -> Result<usize> {
    match build_unsigned(version, fee_payer, instructions, Hash::default(), budget) {
        Ok(tx) => serialized_size(&tx),
        Err(e) => {
            // Over-limit is a measurement result, not a compile failure.
            let text = e.to_string();
            if text.contains("over the") {
                let probe = build_unsigned_unchecked(
                    version,
                    fee_payer,
                    instructions,
                    Hash::default(),
                    budget,
                )?;
                serialized_size(&probe)
            } else {
                Err(e)
            }
        }
    }
}

/// [`build_unsigned`] without the limit checks: for callers that measure and
/// report an over-size transaction with their own error type.
pub fn build_unsigned_unchecked(
    version: TxVersion,
    fee_payer: &Pubkey,
    instructions: &[Instruction],
    recent_blockhash: Hash,
    budget: Option<&ComputeBudget>,
) -> Result<VersionedTransaction> {
    let message = match version {
        TxVersion::V0 => {
            let with_budget: Vec<Instruction> = match budget {
                Some(budget) => budget
                    .instructions()
                    .into_iter()
                    .chain(instructions.iter().cloned())
                    .collect(),
                None => instructions.to_vec(),
            };
            VersionedMessage::V0(
                v0::Message::try_compile(fee_payer, &with_budget, &[], recent_blockhash)
                    .map_err(|e| Error::Other(format!("failed to compile v0 message: {e}")))?,
            )
        }
        TxVersion::V1 => VersionedMessage::V1(
            v1::Message::try_compile_with_config(
                fee_payer,
                instructions,
                recent_blockhash,
                budget
                    .copied()
                    .unwrap_or(ComputeBudget::runtime_default(instructions.len()))
                    .v1_config(),
            )
            .map_err(|e| Error::Other(format!("failed to compile v1 message: {e}")))?,
        ),
    };
    Ok(VersionedTransaction {
        signatures: vec![Signature::default(); message.header().num_required_signatures as usize],
        message,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use solana_system_interface::instruction as system_instruction;

    fn transfers(from: &Pubkey, n: usize) -> Vec<Instruction> {
        (0..n)
            .map(|_| system_instruction::transfer(from, &Pubkey::new_unique(), 1))
            .collect()
    }

    #[test]
    fn v0_gets_budget_instructions_and_v1_gets_header_config() {
        let payer = Pubkey::new_unique();
        let budget = ComputeBudget::new(50_000, 10);
        let ixs = transfers(&payer, 1);

        let v0 =
            build_unsigned(TxVersion::V0, &payer, &ixs, Hash::default(), Some(&budget)).unwrap();
        assert_eq!(v0.message.instructions().len(), 3);
        assert_eq!(v0.signatures.len(), 1);

        let v1 =
            build_unsigned(TxVersion::V1, &payer, &ixs, Hash::default(), Some(&budget)).unwrap();
        assert_eq!(v1.message.instructions().len(), 1);
        match &v1.message {
            VersionedMessage::V1(m) => {
                assert_eq!(m.config.compute_unit_limit, Some(50_000));
                assert_eq!(m.config.priority_fee, Some(1));
            }
            _ => panic!("expected v1"),
        }
        let defaulted = build_unsigned(TxVersion::V1, &payer, &ixs, Hash::default(), None).unwrap();
        match &defaulted.message {
            VersionedMessage::V1(m) => assert_eq!(m.config.compute_unit_limit, Some(200_000)),
            _ => panic!("expected v1"),
        }
    }

    #[test]
    fn v1_carries_what_v0_cannot() {
        let payer = Pubkey::new_unique();
        let budget = ComputeBudget::new(200_000, 1);
        // 40 transfers to distinct recipients: 42 static accounts, ~1.4 KB.
        let ixs = transfers(&payer, 40);
        let v0 = build_unsigned(TxVersion::V0, &payer, &ixs, Hash::default(), Some(&budget));
        assert!(v0.unwrap_err().to_string().contains("1232-byte limit"));
        let v1 =
            build_unsigned(TxVersion::V1, &payer, &ixs, Hash::default(), Some(&budget)).unwrap();
        assert!(serialized_size(&v1).unwrap() <= 4096);

        // 63 recipients push past the 64-address cap.
        let ixs = transfers(&payer, 63);
        let err = build_unsigned(TxVersion::V1, &payer, &ixs, Hash::default(), Some(&budget))
            .unwrap_err();
        assert!(err.to_string().contains("accounts"), "{err}");
    }

    #[test]
    fn measure_reports_over_limit_sizes_instead_of_failing() {
        let payer = Pubkey::new_unique();
        let ixs = transfers(&payer, 40);
        let size = measure(TxVersion::V0, &payer, &ixs, None).unwrap();
        assert!(size > TxVersion::V0.limits().max_bytes);
        let small = measure(TxVersion::V0, &payer, &ixs[..1], None).unwrap();
        assert_eq!(
            small,
            serialized_size(
                &build_unsigned(TxVersion::V0, &payer, &ixs[..1], Hash::default(), None).unwrap()
            )
            .unwrap()
        );
    }
}
