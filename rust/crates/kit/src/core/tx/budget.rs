//! Compute budget as one value with two encodings: two ComputeBudget
//! instructions for version-0 messages, the header `TransactionConfig` for
//! version 1.

use solana_instruction::Instruction;
use solana_message::compiled_instruction::CompiledInstruction;
use solana_message::{v1, VersionedMessage};
use solana_pubkey::Pubkey;

use super::version::TxVersion;
use crate::core::{Error, Result};

/// The ComputeBudget program.
pub const COMPUTE_BUDGET_PROGRAM_ID: Pubkey =
    Pubkey::from_str_const("ComputeBudget111111111111111111111111111111");

/// `SetComputeUnitLimit` instruction tag.
pub const SET_UNIT_LIMIT_TAG: u8 = 2;
/// `SetComputeUnitPrice` instruction tag.
pub const SET_UNIT_PRICE_TAG: u8 = 3;
/// `SetLoadedAccountsDataSizeLimit` instruction tag.
pub const SET_LOADED_ACCOUNTS_DATA_SIZE_LIMIT_TAG: u8 = 4;

/// The runtime's maximum for loaded account data, and the value a version-0
/// transaction gets when it sets no limit. A version-1 transaction that sets
/// no limit is budgeted zero bytes and cannot execute, so builders default to
/// this. The cost model bills the requested limit in 32 KiB pages, which only
/// affects scheduling priority.
pub const MAX_LOADED_ACCOUNTS_DATA_SIZE_BYTES: u32 = 64 * 1024 * 1024;

/// A compute budget request, independent of message version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ComputeBudget {
    /// Compute unit limit.
    pub unit_limit: u32,
    /// Priority fee price in micro-lamports per compute unit.
    pub unit_price_micro_lamports: u64,
    /// Loaded account data limit in bytes.
    pub loaded_accounts_data_size_limit: u32,
}

impl ComputeBudget {
    /// A budget with the given limit and price and the runtime's maximum
    /// loaded-data limit.
    pub const fn new(unit_limit: u32, unit_price_micro_lamports: u64) -> Self {
        Self {
            unit_limit,
            unit_price_micro_lamports,
            loaded_accounts_data_size_limit: MAX_LOADED_ACCOUNTS_DATA_SIZE_BYTES,
        }
    }

    /// Total priority fee in lamports, rounded up: what a version-1 header
    /// carries in place of a per-unit price.
    pub fn priority_fee_lamports(&self) -> u64 {
        let micro = self.unit_limit as u128 * self.unit_price_micro_lamports as u128;
        micro.div_ceil(1_000_000).min(u64::MAX as u128) as u64
    }

    /// The version-0 encoding: `SetComputeUnitLimit` then `SetComputeUnitPrice`.
    pub fn instructions(&self) -> Vec<Instruction> {
        vec![
            unit_limit_instruction(self.unit_limit),
            unit_price_instruction(self.unit_price_micro_lamports),
        ]
    }

    /// The version-1 encoding.
    pub fn v1_config(&self) -> v1::TransactionConfig {
        v1::TransactionConfig::empty()
            .with_compute_unit_limit(self.unit_limit)
            .with_priority_fee(self.priority_fee_lamports())
            .with_loaded_accounts_data_size_limit(self.loaded_accounts_data_size_limit)
    }
}

/// `SetComputeUnitLimit(units)`.
pub fn unit_limit_instruction(units: u32) -> Instruction {
    let mut data = vec![SET_UNIT_LIMIT_TAG];
    data.extend_from_slice(&units.to_le_bytes());
    Instruction {
        program_id: COMPUTE_BUDGET_PROGRAM_ID,
        accounts: vec![],
        data,
    }
}

/// `SetComputeUnitPrice(micro_lamports)`.
pub fn unit_price_instruction(micro_lamports: u64) -> Instruction {
    let mut data = vec![SET_UNIT_PRICE_TAG];
    data.extend_from_slice(&micro_lamports.to_le_bytes());
    Instruction {
        program_id: COMPUTE_BUDGET_PROGRAM_ID,
        accounts: vec![],
        data,
    }
}

/// A decoded ComputeBudget instruction a sponsor policy may permit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComputeBudgetOp {
    /// `SetComputeUnitLimit(units)`.
    UnitLimit(u32),
    /// `SetComputeUnitPrice(microLamportsPerComputeUnit)`.
    UnitPrice(u64),
    /// `SetLoadedAccountsDataSizeLimit(bytes)`.
    LoadedAccountsDataSizeLimit(u32),
}

/// Decode a ComputeBudget instruction's data. Returns `None` for any other
/// opcode or a malformed length; callers decide whether that is an error.
pub fn decode_compute_budget_op(ix: &CompiledInstruction) -> Option<ComputeBudgetOp> {
    match (ix.data.first().copied(), ix.data.len()) {
        (Some(SET_UNIT_LIMIT_TAG), 5) => Some(ComputeBudgetOp::UnitLimit(u32::from_le_bytes(
            ix.data[1..5].try_into().expect("4-byte slice"),
        ))),
        (Some(SET_UNIT_PRICE_TAG), 9) => Some(ComputeBudgetOp::UnitPrice(u64::from_le_bytes(
            ix.data[1..9].try_into().expect("8-byte slice"),
        ))),
        (Some(SET_LOADED_ACCOUNTS_DATA_SIZE_LIMIT_TAG), 5) => {
            Some(ComputeBudgetOp::LoadedAccountsDataSizeLimit(
                u32::from_le_bytes(ix.data[1..5].try_into().expect("4-byte slice")),
            ))
        }
        _ => None,
    }
}

/// The compute budget a message declares, normalized across versions so one
/// cap applies to both encodings.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DeclaredBudget {
    /// Compute unit limit, if declared.
    pub unit_limit: Option<u32>,
    /// Price in micro-lamports per compute unit, if declared. For version 1
    /// this is derived from the total `priority_fee`, rounded up, so a cap
    /// check on it is never more lenient than the same cap on version 0.
    pub unit_price_micro_lamports: Option<u64>,
    /// Loaded account data limit, if declared.
    pub loaded_accounts_data_size_limit: Option<u32>,
    /// Indices of the ComputeBudget instructions that carried the budget
    /// (version 0 only). Verifiers use it to skip them in shape checks.
    pub instruction_indexes: Vec<usize>,
}

impl DeclaredBudget {
    /// Read the budget a message declares.
    ///
    /// Version 0: scans top-level ComputeBudget instructions. A duplicate
    /// limit or price, or an unknown ComputeBudget opcode, is an error.
    /// Version 1: reads the header config. Any ComputeBudget instruction is an
    /// error: the runtime ignores them, so a verifier that bounded them would
    /// be bounding nothing. `compute_unit_limit` must be present; a version-1
    /// transaction without it is budgeted zero compute units.
    pub fn of(message: &VersionedMessage) -> Result<DeclaredBudget> {
        let version = TxVersion::of(message)?;
        let keys = message.static_account_keys();
        let is_compute_budget = |ix: &CompiledInstruction| {
            keys.get(ix.program_id_index as usize) == Some(&COMPUTE_BUDGET_PROGRAM_ID)
        };
        match version {
            TxVersion::V1 => {
                if message.instructions().iter().any(is_compute_budget) {
                    return Err(Error::Other(
                        "version 1 transactions must not contain ComputeBudget instructions".into(),
                    ));
                }
                let VersionedMessage::V1(v1) = message else {
                    unreachable!("version checked above")
                };
                let unit_limit = v1.config.compute_unit_limit.ok_or_else(|| {
                    Error::Other("version 1 transaction config must set computeUnitLimit".into())
                })?;
                let unit_price_micro_lamports = v1.config.priority_fee.map(|fee| {
                    if unit_limit == 0 {
                        u64::MAX
                    } else {
                        let micro = fee as u128 * 1_000_000u128;
                        micro.div_ceil(unit_limit as u128).min(u64::MAX as u128) as u64
                    }
                });
                Ok(DeclaredBudget {
                    unit_limit: Some(unit_limit),
                    unit_price_micro_lamports,
                    loaded_accounts_data_size_limit: v1.config.loaded_accounts_data_size_limit,
                    instruction_indexes: Vec::new(),
                })
            }
            TxVersion::V0 => {
                let mut budget = DeclaredBudget::default();
                for (index, ix) in message.instructions().iter().enumerate() {
                    if !is_compute_budget(ix) {
                        continue;
                    }
                    match decode_compute_budget_op(ix) {
                        Some(ComputeBudgetOp::UnitLimit(units)) => {
                            if budget.unit_limit.replace(units).is_some() {
                                return Err(Error::Other(
                                    "duplicate SetComputeUnitLimit instruction".into(),
                                ));
                            }
                        }
                        Some(ComputeBudgetOp::UnitPrice(price)) => {
                            if budget.unit_price_micro_lamports.replace(price).is_some() {
                                return Err(Error::Other(
                                    "duplicate SetComputeUnitPrice instruction".into(),
                                ));
                            }
                        }
                        Some(ComputeBudgetOp::LoadedAccountsDataSizeLimit(bytes)) => {
                            if budget
                                .loaded_accounts_data_size_limit
                                .replace(bytes)
                                .is_some()
                            {
                                return Err(Error::Other(
                                    "duplicate SetLoadedAccountsDataSizeLimit instruction".into(),
                                ));
                            }
                        }
                        None => {
                            return Err(Error::Other(
                                "unsupported ComputeBudget instruction".into(),
                            ))
                        }
                    }
                    budget.instruction_indexes.push(index);
                }
                Ok(budget)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use solana_hash::Hash;
    use solana_system_interface::instruction as system_instruction;

    fn transfer() -> Instruction {
        system_instruction::transfer(&Pubkey::new_unique(), &Pubkey::new_unique(), 1)
    }

    #[test]
    fn priority_fee_rounds_up_to_whole_lamports() {
        // 20_000 CU × 1 µlamport = 0.02 lamports → 1 lamport.
        assert_eq!(ComputeBudget::new(20_000, 1).priority_fee_lamports(), 1);
        // 400_000 CU × 5_000_000 µlamports = 2_000_000 lamports exactly.
        assert_eq!(
            ComputeBudget::new(400_000, 5_000_000).priority_fee_lamports(),
            2_000_000
        );
        assert_eq!(ComputeBudget::new(0, 5).priority_fee_lamports(), 0);
    }

    #[test]
    fn v0_budget_round_trips_through_instructions() {
        let budget = ComputeBudget::new(200_000, 1_000);
        let mut ixs = budget.instructions();
        ixs.push(transfer());
        let msg = VersionedMessage::V0(
            solana_message::v0::Message::try_compile(
                &Pubkey::new_unique(),
                &ixs,
                &[],
                Hash::default(),
            )
            .unwrap(),
        );
        let declared = DeclaredBudget::of(&msg).unwrap();
        assert_eq!(declared.unit_limit, Some(200_000));
        assert_eq!(declared.unit_price_micro_lamports, Some(1_000));
        assert_eq!(declared.instruction_indexes, vec![0, 1]);
    }

    #[test]
    fn v1_budget_is_read_from_the_header_and_price_is_never_understated() {
        let payer = Pubkey::new_unique();
        // 20_000 CU with a 1-lamport total fee is 50 µlamports/CU exactly.
        let budget = ComputeBudget::new(20_000, 50);
        let msg = VersionedMessage::V1(
            v1::Message::try_compile_with_config(
                &payer,
                &[transfer()],
                Hash::default(),
                budget.v1_config(),
            )
            .unwrap(),
        );
        let declared = DeclaredBudget::of(&msg).unwrap();
        assert_eq!(declared.unit_limit, Some(20_000));
        assert_eq!(declared.unit_price_micro_lamports, Some(50));
        assert_eq!(
            declared.loaded_accounts_data_size_limit,
            Some(MAX_LOADED_ACCOUNTS_DATA_SIZE_BYTES)
        );
        assert!(declared.instruction_indexes.is_empty());

        // A fee that does not divide evenly is rounded up, so a per-CU cap is
        // at least as strict as it is on version 0.
        let cfg = v1::TransactionConfig::empty()
            .with_compute_unit_limit(3)
            .with_priority_fee(1);
        let msg = VersionedMessage::V1(
            v1::Message::try_compile_with_config(&payer, &[transfer()], Hash::default(), cfg)
                .unwrap(),
        );
        assert_eq!(
            DeclaredBudget::of(&msg).unwrap().unit_price_micro_lamports,
            Some(333_334)
        );
    }

    #[test]
    fn v1_rejects_compute_budget_instructions_and_missing_limit() {
        let payer = Pubkey::new_unique();
        let mut ixs = ComputeBudget::new(1, 1).instructions();
        ixs.push(transfer());
        let msg = VersionedMessage::V1(
            v1::Message::try_compile_with_config(
                &payer,
                &ixs,
                Hash::default(),
                ComputeBudget::new(1, 1).v1_config(),
            )
            .unwrap(),
        );
        assert!(DeclaredBudget::of(&msg)
            .unwrap_err()
            .to_string()
            .contains("ComputeBudget"));

        let msg = VersionedMessage::V1(
            v1::Message::try_compile_with_config(
                &payer,
                &[transfer()],
                Hash::default(),
                v1::TransactionConfig::empty(),
            )
            .unwrap(),
        );
        assert!(DeclaredBudget::of(&msg)
            .unwrap_err()
            .to_string()
            .contains("computeUnitLimit"));
    }

    #[test]
    fn legacy_messages_are_rejected() {
        let msg = VersionedMessage::Legacy(solana_message::Message::new(
            &[transfer()],
            Some(&Pubkey::new_unique()),
        ));
        assert!(DeclaredBudget::of(&msg)
            .unwrap_err()
            .to_string()
            .contains("legacy"));
    }
}
