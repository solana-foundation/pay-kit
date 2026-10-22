//! Envelope checks every verifier runs before it looks at an instruction:
//! accepted version, no address lookup tables, size within the version's
//! limit. Instruction-level policy stays with each scheme.

use solana_message::VersionedMessage;
use solana_pubkey::Pubkey;
use solana_rpc_client::rpc_client::RpcClient;
use solana_transaction::versioned::{TransactionVersion, VersionedTransaction};

use super::budget::{DeclaredBudget, MAX_LOADED_ACCOUNTS_DATA_SIZE_BYTES};
use super::build::check_limits;
use super::version::TxVersion;
use crate::core::{Error, Result};

/// The `enable_tx_v1` feature gate (SIMD-0385).
pub const TX_V1_FEATURE_GATE: Pubkey =
    Pubkey::from_str_const("txv1aq4pp281K9um3tnPgkfX8UqtFT6wcVW3hNezGLL");

/// The Feature program, owner of every activated feature-gate account.
pub const FEATURE_PROGRAM_ID: Pubkey =
    Pubkey::from_str_const("Feature111111111111111111111111111111111111");

/// Whether a server accepts and builds version-1 transactions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TxV1Mode {
    /// Probe the `enable_tx_v1` gate on the configured RPC once at startup.
    #[default]
    Auto,
    /// Accept and build version 1 without probing.
    On,
    /// Version 0 only.
    Off,
}

/// Whether the `enable_tx_v1` gate is active on the cluster behind `rpc`: the
/// gate account exists, is owned by the Feature program, and records an
/// activation slot. A missing account, a system-owned placeholder (the
/// staged-but-not-activated state) or an RPC error all read as inactive.
pub fn tx_v1_active(rpc: &RpcClient) -> bool {
    match rpc.get_account(&TX_V1_FEATURE_GATE) {
        Ok(account) => account.owner == FEATURE_PROGRAM_ID && account.data.first() == Some(&1),
        Err(_) => false,
    }
}

impl TxV1Mode {
    /// The accepted version set under this mode, probing the gate for `Auto`.
    pub fn resolve(self, rpc: &RpcClient) -> Vec<TxVersion> {
        match self {
            TxV1Mode::Off => vec![TxVersion::V0],
            TxV1Mode::On => vec![TxVersion::V0, TxVersion::V1],
            TxV1Mode::Auto => {
                if tx_v1_active(rpc) {
                    vec![TxVersion::V0, TxVersion::V1]
                } else {
                    vec![TxVersion::V0]
                }
            }
        }
    }
}

/// The version a builder should emit for a counterparty that accepts
/// `accepted`: the highest one.
pub fn highest(accepted: &[TxVersion]) -> TxVersion {
    accepted.iter().copied().max().unwrap_or(TxVersion::V0)
}

/// The version a client builds: the highest one the challenge accepts
/// (`[0]` when it advertises none) that the signer can also sign. A signer
/// that cannot sign anything the server accepts is an error up front rather
/// than a device rejection at signing time.
pub fn negotiate(
    advertised: Option<&[TxVersion]>,
    max_signable: Option<TxVersion>,
) -> Result<TxVersion> {
    let accepted = super::version::accepted_versions(advertised);
    accepted
        .iter()
        .copied()
        .filter(|v| max_signable.is_none_or(|max| *v <= max))
        .max()
        .ok_or_else(|| {
            Error::Other(format!(
                "the server accepts transaction versions [{}] but the signer signs up to version {}",
                accepted
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", "),
                max_signable.map(|v| v.to_string()).unwrap_or_default()
            ))
        })
}

/// For a version-1 message, bound the header compute config with the caps a
/// verifier applies to ComputeBudget instructions on version 0: the unit
/// limit and the per-unit price (derived from the total fee, rounded up).
/// Version-0 messages are left to the verifier's own instruction checks so
/// their diagnostics are unchanged. Returns the declared budget.
pub fn check_v1_budget_caps(
    message: &VersionedMessage,
    max_unit_limit: u32,
    max_unit_price_micro_lamports: u64,
) -> Result<Option<DeclaredBudget>> {
    if TxVersion::of(message)? != TxVersion::V1 {
        return Ok(None);
    }
    let declared = DeclaredBudget::of(message)?;
    if let Some(limit) = declared.unit_limit {
        // A zero limit fails execution after the fee payer is charged.
        if limit == 0 {
            return Err(Error::Other("compute unit limit must be positive".into()));
        }
        if limit > max_unit_limit {
            return Err(Error::Other(format!(
                "compute unit limit {limit} exceeds maximum {max_unit_limit}"
            )));
        }
    }
    if let Some(price) = declared.unit_price_micro_lamports {
        if price > max_unit_price_micro_lamports {
            return Err(Error::Other(format!(
                "compute unit price {price} exceeds maximum {max_unit_price_micro_lamports}"
            )));
        }
    }
    // An absent or smaller loaded-data limit can fail the transaction at
    // load time, after fees are charged; version 0 always gets the maximum.
    if declared.loaded_accounts_data_size_limit != Some(MAX_LOADED_ACCOUNTS_DATA_SIZE_BYTES) {
        return Err(Error::Other(format!(
            "version 1 loaded accounts data size limit must be {MAX_LOADED_ACCOUNTS_DATA_SIZE_BYTES}"
        )));
    }
    Ok(Some(declared))
}

/// Version-0 (and legacy) counterpart of [`check_v1_budget_caps`] for a
/// message a server co-signs: every ComputeBudget instruction carries no
/// accounts, no opcode is duplicated or unsupported (a loaded-data limit
/// included), and the declared unit limit and price are within the caps.
/// Version-1 messages return `None`.
pub fn check_v0_budget_caps(
    message: &VersionedMessage,
    max_unit_limit: u32,
    max_unit_price_micro_lamports: u64,
) -> Result<Option<DeclaredBudget>> {
    if TxVersion::of(message)? != TxVersion::V0 {
        return Ok(None);
    }
    let declared = DeclaredBudget::of(message)?;
    let instructions = message.instructions();
    if declared
        .instruction_indexes
        .iter()
        .any(|&index| !instructions[index].accounts.is_empty())
    {
        return Err(Error::Other(
            "ComputeBudget instructions must not have accounts".into(),
        ));
    }
    if declared.loaded_accounts_data_size_limit.is_some() {
        return Err(Error::Other(
            "SetLoadedAccountsDataSizeLimit is not supported".into(),
        ));
    }
    if let Some(limit) = declared.unit_limit {
        // A zero limit fails execution after the fee payer is charged.
        if limit == 0 {
            return Err(Error::Other("compute unit limit must be positive".into()));
        }
        if limit > max_unit_limit {
            return Err(Error::Other(format!(
                "compute unit limit {limit} exceeds maximum {max_unit_limit}"
            )));
        }
    }
    if let Some(price) = declared.unit_price_micro_lamports {
        if price > max_unit_price_micro_lamports {
            return Err(Error::Other(format!(
                "compute unit price {price} exceeds maximum {max_unit_price_micro_lamports}"
            )));
        }
        // Without a declared limit the runtime prices the instruction-count
        // default, which the cap must bound just the same.
        if price > 0 && declared.unit_limit.is_none() {
            let budgeted = instructions.len() - declared.instruction_indexes.len();
            let implicit = super::budget::ComputeBudget::runtime_default(budgeted).unit_limit;
            if implicit > max_unit_limit {
                return Err(Error::Other(format!(
                    "implicit compute unit limit {implicit} exceeds maximum {max_unit_limit}; \
                     declare SetComputeUnitLimit"
                )));
            }
        }
    }
    Ok(Some(declared))
}

/// Highest total priority fee, in lamports, a fee sponsor pays for one
/// co-signed transaction: 200,000 compute units at 10,000 micro-lamports per
/// unit, the sponsored MPP charge policy.
pub const MAX_SPONSORED_PRIORITY_FEE_LAMPORTS: u64 = 2_000;

/// Bound the total priority fee a sponsor would pay for `message`, whatever
/// mix of unit limit and price the client chose. Per-field caps alone let the
/// largest limit pair with the largest price.
///
/// Version 1 is read from the header `priority_fee`. Version 0 multiplies the
/// declared price by the declared limit, or by the runtime default the
/// instruction count implies when no limit is declared. Returns the fee.
pub fn check_priority_fee(message: &VersionedMessage, max_lamports: u64) -> Result<u64> {
    let declared = DeclaredBudget::of(message)?;
    let fee = match message {
        VersionedMessage::V1(v1) => v1.config.priority_fee.unwrap_or(0),
        _ => {
            let price = declared.unit_price_micro_lamports.unwrap_or(0);
            let limit = declared.unit_limit.unwrap_or_else(|| {
                let budgeted = message.instructions().len() - declared.instruction_indexes.len();
                super::budget::ComputeBudget::runtime_default(budgeted).unit_limit
            });
            super::budget::ComputeBudget::new(limit, price).priority_fee_lamports()
        }
    };
    if fee > max_lamports {
        return Err(Error::Other(format!(
            "priority fee {fee} lamports exceeds the sponsored maximum {max_lamports}"
        )));
    }
    Ok(fee)
}

/// Require a version-0 budget's ComputeBudget instructions to be the leading
/// prefix of the message, `SetComputeUnitLimit` before `SetComputeUnitPrice`.
pub fn require_budget_prefix(message: &VersionedMessage, declared: &DeclaredBudget) -> Result<()> {
    if declared
        .instruction_indexes
        .iter()
        .enumerate()
        .any(|(position, &index)| position != index)
    {
        return Err(Error::Other(
            "ComputeBudget instructions must lead the transaction".into(),
        ));
    }
    if declared.unit_limit.is_some()
        && declared.unit_price_micro_lamports.is_some()
        && !matches!(
            message
                .instructions()
                .first()
                .and_then(super::budget::decode_compute_budget_op),
            Some(super::budget::ComputeBudgetOp::UnitLimit(_))
        )
    {
        return Err(Error::Other(
            "SetComputeUnitLimit must precede SetComputeUnitPrice".into(),
        ));
    }
    Ok(())
}

/// What a server advertises: `None` when only the default version is
/// accepted, so the wire shape is unchanged for version-0-only servers.
pub fn advertised(accepted: &[TxVersion]) -> Option<Vec<TxVersion>> {
    if accepted == super::version::DEFAULT_ACCEPTED_VERSIONS {
        None
    } else {
        Some(accepted.to_vec())
    }
}

/// Reject any message that resolves accounts through address lookup tables.
/// Verifiers pin the fee payer and scan instruction accounts through
/// `static_account_keys()`; a lookup table would let a transaction touch
/// accounts they cannot see.
pub fn require_static_accounts(message: &VersionedMessage) -> Result<()> {
    if message
        .address_table_lookups()
        .is_some_and(|lookups| !lookups.is_empty())
    {
        return Err(Error::Other(
            "transactions with address lookup tables are not supported".into(),
        ));
    }
    Ok(())
}

/// Check the transaction envelope: the message version is one of `accepted`,
/// no address lookup tables, and the serialized size and counts are within the
/// version's limits. Returns the version.
pub fn check_envelope(tx: &VersionedTransaction, accepted: &[TxVersion]) -> Result<TxVersion> {
    let version = TxVersion::of(&tx.message)?;
    if !accepted.contains(&version) {
        return Err(Error::Other(format!(
            "transaction version {version} is not accepted; accepted versions: {}",
            accepted
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        )));
    }
    require_static_accounts(&tx.message)?;
    check_limits(tx, version)?;
    Ok(version)
}

/// Verify every signature a client already placed on a transaction the server
/// is about to co-sign, before it signs, simulates or pays for anything.
///
/// The signature slots must match the message's required signers. When
/// `server_fee_payer` is set it must be account key zero with an empty slot,
/// left for the server; every other required signature must verify against
/// the exact message. Signer membership alone proves nothing: a corrupted
/// signature only surfaces at broadcast, after earlier sponsored transactions
/// may already have landed.
pub fn require_presigned(
    tx: &VersionedTransaction,
    server_fee_payer: Option<&Pubkey>,
) -> Result<()> {
    let required = usize::from(tx.message.header().num_required_signatures);
    let keys = tx.message.static_account_keys();
    if tx.signatures.len() != required || keys.len() < required {
        return Err(Error::Other(
            "transaction signature slots do not match its required signers".into(),
        ));
    }
    let message = tx.message.serialize();
    for (index, (signature, key)) in tx.signatures.iter().zip(keys).enumerate() {
        if server_fee_payer == Some(key) {
            if index != 0 || *signature != solana_signature::Signature::default() {
                return Err(Error::Other(
                    "fee-payer signature slot must be empty before server co-signing".into(),
                ));
            }
            continue;
        }
        if !signature.verify(key.as_ref(), &message) {
            return Err(Error::Other(format!(
                "invalid client transaction signature for required signer {key}"
            )));
        }
    }
    Ok(())
}

/// Version policy for a transaction read back from the RPC by signature.
/// `maxSupportedTransactionVersion` only bounds what the node returns; the
/// server still accepts only its configured versions, exactly as for a
/// transaction credential. A reported `legacy` is policed as version 0 (see
/// [`TxVersion::of`]); a missing version is refused, since nodes report one
/// for every transaction once asked.
pub fn check_reported_version(
    reported: Option<&TransactionVersion>,
    accepted: &[TxVersion],
) -> Result<TxVersion> {
    let version = match reported {
        Some(TransactionVersion::Number(n)) => TxVersion::try_from(*n).map_err(Error::Other)?,
        Some(TransactionVersion::Legacy(_)) => TxVersion::V0,
        None => {
            return Err(Error::Other(
                "RPC did not report the transaction version".into(),
            ))
        }
    };
    if !accepted.contains(&version) {
        return Err(Error::Other(format!(
            "transaction version {version} is not accepted; accepted versions: {}",
            accepted
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        )));
    }
    Ok(version)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn negotiate_picks_the_highest_version_the_signer_can_sign() {
        let both = [TxVersion::V0, TxVersion::V1];
        assert_eq!(negotiate(Some(&both), None).unwrap(), TxVersion::V1);
        assert_eq!(
            negotiate(Some(&both), Some(TxVersion::V0)).unwrap(),
            TxVersion::V0
        );
        assert_eq!(negotiate(None, Some(TxVersion::V0)).unwrap(), TxVersion::V0);
        let err = negotiate(Some(&[TxVersion::V1]), Some(TxVersion::V0))
            .unwrap_err()
            .to_string();
        assert!(err.contains("signs up to version 0"), "{err}");
    }

    #[test]
    fn reported_version_follows_the_accepted_set() {
        use solana_transaction::versioned::Legacy;
        let v0_only = [TxVersion::V0];
        let both = [TxVersion::V0, TxVersion::V1];
        assert_eq!(
            check_reported_version(Some(&TransactionVersion::Number(0)), &v0_only).unwrap(),
            TxVersion::V0
        );
        assert_eq!(
            check_reported_version(Some(&TransactionVersion::Number(1)), &both).unwrap(),
            TxVersion::V1
        );
        let err = check_reported_version(Some(&TransactionVersion::Number(1)), &v0_only)
            .unwrap_err()
            .to_string();
        assert!(err.contains("version 1 is not accepted"), "{err}");
        // A reported legacy message is policed as version 0: accepted exactly
        // when version 0 is, refused when only version 1 is accepted.
        assert_eq!(
            check_reported_version(Some(&TransactionVersion::Legacy(Legacy::Legacy)), &both)
                .unwrap(),
            TxVersion::V0
        );
        assert!(check_reported_version(
            Some(&TransactionVersion::Legacy(Legacy::Legacy)),
            &[TxVersion::V1]
        )
        .is_err());
        assert!(check_reported_version(None, &both).is_err());
        assert!(check_reported_version(Some(&TransactionVersion::Number(7)), &both).is_err());
    }
    use crate::core::tx::budget::ComputeBudget;
    use crate::core::tx::build::build_unsigned;
    use solana_hash::Hash;
    use solana_message::v0;
    use solana_pubkey::Pubkey;
    use solana_signature::Signature;
    use solana_system_interface::instruction as system_instruction;

    #[test]
    fn envelope_enforces_the_advertised_set() {
        let payer = Pubkey::new_unique();
        let ixs = [system_instruction::transfer(
            &payer,
            &Pubkey::new_unique(),
            1,
        )];
        let budget = ComputeBudget::new(10_000, 1);
        let v1 =
            build_unsigned(TxVersion::V1, &payer, &ixs, Hash::default(), Some(&budget)).unwrap();
        let v0 = build_unsigned(TxVersion::V0, &payer, &ixs, Hash::default(), None).unwrap();

        assert_eq!(
            check_envelope(&v0, &[TxVersion::V0]).unwrap(),
            TxVersion::V0
        );
        assert!(check_envelope(&v1, &[TxVersion::V0])
            .unwrap_err()
            .to_string()
            .contains("not accepted"));
        assert_eq!(
            check_envelope(&v1, &[TxVersion::V0, TxVersion::V1]).unwrap(),
            TxVersion::V1
        );
    }

    #[test]
    fn modes_resolve_without_probing_except_auto() {
        let rpc = RpcClient::new("http://127.0.0.1:1".to_string());
        assert_eq!(TxV1Mode::Off.resolve(&rpc), vec![TxVersion::V0]);
        assert_eq!(
            TxV1Mode::On.resolve(&rpc),
            vec![TxVersion::V0, TxVersion::V1]
        );
        assert_eq!(highest(&[TxVersion::V0, TxVersion::V1]), TxVersion::V1);
        assert_eq!(highest(&[]), TxVersion::V0);
        assert_eq!(advertised(&[TxVersion::V0]), None);
        assert_eq!(
            advertised(&[TxVersion::V0, TxVersion::V1]),
            Some(vec![TxVersion::V0, TxVersion::V1])
        );
    }

    #[test]
    fn v1_budget_caps_apply_to_the_header() {
        let payer = Pubkey::new_unique();
        let ixs = [system_instruction::transfer(
            &payer,
            &Pubkey::new_unique(),
            1,
        )];
        // 20_000 CU at 5 lamports/CU (5_000_000 µlamports) = 100_000 lamports.
        let budget = ComputeBudget::new(20_000, 5_000_000);
        let tx =
            build_unsigned(TxVersion::V1, &payer, &ixs, Hash::default(), Some(&budget)).unwrap();
        assert!(check_v1_budget_caps(&tx.message, 200_000, 5_000_000).is_ok());
        assert!(check_v1_budget_caps(&tx.message, 10_000, 5_000_000)
            .unwrap_err()
            .to_string()
            .contains("unit limit"));
        assert!(check_v1_budget_caps(&tx.message, 200_000, 10_000)
            .unwrap_err()
            .to_string()
            .contains("unit price"));
        // The loaded-data limit must be the runtime maximum: zero (or
        // absent) fails loading after the sponsor is charged.
        for loaded in [
            Some(0),
            Some(1),
            Some(MAX_LOADED_ACCOUNTS_DATA_SIZE_BYTES + 1),
            None,
        ] {
            let mut config = budget.v1_config();
            config.loaded_accounts_data_size_limit = loaded;
            let msg = VersionedMessage::V1(
                solana_message::v1::Message::try_compile_with_config(
                    &payer,
                    &ixs,
                    Hash::default(),
                    config,
                )
                .unwrap(),
            );
            assert!(check_v1_budget_caps(&msg, 200_000, 5_000_000)
                .unwrap_err()
                .to_string()
                .contains("loaded accounts data size"));
        }
        let zero = ComputeBudget::new(0, 0);
        let tx = build_unsigned(TxVersion::V1, &payer, &ixs, Hash::default(), Some(&zero)).unwrap();
        assert!(check_v1_budget_caps(&tx.message, 200_000, 5_000_000)
            .unwrap_err()
            .to_string()
            .contains("must be positive"));
        // Version 0 is left to the instruction-level checks.
        let v0 =
            build_unsigned(TxVersion::V0, &payer, &ixs, Hash::default(), Some(&budget)).unwrap();
        assert!(check_v1_budget_caps(&v0.message, 1, 1).unwrap().is_none());
    }

    #[test]
    fn v0_budget_policy_rejects_duplicates_and_misplaced_instructions() {
        use crate::core::tx::budget::{unit_limit_instruction, unit_price_instruction};
        let payer = Pubkey::new_unique();
        let transfer = system_instruction::transfer(&payer, &Pubkey::new_unique(), 1);
        let message = |ixs: &[solana_instruction::Instruction]| {
            VersionedMessage::V0(
                v0::Message::try_compile(&payer, ixs, &[], Hash::default()).unwrap(),
            )
        };
        let check = |msg: &VersionedMessage| {
            check_v0_budget_caps(msg, 200_000, 10_000)
                .and_then(|declared| require_budget_prefix(msg, declared.as_ref().unwrap()))
        };

        // Canonical prefix, and no budget at all.
        let canonical = message(&[
            unit_limit_instruction(200_000),
            unit_price_instruction(10_000),
            transfer.clone(),
        ]);
        assert!(check(&canonical).is_ok());
        assert!(check(&message(std::slice::from_ref(&transfer))).is_ok());

        let duplicate = message(&[
            unit_limit_instruction(1_000),
            unit_limit_instruction(2_000),
            transfer.clone(),
        ]);
        assert!(check(&duplicate)
            .unwrap_err()
            .to_string()
            .contains("duplicate"));
        let trailing = message(&[transfer.clone(), unit_price_instruction(10)]);
        assert!(check(&trailing).unwrap_err().to_string().contains("lead"));
        let reversed = message(&[
            unit_price_instruction(10),
            unit_limit_instruction(1_000),
            transfer.clone(),
        ]);
        assert!(check(&reversed)
            .unwrap_err()
            .to_string()
            .contains("precede"));
        let mut with_account = unit_limit_instruction(1_000);
        with_account
            .accounts
            .push(solana_instruction::AccountMeta::new_readonly(payer, false));
        assert!(check(&message(&[with_account, transfer.clone()]))
            .unwrap_err()
            .to_string()
            .contains("accounts"));
        let mut loaded = unit_limit_instruction(1_000);
        loaded.data[0] = crate::core::tx::budget::SET_LOADED_ACCOUNTS_DATA_SIZE_LIMIT_TAG;
        assert!(check(&message(&[loaded, transfer.clone()]))
            .unwrap_err()
            .to_string()
            .contains("LoadedAccountsDataSizeLimit"));
        assert!(check(&message(&[
            unit_limit_instruction(200_001),
            transfer.clone()
        ]))
        .is_err());
        assert!(check(&message(&[
            unit_price_instruction(10_001),
            transfer.clone()
        ]))
        .is_err());
        assert!(
            check(&message(&[unit_limit_instruction(0), transfer.clone()]))
                .unwrap_err()
                .to_string()
                .contains("must be positive")
        );
        assert!(check(&message(&[unit_limit_instruction(1), transfer.clone()])).is_ok());

        // A priced budget with no limit is held to the cap through the
        // runtime's per-instruction default.
        assert!(check(&message(&[unit_price_instruction(10), transfer.clone()])).is_ok());
        let two = message(&[
            unit_price_instruction(10),
            transfer.clone(),
            transfer.clone(),
        ]);
        assert!(check(&two)
            .unwrap_err()
            .to_string()
            .contains("implicit compute unit limit 400000"));
        assert!(check(&message(&[transfer.clone(), transfer.clone()])).is_ok());
        assert!(check(&message(&[
            unit_limit_instruction(200_000),
            unit_price_instruction(10),
            transfer.clone(),
            transfer
        ]))
        .is_ok());
    }

    #[test]
    fn lookup_tables_are_rejected() {
        let payer = Pubkey::new_unique();
        let table = solana_message::AddressLookupTableAccount {
            key: Pubkey::new_unique(),
            addresses: vec![Pubkey::new_unique()],
        };
        let ix = system_instruction::transfer(&payer, &table.addresses[0], 1);
        let message = VersionedMessage::V0(
            v0::Message::try_compile(&payer, &[ix], std::slice::from_ref(&table), Hash::default())
                .unwrap(),
        );
        let tx = VersionedTransaction {
            signatures: vec![Signature::default()],
            message,
        };
        assert!(check_envelope(&tx, &[TxVersion::V0])
            .unwrap_err()
            .to_string()
            .contains("lookup tables"));
    }
}
