//! Envelope checks every verifier runs before it looks at an instruction:
//! accepted version, no address lookup tables, size within the version's
//! limit. Instruction-level policy stays with each scheme.

use solana_message::VersionedMessage;
use solana_pubkey::Pubkey;
use solana_rpc_client::rpc_client::RpcClient;
use solana_transaction::versioned::{TransactionVersion, VersionedTransaction};

use super::budget::DeclaredBudget;
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
    Ok(Some(declared))
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

/// Version policy for a transaction read back from the RPC by signature.
/// `maxSupportedTransactionVersion` only bounds what the node returns; the
/// server still accepts only its configured versions, exactly as for a
/// transaction credential. Legacy is refused, and so is a missing version:
/// nodes report one for every versioned transaction once asked.
pub fn check_reported_version(
    reported: Option<&TransactionVersion>,
    accepted: &[TxVersion],
) -> Result<TxVersion> {
    let version = match reported {
        Some(TransactionVersion::Number(n)) => TxVersion::try_from(*n).map_err(Error::Other)?,
        Some(TransactionVersion::Legacy(_)) => {
            return Err(Error::Other(
                "legacy transactions are not supported; use a version 0 or version 1 message"
                    .into(),
            ))
        }
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
        assert!(
            check_reported_version(Some(&TransactionVersion::Legacy(Legacy::Legacy)), &both)
                .is_err()
        );
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
        // Version 0 is left to the instruction-level checks.
        let v0 =
            build_unsigned(TxVersion::V0, &payer, &ixs, Hash::default(), Some(&budget)).unwrap();
        assert!(check_v1_budget_caps(&v0.message, 1, 1).unwrap().is_none());
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
