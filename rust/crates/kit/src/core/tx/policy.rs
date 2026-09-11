//! Envelope checks every verifier runs before it looks at an instruction:
//! accepted version, no address lookup tables, size within the version's
//! limit. Instruction-level policy stays with each scheme.

use solana_message::VersionedMessage;
use solana_transaction::versioned::VersionedTransaction;

use super::build::check_limits;
use super::version::TxVersion;
use crate::core::{Error, Result};

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

#[cfg(test)]
mod tests {
    use super::*;
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
