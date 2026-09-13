//! Canonical wire encoding for every message version.
//!
//! Version-1 transactions put the version byte first and the signatures last
//! as a fixed-length array, which serde/bincode cannot express: bincode output
//! for a version-1 `VersionedTransaction` is wrong on the wire. wincode is the
//! SDK's canonical encoder for all versions and is the only one used here.

use base64::Engine as _;
use solana_transaction::versioned::VersionedTransaction;

use super::version::TxVersion;
use crate::core::{Error, Result};

/// Serialize to canonical wire bytes.
pub fn serialize(tx: &VersionedTransaction) -> Result<Vec<u8>> {
    wincode::serialize(tx)
        .map_err(|e| Error::Serialization(format!("transaction serialization failed: {e}")))
}

/// Serialized wire size in bytes.
pub fn serialized_size(tx: &VersionedTransaction) -> Result<usize> {
    serialize(tx).map(|bytes| bytes.len())
}

/// Base64 (standard alphabet, padded) of the canonical wire bytes: the form
/// every MPP and x402 payload carries.
pub fn encode(tx: &VersionedTransaction) -> Result<String> {
    serialize(tx).map(|bytes| base64::engine::general_purpose::STANDARD.encode(bytes))
}

/// Decode a base64 payload transaction. The version byte selects the layout,
/// so both supported versions decode here; a legacy message decodes but is
/// rejected, since the kit does not accept it.
pub fn decode(b64: &str) -> Result<VersionedTransaction> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .map_err(|e| Error::Other(format!("invalid base64 transaction: {e}")))?;
    decode_bytes(&bytes)
}

/// [`decode`] for already base64-decoded bytes.
pub fn decode_bytes(bytes: &[u8]) -> Result<VersionedTransaction> {
    let tx: VersionedTransaction = wincode::deserialize(bytes)
        .map_err(|e| Error::Other(format!("invalid transaction: {e}")))?;
    TxVersion::of(&tx.message)?;
    // The decoder ignores trailing bytes, and a payload is only acceptable in
    // its canonical form: what the signatures cover is exactly what re-encodes.
    if serialize(&tx)? != bytes {
        return Err(Error::Other(
            "invalid transaction: non-canonical encoding or trailing bytes".into(),
        ));
    }
    Ok(tx)
}

#[cfg(test)]
mod tests {
    use super::*;
    use solana_hash::Hash;
    use solana_message::{v0, v1, Message, VersionedMessage};
    use solana_pubkey::Pubkey;
    use solana_signature::Signature;
    use solana_system_interface::instruction as system_instruction;

    fn transfer(from: &Pubkey) -> solana_instruction::Instruction {
        system_instruction::transfer(from, &Pubkey::new_unique(), 1)
    }

    fn unsigned(message: VersionedMessage) -> VersionedTransaction {
        VersionedTransaction {
            signatures: vec![
                Signature::default();
                message.header().num_required_signatures as usize
            ],
            message,
        }
    }

    #[test]
    fn v0_round_trips_and_matches_bincode() {
        let payer = Pubkey::new_unique();
        let tx = unsigned(VersionedMessage::V0(
            v0::Message::try_compile(&payer, &[transfer(&payer)], &[], Hash::default()).unwrap(),
        ));
        let bytes = serialize(&tx).unwrap();
        // For version 0 the canonical bytes equal what every deployed peer
        // produces with bincode, so the wire format is unchanged.
        assert_eq!(bytes, bincode::serialize(&tx).unwrap());
        assert_eq!(
            bytes[64 + 1],
            0x80,
            "version-0 prefix follows one signature"
        );
        assert_eq!(decode(&encode(&tx).unwrap()).unwrap(), tx);
    }

    #[test]
    fn v1_round_trips_with_version_byte_first_and_signatures_last() {
        let payer = Pubkey::new_unique();
        let cfg = v1::TransactionConfig::empty().with_compute_unit_limit(10_000);
        let tx = unsigned(VersionedMessage::V1(
            v1::Message::try_compile_with_config(&payer, &[transfer(&payer)], Hash::default(), cfg)
                .unwrap(),
        ));
        let bytes = serialize(&tx).unwrap();
        assert_eq!(bytes[0], v1::V1_PREFIX);
        assert_eq!(&bytes[bytes.len() - 64..], &[0u8; 64]);
        assert_ne!(bytes, bincode::serialize(&tx).unwrap());
        assert_eq!(decode(&encode(&tx).unwrap()).unwrap(), tx);
    }

    #[test]
    fn legacy_payloads_are_rejected() {
        let payer = Pubkey::new_unique();
        let tx = unsigned(VersionedMessage::Legacy(Message::new(
            &[transfer(&payer)],
            Some(&payer),
        )));
        let b64 =
            base64::engine::general_purpose::STANDARD.encode(bincode::serialize(&tx).unwrap());
        assert!(decode(&b64).unwrap_err().to_string().contains("legacy"));
    }

    #[test]
    fn trailing_bytes_are_rejected() {
        let payer = Pubkey::new_unique();
        let tx = unsigned(VersionedMessage::V0(
            v0::Message::try_compile(&payer, &[transfer(&payer)], &[], Hash::default()).unwrap(),
        ));
        let mut bytes = serialize(&tx).unwrap();
        bytes.push(0);
        assert!(decode_bytes(&bytes).is_err());
    }
}
