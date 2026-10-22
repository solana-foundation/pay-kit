//! Message versions the kit builds and accepts, and their wire limits.

use serde::{Deserialize, Serialize};
use solana_message::{v1, VersionedMessage};

use crate::core::Result;

/// A Solana transaction message version the kit builds and advertises.
///
/// Serializes as the integer the Wallet Standard uses for
/// `supportedTransactionVersions` (`0`, `1`). `"legacy"` is deliberately not
/// representable: legacy (unprefixed) messages are never built or advertised.
/// Servers still accept them from existing clients and police them as
/// version 0, see [`TxVersion::of`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(into = "u8", try_from = "u8")]
pub enum TxVersion {
    /// Version 0: versioned message, address lookup tables allowed by the
    /// runtime but never used or accepted by the kit. 1232-byte packet limit.
    V0,
    /// Version 1 (SIMD-0385): 4096-byte transactions with the compute budget
    /// carried in the message header. No address lookup tables.
    V1,
}

impl Default for TxVersion {
    /// The protocol default when nothing is advertised.
    fn default() -> Self {
        TxVersion::V0
    }
}

impl From<TxVersion> for u8 {
    fn from(v: TxVersion) -> u8 {
        match v {
            TxVersion::V0 => 0,
            TxVersion::V1 => 1,
        }
    }
}

impl TryFrom<u8> for TxVersion {
    type Error = String;
    fn try_from(v: u8) -> std::result::Result<Self, String> {
        match v {
            0 => Ok(TxVersion::V0),
            1 => Ok(TxVersion::V1),
            other => Err(format!("unsupported transaction version {other}")),
        }
    }
}

impl std::fmt::Display for TxVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", u8::from(*self))
    }
}

/// Per-version wire limits enforced at build time and at verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TxLimits {
    /// Maximum serialized transaction size in bytes.
    pub max_bytes: usize,
    /// Maximum static account keys.
    pub max_static_accounts: usize,
    /// Maximum top-level instructions, where the format bounds it.
    pub max_instructions: Option<usize>,
    /// Maximum required signatures, where the format bounds it.
    pub max_signatures: Option<usize>,
}

/// Solana packet limit: the legacy / version-0 transaction size cap
/// (IPv6 minimum MTU 1280 minus a 40-byte IPv6 header and an 8-byte UDP
/// header). Value and derivation match `solana_packet::PACKET_DATA_SIZE`.
pub const PACKET_DATA_SIZE: usize = 1280 - 40 - 8;

/// Runtime account-lock limit shared by every message version.
pub const MAX_TX_ACCOUNT_LOCKS: usize = 64;

impl TxVersion {
    /// Wire limits of this version.
    pub const fn limits(self) -> TxLimits {
        match self {
            TxVersion::V0 => TxLimits {
                max_bytes: PACKET_DATA_SIZE,
                max_static_accounts: MAX_TX_ACCOUNT_LOCKS,
                max_instructions: None,
                max_signatures: None,
            },
            TxVersion::V1 => TxLimits {
                max_bytes: v1::MAX_TRANSACTION_SIZE,
                max_static_accounts: v1::MAX_ADDRESSES as usize,
                max_instructions: Some(v1::MAX_INSTRUCTIONS as usize),
                max_signatures: Some(v1::MAX_SIGNATURES as usize),
            },
        }
    }

    /// The policy version of a decoded message.
    ///
    /// A legacy (unprefixed) message is policed as version 0: it shares the
    /// 1232-byte packet limit, carries its compute budget as ComputeBudget
    /// instructions, and cannot reference address lookup tables. Servers keep
    /// accepting legacy messages from existing clients for backward
    /// compatibility whenever they accept version 0; the kit never builds or
    /// advertises legacy itself.
    pub fn of(message: &VersionedMessage) -> Result<TxVersion> {
        match message {
            VersionedMessage::Legacy(_) | VersionedMessage::V0(_) => Ok(TxVersion::V0),
            VersionedMessage::V1(_) => Ok(TxVersion::V1),
        }
    }
}

/// The accepted set when a challenge or requirements object carries no
/// `transactionVersions`.
pub const DEFAULT_ACCEPTED_VERSIONS: &[TxVersion] = &[TxVersion::V0];

/// Resolve an optional advertised `transactionVersions` list to the accepted
/// set, applying the protocol default only when the field is absent. A
/// present, empty list accepts nothing (RULINGS T2: MPP "Defaults to `[0]`
/// when omitted", x402 "When the field is absent, the accepted set is
/// `[0]`").
pub fn accepted_versions(advertised: Option<&[TxVersion]>) -> &[TxVersion] {
    match advertised {
        Some(list) => list,
        None => DEFAULT_ACCEPTED_VERSIONS,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_serialize_as_wallet_standard_integers() {
        let json = serde_json::to_string(&vec![TxVersion::V0, TxVersion::V1]).unwrap();
        assert_eq!(json, "[0,1]");
        let parsed: Vec<TxVersion> = serde_json::from_str("[1, 0]").unwrap();
        assert_eq!(parsed, vec![TxVersion::V1, TxVersion::V0]);
        assert!(serde_json::from_str::<Vec<TxVersion>>("[\"legacy\"]").is_err());
        assert!(serde_json::from_str::<Vec<TxVersion>>("[2]").is_err());
    }

    #[test]
    fn only_an_absent_advertisement_means_version_zero() {
        assert_eq!(accepted_versions(None), &[TxVersion::V0]);
        // Present and empty is not absent (RULINGS T2).
        assert!(accepted_versions(Some(&[])).is_empty());
        assert_eq!(accepted_versions(Some(&[TxVersion::V1])), &[TxVersion::V1]);
    }

    #[test]
    fn legacy_messages_are_policed_as_version_zero() {
        let payer = solana_pubkey::Pubkey::new_unique();
        let legacy = VersionedMessage::Legacy(solana_message::Message::new(
            &[solana_system_interface::instruction::transfer(
                &payer,
                &solana_pubkey::Pubkey::new_unique(),
                1,
            )],
            Some(&payer),
        ));
        assert_eq!(TxVersion::of(&legacy).unwrap(), TxVersion::V0);
    }

    #[test]
    fn limits_follow_the_sdk_constants() {
        assert_eq!(TxVersion::V0.limits().max_bytes, 1232);
        assert_eq!(TxVersion::V1.limits().max_bytes, 4096);
        assert_eq!(TxVersion::V1.limits().max_instructions, Some(64));
        assert_eq!(TxVersion::V1.limits().max_signatures, Some(12));
    }
}
