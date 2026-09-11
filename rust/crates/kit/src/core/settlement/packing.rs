//! Greedy, size-bounded packing of per-channel instruction groups into
//! transactions of one message version, without address lookup tables.
//!
//! Callers supply an operation-specific count cap; this module independently
//! enforces the version's wire limits through [`crate::core::tx::measure`]. A
//! voucher settlement and a reclaim have different account and data
//! footprints, so there is deliberately no global "channels per transaction"
//! default here.
//!
//! Shared by both the mpp session and x402 settlement paths via the worker.

use solana_instruction::Instruction;
use solana_pubkey::Pubkey;

use crate::core::tx::{measure, TxVersion};
use crate::core::Result;

/// One channel operation's instructions, tagged with its id for tracing,
/// metrics, and reconciliation.
#[derive(Debug, Clone)]
pub struct ChannelInstructionGroup {
    pub channel_id: String,
    pub instructions: Vec<Instruction>,
}

/// Serialized size of a `version` transaction carrying `instructions`,
/// fee-paid by `payer`, with no compute budget. Exact for the signed
/// transaction: signatures are fixed-size and the blockhash does not change
/// the length. Errors only when the instructions cannot be compiled at all.
pub fn tx_size(version: TxVersion, instructions: &[Instruction], payer: &Pubkey) -> Result<usize> {
    measure(version, payer, instructions, None)
}

/// The shared batch-boundary rule for greedy packing: whether appending a
/// group whose flattened instructions are `next` to a current batch holding
/// `cur_group_count` groups (flattened to `cur`) would overflow the caller's
/// operation-specific cap or the version's size limit. A group that cannot be
/// measured counts as overflowing, so it is sealed into its own batch and
/// surfaces as an error at build time rather than being dropped.
///
/// Used by both [`pack`] and the worker's `regroup` so the packing rule lives
/// in one place. Note: it rebuilds and serializes the candidate message on each
/// call, so a greedy packer built on it is O(n²) in instruction bytes — fine
/// for realistic batch sizes (a handful of channels), not for large fan-in.
pub fn would_overflow_tx(
    version: TxVersion,
    cur: &[Instruction],
    cur_group_count: usize,
    next: &[Instruction],
    payer: &Pubkey,
    max_groups_per_tx: usize,
) -> bool {
    if cur_group_count >= max_groups_per_tx.max(1) {
        return true;
    }
    let mut probe: Vec<Instruction> = cur.to_vec();
    probe.extend_from_slice(next);
    match tx_size(version, &probe, payer) {
        Ok(size) => size > version.limits().max_bytes,
        Err(_) => true,
    }
}

/// Greedily group channel operations into `version`-sized batches. Each
/// returned batch's flattened instructions fit the version's size limit and
/// hold at most `max_groups_per_tx` operations. A single operation that alone
/// exceeds the limit is returned as its own over-size batch; the caller
/// surfaces that as an error rather than silently dropping it.
pub fn pack(
    version: TxVersion,
    channels: Vec<ChannelInstructionGroup>,
    payer: &Pubkey,
    max_groups_per_tx: usize,
) -> Vec<Vec<ChannelInstructionGroup>> {
    let mut out: Vec<Vec<ChannelInstructionGroup>> = Vec::new();
    let mut cur: Vec<ChannelInstructionGroup> = Vec::new();

    for ch in channels {
        if !cur.is_empty() {
            let cur_ix: Vec<Instruction> = cur
                .iter()
                .flat_map(|c| c.instructions.iter().cloned())
                .collect();
            if would_overflow_tx(
                version,
                &cur_ix,
                cur.len(),
                &ch.instructions,
                payer,
                max_groups_per_tx,
            ) {
                out.push(std::mem::take(&mut cur));
            }
        }
        cur.push(ch);
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::payment_channels::{
        build_reclaim_instruction, build_settle_and_seal_instructions, default_program_id,
        max_reclaims_per_tx, max_voucher_settlements_per_tx,
    };

    fn pk(tag: u8, seed: u64) -> Pubkey {
        let mut b = [0u8; 32];
        b[0] = tag;
        b[1..9].copy_from_slice(&seed.to_le_bytes());
        Pubkey::new_from_array(b)
    }

    /// Per-channel **settle+seal** instructions (ed25519 verify + settle):
    /// the on-chain close that the worker batches. `operator` is the shared
    /// fee-payer/authority; channel + authorized_signer are unique per channel,
    /// so the message dedups shared keys exactly as on-chain. (Distribute — the
    /// fund sweep — is a separate batched pass and excluded here.)
    fn voucher_settlement_instructions(i: u64) -> ChannelInstructionGroup {
        let program_id = default_program_id();
        let operator = pk(0xAA, 0); // shared fee-payer / authority
        let channel = pk(0x01, i);
        let authorized_signer = pk(0x02, i);
        let sig = [7u8; 64];

        let ixs = build_settle_and_seal_instructions(
            &operator,
            &channel,
            &authorized_signer,
            Some(&sig),
            1_000,
            9_999_999_999,
            &program_id,
        )
        .unwrap();
        ChannelInstructionGroup {
            channel_id: channel.to_string(),
            instructions: ixs,
        }
    }

    fn fits(version: TxVersion, payer: &Pubkey, ixs: &[Instruction]) -> bool {
        let limits = version.limits();
        let Ok(tx) = crate::core::tx::build_unsigned_unchecked(
            version,
            payer,
            ixs,
            solana_hash::Hash::default(),
            None,
        ) else {
            return false;
        };
        crate::core::tx::serialized_size(&tx).unwrap() <= limits.max_bytes
            && tx.message.static_account_keys().len() <= limits.max_static_accounts
            && limits
                .max_instructions
                .is_none_or(|max| tx.message.instructions().len() <= max)
    }

    #[test]
    fn voucher_settlement_limit_matches_wire_size() {
        let operator = pk(0xAA, 0);
        for version in [TxVersion::V0, TxVersion::V1] {
            let mut max_fit = 0usize;
            for n in 1..=40u64 {
                let chans: Vec<_> = (0..n).map(voucher_settlement_instructions).collect();
                let flat: Vec<Instruction> = chans
                    .iter()
                    .flat_map(|c| c.instructions.iter().cloned())
                    .collect();
                if fits(version, &operator, &flat) {
                    max_fit = n as usize;
                }
            }
            assert_eq!(
                max_fit,
                max_voucher_settlements_per_tx(version),
                "version {version} voucher settlement cap must match the calibrated wire limits"
            );
        }
    }

    #[test]
    fn reclaim_limit_matches_wire_size_with_shared_rent_payer() {
        let operator = pk(0xAA, 0);
        let program_id = default_program_id();
        for version in [TxVersion::V0, TxVersion::V1] {
            let mut max_fit = 0usize;
            for n in 1..=80u64 {
                let instructions: Vec<_> = (0..n)
                    .map(|i| build_reclaim_instruction(&pk(0x03, i), &operator, &program_id))
                    .collect();
                if fits(version, &operator, &instructions) {
                    max_fit = n as usize;
                }
            }
            assert_eq!(
                max_fit,
                max_reclaims_per_tx(version),
                "version {version} reclaim cap must match the calibrated wire limits"
            );
        }
    }

    #[test]
    fn pack_respects_byte_and_operation_limits() {
        let operator = pk(0xAA, 0);
        let channels: Vec<_> = (0..10).map(voucher_settlement_instructions).collect();

        // Byte-bounded packing (generous count cap).
        let batches = pack(TxVersion::V0, channels.clone(), &operator, 1000);
        assert!(!batches.is_empty());
        for b in &batches {
            let flat: Vec<Instruction> = b
                .iter()
                .flat_map(|c| c.instructions.iter().cloned())
                .collect();
            assert!(
                tx_size(TxVersion::V0, &flat, &operator).unwrap()
                    <= TxVersion::V0.limits().max_bytes,
                "batch exceeds packet size"
            );
        }
        assert_eq!(batches.iter().map(|b| b.len()).sum::<usize>(), 10);

        // Count cap of 1 ⇒ one channel per batch.
        let singles = pack(TxVersion::V0, channels, &operator, 1);
        assert_eq!(singles.len(), 10);
        assert!(singles.iter().all(|b| b.len() == 1));
    }
}
