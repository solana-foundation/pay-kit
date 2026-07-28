//! Greedy, size-bounded packing of per-channel instruction groups into legacy
//! transactions (no address lookup tables).
//!
//! Callers supply an operation-specific count cap; this module independently
//! enforces the Solana packet limit. A voucher settlement and a reclaim have
//! different account and data footprints, so there is deliberately no global
//! "channels per transaction" default here.
//!
//! Shared by both the mpp session and x402 settlement paths via the worker.

use solana_instruction::Instruction;
use solana_message::Message;
use solana_pubkey::Pubkey;

/// Max serialized transaction size (Solana packet limit).
pub const MAX_TX_BYTES: usize = 1232;

/// One channel operation's instructions, tagged with its id for tracing,
/// metrics, and reconciliation.
#[derive(Debug, Clone)]
pub struct ChannelInstructionGroup {
    pub channel_id: String,
    pub instructions: Vec<Instruction>,
}

/// Serialized size of a legacy transaction carrying `instructions`, fee-paid by
/// `payer`. Computed without signing: message bytes + the signature array
/// (`num_required_signatures * 64`) + the compact-u16 length prefix.
pub fn tx_size(instructions: &[Instruction], payer: &Pubkey) -> usize {
    let msg = Message::new(instructions, Some(payer));
    let sigs = msg.header.num_required_signatures as usize;
    let sig_prefix = if sigs < 128 { 1 } else { 2 };
    msg.serialize().len() + sigs * 64 + sig_prefix
}

/// The shared batch-boundary rule for greedy packing: whether appending a
/// group whose flattened instructions are `next` to a current batch holding
/// `cur_group_count` groups (flattened to `cur`) would overflow the caller's
/// operation-specific cap or the [`MAX_TX_BYTES`] byte limit.
///
/// Used by both [`pack`] and the worker's `regroup` so the packing rule lives
/// in one place. Note: it rebuilds and serializes the candidate message on each
/// call, so a greedy packer built on it is O(n²) in instruction bytes — fine
/// for realistic batch sizes (a handful of channels), not for large fan-in.
pub fn would_overflow_tx(
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
    tx_size(&probe, payer) > MAX_TX_BYTES
}

/// Greedily group channel operations into legacy-tx-sized batches. Each
/// returned batch's flattened instructions serialize to `<= MAX_TX_BYTES` and
/// hold at most `max_groups_per_tx` operations. A single operation that alone
/// exceeds the limit is returned as its own over-size batch; the caller
/// surfaces that as an error rather than silently dropping it.
pub fn pack(
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
        MAX_RECLAIMS_PER_TX, MAX_VOUCHER_SETTLEMENTS_PER_TX,
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

    #[test]
    fn voucher_settlement_limit_matches_wire_size() {
        let operator = pk(0xAA, 0);
        let mut max_fit = 0usize;
        for n in 1..=12u64 {
            let chans: Vec<_> = (0..n).map(voucher_settlement_instructions).collect();
            let flat: Vec<Instruction> = chans
                .iter()
                .flat_map(|c| c.instructions.iter().cloned())
                .collect();
            let size = tx_size(&flat, &operator);
            eprintln!(
                "channels={n:2}  tx_bytes={size:4}  fits={}",
                size <= MAX_TX_BYTES
            );
            if size <= MAX_TX_BYTES {
                max_fit = n as usize;
            }
        }
        assert_eq!(
            max_fit, MAX_VOUCHER_SETTLEMENTS_PER_TX,
            "voucher settlement cap must match the calibrated packet-size limit"
        );
    }

    #[test]
    fn reclaim_limit_matches_wire_size_with_shared_rent_payer() {
        let operator = pk(0xAA, 0);
        let program_id = default_program_id();
        let mut max_fit = 0usize;
        for n in 1..=64u64 {
            let instructions: Vec<_> = (0..n)
                .map(|i| build_reclaim_instruction(&pk(0x03, i), &operator, &program_id))
                .collect();
            if tx_size(&instructions, &operator) <= MAX_TX_BYTES {
                max_fit = n as usize;
            }
        }
        assert_eq!(
            max_fit, MAX_RECLAIMS_PER_TX,
            "reclaim cap must match the calibrated packet-size limit"
        );
    }

    #[test]
    fn pack_respects_byte_and_operation_limits() {
        let operator = pk(0xAA, 0);
        let channels: Vec<_> = (0..10).map(voucher_settlement_instructions).collect();

        // Byte-bounded packing (generous count cap).
        let batches = pack(channels.clone(), &operator, 1000);
        assert!(!batches.is_empty());
        for b in &batches {
            let flat: Vec<Instruction> = b
                .iter()
                .flat_map(|c| c.instructions.iter().cloned())
                .collect();
            assert!(
                tx_size(&flat, &operator) <= MAX_TX_BYTES,
                "batch exceeds packet size"
            );
        }
        assert_eq!(batches.iter().map(|b| b.len()).sum::<usize>(), 10);

        // Count cap of 1 ⇒ one channel per batch.
        let singles = pack(channels, &operator, 1);
        assert_eq!(singles.len(), 10);
        assert!(singles.iter().all(|b| b.len() == 1));
    }
}
