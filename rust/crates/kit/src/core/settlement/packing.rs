//! Greedy, size-bounded packing of per-channel settlement instructions into
//! legacy transactions (no address lookup tables).
//!
//! Each channel's settlement is a small group of instructions (ed25519 verify +
//! settle/finalize + distribute). We pack as many channels as fit under the
//! Solana packet limit, sealing a transaction and starting a new one when the
//! next channel would overflow (by serialized bytes or a configured cap).
//!
//! Shared by both the mpp session and x402 settlement paths via the worker.

use solana_instruction::Instruction;
use solana_message::Message;
use solana_pubkey::Pubkey;

/// Max serialized transaction size (Solana packet limit).
pub const MAX_TX_BYTES: usize = 1232;

/// Calibrated default cap on channels per legacy settle tx (P0: settle+finalize
/// is ~252 bytes/channel ⇒ 3 fit in 986 B, 4 overflow at 1238 B). Packing is
/// also byte-bounded, so this is a safety ceiling, not the sole limit.
pub const DEFAULT_MAX_CHANNELS_PER_TX: usize = 3;

/// One channel's settlement instructions, tagged with its id for
/// tracing/metrics/reconciliation.
#[derive(Debug, Clone)]
pub struct ChannelInstructions {
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
/// channel whose flattened instructions are `next` to a current batch holding
/// `cur_count` channels (flattened to `cur`) would overflow the per-tx channel
/// cap or the [`MAX_TX_BYTES`] byte limit.
///
/// Used by both [`pack`] and the worker's `regroup` so the packing rule lives
/// in one place. Note: it rebuilds and serializes the candidate message on each
/// call, so a greedy packer built on it is O(n²) in instruction bytes — fine
/// for realistic batch sizes (a handful of channels), not for large fan-in.
pub fn would_overflow_tx(
    cur: &[Instruction],
    cur_count: usize,
    next: &[Instruction],
    payer: &Pubkey,
    max_per_tx: usize,
) -> bool {
    if cur_count >= max_per_tx.max(1) {
        return true;
    }
    let mut probe: Vec<Instruction> = cur.to_vec();
    probe.extend_from_slice(next);
    tx_size(&probe, payer) > MAX_TX_BYTES
}

/// Greedily group channels into legacy-tx-sized batches. Each returned batch's
/// flattened instructions serialize to `<= MAX_TX_BYTES` and hold at most
/// `max_per_tx` channels. A single channel that alone exceeds the limit is
/// returned as its own (over-size) batch — the caller surfaces that as an error
/// at broadcast rather than silently dropping it.
pub fn pack(
    channels: Vec<ChannelInstructions>,
    payer: &Pubkey,
    max_per_tx: usize,
) -> Vec<Vec<ChannelInstructions>> {
    let mut out: Vec<Vec<ChannelInstructions>> = Vec::new();
    let mut cur: Vec<ChannelInstructions> = Vec::new();

    for ch in channels {
        if !cur.is_empty() {
            let cur_ix: Vec<Instruction> = cur
                .iter()
                .flat_map(|c| c.instructions.iter().cloned())
                .collect();
            if would_overflow_tx(&cur_ix, cur.len(), &ch.instructions, payer, max_per_tx) {
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
        build_settle_and_finalize_instructions, default_program_id,
    };

    fn pk(tag: u8, seed: u64) -> Pubkey {
        let mut b = [0u8; 32];
        b[0] = tag;
        b[1..9].copy_from_slice(&seed.to_le_bytes());
        Pubkey::new_from_array(b)
    }

    /// Per-channel **settle+finalize** instructions (ed25519 verify + settle):
    /// the on-chain close that the worker batches. `operator` is the shared
    /// fee-payer/authority; channel + authorized_signer are unique per channel,
    /// so the message dedups shared keys exactly as on-chain. (Distribute — the
    /// fund sweep — is a separate batched pass and excluded here.)
    fn channel_instructions(i: u64) -> ChannelInstructions {
        let program_id = default_program_id();
        let operator = pk(0xAA, 0); // shared fee-payer / authority
        let channel = pk(0x01, i);
        let authorized_signer = pk(0x02, i);
        let sig = [7u8; 64];

        let ixs = build_settle_and_finalize_instructions(
            &operator,
            &channel,
            &authorized_signer,
            Some(&sig),
            1_000,
            9_999_999_999,
            &program_id,
        )
        .unwrap();
        ChannelInstructions {
            channel_id: channel.to_string(),
            instructions: ixs,
        }
    }

    /// P0 calibration: how many channels fit in one legacy settle tx?
    #[test]
    fn calibrate_channels_per_tx() {
        let operator = pk(0xAA, 0);
        let mut max_fit = 0usize;
        for n in 1..=12u64 {
            let chans: Vec<_> = (0..n).map(channel_instructions).collect();
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
        eprintln!("CALIBRATION: max channels per legacy settle tx = {max_fit}");
        assert!(max_fit >= 1, "at least one channel must fit in a tx");
    }

    #[test]
    fn pack_respects_byte_and_count_limits() {
        let operator = pk(0xAA, 0);
        let channels: Vec<_> = (0..10).map(channel_instructions).collect();

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
