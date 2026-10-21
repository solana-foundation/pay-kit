//! Transaction plumbing for the filler: wire decode/encode through the kit,
//! decompile a static-key message into instructions and back, re-sign, and
//! the x402 `exact` static-layout builder (scheme_exact_svm §3.1).

use std::str::FromStr;

use base64::Engine;
use ed25519_dalek::Signer as _;
use solana_hash::Hash;
use solana_instruction::{AccountMeta, Instruction};
use solana_message::{v0, VersionedMessage};
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use solana_transaction::versioned::VersionedTransaction;

use crate::keys::{self, ata, pubkey, COMPUTE_BUDGET_PROGRAM, MEMO_PROGRAM, TOKEN_PROGRAM};

pub fn decode_b64(transaction: &str) -> Result<VersionedTransaction, String> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(transaction)
        .map_err(|e| format!("transaction base64: {e}"))?;
    solana_pay_kit::core::tx::decode_bytes(&bytes).map_err(|e| format!("transaction decode: {e}"))
}

pub fn encode_b64(tx: &VersionedTransaction) -> Result<String, String> {
    solana_pay_kit::core::tx::encode(tx).map_err(|e| format!("transaction encode: {e}"))
}

/// A message's instructions with account roles resolved from the header.
/// Only static-key messages (no lookup tables), which is all the kit builds.
#[derive(Debug, Clone, PartialEq)]
pub struct Decompiled {
    pub fee_payer: Pubkey,
    pub blockhash: Hash,
    pub instructions: Vec<Instruction>,
}

pub fn decompile(message: &VersionedMessage) -> Result<Decompiled, String> {
    let keys = message.static_account_keys();
    let header = message.header();
    if let VersionedMessage::V0(m) = message {
        if !m.address_table_lookups.is_empty() {
            return Err("address lookup tables are not supported".into());
        }
    }
    let signed = header.num_required_signatures as usize;
    let readonly_signed = header.num_readonly_signed_accounts as usize;
    let readonly_unsigned = header.num_readonly_unsigned_accounts as usize;
    let is_writable = |i: usize| {
        if i < signed {
            i < signed - readonly_signed
        } else {
            i < keys.len() - readonly_unsigned
        }
    };
    let instructions = message
        .instructions()
        .iter()
        .map(|ix| {
            let program_id = *keys
                .get(ix.program_id_index as usize)
                .ok_or("program index out of range")?;
            let accounts = ix
                .accounts
                .iter()
                .map(|&a| {
                    let a = a as usize;
                    let key = *keys.get(a).ok_or("account index out of range")?;
                    Ok(AccountMeta {
                        pubkey: key,
                        is_signer: a < signed,
                        is_writable: is_writable(a),
                    })
                })
                .collect::<Result<Vec<_>, &str>>()?;
            Ok(Instruction {
                program_id,
                accounts,
                data: ix.data.clone(),
            })
        })
        .collect::<Result<Vec<_>, &str>>()?;
    Ok(Decompiled {
        fee_payer: *keys.first().ok_or("message has no account keys")?,
        blockhash: *message.recent_blockhash(),
        instructions,
    })
}

/// Compile back into an unsigned version-0 transaction (all slots empty).
pub fn compile_v0(decompiled: &Decompiled) -> Result<VersionedTransaction, String> {
    let message = v0::Message::try_compile(
        &decompiled.fee_payer,
        &decompiled.instructions,
        &[],
        decompiled.blockhash,
    )
    .map_err(|e| format!("compile v0 message: {e}"))?;
    let message = VersionedMessage::V0(message);
    Ok(VersionedTransaction {
        signatures: vec![Signature::default(); message.header().num_required_signatures as usize],
        message,
    })
}

/// Sign every listed seed's slot (seeds whose pubkey is not a required
/// signer are ignored); other slots stay as they are.
pub fn sign_slots(tx: &mut VersionedTransaction, seeds: &[[u8; 32]]) {
    let message = tx.message.serialize();
    let required = tx.message.header().num_required_signatures as usize;
    for seed in seeds {
        let key = keys::signing_key(*seed);
        let signer = Pubkey::new_from_array(key.verifying_key().to_bytes());
        if let Some(index) = tx
            .message
            .static_account_keys()
            .iter()
            .take(required)
            .position(|k| *k == signer)
        {
            tx.signatures[index] = Signature::from(key.sign(&message).to_bytes());
        }
    }
}

/// What a required signer's slot holds: nothing yet (a co-signer such as a
/// sponsoring fee payer signs later), a valid signature over the message, or
/// bytes that do not verify.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Slot {
    Empty,
    Signed,
    Invalid,
}

/// Each required signer with the state of its slot, in message order.
pub fn signature_slots(tx: &VersionedTransaction) -> Vec<(String, Slot)> {
    let message = tx.message.serialize();
    let required = tx.message.header().num_required_signatures as usize;
    tx.message
        .static_account_keys()
        .iter()
        .take(required)
        .enumerate()
        .map(|(index, key)| {
            let slot = match tx.signatures.get(index) {
                None => Slot::Invalid,
                Some(sig) if *sig == Signature::default() => Slot::Empty,
                Some(sig) if sig.verify(key.as_ref(), &message) => Slot::Signed,
                Some(_) => Slot::Invalid,
            };
            (key.to_string(), slot)
        })
        .collect()
}

/// The x402 `exact` static layout every verify vector carries (§3.1):
///
/// 1. ComputeBudget SetComputeUnitLimit (200_000)
/// 2. ComputeBudget SetComputeUnitPrice (1 micro-lamport)
/// 3. TransferChecked client ATA -> `pay_to` ATA, authority = client
/// 4. Memo
///
/// Fee payer is the sponsor; its slot is left empty. The client signs.
pub struct StaticLayout<'a> {
    pub fee_payer: &'a str,
    pub mint: &'a str,
    pub pay_to: &'a str,
    pub amount: u64,
    pub decimals: u8,
    pub memo: &'a str,
}

pub fn x402_static_layout(layout: &StaticLayout<'_>) -> Result<VersionedTransaction, String> {
    let client = keys::pubkey_of_seed(keys::CLIENT_SEED);
    let token_program = pubkey(TOKEN_PROGRAM);
    let source = ata(&client.to_string(), layout.mint, TOKEN_PROGRAM);
    let destination = ata(layout.pay_to, layout.mint, TOKEN_PROGRAM);
    let mut transfer = vec![12u8];
    transfer.extend_from_slice(&layout.amount.to_le_bytes());
    transfer.push(layout.decimals);
    let mut limit = vec![2u8];
    limit.extend_from_slice(&200_000u32.to_le_bytes());
    let mut price = vec![3u8];
    price.extend_from_slice(&1u64.to_le_bytes());
    let instructions = vec![
        Instruction {
            program_id: pubkey(COMPUTE_BUDGET_PROGRAM),
            accounts: vec![],
            data: limit,
        },
        Instruction {
            program_id: pubkey(COMPUTE_BUDGET_PROGRAM),
            accounts: vec![],
            data: price,
        },
        Instruction {
            program_id: token_program,
            accounts: vec![
                AccountMeta::new(source, false),
                AccountMeta::new_readonly(pubkey(layout.mint), false),
                AccountMeta::new(destination, false),
                AccountMeta::new_readonly(client, true),
            ],
            data: transfer,
        },
        Instruction {
            program_id: pubkey(MEMO_PROGRAM),
            accounts: vec![],
            data: layout.memo.as_bytes().to_vec(),
        },
    ];
    let mut tx = compile_v0(&Decompiled {
        fee_payer: pubkey(layout.fee_payer),
        blockhash: Hash::from_str(keys::BLOCKHASH).map_err(|e| e.to_string())?,
        instructions,
    })?;
    sign_slots(&mut tx, &[keys::CLIENT_SEED]);
    Ok(tx)
}

/// Deterministic 32-character memo nonce for a vector id, the formula the
/// retired `gen-x402-verify-vectors.ts` used: the id's `[a-z0-9]` characters,
/// first 16, right-padded with `0`, then 17 zeros, cut to 32.
pub fn memo_nonce(id: &str) -> String {
    let compact: String = id
        .chars()
        .filter(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        .take(16)
        .collect();
    format!("{compact:0<16}00000000000000000")[..32].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decompile_compile_round_trips_the_static_layout() {
        let tx = x402_static_layout(&StaticLayout {
            fee_payer: keys::X402_SERVER_FEE_PAYER,
            mint: keys::MINT,
            pay_to: keys::X402_PAY_TO,
            amount: 1000,
            decimals: 6,
            memo: "0123456789abcdef0123456789abcdef",
        })
        .unwrap();
        let mut again = compile_v0(&decompile(&tx.message).unwrap()).unwrap();
        sign_slots(&mut again, &[keys::CLIENT_SEED]);
        assert_eq!(encode_b64(&tx).unwrap(), encode_b64(&again).unwrap());
    }

    #[test]
    fn memo_nonce_matches_the_retired_generator() {
        assert_eq!(
            memo_nonce("x402-exact-v2-verify-accept"),
            "x402exactv2verif0000000000000000"
        );
        assert_eq!(memo_nonce("x402-exact-v2-verify-accept").len(), 32);
    }
}
