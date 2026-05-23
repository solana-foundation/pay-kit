// Golden-vector generator for the Kotlin transaction codec parity tests.
// Builds a deterministic legacy SystemProgram transfer transaction with
// a fixed seed and fixed blockhash, then prints the bincode-serialized
// bytes as a hex string. The Kotlin codec must produce the same bytes.
use ed25519_dalek::SigningKey;
use solana_hash::Hash;
use solana_message::Message;
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use solana_system_interface::instruction as system_instruction;
use solana_transaction::Transaction;
use std::str::FromStr;

fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{:02x}", b));
    }
    out
}

fn main() {
    // Deterministic Ed25519 seed = 32 byte 0x42.
    let sk = SigningKey::from_bytes(&[0x42; 32]);
    let pubkey_bytes = sk.verifying_key().to_bytes();
    let from = Pubkey::from(pubkey_bytes);
    let to = Pubkey::from_str("CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY").unwrap();

    let ix = system_instruction::transfer(&from, &to, 1_000_000);
    // 32 byte zero blockhash so the message bytes stay deterministic.
    let blockhash = Hash::new_from_array([0u8; 32]);
    let message = Message::new_with_blockhash(&[ix], Some(&from), &blockhash);
    let mut tx = Transaction::new_unsigned(message);

    let message_bytes = tx.message_data();
    use ed25519_dalek::Signer;
    let sig_bytes = sk.sign(&message_bytes).to_bytes();
    tx.signatures[0] = Signature::from(<[u8; 64]>::from(sig_bytes));

    let serialized = bincode::serialize(&tx).unwrap();
    println!("PUBKEY_HEX: {}", to_hex(&pubkey_bytes));
    println!("MESSAGE_HEX: {}", to_hex(&message_bytes));
    println!("TX_HEX: {}", to_hex(&serialized));
    println!("SIG_HEX: {}", to_hex(&sig_bytes));
}
