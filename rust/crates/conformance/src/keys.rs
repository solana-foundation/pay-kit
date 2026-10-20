//! Deterministic keys, addresses and chain constants shared by every case.
//!
//! The values match the hand-written vectors this crate replaces, so a
//! regenerated vector differs from its predecessor only where the kit
//! disagrees, never because of a fresh key.

use ed25519_dalek::SigningKey;
use serde_json::{json, Value};
use solana_pubkey::Pubkey;

/// Client (payer) seed: `[7; 32]`. Its pubkey is [`CLIENT`].
pub const CLIENT_SEED: [u8; 32] = [7; 32];
pub const CLIENT: &str = "GmaDrppBC7P5ARKV8g3djiwP89vz1jLK23V2GBjuAEGB";

/// x402 server fee-payer (sponsor) seed: `[9; 32]`. Its pubkey is
/// [`X402_SERVER_FEE_PAYER`]. The MPP charge vectors use the same address as
/// their recipient.
pub const X402_SERVER_FEE_PAYER_SEED: [u8; 32] = [9; 32];
pub const X402_SERVER_FEE_PAYER: &str = "J2xccRtuG43drESLYznHhLhQkLTdfepcKYbiQ9BsJVaf";

pub const CHARGE_RECIPIENT: &str = "J2xccRtuG43drESLYznHhLhQkLTdfepcKYbiQ9BsJVaf";
pub const SPLIT_RECIPIENT: &str = "AoVsGaj8MSJ6xwKxfFxo9iZWH3enC8RRTXKH2fx2F8os";
/// A second split recipient (vote program id: a valid curve-off address
/// nobody signs for).
pub const SPLIT_RECIPIENT_2: &str = "Vote111111111111111111111111111111111111111";

/// SPL Token mint used by most vectors.
pub const MINT: &str = "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU";
/// A second SPL Token mint (mutation target for wrong-mint cases).
pub const OTHER_MINT: &str = "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB";
/// Token-2022 mint.
pub const MINT_2022: &str = "2b1kV6DkPAnxd5ixfnxCpjxmKwqjjaYmCZfHsFu24GXo";
/// Mainnet USDC.
pub const MAINNET_USDC: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";

pub const X402_PAY_TO: &str = "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY";
/// A second x402 merchant (cross-route and wrong-recipient cases).
pub const X402_OTHER_PAY_TO: &str = "Stake11111111111111111111111111111111111111";
/// `extra.feePayer` advertised by the x402 build offers, seed `[11; 32]`.
/// The harness holds its secret so `pkc run --cross` can configure every
/// server SDK (most refuse a sponsor without a key) to verify the builds.
pub const X402_OFFER_FEE_PAYER_SEED: [u8; 32] = [11; 32];
pub const X402_OFFER_FEE_PAYER: &str = "7v54NWdBtkjuAFJrLGsS2SXnuk8nKam81mZJeeYxVFi9";

pub const DEVNET_CAIP2: &str = "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1";
pub const MAINNET_CAIP2: &str = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp";

pub const BLOCKHASH: &str = "11111111111111111111111111111111";

pub const SYSTEM_PROGRAM: &str = "11111111111111111111111111111111";
pub const TOKEN_PROGRAM: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
pub const TOKEN_2022_PROGRAM: &str = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";
pub const ATA_PROGRAM: &str = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL";
pub const MEMO_PROGRAM: &str = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr";
pub const COMPUTE_BUDGET_PROGRAM: &str = "ComputeBudget111111111111111111111111111111";

pub fn signing_key(seed: [u8; 32]) -> SigningKey {
    SigningKey::from_bytes(&seed)
}

/// 64-byte `seed || pubkey` secret, the vectors' `*SecretKey` encoding.
pub fn keypair_bytes(seed: [u8; 32]) -> [u8; 64] {
    signing_key(seed).to_keypair_bytes()
}

pub fn secret_json(seed: [u8; 32]) -> Value {
    json!(keypair_bytes(seed).to_vec())
}

pub fn pubkey(address: &str) -> Pubkey {
    address
        .parse()
        .unwrap_or_else(|e| panic!("invalid address {address}: {e}"))
}

pub fn pubkey_of_seed(seed: [u8; 32]) -> Pubkey {
    Pubkey::new_from_array(signing_key(seed).verifying_key().to_bytes())
}

/// Associated token account of `owner` for `mint` under `token_program`.
pub fn ata(owner: &str, mint: &str, token_program: &str) -> Pubkey {
    let token_program = pubkey(token_program);
    let mint = pubkey(mint);
    let owner = pubkey(owner);
    Pubkey::find_program_address(
        &[owner.as_ref(), token_program.as_ref(), mint.as_ref()],
        &pubkey(ATA_PROGRAM),
    )
    .0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seeds_derive_the_published_addresses() {
        assert_eq!(pubkey_of_seed(CLIENT_SEED).to_string(), CLIENT);
        assert_eq!(
            pubkey_of_seed(X402_SERVER_FEE_PAYER_SEED).to_string(),
            X402_SERVER_FEE_PAYER
        );
        assert_eq!(
            pubkey_of_seed(X402_OFFER_FEE_PAYER_SEED).to_string(),
            X402_OFFER_FEE_PAYER
        );
    }

    #[test]
    fn constants_are_valid_addresses() {
        for address in [
            CLIENT,
            X402_SERVER_FEE_PAYER,
            SPLIT_RECIPIENT,
            SPLIT_RECIPIENT_2,
            MINT,
            OTHER_MINT,
            MINT_2022,
            MAINNET_USDC,
            X402_PAY_TO,
            X402_OTHER_PAY_TO,
            X402_OFFER_FEE_PAYER,
        ] {
            pubkey(address);
        }
    }
}
