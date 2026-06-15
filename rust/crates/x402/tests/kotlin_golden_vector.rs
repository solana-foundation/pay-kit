//! Cross-SDK check: the Kotlin x402 client's deterministic golden v0 SPL
//! transaction (pinned in
//! `kotlin/src/test/kotlin/.../V0MessageDecodeTest.kt::goldenV0SplVector`)
//! must pass the rust spine's `verify_exact_versioned_transaction`.
//!
//! This guards the web3-solana-built `transferChecked` (including its
//! authority account flags) against the canonical verifier the facilitators
//! run. Regenerate `GOLDEN_V0_SPL` here and in the Kotlin test together.

use base64::Engine;
use solana_transaction::versioned::VersionedTransaction;
use solana_x402::protocol::schemes::exact::SOLANA_DEVNET;
use solana_x402::protocol::schemes::exact::{
    verify_exact_versioned_transaction, PaymentRequirements,
};

const GOLDEN_V0_SPL: &str = concat!(
    "AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    "AAAAAAAAAAAAAAAAAAB4h5vIpEc09XZggnFHUKeev74bRgbaLMRFgh2NYV2ofkmx2Uf",
    "73Med0jbNhE6iPdgxhwDuV+Q/XoL2Fh6zIB8OgAIAAwdMxL7ko8h9WkSW5SwlG67XtS",
    "JZiRPvwPGK09Jf9vRbhSFS+NGbeR0kRTJC4V8uq2y3z/p7al7TAJeWDgaYgdsSqLucG",
    "/Qd4v5NMjQTvkWRrUlxle0D7MY2HMM6QMNHb6QF0v9ZVulbhkOsQH9ttW6uJjl0kF0Q",
    "I+cdo95TKOHKWwMGRm/lIRcy/+ytunLDm+e8jOW7xfcSayxDmzpAAAAAO0Qss5EhV/E",
    "6kz0BNCgtAytf/s0Botvxt3kGCN8ALqcG3fbh12Whk9nL4UbO63msHLSF7V9bN5E6jP",
    "WFfv8AqQcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHAwQABQIgTgAABAAJAw",
    "EAAAAAAAAABgQCBQMBCgzoAwAAAAAAAAYA",
);

const PAY_TO: &str = "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY";
const FEE_PAYER: &str = "6AfzJJo1KfhNWKe56wa5EWszTNQ7B1W5Kfh5SY2JkRGQ";
const USDC_DEVNET: &str = "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU";
const TOKEN_PROGRAM: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";

fn requirements() -> PaymentRequirements {
    PaymentRequirements {
        network: SOLANA_DEVNET.to_string(),
        cluster: Some("devnet".to_string()),
        recipient: PAY_TO.to_string(),
        amount: "1000".to_string(),
        currency: USDC_DEVNET.to_string(),
        decimals: Some(6),
        token_program: Some(TOKEN_PROGRAM.to_string()),
        resource: "/resource".to_string(),
        description: None,
        max_age: None,
        recent_blockhash: None,
        fee_payer: Some(true),
        fee_payer_key: Some(FEE_PAYER.to_string()),
        extra: None,
        accepted: None,
        resource_info: None,
    }
}

#[test]
fn kotlin_golden_v0_spl_passes_rust_verifier() {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(GOLDEN_V0_SPL)
        .expect("golden vector must be valid base64");
    let tx: VersionedTransaction = bincode::deserialize(&bytes)
        .expect("golden vector must deserialize as a VersionedTransaction");

    let fee_payer = solana_pubkey::Pubkey::try_from(FEE_PAYER).unwrap();
    verify_exact_versioned_transaction(&tx, &requirements(), &[fee_payer])
        .expect("Kotlin golden v0 SPL transaction must pass the rust verifier");
}
