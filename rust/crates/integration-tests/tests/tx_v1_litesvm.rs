//! Transaction V1 (SIMD-0385) end to end against LiteSVM: build with
//! `core::tx`, sign through `core::signing`, execute, and round-trip the
//! canonical wire encoding. LiteSVM 0.16 executes version-1 transactions and
//! reads the compute budget from the header config.

use litesvm::LiteSVM;
use solana_pay_kit::core::signing::sign_versioned_transaction_slot;
use solana_pay_kit::core::tx::{self, ComputeBudget, TxVersion};
use solana_pay_kit::solana_keychain::{MemorySigner, SolanaSigner};
use solana_pubkey::Pubkey;
use solana_system_interface::instruction as system_instruction;

/// LiteSVM's funded airdrop keypair, wrapped in the kit's software signer.
fn payer(svm: &LiteSVM) -> MemorySigner {
    MemorySigner::from_bytes(svm.airdrop_keypair_bytes()).expect("64-byte keypair")
}

#[tokio::test]
async fn v1_transfer_batch_executes_where_v0_cannot_be_built() {
    let mut svm = LiteSVM::new();
    let signer = payer(&svm);
    let payer = signer.pubkey();

    // 40 transfers to distinct recipients: 42 static accounts and ~1.4 KB of
    // message, past the version-0 packet limit but inside version 1's 4096.
    let recipients: Vec<Pubkey> = (0..40).map(|_| Pubkey::new_unique()).collect();
    let ixs: Vec<_> = recipients
        .iter()
        .map(|to| system_instruction::transfer(&payer, to, 1_000_000))
        .collect();
    let blockhash = svm.latest_blockhash();

    let v0 = tx::build_unsigned(TxVersion::V0, &payer, &ixs, blockhash, None);
    assert!(v0.unwrap_err().to_string().contains("1232-byte limit"));

    let budget = ComputeBudget::new(400_000, 1);
    let mut tx = tx::build_unsigned(TxVersion::V1, &payer, &ixs, blockhash, Some(&budget)).unwrap();
    sign_versioned_transaction_slot(&signer, &mut tx)
        .await
        .unwrap();

    // Canonical bytes: version byte first, one 64-byte signature last.
    let bytes = tx::serialize(&tx).unwrap();
    assert!(bytes.len() > 1232 && bytes.len() <= 4096, "{}", bytes.len());
    assert_eq!(bytes[0], solana_message::v1::V1_PREFIX);
    assert_eq!(tx::decode(&tx::encode(&tx).unwrap()).unwrap(), tx);

    let result = svm.send_transaction(tx.clone());
    assert!(result.is_ok(), "{result:?}");
    for to in &recipients {
        assert_eq!(svm.get_balance(to), Some(1_000_000));
    }
}

#[tokio::test]
async fn v1_without_a_compute_budget_gets_the_runtime_default_and_executes() {
    let mut svm = LiteSVM::new();
    let signer = payer(&svm);
    let payer = signer.pubkey();

    let to = Pubkey::new_unique();
    let ixs = [system_instruction::transfer(&payer, &to, 1_000_000)];
    let mut tx =
        tx::build_unsigned(TxVersion::V1, &payer, &ixs, svm.latest_blockhash(), None).unwrap();
    sign_versioned_transaction_slot(&signer, &mut tx)
        .await
        .unwrap();
    let result = svm.send_transaction(tx);
    assert!(result.is_ok(), "{result:?}");
    assert_eq!(svm.get_balance(&to), Some(1_000_000));
}
