//! Shared transaction-signing helpers.
//!
//! Transaction bytes must go through a signer's transaction-signing path.
//! `sign_message` is reserved for protocol and off-chain messages because
//! hardware wallets may wrap those bytes in Solana's off-chain envelope.

use solana_keychain::SolanaSigner;
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use solana_transaction::versioned::VersionedTransaction;

use crate::core::{Error, Result};

/// Connect to a Ledger using the default device selection policy.
///
/// This protocol-neutral wrapper keeps downstream applications insulated from
/// the keychain backend's constructor details. `derivation_path` defaults to
/// Ledger Live's first Solana account when omitted. Set
/// `confirm_pubkey_on_device` while registering an account, but not on every
/// subsequent signing connection.
#[cfg(feature = "ledger")]
pub fn connect_ledger(
    derivation_path: Option<&str>,
    confirm_pubkey_on_device: bool,
) -> std::result::Result<solana_keychain::Signer, solana_keychain::SignerError> {
    solana_keychain::LedgerSigner::connect(derivation_path, confirm_pubkey_on_device, None)
        .map(solana_keychain::Signer::Ledger)
}

/// Sign the calling signer's required slot in a legacy or v0 transaction.
///
/// `VersionedTransaction` covers both wire formats. The keychain method takes
/// the serialized message so hardware wallets can route it through their
/// transaction parser while software signers preserve their existing raw
/// Ed25519 signature.
pub async fn sign_versioned_transaction_slot(
    signer: &dyn SolanaSigner,
    tx: &mut VersionedTransaction,
) -> Result<()> {
    let signer_pubkey = signer.pubkey();
    let signer_index = tx
        .message
        .static_account_keys()
        .iter()
        .position(|key| key == &signer_pubkey)
        .ok_or_else(|| Error::Other("signer not found in transaction accounts".into()))?;
    let required_signatures = tx.message.header().num_required_signatures as usize;
    if signer_index >= required_signatures {
        return Err(Error::Other(
            "signer is not a required transaction signer".into(),
        ));
    }
    if tx.signatures.len() != required_signatures {
        return Err(Error::Other(format!(
            "transaction has {} signature slots but requires {required_signatures}",
            tx.signatures.len()
        )));
    }

    let signature = signer
        .sign_transaction_message(&tx.message.serialize())
        .await
        .map_err(|error| Error::Other(format!("transaction signing failed: {error}")))?;
    tx.signatures[signer_index] = Signature::from(<[u8; 64]>::from(signature));
    Ok(())
}

/// Co-sign slot zero after pinning both the signer and transaction fee payer.
pub async fn cosign_versioned_fee_payer(
    signer: &dyn SolanaSigner,
    expected_fee_payer: &Pubkey,
    tx: &mut VersionedTransaction,
) -> Result<()> {
    if signer.pubkey() != *expected_fee_payer {
        return Err(Error::Other(
            "fee payer signer does not match the expected fee payer".into(),
        ));
    }
    if tx.message.static_account_keys().first() != Some(expected_fee_payer) {
        return Err(Error::Other(
            "transaction fee payer does not match the expected fee payer".into(),
        ));
    }
    sign_versioned_transaction_slot(signer, tx).await
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;
    use solana_hash::Hash;
    use solana_keychain::{SignTransactionResult, SignerError};
    use solana_message::{v0, Message, VersionedMessage};
    use solana_system_interface::instruction as system_instruction;
    use solana_transaction::Transaction;

    use super::*;

    struct TransactionOnlySigner {
        pubkey: Pubkey,
        signed_message: std::sync::Mutex<Vec<u8>>,
    }

    impl TransactionOnlySigner {
        fn new(pubkey: Pubkey) -> Self {
            Self {
                pubkey,
                signed_message: std::sync::Mutex::new(Vec::new()),
            }
        }
    }

    #[async_trait]
    impl SolanaSigner for TransactionOnlySigner {
        fn pubkey(&self) -> Pubkey {
            self.pubkey
        }

        async fn sign_transaction(
            &self,
            _tx: &mut Transaction,
        ) -> std::result::Result<SignTransactionResult, SignerError> {
            Err(SignerError::Other("unused legacy path".into()))
        }

        async fn sign_message(
            &self,
            _message: &[u8],
        ) -> std::result::Result<Signature, SignerError> {
            Err(SignerError::Other("wrong off-chain path".into()))
        }

        async fn sign_transaction_message(
            &self,
            message: &[u8],
        ) -> std::result::Result<Signature, SignerError> {
            *self.signed_message.lock().unwrap() = message.to_vec();
            Ok(Signature::from([7u8; 64]))
        }

        async fn is_available(&self) -> bool {
            true
        }
    }

    #[tokio::test]
    async fn signs_only_the_calling_signers_required_slot() {
        let fee_payer = Pubkey::new_unique();
        let signer = TransactionOnlySigner::new(Pubkey::new_unique());
        let recipient = Pubkey::new_unique();
        let instruction = system_instruction::transfer(&signer.pubkey(), &recipient, 1);
        let message =
            Message::new_with_blockhash(&[instruction], Some(&fee_payer), &Hash::new_unique());
        let mut tx = VersionedTransaction::from(Transaction::new_unsigned(message));

        sign_versioned_transaction_slot(&signer, &mut tx)
            .await
            .unwrap();

        let signer_index = tx
            .message
            .static_account_keys()
            .iter()
            .position(|key| key == &signer.pubkey())
            .unwrap();
        assert_ne!(signer_index, 0);
        assert_eq!(tx.signatures[0], Signature::default());
        assert_eq!(tx.signatures[signer_index], Signature::from([7u8; 64]));
        assert_eq!(
            *signer.signed_message.lock().unwrap(),
            tx.message.serialize()
        );
    }

    #[tokio::test]
    async fn cosigns_v0_fee_payer_without_replacing_the_payer_signature() {
        let fee_payer = TransactionOnlySigner::new(Pubkey::new_unique());
        let payer = Pubkey::new_unique();
        let recipient = Pubkey::new_unique();
        let instruction = system_instruction::transfer(&payer, &recipient, 1);
        let message = VersionedMessage::V0(
            v0::Message::try_compile(&fee_payer.pubkey(), &[instruction], &[], Hash::new_unique())
                .unwrap(),
        );
        let mut tx = VersionedTransaction {
            signatures: vec![
                Signature::default();
                message.header().num_required_signatures as usize
            ],
            message,
        };
        let payer_index = tx
            .message
            .static_account_keys()
            .iter()
            .position(|key| key == &payer)
            .unwrap();
        tx.signatures[payer_index] = Signature::from([9u8; 64]);

        cosign_versioned_fee_payer(&fee_payer, &fee_payer.pubkey(), &mut tx)
            .await
            .unwrap();

        assert_eq!(tx.signatures[0], Signature::from([7u8; 64]));
        assert_eq!(tx.signatures[payer_index], Signature::from([9u8; 64]));
        assert_eq!(
            *fee_payer.signed_message.lock().unwrap(),
            tx.message.serialize()
        );
    }
}
