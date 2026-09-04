//! Shared transaction-signing helpers.
//!
//! These route through `TransactionSigner::sign_transaction`, so a backend that
//! cannot raw-sign arbitrary bytes -- a hardware wallet -- works here. The
//! previous `sign_message(&tx.message.serialize())` form assumed a software key
//! that raw-ed25519-signs anything, which is why hardware support had to stay
//! out; keychain 2.x publishes a versioned-transaction signing API, so the
//! assumption is no longer needed. For software backends the bytes signed are
//! unchanged, so signatures are byte-identical to before.

use solana_keychain::TransactionSigner;
use solana_pubkey::Pubkey;
use solana_transaction::versioned::VersionedTransaction;
use solana_transaction::Transaction;

use crate::core::{Error, Result};

/// Sign the calling signer's required slot in a legacy or v0 transaction.
pub async fn sign_versioned_transaction_slot(
    signer: &dyn TransactionSigner,
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

    // `sign_transaction` places the signature at this signer's own index and
    // leaves every other slot untouched, which is what the checks above have
    // just established is safe. The `signer_index` computed above is therefore
    // still the slot that changes; it stays computed because the validation
    // depends on it.
    signer
        .sign_transaction(tx)
        .await
        .map_err(|error| Error::Other(format!("transaction signing failed: {error}")))?;
    Ok(())
}

/// Sign a legacy transaction through the versioned signing API.
///
/// `TransactionSigner::sign_transaction` takes a `VersionedTransaction`, while
/// much of the kit still builds legacy `Transaction`s and serializes them as
/// such. Converting to a versioned view is lossless in both directions here: a
/// legacy transaction becomes `VersionedMessage::Legacy`, which leaves the
/// account keys, the header and therefore the signature slot ordering exactly
/// as they were, so copying the signature vector back is a faithful round-trip.
///
/// This keeps the conversion in one place rather than at each call site, and
/// leaves callers free to go on serializing the legacy transaction.
pub async fn sign_legacy_transaction(
    signer: &dyn TransactionSigner,
    tx: &mut Transaction,
) -> Result<()> {
    let mut versioned = VersionedTransaction::from(tx.clone());
    signer
        .sign_transaction(&mut versioned)
        .await
        .map_err(|error| Error::Other(format!("transaction signing failed: {error}")))?;
    tx.signatures = versioned.signatures;
    Ok(())
}

/// Co-sign the transaction's fee-payer slot after pinning the expected sponsor.
///
/// `expected_fee_payer` must be the pre-configured sponsor key, not a value
/// derived from `signer`. The sponsor must be both the supplied signer and
/// account key zero: accepting it at a later index would let a crafted
/// transaction leave its actual fee payer unsigned.
pub async fn cosign_versioned_fee_payer(
    signer: &dyn TransactionSigner,
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

/// Co-sign a legacy transaction's fee-payer slot after pinning the sponsor.
///
/// The legacy counterpart to `cosign_versioned_fee_payer`, for the paths that
/// still build and serialize a legacy `Transaction`. It runs the same sponsor
/// and slot validation, and routes the signature through `sign_transaction`, so
/// a hardware backend works here too. The round-trip through the versioned view
/// is faithful for the same reason `sign_legacy_transaction` documents.
pub async fn cosign_legacy_fee_payer(
    signer: &dyn TransactionSigner,
    expected_fee_payer: &Pubkey,
    tx: &mut Transaction,
) -> Result<()> {
    let mut versioned = VersionedTransaction::from(tx.clone());
    cosign_versioned_fee_payer(signer, expected_fee_payer, &mut versioned).await?;
    tx.signatures = versioned.signatures;
    Ok(())
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;
    use solana_hash::Hash;
    use solana_keychain::transaction_util::TransactionUtil;
    use solana_keychain::{SignTransactionResult, SignerError, SolanaSigner};
    use solana_message::{v0, Message, VersionedMessage};
    use solana_signature::Signature;
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

        async fn sign_message(
            &self,
            _message: &[u8],
        ) -> std::result::Result<Signature, SignerError> {
            // Stands in for a hardware backend: raw-byte signing is exactly what
            // such a signer cannot do, so the helpers must never reach this.
            Err(SignerError::Other(
                "sign_message must not be used to sign a transaction".into(),
            ))
        }

        async fn is_available(&self) -> bool {
            true
        }
    }

    #[async_trait]
    impl TransactionSigner for TransactionOnlySigner {
        async fn sign_transaction(
            &self,
            tx: &mut VersionedTransaction,
        ) -> std::result::Result<SignTransactionResult, SignerError> {
            *self.signed_message.lock().unwrap() = tx.message.serialize();
            let signature = Signature::from([7u8; 64]);
            TransactionUtil::add_signature_to_transaction(tx, &self.pubkey, signature)?;
            let signed = (TransactionUtil::serialize_transaction(tx)?, signature);
            Ok(TransactionUtil::classify_signed_transaction(tx, signed))
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
    async fn legacy_fee_payer_cosign_never_calls_sign_message() {
        // `TransactionOnlySigner::sign_message` returns an error, standing in
        // for a hardware backend that cannot raw-sign arbitrary bytes. If this
        // helper regressed to `sign_message(&tx.message_data())` the call would
        // fail rather than quietly signing the wrong bytes.
        let signer = TransactionOnlySigner::new(Pubkey::new_unique());
        let fee_payer = signer.pubkey();
        let source = Pubkey::new_unique();
        let recipient = Pubkey::new_unique();
        let instruction = system_instruction::transfer(&source, &recipient, 1);
        let message =
            Message::new_with_blockhash(&[instruction], Some(&fee_payer), &Hash::new_unique());
        let mut tx = Transaction::new_unsigned(message);

        cosign_legacy_fee_payer(&signer, &fee_payer, &mut tx)
            .await
            .unwrap();

        // Signed the fee-payer slot, and covered the transaction message rather
        // than some other byte string.
        assert_eq!(tx.signatures[0], Signature::from([7u8; 64]));
        assert_eq!(
            *signer.signed_message.lock().unwrap(),
            VersionedTransaction::from(tx.clone()).message.serialize()
        );
        // Every other required slot is left for its own signer.
        assert_eq!(tx.signatures[1], Signature::default());
    }

    #[tokio::test]
    async fn legacy_fee_payer_cosign_rejects_a_sponsor_that_is_not_the_fee_payer() {
        // The sponsor must be account key zero. Signing it at a later index
        // would leave the transaction's actual fee payer unsigned.
        let signer = TransactionOnlySigner::new(Pubkey::new_unique());
        let other_fee_payer = Pubkey::new_unique();
        let instruction = system_instruction::transfer(&signer.pubkey(), &other_fee_payer, 1);
        let message = Message::new_with_blockhash(
            &[instruction],
            Some(&other_fee_payer),
            &Hash::new_unique(),
        );
        let mut tx = Transaction::new_unsigned(message);

        let err = cosign_legacy_fee_payer(&signer, &signer.pubkey(), &mut tx)
            .await
            .expect_err("a sponsor that is not account key zero must be rejected");
        assert!(err.to_string().contains("fee payer"), "{err}");
        assert!(tx.signatures.iter().all(|s| *s == Signature::default()));
    }

    #[tokio::test]
    async fn legacy_signing_preserves_other_slots_signatures() {
        // The legacy shim round-trips through a versioned view. If that
        // conversion dropped or reordered signatures, a co-signing flow would
        // silently discard a signature already collected -- so pin it.
        //
        // Two required signers: `fee_payer` (account key 0) and the transfer
        // source, which is the signer under test.
        let signer = TransactionOnlySigner::new(Pubkey::new_unique());
        let fee_payer = Pubkey::new_unique();
        let recipient = Pubkey::new_unique();
        let instruction = system_instruction::transfer(&signer.pubkey(), &recipient, 1);
        let message =
            Message::new_with_blockhash(&[instruction], Some(&fee_payer), &Hash::new_unique());
        let mut tx = Transaction::new_unsigned(message);

        let fee_payer_index = tx
            .message
            .account_keys
            .iter()
            .position(|key| key == &fee_payer)
            .unwrap();
        let signer_index = tx
            .message
            .account_keys
            .iter()
            .position(|key| key == &signer.pubkey())
            .unwrap();
        assert_ne!(signer_index, fee_payer_index);

        // Stand in for a signature already collected from the fee payer.
        let preexisting = Signature::from([9u8; 64]);
        tx.signatures[fee_payer_index] = preexisting;

        let expected_message = VersionedTransaction::from(tx.clone()).message.serialize();

        sign_legacy_transaction(&signer, &mut tx).await.unwrap();

        assert_eq!(
            tx.signatures[fee_payer_index], preexisting,
            "an already-collected signature must survive the versioned round-trip"
        );
        assert_eq!(tx.signatures[signer_index], Signature::from([7u8; 64]));
        // The bytes the signer saw are the transaction message itself.
        assert_eq!(*signer.signed_message.lock().unwrap(), expected_message);
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
