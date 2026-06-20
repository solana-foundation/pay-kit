//! Token-2022 confidential transfer support.
//!
//! Gated behind the `confidential` feature. This module bridges the crate's
//! async [`SolanaSigner`] to `solana-zk-sdk`'s key-derivation API and (in
//! follow-up work) builds the multi-transaction confidential transfer bundle
//! described by the Solana charge spec's confidential profile.

use solana_keychain::SolanaSigner;
use solana_pubkey::Pubkey;
use solana_zk_sdk::encryption::{
    auth_encryption::AeKey,
    derivation::derive_confidential_keys_from_signature,
    elgamal::{ElGamalCiphertext, ElGamalKeypair},
};
use solana_zk_sdk_pod::encryption::elgamal::PodElGamalCiphertext;

use crate::error::Error;

/// Bit width of the low half of a split confidential-transfer amount; the high
/// half carries the remaining bits (`amount = lo + (hi << 16)`).
const TRANSFER_AMOUNT_LO_BITS: u32 = 16;

/// The ElGamal + AES keys controlling a confidential token account.
///
/// Both are deterministically derived from the account owner's wallet
/// signature over a public seed, so they never need separate storage and can
/// be re-derived on demand whenever encryption or decryption is needed.
pub struct ConfidentialKeys {
    /// Twisted-ElGamal keypair. Its public key is recorded in the account's
    /// `ConfidentialTransferAccount` extension and amounts are encrypted under
    /// it.
    pub elgamal: ElGamalKeypair,
    /// AES-GCM-SIV key for the fast "available balance" decryption path (lets
    /// the owner read its balance without solving a discrete log).
    pub ae: AeKey,
}

/// Derive the confidential-account keys for `token_account` from `signer`.
///
/// The public seed is the token account address, matching the spl-token
/// convention `ElGamalKeypair::new_from_signer(signer, &address.to_bytes())`,
/// so keys derived here interoperate with accounts configured by the standard
/// CLI and wallets. The wallet signs the seed (asynchronously — possibly via
/// hardware or Touch ID) and the resulting signature is hashed into the keys.
///
/// Because [`SolanaSigner`] is async whereas `solana-zk-sdk`'s
/// `derive_confidential_keys` expects the synchronous std `Signer`, we sign the
/// seed here and feed the signature to
/// [`derive_confidential_keys_from_signature`] — the same modern KDF that
/// non-`Signer` adapters (hardware wallets, KMS, Secure Enclave) use, so derived
/// keys stay interoperable with accounts configured by current spl-token tooling.
pub async fn derive_confidential_keys(
    signer: &dyn SolanaSigner,
    token_account: &Pubkey,
) -> Result<ConfidentialKeys, Error> {
    let seed = token_account.to_bytes();
    let signature = signer
        .sign_message(&seed)
        .await
        .map_err(|e| Error::Other(format!("failed to sign confidential key seed: {e}")))?;

    let (elgamal, ae) = derive_confidential_keys_from_signature(&signature)
        .map_err(|e| Error::Other(format!("failed to derive confidential keys: {e}")))?;

    Ok(ConfidentialKeys { elgamal, ae })
}

/// Recover a confidential transfer amount from its auditor ciphertexts.
///
/// A confidential transfer encrypts the amount — split into a low 16-bit part
/// and a high part — under the mint auditor's ElGamal key. The verifying server
/// holds the auditor secret, so it can decrypt both halves and recombine them
/// to confirm the on-chain amount matches the charge, without the amount ever
/// appearing in cleartext on-chain. Returns `None` if either half fails to
/// decrypt (e.g. wrong auditor key or a malformed ciphertext).
///
/// `ciphertext_lo`/`ciphertext_hi` are the auditor-handle ciphertexts carried by
/// the Token-2022 `Transfer` instruction (and produced by proof generation as
/// `CiphertextValidityProofWithAuditorCiphertext`).
pub fn recover_amount_via_auditor(
    auditor: &ElGamalKeypair,
    ciphertext_lo: &PodElGamalCiphertext,
    ciphertext_hi: &PodElGamalCiphertext,
) -> Option<u64> {
    let lo_ct = ElGamalCiphertext::from_bytes(&ciphertext_lo.0)?;
    let hi_ct = ElGamalCiphertext::from_bytes(&ciphertext_hi.0)?;
    let lo = auditor.secret().decrypt_u32(&lo_ct)?;
    let hi = auditor.secret().decrypt_u32(&hi_ct)?;
    hi.checked_shl(TRANSFER_AMOUNT_LO_BITS)?.checked_add(lo)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn memory_signer(seed_byte: u8) -> Box<dyn SolanaSigner> {
        let sk = ed25519_dalek::SigningKey::from_bytes(&[seed_byte; 32]);
        let mut kp = [0u8; 64];
        kp[..32].copy_from_slice(sk.as_bytes());
        kp[32..].copy_from_slice(sk.verifying_key().as_bytes());
        Box::new(solana_keychain::MemorySigner::from_bytes(&kp).expect("valid keypair"))
    }

    #[tokio::test]
    async fn derivation_is_deterministic() {
        let signer = memory_signer(7);
        let account = Pubkey::new_unique();

        let a = derive_confidential_keys(signer.as_ref(), &account)
            .await
            .expect("derive a");
        let b = derive_confidential_keys(signer.as_ref(), &account)
            .await
            .expect("derive b");

        // Same signer + same account address ⇒ identical keys (re-derivable
        // on demand, no separate storage needed).
        assert_eq!(a.elgamal.pubkey(), b.elgamal.pubkey());
    }

    #[tokio::test]
    async fn derivation_varies_by_account() {
        let signer = memory_signer(7);
        let acct1 = Pubkey::new_unique();
        let acct2 = Pubkey::new_unique();

        let k1 = derive_confidential_keys(signer.as_ref(), &acct1)
            .await
            .expect("derive acct1");
        let k2 = derive_confidential_keys(signer.as_ref(), &acct2)
            .await
            .expect("derive acct2");

        // Different public seed (account address) ⇒ different ElGamal key.
        assert_ne!(k1.elgamal.pubkey(), k2.elgamal.pubkey());
    }

    #[tokio::test]
    async fn derivation_varies_by_signer() {
        let account = Pubkey::new_unique();
        let s1 = memory_signer(7);
        let s2 = memory_signer(9);

        let k1 = derive_confidential_keys(s1.as_ref(), &account)
            .await
            .expect("derive s1");
        let k2 = derive_confidential_keys(s2.as_ref(), &account)
            .await
            .expect("derive s2");

        // Different wallet ⇒ different ElGamal key for the same address.
        assert_ne!(k1.elgamal.pubkey(), k2.elgamal.pubkey());
    }

    /// End-to-end crypto check against the real ZK ElGamal Proof program in
    /// litesvm: generate the three split-transfer proofs exactly as the bundle
    /// builder does, then submit each to the program for inline verification
    /// (`ContextStateInfo = None`). The program accepts a proof iff it is
    /// cryptographically valid AND in the byte format this agave/zk-sdk version
    /// expects — so a green run confirms our proof generation is correct and
    /// format-compatible with the cluster litesvm emulates.
    #[test]
    fn zk_proof_program_accepts_generated_transfer_proofs() {
        use litesvm::LiteSVM;
        use solana_keypair::Keypair;
        use solana_message::Message;
        use solana_signer::Signer;
        use solana_transaction::Transaction;
        use solana_zk_elgamal_proof_interface::instruction::ProofInstruction;
        use solana_zk_sdk::encryption::{auth_encryption::AeKey, elgamal::ElGamalKeypair};
        use spl_token_confidential_transfer_proof_generation::transfer::transfer_split_proof_data;

        let mut svm = LiteSVM::new();
        let payer = Keypair::new();
        svm.airdrop(&payer.pubkey(), 1_000_000_000).unwrap();

        // Sender, recipient, and auditor keys + a synthetic sender balance
        // (available ciphertext under the sender key, AES-decryptable copy).
        let sender = ElGamalKeypair::new_rand();
        let aes = AeKey::new_rand();
        let recipient = ElGamalKeypair::new_rand();
        let auditor = ElGamalKeypair::new_rand();
        let balance: u64 = 1_000;
        let amount: u64 = 100;
        let available = sender.pubkey().encrypt(balance);
        let decryptable = aes.encrypt(balance);

        let proof = transfer_split_proof_data(
            &available,
            &decryptable,
            amount,
            &sender,
            &aes,
            recipient.pubkey(),
            Some(auditor.pubkey()),
        )
        .expect("generate split-transfer proofs");

        let submit = |svm: &mut LiteSVM, ix: solana_instruction::Instruction, label: &str| {
            let blockhash = svm.latest_blockhash();
            let msg = Message::new_with_blockhash(&[ix], Some(&payer.pubkey()), &blockhash);
            let mut tx = Transaction::new_unsigned(msg);
            tx.signatures[0] = payer.sign_message(&tx.message_data());
            svm.send_transaction(tx)
                .unwrap_or_else(|e| panic!("{label} proof rejected by ZK program: {e:?}"));
        };

        submit(
            &mut svm,
            ProofInstruction::VerifyCiphertextCommitmentEquality
                .encode_verify_proof(None, &proof.equality_proof_data),
            "equality",
        );
        submit(
            &mut svm,
            ProofInstruction::VerifyBatchedGroupedCiphertext3HandlesValidity.encode_verify_proof(
                None,
                &proof
                    .ciphertext_validity_proof_data_with_ciphertext
                    .proof_data,
            ),
            "ciphertext-validity",
        );
        submit(
            &mut svm,
            ProofInstruction::VerifyBatchedRangeProofU128
                .encode_verify_proof(None, &proof.range_proof_data),
            "range",
        );
    }

    /// The auditor (verifying server) recovers the exact transferred amount
    /// from the transfer's auditor ciphertexts — including amounts that span
    /// the 16-bit lo/hi split — so it can confirm the on-chain amount matches
    /// the charge. This is the core of server-side bundle verification.
    #[test]
    fn auditor_recovers_transfer_amount() {
        use solana_zk_sdk::encryption::{auth_encryption::AeKey, elgamal::ElGamalKeypair};
        use spl_token_confidential_transfer_proof_generation::transfer::transfer_split_proof_data;

        let sender = ElGamalKeypair::new_rand();
        let aes = AeKey::new_rand();
        let recipient = ElGamalKeypair::new_rand();
        let auditor = ElGamalKeypair::new_rand();
        let wrong_auditor = ElGamalKeypair::new_rand();
        let balance: u64 = 10_000_000;

        // Amounts below, at, and above the 16-bit lo boundary.
        for amount in [1u64, 100, 65_535, 65_536, 70_000, 1_000_000] {
            let available = sender.pubkey().encrypt(balance);
            let decryptable = aes.encrypt(balance);
            let proof = transfer_split_proof_data(
                &available,
                &decryptable,
                amount,
                &sender,
                &aes,
                recipient.pubkey(),
                Some(auditor.pubkey()),
            )
            .expect("generate proofs");
            let ct = &proof.ciphertext_validity_proof_data_with_ciphertext;

            let recovered =
                recover_amount_via_auditor(&auditor, &ct.ciphertext_lo, &ct.ciphertext_hi)
                    .expect("auditor decrypts amount");
            assert_eq!(recovered, amount, "auditor must recover the exact amount");

            // A different auditor key must not recover the charged amount.
            let wrong =
                recover_amount_via_auditor(&wrong_auditor, &ct.ciphertext_lo, &ct.ciphertext_hi);
            assert_ne!(
                wrong,
                Some(amount),
                "wrong auditor key must not recover the amount"
            );
        }
    }
}
