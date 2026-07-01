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

use crate::mpp::error::Error;

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

/// Recover a confidential-transfer amount from a split (low 16-bit / high)
/// ElGamal ciphertext pair, using the ElGamal secret of whoever the ciphertexts
/// were encrypted for.
///
/// This is the shared decryption primitive for confidential-balance amounts.
/// The verifying party uses it with **its own** key on the ciphertexts encoded
/// for it: the payee (gateway) decrypts the **receiver** handle / its pending
/// balance with its recipient key to confirm it was paid; a mint **auditor**
/// (the issuer's compliance role — not the gateway) would use the auditor key
/// on the auditor handle. Either way the amount never appears in cleartext
/// on-chain. Returns `None` if either half fails to decrypt (wrong key or a
/// malformed ciphertext).
///
/// `ciphertext_lo`/`ciphertext_hi` are the 64-byte ElGamal ciphertexts for the
/// two halves of the amount (`amount = lo + (hi << 16)`).
pub fn recover_split_amount(
    key: &ElGamalKeypair,
    ciphertext_lo: &[u8],
    ciphertext_hi: &[u8],
) -> Option<u64> {
    let lo_ct = ElGamalCiphertext::from_bytes(ciphertext_lo)?;
    let hi_ct = ElGamalCiphertext::from_bytes(ciphertext_hi)?;
    let lo = key.secret().decrypt_u32(&lo_ct)?;
    let hi = key.secret().decrypt_u32(&hi_ct)?;
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
    #[cfg(feature = "litesvm-tests")]
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

    /// Full Token-2022 confidential-transfer lifecycle in litesvm, proving
    /// RECIPIENT-SIDE amount verification: the payee decrypts what it received
    /// with its OWN ElGamal key (not an auditor key).
    ///
    /// Lifecycle: create a confidential mint (auto-approve, no auditor) →
    /// configure sender + recipient confidential accounts (PubkeyValidity proof
    /// verified inline into a context account) → fund sender (mint → deposit →
    /// apply-pending) → confidential transfer sender→recipient (the 3 split
    /// proofs verified inline into context accounts, then `inner_transfer`
    /// referencing them) → read the recipient's `ConfidentialTransferAccount`
    /// and recover the amount from its **pending balance** ciphertexts with the
    /// recipient's own key.
    ///
    /// Token-2022 is loaded automatically: `LiteSVM::new()` calls
    /// `with_default_programs()`, which registers `spl_token_2022` (v11 ELF) and
    /// the associated-token-account program — no manual `add_program` needed.
    /// The ZK ElGamal Proof program is a litesvm builtin. No spl-record: litesvm
    /// does not enforce the 1232-byte packet limit, so every proof (incl. the
    /// U128 range proof) is verified inline into a context-state account.
    #[cfg(feature = "litesvm-tests")]
    #[test]
    fn recipient_recovers_confidential_transfer_amount_in_litesvm() {
        use std::mem::size_of;

        use litesvm::LiteSVM;
        use solana_address::Address;
        use solana_keypair::Keypair;
        use solana_signer::Signer;
        use solana_system_interface::instruction as system_instruction;
        use solana_transaction::Transaction;
        use solana_zk_elgamal_proof_interface::{
            instruction::{ContextStateInfo, ProofInstruction},
            proof_data::{
                BatchedGroupedCiphertext3HandlesValidityProofContext, BatchedRangeProofContext,
                CiphertextCommitmentEqualityProofContext, PubkeyValidityProofContext,
            },
            state::ProofContextState,
        };
        use solana_zk_sdk::{
            encryption::{auth_encryption::AeKey, elgamal::ElGamalKeypair},
            zk_elgamal_proof_program::pubkey_validity::build_pubkey_validity_proof_data,
        };
        use spl_associated_token_account::{
            get_associated_token_address_with_program_id,
            instruction::create_associated_token_account,
        };
        use spl_token_2022::{
            extension::{
                confidential_transfer::{
                    instruction::{
                        apply_pending_balance, configure_account, deposit, initialize_mint,
                        inner_transfer,
                    },
                    ConfidentialTransferAccount,
                },
                BaseStateWithExtensions, ExtensionType, StateWithExtensions,
            },
            instruction::{initialize_mint as initialize_mint_base, mint_to, reallocate},
            solana_zk_sdk::encryption::pod::elgamal::PodElGamalCiphertext as PodElGamalCiphertextLegacy,
            state::{Account as TokenAccount, Mint},
        };
        use spl_token_confidential_transfer_proof_extraction::instruction::ProofLocation;
        use spl_token_confidential_transfer_proof_generation::transfer::transfer_split_proof_data;

        let zk_program = Pubkey::from_str_const("ZkE1Gama1Proof11111111111111111111111111111");
        let token_program = spl_token_2022::id();
        let decimals: u8 = 0;

        // POD byte-casts across the zk-sdk 7 (proof gen) ↔ 4.0 (token-2022
        // instruction ABI) boundary. The canonical copies live in
        // `client::confidential`; call them here so a future zk-sdk bump can't
        // fix prod while leaving a stale test cast green.
        use crate::mpp::client::confidential::{
            cast_ae_ciphertext_v7_to_legacy, cast_elgamal_ciphertext_v7_to_legacy,
            cast_elgamal_pubkey_legacy_to_v7,
        };

        let mut svm = LiteSVM::new();
        let payer = Keypair::new();
        svm.airdrop(&payer.pubkey(), 100_000_000_000).unwrap();

        // Tiny helper: build, sign, and submit a legacy tx; panic with context.
        let submit = |svm: &mut LiteSVM,
                      ixs: &[solana_instruction::Instruction],
                      extra_signers: &[&Keypair],
                      label: &str| {
            let blockhash = svm.latest_blockhash();
            let msg =
                solana_message::Message::new_with_blockhash(ixs, Some(&payer.pubkey()), &blockhash);
            let mut tx = Transaction::new_unsigned(msg);
            let data = tx.message_data();
            set_sig(&mut tx, &payer.pubkey(), payer.sign_message(&data));
            for kp in extra_signers {
                set_sig(&mut tx, &kp.pubkey(), kp.sign_message(&data));
            }
            svm.send_transaction(tx)
                .unwrap_or_else(|e| panic!("{label} failed: {:?}", e.err));
        };
        fn set_sig(tx: &mut Transaction, pk: &Pubkey, sig: solana_signature::Signature) {
            let idx = tx
                .message
                .account_keys
                .iter()
                .position(|k| k == pk)
                .unwrap_or_else(|| panic!("signer {pk} not in tx accounts"));
            tx.signatures[idx] = sig;
        }

        // ---------------------------------------------------------------
        // 1. Create the confidential mint (Token-2022 + ConfidentialTransfer
        //    extension): auto-approve, no auditor.
        // ---------------------------------------------------------------
        let mint = Keypair::new();
        let mint_authority = Keypair::new();
        let mint_space = ExtensionType::try_calculate_account_len::<Mint>(&[
            ExtensionType::ConfidentialTransferMint,
        ])
        .unwrap();
        let mint_rent = svm.minimum_balance_for_rent_exemption(mint_space);
        submit(
            &mut svm,
            &[
                system_instruction::create_account(
                    &payer.pubkey(),
                    &mint.pubkey(),
                    mint_rent,
                    mint_space as u64,
                    &token_program,
                ),
                initialize_mint(
                    &token_program,
                    &mint.pubkey(),
                    None, // confidential-transfer authority
                    true, // auto_approve_new_accounts
                    None, // no auditor — recipient verification doesn't need one
                )
                .unwrap(),
                initialize_mint_base(
                    &token_program,
                    &mint.pubkey(),
                    &mint_authority.pubkey(),
                    None,
                    decimals,
                )
                .unwrap(),
            ],
            &[&mint],
            "create confidential mint",
        );

        // ---------------------------------------------------------------
        // 2. Configure sender + recipient confidential accounts. Each owner
        //    holds its own ElGamal + AES key. PubkeyValidity proof is verified
        //    inline into a context account, then `configure_account` references
        //    it via ProofLocation::ContextStateAccount.
        // ---------------------------------------------------------------
        let configure = |svm: &mut LiteSVM, owner: &Keypair| -> (Pubkey, ElGamalKeypair, AeKey) {
            let ata = get_associated_token_address_with_program_id(
                &owner.pubkey(),
                &mint.pubkey(),
                &token_program,
            );
            // Create the ATA (base token account, no CT extension yet).
            submit(
                svm,
                &[create_associated_token_account(
                    &payer.pubkey(),
                    &owner.pubkey(),
                    &mint.pubkey(),
                    &token_program,
                )],
                &[],
                "create ATA",
            );

            // Per-account keys (consistent across configure/deposit/apply/transfer).
            let elgamal = ElGamalKeypair::new_rand();
            let ae = AeKey::new_rand();
            let decryptable_zero = cast_ae_ciphertext_v7_to_legacy(&ae.encrypt(0u64));

            // PubkeyValidity proof verified inline into a context account.
            let proof_data = build_pubkey_validity_proof_data(&elgamal).unwrap();
            let proof_account = Keypair::new();
            let ctx_size = size_of::<ProofContextState<PubkeyValidityProofContext>>();
            let ctx_rent = svm.minimum_balance_for_rent_exemption(ctx_size);
            let create_ctx = system_instruction::create_account(
                &payer.pubkey(),
                &proof_account.pubkey(),
                ctx_rent,
                ctx_size as u64,
                &zk_program,
            );
            let verify = ProofInstruction::VerifyPubkeyValidity.encode_verify_proof(
                Some(ContextStateInfo {
                    context_state_account: &Address::from(proof_account.pubkey().to_bytes()),
                    context_state_authority: &Address::from(owner.pubkey().to_bytes()),
                }),
                &proof_data,
            );

            // Reallocate the ATA for the CT extension, then configure_account
            // referencing the verified proof context.
            let realloc = reallocate(
                &token_program,
                &ata,
                &payer.pubkey(),
                &owner.pubkey(),
                &[&owner.pubkey()],
                &[ExtensionType::ConfidentialTransferAccount],
            )
            .unwrap();
            let proof_loc = ProofLocation::ContextStateAccount(&proof_account.pubkey());
            let configure_ixs = configure_account(
                &token_program,
                &ata,
                &mint.pubkey(),
                &decryptable_zero,
                65536, // max_pending_balance_credit_counter
                &owner.pubkey(),
                &[],
                proof_loc,
            )
            .unwrap();

            let mut ixs = vec![create_ctx, verify, realloc];
            ixs.extend(configure_ixs);
            submit(svm, &ixs, &[owner, &proof_account], "configure account");

            (ata, elgamal, ae)
        };

        let sender = Keypair::new();
        let recipient = Keypair::new();
        let (sender_ata, sender_elgamal, sender_ae) = configure(&mut svm, &sender);
        let (recipient_ata, recipient_elgamal, _recipient_ae) = configure(&mut svm, &recipient);

        // ---------------------------------------------------------------
        // 3. Fund the sender: mint plaintext tokens → deposit into pending
        //    confidential balance → apply_pending_balance to make it available.
        // ---------------------------------------------------------------
        let starting_balance: u64 = 50_000;
        submit(
            &mut svm,
            &[mint_to(
                &token_program,
                &mint.pubkey(),
                &sender_ata,
                &mint_authority.pubkey(),
                &[],
                starting_balance,
            )
            .unwrap()],
            &[&mint_authority],
            "mint_to sender",
        );
        submit(
            &mut svm,
            &[deposit(
                &token_program,
                &sender_ata,
                &mint.pubkey(),
                starting_balance,
                decimals,
                &sender.pubkey(),
                &[&sender.pubkey()],
            )
            .unwrap()],
            &[&sender],
            "deposit",
        );
        // apply_pending_balance: decrypt pending, re-encrypt as new available.
        {
            let acc = svm.get_account(&sender_ata).unwrap();
            let state = StateWithExtensions::<TokenAccount>::unpack(&acc.data).unwrap();
            let ext = state
                .get_extension::<ConfidentialTransferAccount>()
                .unwrap();
            let decrypt = |key: &ElGamalKeypair, ct: &PodElGamalCiphertextLegacy| -> u64 {
                let bytes: [u8; 64] = bytemuck::bytes_of(ct).try_into().unwrap();
                let c = solana_zk_sdk::encryption::elgamal::ElGamalCiphertext::from_bytes(&bytes)
                    .unwrap();
                key.secret().decrypt_u32(&c).unwrap()
            };
            let pending_lo = decrypt(&sender_elgamal, &ext.pending_balance_lo);
            let pending_hi = decrypt(&sender_elgamal, &ext.pending_balance_hi);
            let pending_total = pending_lo + (pending_hi << 16);
            let expected_counter: u64 = ext.pending_balance_credit_counter.into();
            let new_decryptable =
                cast_ae_ciphertext_v7_to_legacy(&sender_ae.encrypt(pending_total));
            let apply_ix = apply_pending_balance(
                &token_program,
                &sender_ata,
                expected_counter,
                &new_decryptable,
                &sender.pubkey(),
                &[&sender.pubkey()],
            )
            .unwrap();
            submit(&mut svm, &[apply_ix], &[&sender], "apply_pending_balance");
        }

        // ---------------------------------------------------------------
        // 4. Confidential transfer sender→recipient. Amount < 65536 so the
        //    whole value sits in the `lo` ciphertext (hi == 0) — matching
        //    recover_split_amount's 16-bit split assumption.
        // ---------------------------------------------------------------
        let amount: u64 = 1_000;

        // Recipient ElGamal pubkey from its configured account (legacy → v7).
        let recipient_acc = svm.get_account(&recipient_ata).unwrap();
        let recipient_state =
            StateWithExtensions::<TokenAccount>::unpack(&recipient_acc.data).unwrap();
        let recipient_ext = recipient_state
            .get_extension::<ConfidentialTransferAccount>()
            .unwrap();
        let recipient_elgamal_pubkey: solana_zk_sdk::encryption::elgamal::ElGamalPubkey =
            cast_elgamal_pubkey_legacy_to_v7(&recipient_ext.elgamal_pubkey)
                .unwrap()
                .try_into()
                .unwrap();

        // Sender's current available balance ciphertext + decryptable.
        let sender_acc = svm.get_account(&sender_ata).unwrap();
        let sender_state = StateWithExtensions::<TokenAccount>::unpack(&sender_acc.data).unwrap();
        let sender_ext = sender_state
            .get_extension::<ConfidentialTransferAccount>()
            .unwrap();
        let current_available: solana_zk_sdk::encryption::elgamal::ElGamalCiphertext = {
            let bytes: [u8; 64] = bytemuck::bytes_of(&sender_ext.available_balance)
                .try_into()
                .unwrap();
            solana_zk_sdk_pod::encryption::elgamal::PodElGamalCiphertext(bytes)
                .try_into()
                .unwrap()
        };
        let current_decryptable: solana_zk_sdk::encryption::auth_encryption::AeCiphertext = {
            let bytes: [u8; 36] = bytemuck::bytes_of(&sender_ext.decryptable_available_balance)
                .try_into()
                .unwrap();
            solana_zk_sdk::encryption::auth_encryption::AeCiphertext::from_bytes(&bytes).unwrap()
        };

        // Generate the three split-transfer proofs (no auditor).
        let proof = transfer_split_proof_data(
            &current_available,
            &current_decryptable,
            amount,
            &sender_elgamal,
            &sender_ae,
            &recipient_elgamal_pubkey,
            None,
        )
        .expect("generate split-transfer proofs");

        // Verify each proof inline into its own context account.
        let make_ctx = |svm: &mut LiteSVM, size: usize| -> Keypair {
            let kp = Keypair::new();
            let rent = svm.minimum_balance_for_rent_exemption(size);
            submit(
                svm,
                &[system_instruction::create_account(
                    &payer.pubkey(),
                    &kp.pubkey(),
                    rent,
                    size as u64,
                    &zk_program,
                )],
                &[&kp],
                "create proof context account",
            );
            kp
        };
        let authority_addr = Address::from(sender.pubkey().to_bytes());

        let equality_account = make_ctx(
            &mut svm,
            size_of::<ProofContextState<CiphertextCommitmentEqualityProofContext>>(),
        );
        let equality_addr = Address::from(equality_account.pubkey().to_bytes());
        submit(
            &mut svm,
            &[
                ProofInstruction::VerifyCiphertextCommitmentEquality.encode_verify_proof(
                    Some(ContextStateInfo {
                        context_state_account: &equality_addr,
                        context_state_authority: &authority_addr,
                    }),
                    &proof.equality_proof_data,
                ),
            ],
            &[],
            "verify equality proof",
        );

        let validity_account = make_ctx(
            &mut svm,
            size_of::<ProofContextState<BatchedGroupedCiphertext3HandlesValidityProofContext>>(),
        );
        let validity_addr = Address::from(validity_account.pubkey().to_bytes());
        submit(
            &mut svm,
            &[
                ProofInstruction::VerifyBatchedGroupedCiphertext3HandlesValidity
                    .encode_verify_proof(
                        Some(ContextStateInfo {
                            context_state_account: &validity_addr,
                            context_state_authority: &authority_addr,
                        }),
                        &proof
                            .ciphertext_validity_proof_data_with_ciphertext
                            .proof_data,
                    ),
            ],
            &[],
            "verify ciphertext-validity proof",
        );

        let range_account = make_ctx(
            &mut svm,
            size_of::<ProofContextState<BatchedRangeProofContext>>(),
        );
        let range_addr = Address::from(range_account.pubkey().to_bytes());
        submit(
            &mut svm,
            &[
                ProofInstruction::VerifyBatchedRangeProofU128.encode_verify_proof(
                    Some(ContextStateInfo {
                        context_state_account: &range_addr,
                        context_state_authority: &authority_addr,
                    }),
                    &proof.range_proof_data,
                ),
            ],
            &[],
            "verify range proof",
        );

        // New decryptable available balance for the sender post-transfer.
        let new_avail = starting_balance - amount;
        let new_decryptable = cast_ae_ciphertext_v7_to_legacy(&sender_ae.encrypt(new_avail));
        let recipient_lo = cast_elgamal_ciphertext_v7_to_legacy(
            &proof
                .ciphertext_validity_proof_data_with_ciphertext
                .ciphertext_lo,
        );
        let recipient_hi = cast_elgamal_ciphertext_v7_to_legacy(
            &proof
                .ciphertext_validity_proof_data_with_ciphertext
                .ciphertext_hi,
        );

        let transfer_ix = inner_transfer(
            &token_program,
            &sender_ata,
            &mint.pubkey(),
            &recipient_ata,
            &new_decryptable,
            &recipient_lo,
            &recipient_hi,
            &sender.pubkey(),
            &[],
            ProofLocation::ContextStateAccount(&equality_account.pubkey()),
            ProofLocation::ContextStateAccount(&validity_account.pubkey()),
            ProofLocation::ContextStateAccount(&range_account.pubkey()),
        )
        .expect("build transfer instruction");
        submit(
            &mut svm,
            &[transfer_ix],
            &[&sender],
            "confidential transfer",
        );

        // ---------------------------------------------------------------
        // 5. THE ASSERTION: the recipient recovers the received amount from
        //    its OWN pending-balance ciphertexts using its OWN ElGamal key —
        //    no auditor key involved.
        // ---------------------------------------------------------------
        let recipient_acc = svm.get_account(&recipient_ata).unwrap();
        let recipient_state =
            StateWithExtensions::<TokenAccount>::unpack(&recipient_acc.data).unwrap();
        let recipient_ext = recipient_state
            .get_extension::<ConfidentialTransferAccount>()
            .unwrap();

        let lo_bytes = bytemuck::bytes_of(&recipient_ext.pending_balance_lo);
        let hi_bytes = bytemuck::bytes_of(&recipient_ext.pending_balance_hi);
        let recovered = recover_split_amount(&recipient_elgamal, lo_bytes, hi_bytes)
            .expect("recipient key recovers received amount");
        assert_eq!(
            recovered, amount,
            "recipient must recover the exact transferred amount with its own key"
        );

        // A different (wrong) key must NOT recover the amount — the recipient
        // assertion is genuinely key-bound.
        let wrong_key = ElGamalKeypair::new_rand();
        assert_ne!(
            recover_split_amount(&wrong_key, lo_bytes, hi_bytes),
            Some(amount),
            "a non-recipient key must not recover the amount"
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
                recover_split_amount(&auditor, &ct.ciphertext_lo.0, &ct.ciphertext_hi.0)
                    .expect("matching key decrypts amount");
            assert_eq!(recovered, amount, "must recover the exact amount");

            // A non-matching key must not recover the charged amount.
            let wrong =
                recover_split_amount(&wrong_auditor, &ct.ciphertext_lo.0, &ct.ciphertext_hi.0);
            assert_ne!(
                wrong,
                Some(amount),
                "wrong auditor key must not recover the amount"
            );
        }
    }
}
