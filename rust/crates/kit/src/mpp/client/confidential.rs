//! Client-side construction of a Token-2022 confidential transfer bundle.
//!
//! Produces the ordered set of signed transactions (`CredentialPayload::Bundle`)
//! that settle a confidential charge: pre-verify the equality, ciphertext-
//! validity, and range proofs into context state accounts, then reference them
//! from the Token-2022 `transfer` instruction, then close the accounts.
//!
//! Proofs are generated with `spl-token-confidential-transfer-proof-generation`
//! (zk-sdk 7.0.1) and byte-cast to spl-token-2022 10.0.0's zk-sdk-4.0 POD types
//! at the instruction boundary (see the `cast_*` helpers). The oversized U128
//! range proof is staged into an spl-record account and verified from there.
//!
//! Clients hold no SOL, so the bundle is gateway-paid: the gateway is the fee
//! payer, rent funder, proof/record-account authority, and rent-reclaim
//! destination on every tx. The client partially signs (transfer authority +
//! ephemeral account keypairs) and leaves the fee-payer slot for the gateway to
//! co-sign at settlement, then the gateway submits the txs in order.

use base64::Engine;
use solana_address::Address;
use solana_hash::Hash;
use solana_instruction::Instruction;
use solana_keychain::SolanaSigner;
use solana_keypair::Keypair;
use solana_message::Message;
use solana_pubkey::Pubkey;
use solana_rpc_client::rpc_client::RpcClient;
use solana_signature::Signature;
use solana_signer::Signer;
use solana_system_interface::instruction as system_instruction;
use std::mem::size_of;
use std::str::FromStr;

use solana_zk_elgamal_proof_interface::{
    instruction::{close_context_state, ContextStateInfo, ProofInstruction},
    proof_data::{
        BatchedGroupedCiphertext2HandlesValidityProofContext,
        BatchedGroupedCiphertext3HandlesValidityProofContext, BatchedRangeProofContext,
        CiphertextCommitmentEqualityProofContext, PercentageWithCapProofContext,
    },
    state::ProofContextState,
};
use solana_zk_sdk::encryption::{
    auth_encryption::AeCiphertext,
    elgamal::{ElGamalCiphertext, ElGamalPubkey},
};
use solana_zk_sdk_pod::encryption::elgamal::{
    PodElGamalCiphertext as PodElGamalCiphertextV7, PodElGamalPubkey as PodElGamalPubkeyV7,
};
use spl_token_2022::{
    extension::{
        confidential_transfer::{
            instruction::{inner_transfer, inner_transfer_with_fee},
            ConfidentialTransferAccount, ConfidentialTransferMint,
        },
        confidential_transfer_fee::ConfidentialTransferFeeConfig,
        transfer_fee::TransferFeeConfig,
        BaseStateWithExtensions, StateWithExtensions,
    },
    solana_zk_sdk::encryption::pod::{
        auth_encryption::PodAeCiphertext as PodAeCiphertextLegacy,
        elgamal::{
            PodElGamalCiphertext as PodElGamalCiphertextLegacy,
            PodElGamalPubkey as PodElGamalPubkeyLegacy,
        },
    },
    state::{Account as TokenAccount, Mint},
};
use spl_token_confidential_transfer_proof_extraction::instruction::ProofLocation;
use spl_token_confidential_transfer_proof_generation::{
    transfer::transfer_split_proof_data, transfer_with_fee::transfer_with_fee_split_proof_data,
};

use crate::mpp::error::Error;
use crate::mpp::protocol::confidential::{derive_confidential_keys, ConfidentialKeys};
use crate::mpp::protocol::solana::CredentialPayload;

/// The native ZK ElGamal Proof program.
const ZK_PROOF_PROGRAM_ID: &str = "ZkE1Gama1Proof11111111111111111111111111111";

/// The ComputeBudget program (CU limit / priority fee).
const COMPUTE_BUDGET_PROGRAM_ID: &str = "ComputeBudget111111111111111111111111111111";

/// CU limit requested on the final transfer tx. The confidential `Transfer`
/// reading three proof context-state accounts plus the in-tx account closes
/// exceeds the 200k default, so we request explicit headroom (well within the
/// server's allow-list cap). Requesting a limit only raises the ceiling — with
/// no priority price set it costs nothing extra (fee is charged on CU used).
const CONFIDENTIAL_TRANSFER_COMPUTE_UNIT_LIMIT: u32 = 500_000;

/// Byte offset of the proof inside an spl-record account
/// (`RecordData::WRITABLE_START_INDEX`: 1-byte version + 32-byte authority).
const RECORD_PROOF_OFFSET: u32 = 33;

/// First record-write payload (smaller: shares its tx with create + initialize).
const RECORD_FIRST_CHUNK: usize = 750;
/// Subsequent record-write payload size (write-only txs).
const RECORD_WRITE_CHUNK: usize = 900;

/// Inputs for building a confidential transfer bundle.
pub struct ConfidentialTransferParams<'a> {
    /// Token-2022 mint (must have the ConfidentialTransfer extension).
    pub mint: &'a Pubkey,
    /// Recipient wallet (owner of the destination confidential account).
    pub recipient: &'a Pubkey,
    /// Transfer amount in base units.
    pub amount: u64,
    /// Gateway fee-payer pubkey (from `methodDetails.feePayerKey`). Clients hold
    /// no SOL, so the gateway is the fee payer, rent funder, proof/record-account
    /// authority, and close (rent-reclaim) destination for every bundle tx.
    pub fee_payer: &'a Pubkey,
    /// Recent blockhash to sign all bundle transactions with. The gateway must
    /// submit the bundle while this blockhash is still valid.
    pub blockhash: Hash,
}

/// Create a fresh ZK proof context-state account sized for proof type `T`,
/// funded by and authorized to the gateway (`fee_payer`). Returns the ephemeral
/// account keypair and its `[create_account, verify]` instruction pair; the
/// proof-specific verify instruction is built by `make_verify`, which receives
/// the `ContextStateInfo` bound to this account + the gateway authority.
///
/// Returning the instruction pair (rather than a finished tx) lets the range
/// site hand its pair into the record-staging path unchanged — a range helper
/// that built a tx would repack the proof bytes and risk the 1232-byte wire
/// limit.
fn proof_context_pair<T: bytemuck::Pod>(
    rpc: &RpcClient,
    fee_payer: &Pubkey,
    fee_payer_addr: &Address,
    zk_program: &Pubkey,
    make_verify: impl FnOnce(ContextStateInfo) -> Instruction,
) -> Result<(Keypair, [Instruction; 2]), Error> {
    let account = Keypair::new();
    let size = size_of::<ProofContextState<T>>();
    let rent = rpc
        .get_minimum_balance_for_rent_exemption(size)
        .map_err(|e| Error::Rpc(e.to_string()))?;
    let create = system_instruction::create_account(
        fee_payer,
        &account.pubkey(),
        rent,
        size as u64,
        zk_program,
    );
    let ctx_addr = Address::from(account.pubkey().to_bytes());
    let verify = make_verify(ContextStateInfo {
        context_state_account: &ctx_addr,
        context_state_authority: fee_payer_addr,
    });
    Ok((account, [create, verify]))
}

/// Build the ordered, partially-signed transaction bundle for a confidential
/// transfer.
///
/// `signer` is the sender; it signs only the transfer authority and the
/// ephemeral proof/record account keypairs. `params.fee_payer` (the gateway)
/// is the fee payer, rent funder, proof/record authority, and rent-reclaim
/// destination on every transaction — its signature slot is left empty for the
/// gateway to co-sign at settlement. Returns the base64-encoded serialized
/// transactions in submission order.
pub async fn build_confidential_transfer_bundle(
    signer: &dyn SolanaSigner,
    rpc: &RpcClient,
    params: ConfidentialTransferParams<'_>,
) -> Result<Vec<String>, Error> {
    let zk_program = Pubkey::from_str(ZK_PROOF_PROGRAM_ID).expect("valid zk proof program id");
    let token_program = spl_token_2022::id();
    let sender_pubkey = signer.pubkey();
    // The gateway pays, funds, and owns every proof/record account.
    let fee_payer = params.fee_payer;
    let fee_payer_addr = Address::from(fee_payer.to_bytes());

    let sender_token_account =
        spl_associated_token_account::get_associated_token_address_with_program_id(
            &sender_pubkey,
            params.mint,
            &token_program,
        );
    let recipient_token_account =
        spl_associated_token_account::get_associated_token_address_with_program_id(
            params.recipient,
            params.mint,
            &token_program,
        );

    // ----- Recipient ElGamal pubkey (legacy 4.0 → v7 byte-cast) -----
    let recipient_acc = rpc
        .get_account(&recipient_token_account)
        .map_err(|e| Error::Rpc(e.to_string()))?;
    let recipient_state = StateWithExtensions::<TokenAccount>::unpack(&recipient_acc.data)
        .map_err(|e| Error::Other(format!("unpack recipient account: {e}")))?;
    let recipient_ext = recipient_state
        .get_extension::<ConfidentialTransferAccount>()
        .map_err(|e| Error::Other(format!("recipient has no confidential account: {e}")))?;
    let recipient_elgamal: ElGamalPubkey =
        cast_elgamal_pubkey_legacy_to_v7(&recipient_ext.elgamal_pubkey)?
            .try_into()
            .map_err(|e| Error::Other(format!("recipient ElGamal pubkey: {e:?}")))?;

    // ----- Auditor ElGamal pubkey (read from the mint; optional) -----
    // The mint may configure no auditor; `transfer_split_proof_data` accepts
    // `None` and the transfer then carries only source + destination handles.
    let mint_acc = rpc
        .get_account(params.mint)
        .map_err(|e| Error::Rpc(e.to_string()))?;
    let mint_state = StateWithExtensions::<Mint>::unpack(&mint_acc.data)
        .map_err(|e| Error::Other(format!("unpack mint: {e}")))?;
    let mint_ext = mint_state
        .get_extension::<ConfidentialTransferMint>()
        .map_err(|e| Error::Other(format!("mint has no confidential config: {e}")))?;
    let auditor_elgamal: Option<ElGamalPubkey> = {
        let pod_opt: Option<PodElGamalPubkeyLegacy> = mint_ext.auditor_elgamal_pubkey.into();
        match pod_opt {
            Some(pod) => Some(
                cast_elgamal_pubkey_legacy_to_v7(&pod)?
                    .try_into()
                    .map_err(|e| Error::Other(format!("auditor ElGamal pubkey: {e:?}")))?,
            ),
            None => None,
        }
    };

    // ----- Confidential-transfer fee config (optional) -----
    // When the mint carries the confidential-transfer fee extension, Token-2022
    // requires the fee-bearing transfer variant (`TransferWithFee`) with its
    // extra fee proofs — even when the fee rate is zero. Capture the
    // withdraw-withheld authority's ElGamal pubkey and the current epoch's fee.
    let fee_params: Option<(ElGamalPubkey, u16, u64)> =
        match mint_state.get_extension::<ConfidentialTransferFeeConfig>() {
            Ok(fee_ext) => {
                let withdraw_withheld_elgamal: ElGamalPubkey = cast_elgamal_pubkey_legacy_to_v7(
                    &fee_ext.withdraw_withheld_authority_elgamal_pubkey,
                )?
                .try_into()
                .map_err(|e| Error::Other(format!("withdraw-withheld ElGamal pubkey: {e:?}")))?;
                let transfer_fee_config =
                    mint_state
                        .get_extension::<TransferFeeConfig>()
                        .map_err(|e| {
                            Error::Other(format!(
                                "mint has confidential fee config but no transfer-fee config: {e}"
                            ))
                        })?;
                // Fee parameters are read for the *current* epoch and baked into the fee
                // proofs. The on-chain `TransferWithFee` re-derives them at execution time, so a
                // mismatch is possible only when the mint has a *scheduled* fee-schedule change
                // (older vs newer fee) AND the bundle is built in the last epoch before the
                // change but lands after the rollover. That case fails closed — the transfer is
                // rejected, never mis-settled — and is retriable by rebuilding the bundle. For
                // mints without a pending change (`older == newer`, the common case, e.g. USDPT)
                // there is no drift. This matches standard spl-token tooling, which likewise reads
                // the current epoch's fee at build time.
                let epoch = rpc
                    .get_epoch_info()
                    .map_err(|e| Error::Rpc(e.to_string()))?
                    .epoch;
                let epoch_fee = transfer_fee_config.get_epoch_fee(epoch);
                let fee_basis_points: u16 = epoch_fee.transfer_fee_basis_points.into();
                let maximum_fee: u64 = epoch_fee.maximum_fee.into();
                Some((withdraw_withheld_elgamal, fee_basis_points, maximum_fee))
            }
            Err(_) => None,
        };

    // ----- Sender keys + current confidential balance -----
    let sender_keys = derive_confidential_keys(signer, &sender_token_account).await?;
    let sender_acc = rpc
        .get_account(&sender_token_account)
        .map_err(|e| Error::Rpc(e.to_string()))?;
    let sender_state = StateWithExtensions::<TokenAccount>::unpack(&sender_acc.data)
        .map_err(|e| Error::Other(format!("unpack sender account: {e}")))?;
    let sender_ext = sender_state
        .get_extension::<ConfidentialTransferAccount>()
        .map_err(|e| Error::Other(format!("sender has no confidential account: {e}")))?;

    let current_available: ElGamalCiphertext =
        cast_elgamal_ciphertext_legacy_to_v7(&sender_ext.available_balance)?
            .try_into()
            .map_err(|e| Error::Other(format!("sender available balance: {e:?}")))?;
    let current_decryptable: AeCiphertext =
        cast_ae_ciphertext_legacy_to_v7(&sender_ext.decryptable_available_balance)?;

    // ----- Pre-flight: fail fast BEFORE the expensive proof generation -----
    // The recipient must accept incoming confidential credits, the sender's
    // account must be approved to transact, and the sender must hold enough
    // confidential balance. (Without these, the bundle would build, generate
    // proofs, and only fail on-chain — or fail late at the subtract below.)
    if !bool::from(recipient_ext.allow_confidential_credits) {
        return Err(Error::Other(
            "recipient does not allow confidential credits".into(),
        ));
    }
    if !bool::from(sender_ext.approved) {
        return Err(Error::Other(
            "sender confidential account is not approved by the mint".into(),
        ));
    }
    let current_plaintext = current_decryptable
        .decrypt(&sender_keys.ae)
        .ok_or_else(|| Error::Other("failed to decrypt sender confidential balance".into()))?;
    let new_plaintext = current_plaintext
        .checked_sub(params.amount)
        .ok_or_else(|| {
            Error::Other(format!(
                "insufficient confidential balance: have {current_plaintext}, need {} base units",
                params.amount
            ))
        })?;

    // Fee-bearing mints (e.g. USDPT) require the `TransferWithFee` variant with
    // its additional fee proofs; delegate to the dedicated builder.
    if let Some((withdraw_withheld_elgamal, fee_basis_points, maximum_fee)) = fee_params {
        return build_confidential_transfer_with_fee_bundle(
            signer,
            rpc,
            &params,
            &sender_token_account,
            &recipient_token_account,
            &token_program,
            &zk_program,
            &sender_keys,
            &current_available,
            &current_decryptable,
            new_plaintext,
            &recipient_elgamal,
            auditor_elgamal.as_ref(),
            &withdraw_withheld_elgamal,
            fee_basis_points,
            maximum_fee,
        )
        .await;
    }

    // ----- Generate the three split-transfer proofs (zk-sdk 7.0.1) -----
    let proof_data = transfer_split_proof_data(
        &current_available,
        &current_decryptable,
        params.amount,
        &sender_keys.elgamal,
        &sender_keys.ae,
        &recipient_elgamal,
        auditor_elgamal.as_ref(),
    )
    .map_err(|e| Error::Other(format!("transfer_split_proof_data: {e}")))?;

    let mut bundle: Vec<String> = Vec::new();

    // ----- 1. Equality proof context account -----
    let (equality_account, equality_ixs) =
        proof_context_pair::<CiphertextCommitmentEqualityProofContext>(
            rpc,
            fee_payer,
            &fee_payer_addr,
            &zk_program,
            |ctx| {
                ProofInstruction::VerifyCiphertextCommitmentEquality
                    .encode_verify_proof(Some(ctx), &proof_data.equality_proof_data)
            },
        )?;
    bundle.push(
        partial_sign_tx(
            signer,
            fee_payer,
            &[&equality_account],
            &equality_ixs,
            params.blockhash,
        )
        .await?,
    );

    // ----- 2. Ciphertext-validity proof context account -----
    let (validity_account, validity_ixs) = proof_context_pair::<
        BatchedGroupedCiphertext3HandlesValidityProofContext,
    >(
        rpc,
        fee_payer,
        &fee_payer_addr,
        &zk_program,
        |ctx| {
            ProofInstruction::VerifyBatchedGroupedCiphertext3HandlesValidity.encode_verify_proof(
                Some(ctx),
                &proof_data
                    .ciphertext_validity_proof_data_with_ciphertext
                    .proof_data,
            )
        },
    )?;
    bundle.push(
        partial_sign_tx(
            signer,
            fee_payer,
            &[&validity_account],
            &validity_ixs,
            params.blockhash,
        )
        .await?,
    );

    // ----- 3. Range proof: stage into an spl-record account, verify from it -----
    let record_account = Keypair::new();
    let (range_account, range_ixs) = proof_context_pair::<BatchedRangeProofContext>(
        rpc,
        fee_payer,
        &fee_payer_addr,
        &zk_program,
        |ctx| {
            ProofInstruction::VerifyBatchedRangeProofU128.encode_verify_proof_from_account(
                Some(ctx),
                &Address::from(record_account.pubkey().to_bytes()),
                RECORD_PROOF_OFFSET,
            )
        },
    )?;
    let proof_bytes = bytemuck::bytes_of(&proof_data.range_proof_data);
    let mut record_txs = stage_range_proof_record(
        signer,
        rpc,
        fee_payer,
        &record_account,
        proof_bytes,
        &range_ixs,
        &[&range_account],
        params.blockhash,
    )
    .await?;
    bundle.append(&mut record_txs);

    // ----- 4. Transfer + close all proof/record accounts -----
    // `new_plaintext` was computed during pre-flight, above.
    let new_decryptable = sender_keys.ae.encrypt(new_plaintext);
    let new_decryptable_legacy = cast_ae_ciphertext_v7_to_legacy(&new_decryptable);

    let auditor_lo_legacy = cast_elgamal_ciphertext_v7_to_legacy(
        &proof_data
            .ciphertext_validity_proof_data_with_ciphertext
            .ciphertext_lo,
    );
    let auditor_hi_legacy = cast_elgamal_ciphertext_v7_to_legacy(
        &proof_data
            .ciphertext_validity_proof_data_with_ciphertext
            .ciphertext_hi,
    );

    let transfer_ix = inner_transfer(
        &token_program,
        &sender_token_account,
        params.mint,
        &recipient_token_account,
        &new_decryptable_legacy,
        &auditor_lo_legacy,
        &auditor_hi_legacy,
        &sender_pubkey,
        &[],
        ProofLocation::ContextStateAccount(&equality_account.pubkey()),
        ProofLocation::ContextStateAccount(&validity_account.pubkey()),
        ProofLocation::ContextStateAccount(&range_account.pubkey()),
    )
    .map_err(|e| Error::Other(format!("build transfer instruction: {e}")))?;

    // Close every proof/record account back to the gateway (it funded the rent
    // and is the authority), so net rent ≈ 0 and the gateway can also sweep
    // orphans after a partial failure.
    let close = |ctx: &Pubkey| {
        close_context_state(
            ContextStateInfo {
                context_state_account: &Address::from(ctx.to_bytes()),
                context_state_authority: &fee_payer_addr,
            },
            &fee_payer_addr,
        )
    };
    // Request a CU limit up front: the confidential transfer + in-tx closes
    // exceed the 200k default, so without this the gateway's simulation step
    // would reject the bundle (or validators would drop it on mainnet).
    let compute_budget_program =
        Pubkey::from_str(COMPUTE_BUDGET_PROGRAM_ID).expect("valid compute budget program id");
    let mut cu_limit_data = vec![2u8]; // SetComputeUnitLimit
    cu_limit_data.extend_from_slice(&CONFIDENTIAL_TRANSFER_COMPUTE_UNIT_LIMIT.to_le_bytes());
    let cu_limit_ix = Instruction {
        program_id: compute_budget_program,
        accounts: vec![],
        data: cu_limit_data,
    };
    let final_ixs = vec![
        cu_limit_ix,
        transfer_ix,
        close(&equality_account.pubkey()),
        close(&validity_account.pubkey()),
        close(&range_account.pubkey()),
        spl_record::instruction::close_account(&record_account.pubkey(), fee_payer, fee_payer),
    ];
    bundle.push(partial_sign_tx(signer, fee_payer, &[], &final_ixs, params.blockhash).await?);

    Ok(bundle)
}

/// Build the confidential transfer bundle for a fee-bearing mint, using the
/// Token-2022 `TransferWithFee` variant. This needs five split proofs (equality,
/// transfer-amount validity, fee sigma / percentage-with-cap, fee validity, and
/// a U256 range proof) versus three for the plain transfer.
#[allow(clippy::too_many_arguments)]
async fn build_confidential_transfer_with_fee_bundle(
    signer: &dyn SolanaSigner,
    rpc: &RpcClient,
    params: &ConfidentialTransferParams<'_>,
    sender_token_account: &Pubkey,
    recipient_token_account: &Pubkey,
    token_program: &Pubkey,
    zk_program: &Pubkey,
    sender_keys: &ConfidentialKeys,
    current_available: &ElGamalCiphertext,
    current_decryptable: &AeCiphertext,
    new_plaintext: u64,
    recipient_elgamal: &ElGamalPubkey,
    auditor_elgamal: Option<&ElGamalPubkey>,
    withdraw_withheld_elgamal: &ElGamalPubkey,
    fee_basis_points: u16,
    maximum_fee: u64,
) -> Result<Vec<String>, Error> {
    let fee_payer = params.fee_payer;
    let fee_payer_addr = Address::from(fee_payer.to_bytes());
    let sender_pubkey = signer.pubkey();

    // ----- Generate the five split transfer-with-fee proofs (zk-sdk 7.0.1) -----
    let proof_data = transfer_with_fee_split_proof_data(
        current_available,
        current_decryptable,
        params.amount,
        &sender_keys.elgamal,
        &sender_keys.ae,
        recipient_elgamal,
        auditor_elgamal,
        withdraw_withheld_elgamal,
        fee_basis_points,
        maximum_fee,
    )
    .map_err(|e| Error::Other(format!("transfer_with_fee_split_proof_data: {e}")))?;

    let mut bundle: Vec<String> = Vec::new();

    // ----- 1. Equality proof context account -----
    let (equality_account, equality_ixs) =
        proof_context_pair::<CiphertextCommitmentEqualityProofContext>(
            rpc,
            fee_payer,
            &fee_payer_addr,
            zk_program,
            |ctx| {
                ProofInstruction::VerifyCiphertextCommitmentEquality
                    .encode_verify_proof(Some(ctx), &proof_data.equality_proof_data)
            },
        )?;
    bundle.push(
        partial_sign_tx(
            signer,
            fee_payer,
            &[&equality_account],
            &equality_ixs,
            params.blockhash,
        )
        .await?,
    );

    // ----- 2. Transfer-amount ciphertext-validity proof (3 handles) -----
    let (validity_account, validity_ixs) = proof_context_pair::<
        BatchedGroupedCiphertext3HandlesValidityProofContext,
    >(
        rpc,
        fee_payer,
        &fee_payer_addr,
        zk_program,
        |ctx| {
            ProofInstruction::VerifyBatchedGroupedCiphertext3HandlesValidity.encode_verify_proof(
                Some(ctx),
                &proof_data
                    .transfer_amount_ciphertext_validity_proof_data_with_ciphertext
                    .proof_data,
            )
        },
    )?;
    bundle.push(
        partial_sign_tx(
            signer,
            fee_payer,
            &[&validity_account],
            &validity_ixs,
            params.blockhash,
        )
        .await?,
    );

    // ----- 3. Fee sigma (percentage-with-cap) proof -----
    let (fee_sigma_account, fee_sigma_ixs) = proof_context_pair::<PercentageWithCapProofContext>(
        rpc,
        fee_payer,
        &fee_payer_addr,
        zk_program,
        |ctx| {
            ProofInstruction::VerifyPercentageWithCap
                .encode_verify_proof(Some(ctx), &proof_data.percentage_with_cap_proof_data)
        },
    )?;
    bundle.push(
        partial_sign_tx(
            signer,
            fee_payer,
            &[&fee_sigma_account],
            &fee_sigma_ixs,
            params.blockhash,
        )
        .await?,
    );

    // ----- 4. Fee ciphertext-validity proof (2 handles) -----
    let (fee_validity_account, fee_validity_ixs) =
        proof_context_pair::<BatchedGroupedCiphertext2HandlesValidityProofContext>(
            rpc,
            fee_payer,
            &fee_payer_addr,
            zk_program,
            |ctx| {
                ProofInstruction::VerifyBatchedGroupedCiphertext2HandlesValidity
                    .encode_verify_proof(Some(ctx), &proof_data.fee_ciphertext_validity_proof_data)
            },
        )?;
    bundle.push(
        partial_sign_tx(
            signer,
            fee_payer,
            &[&fee_validity_account],
            &fee_validity_ixs,
            params.blockhash,
        )
        .await?,
    );

    // ----- 5. Range proof (U256): stage into an spl-record account -----
    let record_account = Keypair::new();
    let (range_account, range_ixs) = proof_context_pair::<BatchedRangeProofContext>(
        rpc,
        fee_payer,
        &fee_payer_addr,
        zk_program,
        |ctx| {
            ProofInstruction::VerifyBatchedRangeProofU256.encode_verify_proof_from_account(
                Some(ctx),
                &Address::from(record_account.pubkey().to_bytes()),
                RECORD_PROOF_OFFSET,
            )
        },
    )?;
    let proof_bytes = bytemuck::bytes_of(&proof_data.range_proof_data);
    let mut record_txs = stage_range_proof_record(
        signer,
        rpc,
        fee_payer,
        &record_account,
        proof_bytes,
        &range_ixs,
        &[&range_account],
        params.blockhash,
    )
    .await?;
    bundle.append(&mut record_txs);

    // ----- 6. TransferWithFee + close all proof/record accounts -----
    let new_decryptable = sender_keys.ae.encrypt(new_plaintext);
    let new_decryptable_legacy = cast_ae_ciphertext_v7_to_legacy(&new_decryptable);
    let auditor_lo_legacy = cast_elgamal_ciphertext_v7_to_legacy(
        &proof_data
            .transfer_amount_ciphertext_validity_proof_data_with_ciphertext
            .ciphertext_lo,
    );
    let auditor_hi_legacy = cast_elgamal_ciphertext_v7_to_legacy(
        &proof_data
            .transfer_amount_ciphertext_validity_proof_data_with_ciphertext
            .ciphertext_hi,
    );

    let transfer_ix = inner_transfer_with_fee(
        token_program,
        sender_token_account,
        params.mint,
        recipient_token_account,
        &new_decryptable_legacy,
        &auditor_lo_legacy,
        &auditor_hi_legacy,
        &sender_pubkey,
        &[],
        ProofLocation::ContextStateAccount(&equality_account.pubkey()),
        ProofLocation::ContextStateAccount(&validity_account.pubkey()),
        ProofLocation::ContextStateAccount(&fee_sigma_account.pubkey()),
        ProofLocation::ContextStateAccount(&fee_validity_account.pubkey()),
        ProofLocation::ContextStateAccount(&range_account.pubkey()),
    )
    .map_err(|e| Error::Other(format!("build transfer_with_fee instruction: {e}")))?;

    let close = |ctx: &Pubkey| {
        close_context_state(
            ContextStateInfo {
                context_state_account: &Address::from(ctx.to_bytes()),
                context_state_authority: &fee_payer_addr,
            },
            &fee_payer_addr,
        )
    };
    let compute_budget_program =
        Pubkey::from_str(COMPUTE_BUDGET_PROGRAM_ID).expect("valid compute budget program id");
    let mut cu_limit_data = vec![2u8]; // SetComputeUnitLimit
    cu_limit_data.extend_from_slice(&CONFIDENTIAL_TRANSFER_COMPUTE_UNIT_LIMIT.to_le_bytes());
    let cu_limit_ix = Instruction {
        program_id: compute_budget_program,
        accounts: vec![],
        data: cu_limit_data,
    };
    let final_ixs = vec![
        cu_limit_ix,
        transfer_ix,
        close(&equality_account.pubkey()),
        close(&validity_account.pubkey()),
        close(&fee_sigma_account.pubkey()),
        close(&fee_validity_account.pubkey()),
        close(&range_account.pubkey()),
        spl_record::instruction::close_account(&record_account.pubkey(), fee_payer, fee_payer),
    ];
    bundle.push(partial_sign_tx(signer, fee_payer, &[], &final_ixs, params.blockhash).await?);

    Ok(bundle)
}

/// Charge-path adapter: build the confidential transfer bundle and wrap it as a
/// `CredentialPayload::Bundle`. Called from the charge credential builder when
/// `methodDetails.confidential` is set.
pub(crate) async fn confidential_charge_payload(
    signer: &dyn SolanaSigner,
    rpc: &RpcClient,
    amount: u64,
    mint: &str,
    recipient: &str,
    fee_payer: &Pubkey,
    blockhash: Hash,
) -> Result<CredentialPayload, Error> {
    let mint_pk =
        Pubkey::from_str(mint).map_err(|e| Error::Other(format!("invalid mint `{mint}`: {e}")))?;
    let recipient_pk = Pubkey::from_str(recipient)
        .map_err(|e| Error::Other(format!("invalid recipient `{recipient}`: {e}")))?;
    let transactions = build_confidential_transfer_bundle(
        signer,
        rpc,
        ConfidentialTransferParams {
            mint: &mint_pk,
            recipient: &recipient_pk,
            amount,
            fee_payer,
            blockhash,
        },
    )
    .await?;
    Ok(CredentialPayload::Bundle { transactions })
}

/// Stage `proof_bytes` into a fresh spl-record account in tx-sized chunks. The
/// first tx creates + initializes + writes the first chunk; the final write tx
/// carries `trailing_ixs` (with `trailing_signers`) so the range context's
/// create-and-verify-from-account ride along. `payer` (the gateway) is the rent
/// funder and record authority, so the gateway co-signs each write at settlement.
/// Returns one partially-signed tx per transaction.
#[allow(clippy::too_many_arguments)]
async fn stage_range_proof_record(
    signer: &dyn SolanaSigner,
    rpc: &RpcClient,
    payer: &Pubkey,
    record_account: &Keypair,
    proof_bytes: &[u8],
    trailing_ixs: &[Instruction],
    trailing_signers: &[&Keypair],
    blockhash: Hash,
) -> Result<Vec<String>, Error> {
    if proof_bytes.is_empty() {
        return Err(Error::Other("range proof had no bytes to stage".into()));
    }
    let space = proof_bytes.len() + RECORD_PROOF_OFFSET as usize;
    let rent = rpc
        .get_minimum_balance_for_rent_exemption(space)
        .map_err(|e| Error::Rpc(e.to_string()))?;

    let first_len = proof_bytes.len().min(RECORD_FIRST_CHUNK);
    let (first, rest) = proof_bytes.split_at(first_len);

    let mut txs = Vec::new();
    let mut offset = 0u64;

    // tx 1: create + initialize + write first chunk.
    txs.push(
        partial_sign_tx(
            signer,
            payer,
            &[record_account],
            &[
                system_instruction::create_account(
                    payer,
                    &record_account.pubkey(),
                    rent,
                    space as u64,
                    &spl_record::id(),
                ),
                spl_record::instruction::initialize(&record_account.pubkey(), payer),
                spl_record::instruction::write(&record_account.pubkey(), payer, 0, first),
            ],
            blockhash,
        )
        .await?,
    );
    offset += first.len() as u64;

    // Remaining chunks are write-only; the trailing ixs ride the last one.
    let mut chunks = rest.chunks(RECORD_WRITE_CHUNK).peekable();
    let mut trailing_attached = false;
    while let Some(chunk) = chunks.next() {
        let mut ixs = vec![spl_record::instruction::write(
            &record_account.pubkey(),
            payer,
            offset,
            chunk,
        )];
        let mut extra: Vec<&Keypair> = Vec::new();
        if chunks.peek().is_none() {
            ixs.extend_from_slice(trailing_ixs);
            extra.extend_from_slice(trailing_signers);
            trailing_attached = true;
        }
        txs.push(partial_sign_tx(signer, payer, &extra, &ixs, blockhash).await?);
        offset += chunk.len() as u64;
    }

    // Single-chunk proof: no write-only tx existed to carry the trailing ixs.
    if !trailing_attached {
        txs.push(partial_sign_tx(signer, payer, trailing_signers, trailing_ixs, blockhash).await?);
    }

    Ok(txs)
}

/// Build a transaction with `fee_payer` (the gateway) as fee payer and
/// partially sign it with the client-held keys only: the sender `signer` when
/// it is a required signer on this tx (e.g. the transfer authority) and any
/// `extra` ephemeral account keypairs. The gateway fee-payer signature slot is
/// left empty (all-zero) for the gateway to co-sign at settlement. Returns the
/// base64-encoded serialized partially-signed transaction.
async fn partial_sign_tx(
    signer: &dyn SolanaSigner,
    fee_payer: &Pubkey,
    extra: &[&Keypair],
    instructions: &[Instruction],
    blockhash: Hash,
) -> Result<String, Error> {
    use solana_transaction::Transaction;
    let message = Message::new_with_blockhash(instructions, Some(fee_payer), &blockhash);
    let mut tx = Transaction::new_unsigned(message);

    // Sign the sender slot only when the sender is a required signer on this tx
    // (the final transfer's authority). The proof/record-account txs have no
    // sender signer — only the gateway (fee payer/authority) and the ephemeral
    // account. Never sign the gateway slot; the gateway co-signs at settlement.
    let sender_pubkey = signer.pubkey();
    let num_signers = tx.message.header.num_required_signatures as usize;
    if tx.message.account_keys[..num_signers].contains(&sender_pubkey) {
        signer
            .sign_transaction(&mut tx)
            .await
            .map_err(|e| Error::Other(format!("signing failed: {e}")))?;
    }

    // Ephemeral account keypairs sign synchronously.
    let msg = tx.message_data();
    for kp in extra {
        set_signature(&mut tx, &kp.pubkey(), kp.sign_message(&msg))?;
    }

    let serialized =
        bincode::serialize(&tx).map_err(|e| Error::Other(format!("serialize tx: {e}")))?;
    Ok(base64::engine::general_purpose::STANDARD.encode(serialized))
}

fn set_signature(
    tx: &mut solana_transaction::Transaction,
    pubkey: &Pubkey,
    sig: Signature,
) -> Result<(), Error> {
    let idx = tx
        .message
        .account_keys
        .iter()
        .position(|k| k == pubkey)
        .ok_or_else(|| Error::Other(format!("signer {pubkey} not in transaction accounts")))?;
    tx.signatures[idx] = sig;
    Ok(())
}

// ---------------------------------------------------------------------------
// POD byte-casts across the zk-sdk 4.0 (token-2022 ABI) ↔ 7.0.1 (proof gen)
// boundary. The wire format of these fixed-size types is identical; the Rust
// types are just version-tagged wrappers.
//
// This is the single canonical copy of these casts — the `protocol::confidential`
// litesvm tests call these (rather than re-deriving them) so a future zk-sdk
// bump can't fix prod while leaving a stale test cast green. (The separate
// integration-test crate keeps its own copy, as it cannot see `pub(crate)`.)
// ---------------------------------------------------------------------------

pub(crate) fn cast_elgamal_pubkey_legacy_to_v7(
    legacy: &PodElGamalPubkeyLegacy,
) -> Result<PodElGamalPubkeyV7, Error> {
    let bytes: [u8; 32] = bytemuck::bytes_of(legacy)
        .try_into()
        .map_err(|_| Error::Other("PodElGamalPubkey size".into()))?;
    Ok(PodElGamalPubkeyV7(bytes))
}

pub(crate) fn cast_elgamal_ciphertext_legacy_to_v7(
    legacy: &PodElGamalCiphertextLegacy,
) -> Result<PodElGamalCiphertextV7, Error> {
    let bytes: [u8; 64] = bytemuck::bytes_of(legacy)
        .try_into()
        .map_err(|_| Error::Other("PodElGamalCiphertext size".into()))?;
    Ok(PodElGamalCiphertextV7(bytes))
}

pub(crate) fn cast_elgamal_ciphertext_v7_to_legacy(
    v7: &PodElGamalCiphertextV7,
) -> PodElGamalCiphertextLegacy {
    PodElGamalCiphertextLegacy::from(v7.0)
}

pub(crate) fn cast_ae_ciphertext_legacy_to_v7(
    legacy: &PodAeCiphertextLegacy,
) -> Result<AeCiphertext, Error> {
    let bytes: [u8; 36] = bytemuck::bytes_of(legacy)
        .try_into()
        .map_err(|_| Error::Other("PodAeCiphertext size".into()))?;
    AeCiphertext::from_bytes(&bytes).ok_or_else(|| Error::Other("decode AeCiphertext".into()))
}

pub(crate) fn cast_ae_ciphertext_v7_to_legacy(v7: &AeCiphertext) -> PodAeCiphertextLegacy {
    PodAeCiphertextLegacy::from(v7.to_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use solana_keychain::{SignTransactionResult, SignerError};
    use solana_zk_sdk::encryption::auth_encryption::AeKey;

    fn memory_signer(seed: u8) -> Box<dyn SolanaSigner> {
        let sk = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
        let mut kp = [0u8; 64];
        kp[..32].copy_from_slice(sk.as_bytes());
        kp[32..].copy_from_slice(sk.verifying_key().as_bytes());
        Box::new(solana_keychain::MemorySigner::from_bytes(&kp).expect("valid keypair"))
    }

    struct TransactionOnlySigner(Pubkey);

    #[async_trait]
    impl SolanaSigner for TransactionOnlySigner {
        fn pubkey(&self) -> Pubkey {
            self.0
        }

        async fn sign_transaction(
            &self,
            tx: &mut solana_transaction::Transaction,
        ) -> std::result::Result<SignTransactionResult, SignerError> {
            let index = tx
                .message
                .account_keys
                .iter()
                .position(|key| key == &self.0)
                .ok_or_else(|| SignerError::Other("missing signer".into()))?;
            let signature = Signature::from([7u8; 64]);
            tx.signatures[index] = signature;
            Ok(SignTransactionResult::Partial((String::new(), signature)))
        }

        async fn sign_message(
            &self,
            _message: &[u8],
        ) -> std::result::Result<Signature, SignerError> {
            Err(SignerError::Other(
                "transaction bytes used the off-chain signing path".into(),
            ))
        }

        async fn is_available(&self) -> bool {
            true
        }
    }

    fn decode_tx(b64: &str) -> solana_transaction::Transaction {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(b64)
            .unwrap();
        bincode::deserialize(&bytes).unwrap()
    }

    #[test]
    fn elgamal_pubkey_cast_preserves_bytes() {
        let legacy = PodElGamalPubkeyLegacy::from([7u8; 32]);
        let v7 = cast_elgamal_pubkey_legacy_to_v7(&legacy).unwrap();
        assert_eq!(v7.0, [7u8; 32]);
    }

    #[test]
    fn elgamal_ciphertext_cast_round_trips() {
        let legacy = PodElGamalCiphertextLegacy::from([3u8; 64]);
        let v7 = cast_elgamal_ciphertext_legacy_to_v7(&legacy).unwrap();
        assert_eq!(v7.0, [3u8; 64]);
        let back = cast_elgamal_ciphertext_v7_to_legacy(&v7);
        assert_eq!(bytemuck::bytes_of(&back), &[3u8; 64]);
    }

    #[test]
    fn ae_ciphertext_cast_round_trips() {
        let ae = AeKey::new_rand();
        let v7 = ae.encrypt(42u64);
        let legacy = cast_ae_ciphertext_v7_to_legacy(&v7);
        let back = cast_ae_ciphertext_legacy_to_v7(&legacy).unwrap();
        assert_eq!(back.decrypt(&ae), Some(42));
    }

    // partial_sign_tx must leave the gateway (fee-payer) slot empty for the
    // gateway to co-sign, while signing the client-held keys.

    #[tokio::test]
    async fn partial_sign_leaves_gateway_unsigned_signs_ephemeral() {
        let signer = memory_signer(1);
        let gateway = memory_signer(2).pubkey();
        let eph = Keypair::new();
        let ix = system_instruction::create_account(
            &gateway,
            &eph.pubkey(),
            1000,
            100,
            &Pubkey::new_unique(),
        );
        let b64 = partial_sign_tx(signer.as_ref(), &gateway, &[&eph], &[ix], Hash::default())
            .await
            .unwrap();
        let tx = decode_tx(&b64);
        let keys = &tx.message.account_keys;

        // Gateway is fee payer (index 0) and MUST be left unsigned.
        let gw = keys.iter().position(|k| *k == gateway).unwrap();
        assert_eq!(tx.signatures[gw], Signature::default());
        // Ephemeral account signed; sender isn't even a signer here.
        let e = keys.iter().position(|k| *k == eph.pubkey()).unwrap();
        assert_ne!(tx.signatures[e], Signature::default());
        assert!(!keys.iter().any(|k| *k == signer.pubkey()));
    }

    #[tokio::test]
    async fn partial_sign_signs_sender_when_it_is_a_required_signer() {
        let signer = TransactionOnlySigner(Pubkey::new_unique());
        let sender = signer.pubkey();
        let gateway = Pubkey::new_unique();
        // Transfer makes `sender` a required signer; gateway is the fee payer.
        let ix = system_instruction::transfer(&sender, &gateway, 1);
        let b64 = partial_sign_tx(&signer, &gateway, &[], &[ix], Hash::default())
            .await
            .unwrap();
        let tx = decode_tx(&b64);
        let keys = &tx.message.account_keys;

        let gw = keys.iter().position(|k| *k == gateway).unwrap();
        assert_eq!(tx.signatures[gw], Signature::default());
        let s = keys.iter().position(|k| *k == sender).unwrap();
        assert_eq!(tx.signatures[s], Signature::from([7u8; 64]));
    }
}
