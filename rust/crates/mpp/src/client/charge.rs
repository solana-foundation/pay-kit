use solana_hash::Hash;
use solana_instruction::{AccountMeta, Instruction};
use solana_keychain::SolanaSigner;
use solana_message::Message;
use solana_pubkey::Pubkey;
use solana_rpc_client::rpc_client::RpcClient;
use solana_signature::Signature;
use solana_system_interface::instruction as system_instruction;
use solana_transaction::Transaction;
use std::str::FromStr;

use crate::error::Error;
use crate::protocol::core::{
    format_authorization, parse_www_authenticate, PaymentChallenge, PaymentCredential,
};
use crate::protocol::intents::ChargeRequest;
use crate::protocol::solana::{programs, CredentialPayload, MethodDetails, Split, MAX_MEMO_BYTES};

/// Build a charge transaction from challenge parameters.
///
/// Returns a `CredentialPayload::Transaction` with the signed (or
/// partially signed) transaction ready to send to the server.
pub async fn build_charge_transaction(
    signer: &dyn SolanaSigner,
    rpc: &RpcClient,
    amount: &str,
    currency: &str,
    recipient: &str,
    method_details: &MethodDetails,
) -> Result<CredentialPayload, Error> {
    build_charge_transaction_with_options(
        signer,
        rpc,
        amount,
        currency,
        recipient,
        method_details,
        BuildChargeTransactionOptions::default(),
    )
    .await
}

/// Options for building a Solana charge transaction.
#[derive(Debug, Clone, Default)]
pub struct BuildChargeTransactionOptions {
    /// Optional root payment memo. Spec-aligned callers pass `ChargeRequest.externalId`.
    pub external_id: Option<String>,
    /// Opt-in: sign for an unknown Token-2022 mint.
    ///
    /// Token-2022 supports transfer hooks that run arbitrary program code on
    /// every transfer. We refuse to sign for mints outside the known
    /// stablecoin allowlist when they live on Token-2022 unless the caller
    /// explicitly accepts that risk by setting this flag. The vanilla Token
    /// Program has no hooks, so arbitrary mints there are always allowed.
    pub allow_unknown_token_2022: bool,
    /// Audit #10: client-side cap on what the wallet will sign.
    ///
    /// When set, the builder refuses to sign a challenge whose `amount`
    /// (in base units) exceeds this value. Intended for auto-pay
    /// integrations where the user can't review each challenge by hand
    /// and the server is therefore implicitly untrusted.
    pub max_amount_base_units: Option<u64>,
    /// Audit #10: client-side pin on the network the wallet will sign for.
    ///
    /// When set, the builder refuses to sign a challenge whose
    /// `methodDetails.network` does not match this value. Prevents an
    /// auto-pay agent meant for one network from being lured into
    /// signing a transaction for another.
    pub expected_network: Option<String>,
}

/// Options for selecting one Solana charge challenge from a challenge set.
#[derive(Debug, Clone, Copy, Default)]
pub struct SelectChargeChallengeOptions<'a> {
    /// Currency symbol or mint address the client wants to pay with.
    ///
    /// Audit #14: this is the *fallback* preference — if
    /// `currency_preferences` is non-empty it takes priority and this
    /// field is ignored. Set one or the other, not both.
    pub currency: Option<&'a str>,
    /// Currency symbols or mint addresses in client preference order.
    ///
    /// Audit #14: when non-empty, takes priority over `currency`.
    pub currency_preferences: &'a [&'a str],
    /// Solana network identifier, one of "mainnet", "devnet", or "localnet"
    /// (spec §7.2). The legacy "mainnet-beta" name is the RPC hostname, not
    /// a canonical slug.
    pub network: Option<&'a str>,
    /// Opt-in: select challenges whose currency is an unknown Token-2022 mint.
    /// See `BuildChargeTransactionOptions::allow_unknown_token_2022` for the
    /// underlying threat model. Default `false` — unknown Token-2022
    /// challenges (and challenges whose token program we can't determine
    /// from `methodDetails`) are skipped.
    pub allow_unknown_token_2022: bool,
}

/// Build a charge transaction from challenge parameters and additional client options.
/// Resolve the blockhash to sign with: prefer the server-provided
/// `recentBlockhash`, else fetch one at `confirmed` commitment.
///
/// Audit #36: ask for `confirmed` explicitly instead of leaning on the RPC
/// client's default commitment. Solana's client guidance recommends
/// `confirmed` for blockhash fetches — a `processed` hash can disappear under
/// reorgs and produce signed transactions that fail with BlockhashNotFound.
fn resolve_blockhash(rpc: &RpcClient, method_details: &MethodDetails) -> Result<Hash, Error> {
    if let Some(bh) = &method_details.recent_blockhash {
        Hash::from_str(bh).map_err(|e| Error::Other(format!("Invalid blockhash: {e}")))
    } else {
        use solana_commitment_config::CommitmentConfig;
        rpc.get_latest_blockhash_with_commitment(CommitmentConfig::confirmed())
            .map(|(hash, _last_valid_block_height)| hash)
            .map_err(|e| Error::Rpc(e.to_string()))
    }
}

pub async fn build_charge_transaction_with_options(
    signer: &dyn SolanaSigner,
    rpc: &RpcClient,
    amount: &str,
    currency: &str,
    recipient: &str,
    method_details: &MethodDetails,
    options: BuildChargeTransactionOptions,
) -> Result<CredentialPayload, Error> {
    let total_amount: u64 = amount
        .parse()
        .map_err(|_| Error::Other(format!("Invalid amount: {amount}")))?;

    // Audit #10: client-side policy gates. Run before any signing work so
    // we never produce a signature for an out-of-policy challenge.
    if let Some(cap) = options.max_amount_base_units {
        if total_amount > cap {
            return Err(Error::Other(format!(
                "Challenge amount {total_amount} exceeds client max_amount_base_units {cap}"
            )));
        }
    }
    if let Some(expected) = options.expected_network.as_deref() {
        let actual = method_details.network.as_deref().unwrap_or("");
        if actual != expected {
            return Err(Error::Other(format!(
                "Challenge network `{actual}` does not match client expected_network `{expected}`"
            )));
        }
    }

    // Confidential charges settle via an encrypted, multi-transaction bundle,
    // not the plaintext transfer this function builds. Validate the spec
    // constraints first (Token-2022, no splits; auditor optional — read from the
    // mint, only rejected if a present hint is empty), then branch to the
    // confidential bundle builder. We MUST NOT silently settle a confidential
    // charge as a cleartext transfer.
    crate::protocol::solana::validate_confidential_charge(currency, method_details)?;
    if method_details.confidential.unwrap_or(false) {
        #[cfg(feature = "confidential")]
        {
            // Clients hold no SOL, so confidential bundles are gateway-paid: the
            // challenge MUST carry the gateway fee-payer key, which becomes the
            // fee payer, rent funder, and proof/record-account authority for
            // every bundle transaction (the client only signs the transfer
            // authority and the ephemeral account keypairs).
            let fee_payer_key = method_details.fee_payer_key.as_deref().ok_or_else(|| {
                Error::InvalidConfig(
                    "confidential charges require feePayerKey (the gateway pays bundle fees)"
                        .into(),
                )
            })?;
            let fee_payer = Pubkey::from_str(fee_payer_key)
                .map_err(|e| Error::Other(format!("invalid feePayerKey `{fee_payer_key}`: {e}")))?;
            // Resolve a currency SYMBOL (e.g. "USDPT") to its mint address, the
            // same way the non-confidential path does — the bundle builder feeds
            // this straight to Pubkey::from_str, so a bare symbol would fail.
            // SOL (resolve_mint -> None) is already rejected by
            // validate_confidential_charge above; guard defensively anyway.
            let mint =
                resolve_mint(currency, method_details.network.as_deref()).ok_or_else(|| {
                    Error::InvalidConfig(
                        "confidential transfers require an SPL Token-2022 mint, not native SOL"
                            .into(),
                    )
                })?;
            let blockhash = resolve_blockhash(rpc, method_details)?;
            return super::confidential::confidential_charge_payload(
                signer,
                rpc,
                total_amount,
                mint,
                recipient,
                &fee_payer,
                blockhash,
            )
            .await;
        }
        #[cfg(not(feature = "confidential"))]
        {
            return Err(Error::Other(
                "Confidential-transfer charges require the `confidential` feature \
                 to be enabled in this build"
                    .into(),
            ));
        }
    }

    let splits = method_details.splits.as_deref().unwrap_or(&[]);
    if splits.len() > crate::protocol::solana::MAX_SPLITS {
        return Err(Error::TooManySplits);
    }

    let splits_total = crate::protocol::solana::checked_sum_split_amounts(splits)
        .ok_or(Error::SplitsExceedAmount)?;
    let primary_amount = total_amount
        .checked_sub(splits_total)
        .ok_or(Error::SplitsExceedAmount)?;
    if primary_amount == 0 {
        return Err(Error::SplitsExceedAmount);
    }

    let signer_pubkey = signer.pubkey();

    let recipient_pubkey =
        Pubkey::from_str(recipient).map_err(|e| Error::Other(format!("Invalid recipient: {e}")))?;

    let use_fee_payer =
        method_details.fee_payer.unwrap_or(false) && method_details.fee_payer_key.is_some();

    let fee_payer_pubkey = if use_fee_payer {
        let key = method_details.fee_payer_key.as_ref().unwrap();
        Some(Pubkey::from_str(key).map_err(|e| Error::Other(format!("Invalid fee payer: {e}")))?)
    } else {
        None
    };

    let mut instructions = Vec::new();

    // Compute budget.
    instructions.push(compute_unit_price_ix(1));
    instructions.push(compute_unit_limit_ix(200_000));

    let mint = resolve_mint(currency, method_details.network.as_deref());
    let has_ata_creation_splits = splits
        .iter()
        .any(|split| split.ata_creation_required == Some(true));

    if has_ata_creation_splits {
        let Some(mint_str) = mint else {
            return Err(Error::Other(
                "ataCreationRequired requires an SPL token charge".into(),
            ));
        };
        if mint_str != currency {
            return Err(Error::Other(
                "ataCreationRequired requires currency to be an SPL token mint address".into(),
            ));
        }
    }

    if let Some(mint_str) = mint {
        build_spl_instructions(
            &mut instructions,
            &signer_pubkey,
            &recipient_pubkey,
            rpc,
            mint_str,
            method_details,
            primary_amount,
            options.external_id.as_deref(),
            splits,
            fee_payer_pubkey.as_ref(),
            options.allow_unknown_token_2022,
        )?;
    } else {
        build_sol_instructions(
            &mut instructions,
            &signer_pubkey,
            &recipient_pubkey,
            primary_amount,
            options.external_id.as_deref(),
            splits,
        )?;
    }

    // Build and sign.
    let blockhash = resolve_blockhash(rpc, method_details)?;

    let actual_fee_payer = fee_payer_pubkey.unwrap_or(signer_pubkey);
    let message = Message::new_with_blockhash(&instructions, Some(&actual_fee_payer), &blockhash);
    let mut tx = Transaction::new_unsigned(message);

    let sig_bytes = signer
        .sign_message(&tx.message_data())
        .await
        .map_err(|e| Error::Other(format!("Signing failed: {e}")))?;
    let sig = Signature::from(<[u8; 64]>::from(sig_bytes));
    let signer_index = tx
        .message
        .account_keys
        .iter()
        .position(|k| k == &signer_pubkey)
        .ok_or_else(|| Error::Other("Signer not found in transaction accounts".to_string()))?;
    tx.signatures[signer_index] = sig;

    let serialized =
        bincode::serialize(&tx).map_err(|e| Error::Other(format!("Serialization failed: {e}")))?;
    let encoded = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &serialized);

    Ok(CredentialPayload::Transaction {
        transaction: encoded,
    })
}

/// Build a credential from a challenge and return the `Authorization` header value.
///
/// Parses the challenge, builds and signs the transaction, and formats the
/// credential as `"Payment <base64url(credential_json)>"`.
pub async fn build_credential_header(
    signer: &dyn SolanaSigner,
    rpc: &RpcClient,
    challenge: &PaymentChallenge,
) -> Result<String, Error> {
    build_credential_header_with_options(signer, rpc, challenge, Default::default()).await
}

/// Like `build_credential_header`, but lets the caller pass
/// `BuildChargeTransactionOptions` — in particular
/// `allow_unknown_token_2022` to opt into signing for unknown Token-2022
/// mints (see that field's docs).
pub async fn build_credential_header_with_options(
    signer: &dyn SolanaSigner,
    rpc: &RpcClient,
    challenge: &PaymentChallenge,
    mut options: BuildChargeTransactionOptions,
) -> Result<String, Error> {
    // Audit #17: refuse to sign anything but a `solana`/`charge`
    // challenge. The lower-level `build_charge_transaction_with_options`
    // takes already-decoded fields and has no notion of method/intent,
    // so the trust boundary belongs at this `PaymentChallenge` entry
    // point. `select_charge_challenge` already filters via the same
    // helper; this gate catches callers who skip it.
    if !is_solana_charge_challenge_name(challenge) {
        return Err(Error::Other(format!(
            "Refusing to sign: challenge is not a solana/charge challenge \
             (method=`{}`, intent=`{}`)",
            challenge.method.as_str(),
            challenge.intent.as_str(),
        )));
    }

    // Audit #10: refuse to sign expired challenges. The protocol allows
    // `expires` to be absent — when it is, we let the challenge through
    // (no client-side anchor to check against).
    if challenge.is_expired() {
        return Err(Error::Other(
            "Challenge has expired; refusing to sign".into(),
        ));
    }

    // Decode the request to get Solana-specific fields.
    let request: crate::protocol::intents::ChargeRequest = challenge
        .request
        .decode()
        .map_err(|e| Error::Other(format!("Failed to decode challenge request: {e}")))?;

    let method_details: MethodDetails = request
        .method_details
        .as_ref()
        .map(|v| serde_json::from_value(v.clone()))
        .transpose()
        .map_err(|e| Error::Other(format!("Invalid method details: {e}")))?
        .unwrap_or_default();

    let recipient = request
        .recipient
        .as_deref()
        .ok_or_else(|| Error::Other("No recipient in challenge".into()))?;

    // Default external_id to the challenge's value if the caller didn't
    // override it (preserves prior build_credential_header behavior).
    if options.external_id.is_none() {
        options.external_id = request.external_id.clone();
    }

    let payload = build_charge_transaction_with_options(
        signer,
        rpc,
        &request.amount,
        &request.currency,
        recipient,
        &method_details,
        options,
    )
    .await?;

    let credential = PaymentCredential::new(challenge.to_echo(), payload);
    format_authorization(&credential)
        .map_err(|e| Error::Other(format!("Failed to format credential: {e}")))
}

/// Parse a `WWW-Authenticate` header into a `PaymentChallenge`.
///
/// Convenience re-export — delegates to `protocol::core::parse_www_authenticate`.
pub fn parse_challenge(header_value: &str) -> Result<PaymentChallenge, Error> {
    parse_www_authenticate(header_value)
}

/// Select the Solana charge challenge the client should sign.
///
/// Servers can return multiple charge challenges for the same resource, for
/// example one challenge per supported stablecoin. This helper filters by
/// network and currency preferences while preserving server order otherwise.
pub fn select_charge_challenge<'a>(
    challenges: &'a [PaymentChallenge],
    options: SelectChargeChallengeOptions<'_>,
) -> Result<Option<&'a PaymentChallenge>, Error> {
    let mut candidates = Vec::new();

    for challenge in challenges {
        if !is_solana_charge_challenge_name(challenge) {
            continue;
        }

        let (request, method_details) = decode_charge_challenge(challenge)?;

        if !matches_network(&method_details, options.network) {
            continue;
        }

        if !options.allow_unknown_token_2022
            && challenge_is_unknown_token_2022(&request, &method_details)
        {
            continue;
        }

        candidates.push((challenge, request, method_details));
    }

    if options.currency_preferences.is_empty() && options.currency.is_none() {
        return Ok(candidates.first().map(|(challenge, _, _)| *challenge));
    }

    for expected in currency_preferences(&options) {
        for (challenge, request, method_details) in &candidates {
            if currencies_match(
                &request.currency,
                expected,
                method_details.network.as_deref(),
            ) {
                return Ok(Some(*challenge));
            }
        }
    }

    Ok(None)
}

/// Returns true if the challenge's currency is an arbitrary mint address
/// (not a recognized stablecoin) AND we cannot confirm its token program
/// is the vanilla Token Program. In both the explicit Token-2022 case and
/// the "no `tokenProgram` hint" case we fail closed — see
/// `BuildChargeTransactionOptions::allow_unknown_token_2022`.
fn challenge_is_unknown_token_2022(
    request: &ChargeRequest,
    method_details: &MethodDetails,
) -> bool {
    if request.currency.eq_ignore_ascii_case("SOL") {
        return false;
    }
    let mint = match crate::protocol::solana::resolve_stablecoin_mint(
        &request.currency,
        method_details.network.as_deref(),
    ) {
        Some(m) => m,
        None => return false,
    };
    if crate::protocol::solana::is_known_stablecoin_mint(mint) {
        return false;
    }
    // Arbitrary mint. Vanilla Token Program is hookless, so accept it; for
    // anything else (Token-2022 or unspecified) we cannot tell that
    // signing is safe.
    !matches!(method_details.token_program.as_deref(), Some(p) if p == programs::TOKEN_PROGRAM)
}

/// Returns true when a challenge is a schema-valid Solana charge challenge.
pub fn is_solana_charge_challenge(challenge: &PaymentChallenge) -> bool {
    is_solana_charge_challenge_name(challenge) && decode_charge_challenge(challenge).is_ok()
}

// ── Compute budget instructions (inline, no heavy dep) ──

fn compute_unit_price_ix(micro_lamports: u64) -> Instruction {
    let program_id = Pubkey::from_str("ComputeBudget111111111111111111111111111111").unwrap();
    let mut data = vec![3u8]; // SetComputeUnitPrice discriminator
    data.extend_from_slice(&micro_lamports.to_le_bytes());
    Instruction {
        program_id,
        accounts: vec![],
        data,
    }
}

fn compute_unit_limit_ix(units: u32) -> Instruction {
    let program_id = Pubkey::from_str("ComputeBudget111111111111111111111111111111").unwrap();
    let mut data = vec![2u8]; // SetComputeUnitLimit discriminator
    data.extend_from_slice(&units.to_le_bytes());
    Instruction {
        program_id,
        accounts: vec![],
        data,
    }
}

// ── Private helpers ──

fn build_sol_instructions(
    instructions: &mut Vec<Instruction>,
    signer_pubkey: &Pubkey,
    recipient: &Pubkey,
    primary_amount: u64,
    external_id: Option<&str>,
    splits: &[Split],
) -> Result<(), Error> {
    instructions.push(system_instruction::transfer(
        signer_pubkey,
        recipient,
        primary_amount,
    ));
    push_memo_instruction(instructions, external_id)?;

    for split in splits {
        let split_recipient = Pubkey::from_str(&split.recipient)
            .map_err(|e| Error::Other(format!("Invalid split recipient: {e}")))?;
        let split_amount: u64 = split
            .amount
            .parse()
            .map_err(|_| Error::Other(format!("Invalid split amount: {}", split.amount)))?;
        instructions.push(system_instruction::transfer(
            signer_pubkey,
            &split_recipient,
            split_amount,
        ));
        push_memo_instruction(instructions, split.memo.as_deref())?;
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn build_spl_instructions(
    instructions: &mut Vec<Instruction>,
    signer_pubkey: &Pubkey,
    recipient: &Pubkey,
    rpc: &RpcClient,
    spl: &str,
    method_details: &MethodDetails,
    primary_amount: u64,
    external_id: Option<&str>,
    splits: &[Split],
    fee_payer: Option<&Pubkey>,
    allow_unknown_token_2022: bool,
) -> Result<(), Error> {
    let mint = Pubkey::from_str(spl).map_err(|e| Error::Other(format!("Invalid mint: {e}")))?;
    let token_program = resolve_token_program(rpc, &mint, method_details)?;

    // Spec §13.3: refuse to sign for an arbitrary Token-2022 mint unless
    // the caller opted in. Transfer hooks run on every transfer and can
    // execute arbitrary program code; the server's pre-broadcast checks
    // do not simulate inner instructions in pull mode. The vanilla Token
    // Program has no hooks, so unknown mints there are allowed.
    if token_program.to_string() == programs::TOKEN_2022_PROGRAM
        && !crate::protocol::solana::is_known_stablecoin_mint(spl)
        && !allow_unknown_token_2022
    {
        return Err(Error::Other(format!(
            "Refusing to sign for unknown Token-2022 mint {spl}: \
             set BuildChargeTransactionOptions::allow_unknown_token_2022 \
             to opt in (Token-2022 supports transfer hooks)"
        )));
    }

    // Audit #42: spec §7.2 requires `decimals` to be present when `currency`
    // is a mint address (i.e. always on this SPL path). Defaulting to 6
    // silently produced wrong-decimals transfers for non-6-decimal tokens.
    let decimals = method_details.decimals.ok_or_else(|| {
        Error::Other("methodDetails.decimals is required for SPL charges (spec §7.2)".into())
    })?;

    let source_ata = get_associated_token_address(signer_pubkey, &mint, &token_program);

    let payer = fee_payer.copied().unwrap_or(*signer_pubkey);

    let add_spl_transfer = |instructions: &mut Vec<Instruction>,
                            dest_owner: &Pubkey,
                            transfer_amount: u64,
                            create_ata: bool|
     -> Result<(), Error> {
        let dest_ata = get_associated_token_address(dest_owner, &mint, &token_program);

        if create_ata {
            instructions.push(create_associated_token_account_idempotent(
                &payer,
                dest_owner,
                &mint,
                &token_program,
            ));
        }

        instructions.push(transfer_checked_ix(
            &token_program,
            &source_ata,
            &mint,
            &dest_ata,
            signer_pubkey,
            transfer_amount,
            decimals,
        ));

        Ok(())
    };

    add_spl_transfer(instructions, recipient, primary_amount, false)?;
    push_memo_instruction(instructions, external_id)?;

    for split in splits {
        let split_recipient = Pubkey::from_str(&split.recipient)
            .map_err(|e| Error::Other(format!("Invalid split recipient: {e}")))?;
        let split_amount: u64 = split
            .amount
            .parse()
            .map_err(|_| Error::Other(format!("Invalid split amount: {}", split.amount)))?;
        // Audit #20: only create the split ATA when the challenge
        // explicitly flags it. The old behaviour auto-created in
        // client-paid mode, letting a hostile server drain the client
        // with N dust splits × ATA rent. Spec §7.2 says the client MUST
        // include the ATA-create ix when `ataCreationRequired` is true;
        // it does not authorize creation otherwise.
        add_spl_transfer(
            instructions,
            &split_recipient,
            split_amount,
            split.ata_creation_required == Some(true),
        )?;
        push_memo_instruction(instructions, split.memo.as_deref())?;
    }

    Ok(())
}

fn push_memo_instruction(
    instructions: &mut Vec<Instruction>,
    memo: Option<&str>,
) -> Result<(), Error> {
    let Some(memo) = memo else {
        return Ok(());
    };
    let data = memo.as_bytes().to_vec();
    if data.len() > MAX_MEMO_BYTES {
        return Err(Error::Other(format!(
            "memo cannot exceed {MAX_MEMO_BYTES} bytes"
        )));
    }
    let memo_program = Pubkey::from_str(programs::MEMO_PROGRAM)
        .map_err(|e| Error::Other(format!("Invalid memo program: {e}")))?;
    instructions.push(Instruction {
        program_id: memo_program,
        accounts: vec![],
        data,
    });
    Ok(())
}

fn resolve_token_program(
    rpc: &RpcClient,
    mint: &Pubkey,
    method_details: &MethodDetails,
) -> Result<Pubkey, Error> {
    let token_program = if let Some(token_program) = method_details.token_program.as_deref() {
        Pubkey::from_str(token_program)
            .map_err(|e| Error::Other(format!("Invalid token program: {e}")))?
    } else {
        rpc.get_account(mint)
            .map_err(|e| Error::Rpc(format!("Failed to fetch mint account: {e}")))?
            .owner
    };

    let token_program_str = token_program.to_string();
    if token_program_str != programs::TOKEN_PROGRAM
        && token_program_str != programs::TOKEN_2022_PROGRAM
    {
        return Err(Error::Other(format!(
            "Unsupported token program: {token_program}"
        )));
    }

    Ok(token_program)
}

fn get_associated_token_address(owner: &Pubkey, mint: &Pubkey, token_program: &Pubkey) -> Pubkey {
    let ata_program = Pubkey::from_str(programs::ASSOCIATED_TOKEN_PROGRAM).unwrap();
    let seeds = &[owner.as_ref(), token_program.as_ref(), mint.as_ref()];
    Pubkey::find_program_address(seeds, &ata_program).0
}

fn create_associated_token_account_idempotent(
    payer: &Pubkey,
    owner: &Pubkey,
    mint: &Pubkey,
    token_program: &Pubkey,
) -> Instruction {
    let ata = get_associated_token_address(owner, mint, token_program);
    let ata_program = Pubkey::from_str(programs::ASSOCIATED_TOKEN_PROGRAM).unwrap();
    let system_program = Pubkey::from_str(programs::SYSTEM_PROGRAM).unwrap();

    Instruction {
        program_id: ata_program,
        accounts: vec![
            AccountMeta::new(*payer, true),
            AccountMeta::new(ata, false),
            AccountMeta::new_readonly(*owner, false),
            AccountMeta::new_readonly(*mint, false),
            AccountMeta::new_readonly(system_program, false),
            AccountMeta::new_readonly(*token_program, false),
        ],
        data: vec![1], // CreateIdempotent discriminator
    }
}

fn transfer_checked_ix(
    token_program: &Pubkey,
    source: &Pubkey,
    mint: &Pubkey,
    destination: &Pubkey,
    authority: &Pubkey,
    amount: u64,
    decimals: u8,
) -> Instruction {
    let mut data = vec![12u8];
    data.extend_from_slice(&amount.to_le_bytes());
    data.push(decimals);

    Instruction {
        program_id: *token_program,
        accounts: vec![
            AccountMeta::new(*source, false),
            AccountMeta::new_readonly(*mint, false),
            AccountMeta::new(*destination, false),
            AccountMeta::new_readonly(*authority, true),
        ],
        data,
    }
}

/// Resolve a currency to an optional mint address.
///
/// Returns `None` for native SOL.
/// Returns `Some(mint_address)` for known stablecoin symbols (e.g.
/// `"USDC"` → the network's USDC mint).
/// Returns `Some(currency)` (passthrough) for anything else — symbol or
/// mint string we don't recognize. Callers handling arbitrary mints MUST
/// validate parseability separately; audit #27 calls out the docstring
/// drift from "Some(mint_address)" alone.
fn resolve_mint<'a>(currency: &'a str, network: Option<&str>) -> Option<&'a str> {
    crate::protocol::solana::resolve_stablecoin_mint(currency, network)
}

fn is_solana_charge_challenge_name(challenge: &PaymentChallenge) -> bool {
    challenge.method.as_str() == "solana" && challenge.intent.as_str() == "charge"
}

fn decode_charge_challenge(
    challenge: &PaymentChallenge,
) -> Result<(ChargeRequest, MethodDetails), Error> {
    let request: ChargeRequest = challenge
        .request
        .decode()
        .map_err(|e| Error::Other(format!("Failed to decode challenge request: {e}")))?;
    if request.recipient.is_none() {
        return Err(Error::Other("No recipient in challenge".into()));
    }
    let method_details = request
        .method_details
        .as_ref()
        .ok_or_else(|| Error::Other("Missing methodDetails in challenge".into()))?
        .clone();
    let method_details = serde_json::from_value(method_details)
        .map_err(|e| Error::Other(format!("Invalid method details: {e}")))?;
    Ok((request, method_details))
}

fn matches_network(method_details: &MethodDetails, network: Option<&str>) -> bool {
    // Audit #37: when methodDetails omits `network`, spec §7.2 says it
    // defaults to `mainnet` — not the legacy "mainnet-beta" RPC hostname.
    match network {
        None => true,
        Some(expected) => {
            method_details
                .network
                .as_deref()
                .unwrap_or(crate::protocol::solana::DEFAULT_NETWORK)
                == expected
        }
    }
}

fn currency_preferences<'a>(options: &SelectChargeChallengeOptions<'a>) -> Vec<&'a str> {
    if !options.currency_preferences.is_empty() {
        return options.currency_preferences.to_vec();
    }
    options.currency.into_iter().collect()
}

fn currencies_match(
    challenge_currency: &str,
    expected_currency: &str,
    network: Option<&str>,
) -> bool {
    crate::protocol::solana::resolve_stablecoin_mint(challenge_currency, network)
        == crate::protocol::solana::resolve_stablecoin_mint(expected_currency, network)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::core::Base64UrlJson;
    use crate::protocol::solana::mints;

    #[test]
    fn parse_challenge_from_header() {
        use base64::Engine;
        let request_json = serde_json::json!({
            "amount": "10000",
            "currency": "USDC",
            "recipient": "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY",
            "methodDetails": {
                "network": "devnet",
                "decimals": 6,
                "tokenProgram": "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
            }
        });
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&request_json).unwrap());
        let header = format!(
            "Payment id=\"abc123\", realm=\"MPP Payment\", method=\"solana\", intent=\"charge\", request=\"{b64}\""
        );

        let parsed = parse_challenge(&header).unwrap();
        assert_eq!(parsed.id, "abc123");
        assert_eq!(parsed.realm, "MPP Payment");
        assert_eq!(parsed.method.as_str(), "solana");

        // Decode the request
        let req: crate::protocol::intents::ChargeRequest = parsed.request.decode().unwrap();
        assert_eq!(req.amount, "10000");
        assert_eq!(req.currency, "USDC");
    }

    fn selection_challenge(
        id: &str,
        method: &str,
        currency: &str,
        network: &str,
    ) -> PaymentChallenge {
        let details = MethodDetails {
            decimals: Some(6),
            fee_payer: Some(true),
            fee_payer_key: Some(RECIPIENT.to_string()),
            network: Some(network.to_string()),
            ..Default::default()
        };
        let request = ChargeRequest {
            amount: "1000".to_string(),
            currency: currency.to_string(),
            method_details: Some(serde_json::to_value(details).unwrap()),
            recipient: Some(RECIPIENT.to_string()),
            ..Default::default()
        };
        PaymentChallenge::new(
            id,
            "test",
            method,
            "charge",
            Base64UrlJson::from_typed(&request).unwrap(),
        )
    }

    #[test]
    fn select_charge_challenge_selects_first_matching_challenge() {
        let challenges = vec![
            selection_challenge("first", "solana", mints::USDC_DEVNET, "devnet"),
            selection_challenge("second", "solana", mints::USDC_DEVNET, "devnet"),
        ];

        let selected =
            select_charge_challenge(&challenges, SelectChargeChallengeOptions::default())
                .unwrap()
                .unwrap();

        assert_eq!(selected.id, "first");
    }

    #[test]
    fn select_charge_challenge_matches_stablecoin_symbol_to_mint_on_network() {
        let challenges = vec![selection_challenge(
            "usdc-devnet",
            "solana",
            mints::USDC_DEVNET,
            "devnet",
        )];

        let selected = select_charge_challenge(
            &challenges,
            SelectChargeChallengeOptions {
                currency: Some("USDC"),
                network: Some("devnet"),
                ..Default::default()
            },
        )
        .unwrap()
        .unwrap();

        assert_eq!(selected.id, "usdc-devnet");
    }

    #[test]
    fn select_charge_challenge_honors_client_currency_preference_order() {
        let challenges = vec![
            selection_challenge("mainnet-usdc", "solana", mints::USDC_MAINNET, "mainnet"),
            selection_challenge("devnet-usdc", "solana", mints::USDC_DEVNET, "devnet"),
        ];

        let selected = select_charge_challenge(
            &challenges,
            SelectChargeChallengeOptions {
                currency_preferences: &[mints::USDC_DEVNET, mints::USDC_MAINNET],
                ..Default::default()
            },
        )
        .unwrap()
        .unwrap();

        assert_eq!(selected.id, "devnet-usdc");
    }

    #[test]
    fn select_charge_challenge_returns_none_when_no_candidate_matches() {
        let challenges = vec![
            selection_challenge("stripe", "stripe", mints::USDC_DEVNET, "devnet"),
            selection_challenge("usdc-mainnet", "solana", mints::USDC_MAINNET, "mainnet"),
        ];

        let selected = select_charge_challenge(
            &challenges,
            SelectChargeChallengeOptions {
                currency: Some("USDC"),
                network: Some("devnet"),
                ..Default::default()
            },
        )
        .unwrap();

        assert!(selected.is_none());
    }

    fn unknown_token_2022_selection_challenge(token_program: Option<&str>) -> PaymentChallenge {
        // A made-up base58 mint address that is NOT in the known stablecoin
        // allowlist. Used to exercise the Token-2022 gate.
        // Valid base58 pubkey not in the stablecoin allowlist.
        const UNKNOWN_MINT: &str = "9XHRopERTd4LfQ8b6e3p9bN2WhxgQzDxFRtbq1XwQ4mP";
        let details = MethodDetails {
            decimals: Some(6),
            network: Some("mainnet".to_string()),
            token_program: token_program.map(|s| s.to_string()),
            ..Default::default()
        };
        let request = ChargeRequest {
            amount: "1000".to_string(),
            currency: UNKNOWN_MINT.to_string(),
            method_details: Some(serde_json::to_value(details).unwrap()),
            recipient: Some(RECIPIENT.to_string()),
            ..Default::default()
        };
        PaymentChallenge::new(
            "unknown-2022",
            "test",
            "solana",
            "charge",
            Base64UrlJson::from_typed(&request).unwrap(),
        )
    }

    #[test]
    fn select_charge_challenge_skips_unknown_token_2022_by_default() {
        let challenges = vec![unknown_token_2022_selection_challenge(Some(
            programs::TOKEN_2022_PROGRAM,
        ))];
        let selected =
            select_charge_challenge(&challenges, SelectChargeChallengeOptions::default()).unwrap();
        assert!(selected.is_none(), "default must skip unknown Token-2022");
    }

    #[test]
    fn select_charge_challenge_skips_unknown_mint_with_no_token_program_hint() {
        // No tokenProgram in methodDetails — we cannot prove it isn't
        // Token-2022, so default must fail closed.
        let challenges = vec![unknown_token_2022_selection_challenge(None)];
        let selected =
            select_charge_challenge(&challenges, SelectChargeChallengeOptions::default()).unwrap();
        assert!(selected.is_none());
    }

    #[test]
    fn select_charge_challenge_accepts_unknown_vanilla_token_mint() {
        // Same unknown mint but explicitly on the vanilla Token Program —
        // no transfer hooks, so the gate does not apply.
        let challenges = vec![unknown_token_2022_selection_challenge(Some(
            programs::TOKEN_PROGRAM,
        ))];
        let selected =
            select_charge_challenge(&challenges, SelectChargeChallengeOptions::default())
                .unwrap()
                .unwrap();
        assert_eq!(selected.id, "unknown-2022");
    }

    #[test]
    fn select_charge_challenge_allows_unknown_token_2022_with_opt_in() {
        let challenges = vec![unknown_token_2022_selection_challenge(Some(
            programs::TOKEN_2022_PROGRAM,
        ))];
        let selected = select_charge_challenge(
            &challenges,
            SelectChargeChallengeOptions {
                allow_unknown_token_2022: true,
                ..Default::default()
            },
        )
        .unwrap()
        .unwrap();
        assert_eq!(selected.id, "unknown-2022");
    }

    #[test]
    fn select_charge_challenge_does_not_gate_known_token_2022_stablecoin() {
        // PYUSD is Token-2022 but in the known allowlist; default selection
        // must still pick it.
        let challenges = vec![selection_challenge(
            "pyusd-mainnet",
            "solana",
            mints::PYUSD_MAINNET,
            "mainnet",
        )];
        let selected = select_charge_challenge(
            &challenges,
            SelectChargeChallengeOptions {
                network: Some("mainnet"),
                ..Default::default()
            },
        )
        .unwrap()
        .unwrap();
        assert_eq!(selected.id, "pyusd-mainnet");
    }

    #[test]
    fn is_solana_charge_challenge_rejects_invalid_request() {
        let challenge = PaymentChallenge::new(
            "invalid",
            "test",
            "solana",
            "charge",
            Base64UrlJson::from_value(&serde_json::json!({ "amount": "1000" })).unwrap(),
        );

        assert!(!is_solana_charge_challenge(&challenge));
    }

    #[test]
    fn resolve_mint_known_symbols() {
        assert_eq!(resolve_mint("SOL", None), None);
        assert_eq!(resolve_mint("sol", None), None);
        assert_eq!(
            resolve_mint("USDC", None),
            Some("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v")
        );
        assert_eq!(
            resolve_mint("USDC", Some("devnet")),
            Some("4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU")
        );
        assert_eq!(
            resolve_mint("USDT", None),
            Some(crate::protocol::solana::mints::USDT_MAINNET)
        );
        assert_eq!(
            resolve_mint("CASH", None),
            Some(crate::protocol::solana::mints::CASH_MAINNET)
        );
        assert_eq!(
            resolve_mint("USDPT", None),
            Some(crate::protocol::solana::mints::USDPT_MAINNET)
        );
    }

    #[test]
    fn resolve_mint_passthrough() {
        assert_eq!(
            resolve_mint("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v", None),
            Some("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v")
        );
    }

    // ── resolve_mint additional coverage ──

    #[test]
    fn resolve_mint_pyusd_mainnet() {
        assert_eq!(
            resolve_mint("PYUSD", None),
            Some("2b1kV6DkPAnxd5ixfnxCpjxmKwqjjaYmCZfHsFu24GXo")
        );
        assert_eq!(
            resolve_mint("PYUSD", Some("mainnet")),
            Some("2b1kV6DkPAnxd5ixfnxCpjxmKwqjjaYmCZfHsFu24GXo")
        );
    }

    #[test]
    fn resolve_mint_pyusd_devnet() {
        assert_eq!(
            resolve_mint("PYUSD", Some("devnet")),
            Some("CXk2AMBfi3TwaEL2468s6zP8xq9NxTXjp9gjMgzeUynM")
        );
    }

    #[test]
    fn resolve_mint_case_insensitive() {
        // "usdc", "Usdc", "uSdC" all resolve the same
        assert_eq!(
            resolve_mint("usdc", None),
            Some("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v")
        );
        assert_eq!(
            resolve_mint("Usdc", Some("devnet")),
            Some("4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU")
        );
        assert_eq!(
            resolve_mint("pyusd", None),
            Some("2b1kV6DkPAnxd5ixfnxCpjxmKwqjjaYmCZfHsFu24GXo")
        );
    }

    #[test]
    fn resolve_mint_unknown_token_returned_as_is() {
        assert_eq!(resolve_mint("BONK", None), Some("BONK"));
        assert_eq!(
            resolve_mint("SomeRandomMint123", Some("devnet")),
            Some("SomeRandomMint123")
        );
    }

    // ── compute budget instruction tests ──

    #[test]
    fn compute_unit_price_ix_structure() {
        let ix = compute_unit_price_ix(42);
        let expected_program =
            Pubkey::from_str("ComputeBudget111111111111111111111111111111").unwrap();
        assert_eq!(ix.program_id, expected_program);
        assert!(ix.accounts.is_empty());
        assert_eq!(ix.data[0], 3u8); // SetComputeUnitPrice discriminator
        let price = u64::from_le_bytes(ix.data[1..9].try_into().unwrap());
        assert_eq!(price, 42);
    }

    #[test]
    fn compute_unit_price_ix_zero() {
        let ix = compute_unit_price_ix(0);
        let price = u64::from_le_bytes(ix.data[1..9].try_into().unwrap());
        assert_eq!(price, 0);
    }

    #[test]
    fn compute_unit_price_ix_max() {
        let ix = compute_unit_price_ix(u64::MAX);
        let price = u64::from_le_bytes(ix.data[1..9].try_into().unwrap());
        assert_eq!(price, u64::MAX);
    }

    #[test]
    fn compute_unit_limit_ix_structure() {
        let ix = compute_unit_limit_ix(200_000);
        let expected_program =
            Pubkey::from_str("ComputeBudget111111111111111111111111111111").unwrap();
        assert_eq!(ix.program_id, expected_program);
        assert!(ix.accounts.is_empty());
        assert_eq!(ix.data[0], 2u8); // SetComputeUnitLimit discriminator
        let units = u32::from_le_bytes(ix.data[1..5].try_into().unwrap());
        assert_eq!(units, 200_000);
    }

    #[test]
    fn compute_unit_limit_ix_zero() {
        let ix = compute_unit_limit_ix(0);
        let units = u32::from_le_bytes(ix.data[1..5].try_into().unwrap());
        assert_eq!(units, 0);
    }

    // ── build_sol_instructions tests ──

    #[test]
    fn build_sol_instructions_no_splits() {
        let signer = Pubkey::new_unique();
        let recipient = Pubkey::new_unique();
        let mut instructions = Vec::new();
        build_sol_instructions(&mut instructions, &signer, &recipient, 1_000_000, None, &[])
            .unwrap();
        assert_eq!(instructions.len(), 1);
        // The system transfer instruction should use the system program
        let system_program = Pubkey::from_str(programs::SYSTEM_PROGRAM).unwrap();
        assert_eq!(instructions[0].program_id, system_program);
    }

    #[test]
    fn build_sol_instructions_with_splits() {
        let signer = Pubkey::new_unique();
        let recipient = Pubkey::new_unique();
        let split_recipient = Pubkey::new_unique();
        let splits = vec![Split {
            recipient: split_recipient.to_string(),
            amount: "500".to_string(),
            ata_creation_required: None,
            label: None,
            memo: None,
        }];
        let mut instructions = Vec::new();
        build_sol_instructions(&mut instructions, &signer, &recipient, 1_000, None, &splits)
            .unwrap();
        // 1 primary transfer + 1 split transfer
        assert_eq!(instructions.len(), 2);
    }

    #[test]
    fn build_sol_instructions_with_external_id_memo() {
        let signer = Pubkey::new_unique();
        let recipient = Pubkey::new_unique();
        let mut instructions = Vec::new();
        build_sol_instructions(
            &mut instructions,
            &signer,
            &recipient,
            1_000,
            Some("order-123"),
            &[],
        )
        .unwrap();

        assert_eq!(instructions.len(), 2);
        assert_eq!(
            instructions[1].program_id,
            Pubkey::from_str(programs::MEMO_PROGRAM).unwrap()
        );
        assert!(instructions[1].accounts.is_empty());
        assert_eq!(instructions[1].data, b"order-123");
    }

    #[test]
    fn build_sol_instructions_with_split_memo() {
        let signer = Pubkey::new_unique();
        let recipient = Pubkey::new_unique();
        let split_recipient = Pubkey::new_unique();
        let splits = vec![Split {
            recipient: split_recipient.to_string(),
            amount: "500".to_string(),
            ata_creation_required: None,
            label: None,
            memo: Some("platform fee".to_string()),
        }];
        let mut instructions = Vec::new();
        build_sol_instructions(&mut instructions, &signer, &recipient, 1_000, None, &splits)
            .unwrap();

        assert_eq!(instructions.len(), 3);
        assert_eq!(
            instructions[2].program_id,
            Pubkey::from_str(programs::MEMO_PROGRAM).unwrap()
        );
        assert!(instructions[2].accounts.is_empty());
        assert_eq!(instructions[2].data, b"platform fee");
    }

    #[test]
    fn build_sol_instructions_rejects_long_split_memo() {
        let signer = Pubkey::new_unique();
        let recipient = Pubkey::new_unique();
        let split_recipient = Pubkey::new_unique();
        let splits = vec![Split {
            recipient: split_recipient.to_string(),
            amount: "500".to_string(),
            ata_creation_required: None,
            label: None,
            memo: Some("x".repeat(567)),
        }];
        let mut instructions = Vec::new();
        let err =
            build_sol_instructions(&mut instructions, &signer, &recipient, 1_000, None, &splits)
                .unwrap_err();

        assert!(format!("{err}").contains("memo cannot exceed 566 bytes"));
    }

    #[test]
    fn build_sol_instructions_rejects_long_external_id_memo() {
        let signer = Pubkey::new_unique();
        let recipient = Pubkey::new_unique();
        let long_memo = "x".repeat(567);
        let mut instructions = Vec::new();
        let err = build_sol_instructions(
            &mut instructions,
            &signer,
            &recipient,
            1_000,
            Some(long_memo.as_str()),
            &[],
        )
        .unwrap_err();

        assert!(format!("{err}").contains("memo cannot exceed 566 bytes"));
    }

    #[test]
    fn build_sol_instructions_invalid_split_recipient() {
        let signer = Pubkey::new_unique();
        let recipient = Pubkey::new_unique();
        let splits = vec![Split {
            recipient: "not-a-pubkey!!!".to_string(),
            amount: "500".to_string(),
            ata_creation_required: None,
            label: None,
            memo: None,
        }];
        let mut instructions = Vec::new();
        let err =
            build_sol_instructions(&mut instructions, &signer, &recipient, 1_000, None, &splits);
        assert!(err.is_err());
        let msg = format!("{}", err.unwrap_err());
        assert!(msg.contains("Invalid split recipient"));
    }

    #[test]
    fn build_sol_instructions_invalid_split_amount() {
        let signer = Pubkey::new_unique();
        let recipient = Pubkey::new_unique();
        let split_recipient = Pubkey::new_unique();
        let splits = vec![Split {
            recipient: split_recipient.to_string(),
            amount: "not_a_number".to_string(),
            ata_creation_required: None,
            label: None,
            memo: None,
        }];
        let mut instructions = Vec::new();
        let err =
            build_sol_instructions(&mut instructions, &signer, &recipient, 1_000, None, &splits);
        assert!(err.is_err());
        let msg = format!("{}", err.unwrap_err());
        assert!(msg.contains("Invalid split amount"));
    }

    // ── get_associated_token_address tests ──

    #[test]
    fn get_ata_deterministic() {
        let owner = Pubkey::new_unique();
        let mint = Pubkey::new_unique();
        let token_program = Pubkey::from_str(programs::TOKEN_PROGRAM).unwrap();
        let ata1 = get_associated_token_address(&owner, &mint, &token_program);
        let ata2 = get_associated_token_address(&owner, &mint, &token_program);
        assert_eq!(ata1, ata2);
    }

    #[test]
    fn get_ata_different_for_different_owners() {
        let owner1 = Pubkey::new_unique();
        let owner2 = Pubkey::new_unique();
        let mint = Pubkey::new_unique();
        let token_program = Pubkey::from_str(programs::TOKEN_PROGRAM).unwrap();
        let ata1 = get_associated_token_address(&owner1, &mint, &token_program);
        let ata2 = get_associated_token_address(&owner2, &mint, &token_program);
        assert_ne!(ata1, ata2);
    }

    #[test]
    fn get_ata_different_for_different_token_programs() {
        let owner = Pubkey::new_unique();
        let mint = Pubkey::new_unique();
        let tp1 = Pubkey::from_str(programs::TOKEN_PROGRAM).unwrap();
        let tp2 = Pubkey::from_str(programs::TOKEN_2022_PROGRAM).unwrap();
        let ata1 = get_associated_token_address(&owner, &mint, &tp1);
        let ata2 = get_associated_token_address(&owner, &mint, &tp2);
        assert_ne!(ata1, ata2);
    }

    // ── create_associated_token_account_idempotent tests ──

    #[test]
    fn create_ata_idempotent_instruction_structure() {
        let payer = Pubkey::new_unique();
        let owner = Pubkey::new_unique();
        let mint = Pubkey::new_unique();
        let token_program = Pubkey::from_str(programs::TOKEN_PROGRAM).unwrap();

        let ix = create_associated_token_account_idempotent(&payer, &owner, &mint, &token_program);

        let ata_program = Pubkey::from_str(programs::ASSOCIATED_TOKEN_PROGRAM).unwrap();
        assert_eq!(ix.program_id, ata_program);
        assert_eq!(ix.accounts.len(), 6);
        assert_eq!(ix.data, vec![1]); // CreateIdempotent discriminator

        // payer is signer and writable
        assert_eq!(ix.accounts[0].pubkey, payer);
        assert!(ix.accounts[0].is_signer);
        assert!(ix.accounts[0].is_writable);

        // owner is read-only
        assert_eq!(ix.accounts[2].pubkey, owner);
        assert!(!ix.accounts[2].is_signer);
        assert!(!ix.accounts[2].is_writable);
    }

    // ── transfer_checked_ix tests ──

    #[test]
    fn transfer_checked_ix_structure() {
        let token_program = Pubkey::from_str(programs::TOKEN_PROGRAM).unwrap();
        let source = Pubkey::new_unique();
        let mint = Pubkey::new_unique();
        let dest = Pubkey::new_unique();
        let authority = Pubkey::new_unique();

        let ix = transfer_checked_ix(&token_program, &source, &mint, &dest, &authority, 42_000, 6);

        assert_eq!(ix.program_id, token_program);
        assert_eq!(ix.accounts.len(), 4);
        assert_eq!(ix.data[0], 12u8); // TransferChecked discriminator
        let amount = u64::from_le_bytes(ix.data[1..9].try_into().unwrap());
        assert_eq!(amount, 42_000);
        assert_eq!(ix.data[9], 6); // decimals

        // source writable, mint read-only, dest writable, authority signer
        assert!(ix.accounts[0].is_writable);
        assert!(!ix.accounts[1].is_writable);
        assert!(ix.accounts[2].is_writable);
        assert!(ix.accounts[3].is_signer);
    }

    // ── parse_challenge error cases ──

    #[test]
    fn parse_challenge_rejects_non_payment_scheme() {
        let err = parse_challenge("Bearer realm=\"test\"");
        assert!(err.is_err());
    }

    #[test]
    fn parse_challenge_rejects_missing_fields() {
        let err = parse_challenge("Payment id=\"abc\"");
        assert!(err.is_err());
    }

    // ── Helpers for async/RPC-bypass tests ──

    fn make_signer() -> Box<dyn SolanaSigner> {
        let sk = ed25519_dalek::SigningKey::from_bytes(&[42u8; 32]);
        let mut kp = [0u8; 64];
        kp[..32].copy_from_slice(sk.as_bytes());
        kp[32..].copy_from_slice(sk.verifying_key().as_bytes());
        Box::new(solana_keychain::MemorySigner::from_bytes(&kp).expect("valid keypair"))
    }

    fn dummy_rpc() -> RpcClient {
        // Never actually contacted — tests bypass RPC via method_details overrides.
        RpcClient::new("http://localhost:1".to_string())
    }

    /// 32 zero bytes in base58 — same as the system program address and a valid Hash.
    const ZERO_HASH: &str = "11111111111111111111111111111111";
    const RECIPIENT: &str = "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY";
    const USDC_MINT: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";

    // A confidential charge given a currency SYMBOL must resolve it to a mint
    // address before the bundle builder (which feeds it to Pubkey::from_str).
    // The builder parses the mint BEFORE the recipient, so with a deliberately
    // invalid recipient the symbol case must fail at "invalid recipient" — proving
    // the mint resolved past its own parse. An unresolved symbol would instead
    // fail earlier at "invalid mint `USDPT`". (Integration tests use raw mint
    // addresses, so only this exercises the symbol path; we stop before any RPC
    // since the blocking RPC client can't run inside a tokio test.)
    #[cfg(feature = "confidential")]
    #[tokio::test]
    async fn build_charge_confidential_resolves_currency_symbol() {
        let signer = make_signer();
        let rpc = dummy_rpc();
        let fee_payer = Pubkey::new_unique();
        let md = MethodDetails {
            recent_blockhash: Some(ZERO_HASH.to_string()),
            fee_payer: Some(true),
            fee_payer_key: Some(fee_payer.to_string()),
            token_program: Some(crate::protocol::solana::programs::TOKEN_2022_PROGRAM.to_string()),
            confidential: Some(true),
            network: Some("mainnet".to_string()),
            ..Default::default()
        };
        let err = build_charge_transaction(
            signer.as_ref(),
            &rpc,
            "1000000",
            "USDPT",
            "not-a-pubkey",
            &md,
        )
        .await
        .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("invalid recipient"),
            "expected to reach recipient parse (symbol resolved), got: {msg}"
        );
        assert!(
            !msg.contains("invalid mint"),
            "currency symbol was not resolved to a mint address: {msg}"
        );
    }

    // ── build_charge_transaction: SOL happy paths ──

    #[tokio::test]
    async fn build_charge_sol_no_splits() {
        let signer = make_signer();
        let rpc = dummy_rpc();
        let md = MethodDetails {
            recent_blockhash: Some(ZERO_HASH.to_string()),
            ..Default::default()
        };
        let payload =
            build_charge_transaction(signer.as_ref(), &rpc, "1000000", "SOL", RECIPIENT, &md)
                .await
                .unwrap();
        assert!(matches!(payload, CredentialPayload::Transaction { .. }));
    }

    #[tokio::test]
    async fn build_charge_sol_with_splits() {
        let signer = make_signer();
        let rpc = dummy_rpc();
        let split_addr = Pubkey::new_unique().to_string();
        let md = MethodDetails {
            recent_blockhash: Some(ZERO_HASH.to_string()),
            splits: Some(vec![Split {
                recipient: split_addr,
                amount: "1000".to_string(),
                ata_creation_required: None,
                label: None,
                memo: None,
            }]),
            ..Default::default()
        };
        let payload =
            build_charge_transaction(signer.as_ref(), &rpc, "5000000", "SOL", RECIPIENT, &md)
                .await
                .unwrap();
        assert!(matches!(payload, CredentialPayload::Transaction { .. }));
    }

    #[tokio::test]
    async fn build_charge_sol_with_fee_payer() {
        let signer = make_signer();
        let rpc = dummy_rpc();
        let fee_payer = Pubkey::new_unique();
        let md = MethodDetails {
            recent_blockhash: Some(ZERO_HASH.to_string()),
            fee_payer: Some(true),
            fee_payer_key: Some(fee_payer.to_string()),
            ..Default::default()
        };
        let payload =
            build_charge_transaction(signer.as_ref(), &rpc, "1000000", "SOL", RECIPIENT, &md)
                .await
                .unwrap();
        assert!(matches!(payload, CredentialPayload::Transaction { .. }));
    }

    // ── build_charge_transaction: error cases ──

    #[tokio::test]
    async fn build_charge_invalid_amount() {
        let signer = make_signer();
        let rpc = dummy_rpc();
        let md = MethodDetails {
            recent_blockhash: Some(ZERO_HASH.to_string()),
            ..Default::default()
        };
        let err =
            build_charge_transaction(signer.as_ref(), &rpc, "not-a-number", "SOL", RECIPIENT, &md)
                .await;
        assert!(err.is_err());
        assert!(format!("{}", err.unwrap_err()).contains("Invalid amount"));
    }

    #[tokio::test]
    async fn build_charge_too_many_splits() {
        let signer = make_signer();
        let rpc = dummy_rpc();
        let splits: Vec<Split> = (0..9)
            .map(|_| Split {
                recipient: Pubkey::new_unique().to_string(),
                amount: "100".to_string(),
                ata_creation_required: None,
                label: None,
                memo: None,
            })
            .collect();
        let md = MethodDetails {
            recent_blockhash: Some(ZERO_HASH.to_string()),
            splits: Some(splits),
            ..Default::default()
        };
        let err =
            build_charge_transaction(signer.as_ref(), &rpc, "1000000", "SOL", RECIPIENT, &md).await;
        assert!(matches!(err, Err(crate::Error::TooManySplits)));
    }

    #[tokio::test]
    async fn build_charge_splits_exceed_amount() {
        let signer = make_signer();
        let rpc = dummy_rpc();
        let md = MethodDetails {
            recent_blockhash: Some(ZERO_HASH.to_string()),
            splits: Some(vec![Split {
                recipient: Pubkey::new_unique().to_string(),
                amount: "1000000".to_string(), // equals total → primary_amount = 0
                ata_creation_required: None,
                label: None,
                memo: None,
            }]),
            ..Default::default()
        };
        let err =
            build_charge_transaction(signer.as_ref(), &rpc, "1000000", "SOL", RECIPIENT, &md).await;
        assert!(matches!(err, Err(crate::Error::SplitsExceedAmount)));
    }

    #[tokio::test]
    async fn build_charge_invalid_recipient() {
        let signer = make_signer();
        let rpc = dummy_rpc();
        let md = MethodDetails {
            recent_blockhash: Some(ZERO_HASH.to_string()),
            ..Default::default()
        };
        let err = build_charge_transaction(
            signer.as_ref(),
            &rpc,
            "1000000",
            "SOL",
            "not-a-pubkey!!!",
            &md,
        )
        .await;
        assert!(err.is_err());
        assert!(format!("{}", err.unwrap_err()).contains("Invalid recipient"));
    }

    #[tokio::test]
    async fn build_charge_invalid_fee_payer_key() {
        let signer = make_signer();
        let rpc = dummy_rpc();
        let md = MethodDetails {
            recent_blockhash: Some(ZERO_HASH.to_string()),
            fee_payer: Some(true),
            fee_payer_key: Some("not-a-valid-key!!!".to_string()),
            ..Default::default()
        };
        let err =
            build_charge_transaction(signer.as_ref(), &rpc, "1000000", "SOL", RECIPIENT, &md).await;
        assert!(err.is_err());
        assert!(format!("{}", err.unwrap_err()).contains("Invalid fee payer"));
    }

    #[tokio::test]
    async fn build_charge_with_split_ata_creation() {
        let signer = make_signer();
        let rpc = dummy_rpc();
        let fee_payer = Pubkey::new_unique();
        let split_recipient = Pubkey::new_unique();
        let md = MethodDetails {
            recent_blockhash: Some(ZERO_HASH.to_string()),
            token_program: Some(programs::TOKEN_PROGRAM.to_string()),
            decimals: Some(6),
            fee_payer: Some(true),
            fee_payer_key: Some(fee_payer.to_string()),
            splits: Some(vec![Split {
                recipient: split_recipient.to_string(),
                amount: "50000".to_string(),
                ata_creation_required: Some(true),
                label: None,
                memo: None,
            }]),
            ..Default::default()
        };
        let payload = build_charge_transaction_with_options(
            signer.as_ref(),
            &rpc,
            "1000000",
            USDC_MINT,
            RECIPIENT,
            &md,
            BuildChargeTransactionOptions::default(),
        )
        .await
        .unwrap();
        assert!(matches!(payload, CredentialPayload::Transaction { .. }));
    }

    #[tokio::test]
    async fn build_charge_rejects_split_ata_creation_with_currency_symbol() {
        let signer = make_signer();
        let rpc = dummy_rpc();
        let fee_payer = Pubkey::new_unique();
        let split_recipient = Pubkey::new_unique();
        let md = MethodDetails {
            recent_blockhash: Some(ZERO_HASH.to_string()),
            token_program: Some(programs::TOKEN_PROGRAM.to_string()),
            decimals: Some(6),
            fee_payer: Some(true),
            fee_payer_key: Some(fee_payer.to_string()),
            splits: Some(vec![Split {
                recipient: split_recipient.to_string(),
                amount: "50000".to_string(),
                ata_creation_required: Some(true),
                label: None,
                memo: None,
            }]),
            ..Default::default()
        };
        let err = build_charge_transaction_with_options(
            signer.as_ref(),
            &rpc,
            "1000000",
            "USDC",
            RECIPIENT,
            &md,
            BuildChargeTransactionOptions::default(),
        )
        .await
        .unwrap_err();
        assert!(format!("{err}").contains("mint address"));
    }

    #[tokio::test]
    async fn build_charge_invalid_blockhash() {
        let signer = make_signer();
        let rpc = dummy_rpc();
        let md = MethodDetails {
            recent_blockhash: Some("not-a-valid-hash!!!".to_string()),
            ..Default::default()
        };
        let err =
            build_charge_transaction(signer.as_ref(), &rpc, "1000000", "SOL", RECIPIENT, &md).await;
        assert!(err.is_err());
        assert!(format!("{}", err.unwrap_err()).contains("Invalid blockhash"));
    }

    // ── build_charge_transaction: SPL path ──

    #[tokio::test]
    async fn build_charge_spl_no_splits() {
        let signer = make_signer();
        let rpc = dummy_rpc();
        let md = MethodDetails {
            recent_blockhash: Some(ZERO_HASH.to_string()),
            token_program: Some(programs::TOKEN_PROGRAM.to_string()),
            decimals: Some(6),
            ..Default::default()
        };
        let payload =
            build_charge_transaction(signer.as_ref(), &rpc, "1000000", "USDC", RECIPIENT, &md)
                .await
                .unwrap();
        assert!(matches!(payload, CredentialPayload::Transaction { .. }));
    }

    #[tokio::test]
    async fn build_charge_spl_with_splits() {
        let signer = make_signer();
        let rpc = dummy_rpc();
        let split_addr = Pubkey::new_unique().to_string();
        let md = MethodDetails {
            recent_blockhash: Some(ZERO_HASH.to_string()),
            token_program: Some(programs::TOKEN_PROGRAM.to_string()),
            decimals: Some(6),
            splits: Some(vec![Split {
                recipient: split_addr,
                amount: "1000".to_string(),
                ata_creation_required: None,
                label: None,
                memo: None,
            }]),
            ..Default::default()
        };
        let payload =
            build_charge_transaction(signer.as_ref(), &rpc, "5000000", "USDC", RECIPIENT, &md)
                .await
                .unwrap();
        assert!(matches!(payload, CredentialPayload::Transaction { .. }));
    }

    // ── resolve_token_program ──

    #[test]
    fn resolve_tp_token_program() {
        let rpc = dummy_rpc();
        let mint = Pubkey::new_unique();
        let md = MethodDetails {
            token_program: Some(programs::TOKEN_PROGRAM.to_string()),
            ..Default::default()
        };
        let tp = resolve_token_program(&rpc, &mint, &md).unwrap();
        assert_eq!(tp.to_string(), programs::TOKEN_PROGRAM);
    }

    #[test]
    fn resolve_tp_token_2022() {
        let rpc = dummy_rpc();
        let mint = Pubkey::new_unique();
        let md = MethodDetails {
            token_program: Some(programs::TOKEN_2022_PROGRAM.to_string()),
            ..Default::default()
        };
        let tp = resolve_token_program(&rpc, &mint, &md).unwrap();
        assert_eq!(tp.to_string(), programs::TOKEN_2022_PROGRAM);
    }

    #[test]
    fn resolve_tp_invalid_program_string() {
        let rpc = dummy_rpc();
        let mint = Pubkey::new_unique();
        let md = MethodDetails {
            token_program: Some("invalid-key!!!".to_string()),
            ..Default::default()
        };
        let err = resolve_token_program(&rpc, &mint, &md);
        assert!(err.is_err());
        assert!(format!("{}", err.unwrap_err()).contains("Invalid token program"));
    }

    #[test]
    fn resolve_tp_unsupported_program() {
        let rpc = dummy_rpc();
        let mint = Pubkey::new_unique();
        // System program is a valid pubkey but not a supported token program.
        let md = MethodDetails {
            token_program: Some(programs::SYSTEM_PROGRAM.to_string()),
            ..Default::default()
        };
        let err = resolve_token_program(&rpc, &mint, &md);
        assert!(err.is_err());
        assert!(format!("{}", err.unwrap_err()).contains("Unsupported token program"));
    }

    // ── build_spl_instructions ──

    #[test]
    fn build_spl_no_splits() {
        let signer_pk = Pubkey::new_unique();
        let recipient = Pubkey::from_str(RECIPIENT).unwrap();
        let rpc = dummy_rpc();
        let md = MethodDetails {
            token_program: Some(programs::TOKEN_PROGRAM.to_string()),
            decimals: Some(6),
            ..Default::default()
        };
        let mut ixs = vec![];
        build_spl_instructions(
            &mut ixs,
            &signer_pk,
            &recipient,
            &rpc,
            USDC_MINT,
            &md,
            1_000_000,
            None,
            &[],
            None,
            false,
        )
        .unwrap();
        assert_eq!(ixs.len(), 1);
    }

    #[test]
    fn build_spl_rejects_missing_decimals() {
        // Audit #42: spec §7.2 requires `decimals` for SPL challenges;
        // we now error instead of silently defaulting to 6.
        let signer_pk = Pubkey::new_unique();
        let recipient = Pubkey::from_str(RECIPIENT).unwrap();
        let rpc = dummy_rpc();
        let md = MethodDetails {
            token_program: Some(programs::TOKEN_PROGRAM.to_string()),
            decimals: None, // missing — must reject
            ..Default::default()
        };
        let mut ixs = vec![];
        let err = build_spl_instructions(
            &mut ixs,
            &signer_pk,
            &recipient,
            &rpc,
            USDC_MINT,
            &md,
            1_000_000,
            None,
            &[],
            None,
            false,
        )
        .err()
        .expect("missing decimals should be rejected");
        assert!(
            format!("{err}").contains("decimals is required"),
            "got: {err}"
        );
    }

    #[test]
    fn build_spl_with_external_id_memo() {
        let signer_pk = Pubkey::new_unique();
        let recipient = Pubkey::from_str(RECIPIENT).unwrap();
        let rpc = dummy_rpc();
        let md = MethodDetails {
            token_program: Some(programs::TOKEN_PROGRAM.to_string()),
            decimals: Some(6),
            ..Default::default()
        };
        let mut ixs = vec![];
        build_spl_instructions(
            &mut ixs,
            &signer_pk,
            &recipient,
            &rpc,
            USDC_MINT,
            &md,
            1_000_000,
            Some("order-123"),
            &[],
            None,
            false,
        )
        .unwrap();

        assert_eq!(ixs.len(), 2);
        assert_eq!(
            ixs[1].program_id,
            Pubkey::from_str(programs::MEMO_PROGRAM).unwrap()
        );
        assert!(ixs[1].accounts.is_empty());
        assert_eq!(ixs[1].data, b"order-123");
    }

    #[test]
    fn build_spl_with_fee_payer() {
        let signer_pk = Pubkey::new_unique();
        let recipient = Pubkey::from_str(RECIPIENT).unwrap();
        let fee_payer = Pubkey::new_unique();
        let rpc = dummy_rpc();
        let md = MethodDetails {
            token_program: Some(programs::TOKEN_PROGRAM.to_string()),
            decimals: Some(6),
            ..Default::default()
        };
        let mut ixs = vec![];
        build_spl_instructions(
            &mut ixs,
            &signer_pk,
            &recipient,
            &rpc,
            USDC_MINT,
            &md,
            1_000_000,
            None,
            &[],
            Some(&fee_payer),
            false,
        )
        .unwrap();
        assert_eq!(ixs.len(), 1);
    }

    #[test]
    fn build_spl_with_splits() {
        // Audit #20: with ata_creation_required=None the client must NOT
        // emit the ATA-create instruction (even in client-paid mode).
        let signer_pk = Pubkey::new_unique();
        let recipient = Pubkey::from_str(RECIPIENT).unwrap();
        let split_recipient = Pubkey::new_unique();
        let rpc = dummy_rpc();
        let md = MethodDetails {
            token_program: Some(programs::TOKEN_PROGRAM.to_string()),
            decimals: Some(6),
            ..Default::default()
        };
        let splits = vec![Split {
            recipient: split_recipient.to_string(),
            amount: "1000".to_string(),
            ata_creation_required: None,
            label: None,
            memo: None,
        }];
        let mut ixs = vec![];
        build_spl_instructions(
            &mut ixs, &signer_pk, &recipient, &rpc, USDC_MINT, &md, 1_000_000, None, &splits, None,
            false,
        )
        .unwrap();
        // 1 primary transfer + 1 split transfer. No split ATA create.
        assert_eq!(ixs.len(), 2);
    }

    #[test]
    fn build_spl_creates_split_ata_only_when_flagged() {
        // Audit #20: ata_creation_required = Some(true) means the client
        // MUST include the ATA-create ix.
        let signer_pk = Pubkey::new_unique();
        let recipient = Pubkey::from_str(RECIPIENT).unwrap();
        let split_recipient = Pubkey::new_unique();
        let rpc = dummy_rpc();
        let md = MethodDetails {
            token_program: Some(programs::TOKEN_PROGRAM.to_string()),
            decimals: Some(6),
            ..Default::default()
        };
        let splits = vec![Split {
            recipient: split_recipient.to_string(),
            amount: "1000".to_string(),
            ata_creation_required: Some(true),
            label: None,
            memo: None,
        }];
        let mut ixs = vec![];
        build_spl_instructions(
            &mut ixs, &signer_pk, &recipient, &rpc, USDC_MINT, &md, 1_000_000, None, &splits, None,
            false,
        )
        .unwrap();
        // 1 primary transfer + 1 ATA create + 1 split transfer.
        assert_eq!(ixs.len(), 3);
    }

    #[test]
    fn build_spl_with_split_memo() {
        let signer_pk = Pubkey::new_unique();
        let recipient = Pubkey::from_str(RECIPIENT).unwrap();
        let split_recipient = Pubkey::new_unique();
        let rpc = dummy_rpc();
        let md = MethodDetails {
            token_program: Some(programs::TOKEN_PROGRAM.to_string()),
            decimals: Some(6),
            ..Default::default()
        };
        let splits = vec![Split {
            recipient: split_recipient.to_string(),
            amount: "1000".to_string(),
            ata_creation_required: None,
            label: None,
            memo: Some("platform fee".to_string()),
        }];
        let mut ixs = vec![];
        build_spl_instructions(
            &mut ixs, &signer_pk, &recipient, &rpc, USDC_MINT, &md, 1_000_000, None, &splits, None,
            false,
        )
        .unwrap();

        // 1 primary transfer + 1 split transfer + 1 split memo (no ATA create).
        assert_eq!(ixs.len(), 3);
        assert_eq!(
            ixs[2].program_id,
            Pubkey::from_str(programs::MEMO_PROGRAM).unwrap()
        );
        assert!(ixs[2].accounts.is_empty());
        assert_eq!(ixs[2].data, b"platform fee");
    }

    #[test]
    fn build_spl_rejects_long_split_memo() {
        let signer_pk = Pubkey::new_unique();
        let recipient = Pubkey::from_str(RECIPIENT).unwrap();
        let split_recipient = Pubkey::new_unique();
        let rpc = dummy_rpc();
        let md = MethodDetails {
            token_program: Some(programs::TOKEN_PROGRAM.to_string()),
            decimals: Some(6),
            ..Default::default()
        };
        let splits = vec![Split {
            recipient: split_recipient.to_string(),
            amount: "1000".to_string(),
            ata_creation_required: None,
            label: None,
            memo: Some("x".repeat(567)),
        }];
        let mut ixs = vec![];
        let err = build_spl_instructions(
            &mut ixs, &signer_pk, &recipient, &rpc, USDC_MINT, &md, 1_000_000, None, &splits, None,
            false,
        )
        .unwrap_err();

        assert!(format!("{err}").contains("memo cannot exceed 566 bytes"));
    }

    #[test]
    fn build_spl_with_fee_payer_split_ata_creation() {
        let signer_pk = Pubkey::new_unique();
        let recipient = Pubkey::from_str(RECIPIENT).unwrap();
        let split_recipient = Pubkey::new_unique();
        let fee_payer = Pubkey::new_unique();
        let rpc = dummy_rpc();
        let md = MethodDetails {
            token_program: Some(programs::TOKEN_PROGRAM.to_string()),
            decimals: Some(6),
            fee_payer: Some(true),
            fee_payer_key: Some(fee_payer.to_string()),
            ..Default::default()
        };
        let splits = vec![Split {
            recipient: split_recipient.to_string(),
            amount: "1000".to_string(),
            ata_creation_required: Some(true),
            label: None,
            memo: None,
        }];
        let mut ixs = vec![];
        build_spl_instructions(
            &mut ixs,
            &signer_pk,
            &recipient,
            &rpc,
            USDC_MINT,
            &md,
            1_000_000,
            None,
            &splits,
            Some(&fee_payer),
            false,
        )
        .unwrap();

        assert_eq!(ixs.len(), 3);
        assert_eq!(ixs[1].accounts[0].pubkey, fee_payer);
        assert_eq!(ixs[1].accounts[2].pubkey, split_recipient);
    }

    #[test]
    fn build_spl_fee_payer_excludes_unmarked_split_ata_creation() {
        let signer_pk = Pubkey::new_unique();
        let recipient = Pubkey::from_str(RECIPIENT).unwrap();
        let split_recipient = Pubkey::new_unique();
        let fee_payer = Pubkey::new_unique();
        let rpc = dummy_rpc();
        let md = MethodDetails {
            token_program: Some(programs::TOKEN_PROGRAM.to_string()),
            decimals: Some(6),
            fee_payer: Some(true),
            fee_payer_key: Some(fee_payer.to_string()),
            ..Default::default()
        };
        let splits = vec![Split {
            recipient: split_recipient.to_string(),
            amount: "1000".to_string(),
            ata_creation_required: None,
            label: None,
            memo: None,
        }];
        let mut ixs = vec![];
        build_spl_instructions(
            &mut ixs,
            &signer_pk,
            &recipient,
            &rpc,
            USDC_MINT,
            &md,
            1_000_000,
            None,
            &splits,
            Some(&fee_payer),
            false,
        )
        .unwrap();
        assert_eq!(ixs.len(), 2);
    }

    #[test]
    fn build_spl_refuses_unknown_token_2022_without_opt_in() {
        // A made-up base58 mint NOT in the known stablecoin allowlist,
        // explicitly placed on Token-2022. Default (allow_unknown_token_2022
        // = false) must refuse.
        // Valid base58 pubkey not in the stablecoin allowlist.
        const UNKNOWN_MINT: &str = "9XHRopERTd4LfQ8b6e3p9bN2WhxgQzDxFRtbq1XwQ4mP";
        let signer_pk = Pubkey::new_unique();
        let recipient = Pubkey::from_str(RECIPIENT).unwrap();
        let rpc = dummy_rpc();
        let md = MethodDetails {
            token_program: Some(programs::TOKEN_2022_PROGRAM.to_string()),
            decimals: Some(6),
            ..Default::default()
        };
        let mut ixs = vec![];
        let err = build_spl_instructions(
            &mut ixs,
            &signer_pk,
            &recipient,
            &rpc,
            UNKNOWN_MINT,
            &md,
            1_000_000,
            None,
            &[],
            None,
            false,
        );
        let err = err.expect_err("should refuse unknown Token-2022 mint");
        assert!(
            format!("{err}").contains("unknown Token-2022 mint"),
            "got: {err}"
        );
    }

    #[test]
    fn build_spl_allows_unknown_token_2022_with_opt_in() {
        // Same setup as above but with the opt-in flag set — gate passes
        // and the function builds successfully.
        // Valid base58 pubkey not in the stablecoin allowlist.
        const UNKNOWN_MINT: &str = "9XHRopERTd4LfQ8b6e3p9bN2WhxgQzDxFRtbq1XwQ4mP";
        let signer_pk = Pubkey::new_unique();
        let recipient = Pubkey::from_str(RECIPIENT).unwrap();
        let rpc = dummy_rpc();
        let md = MethodDetails {
            token_program: Some(programs::TOKEN_2022_PROGRAM.to_string()),
            decimals: Some(6),
            ..Default::default()
        };
        let mut ixs = vec![];
        build_spl_instructions(
            &mut ixs,
            &signer_pk,
            &recipient,
            &rpc,
            UNKNOWN_MINT,
            &md,
            1_000_000,
            None,
            &[],
            None,
            true,
        )
        .unwrap();
        assert!(!ixs.is_empty());
    }

    #[test]
    fn build_spl_allows_unknown_vanilla_token_mint() {
        // Arbitrary mint on the vanilla Token Program (no transfer hooks)
        // — gate does not apply.
        // Valid base58 pubkey not in the stablecoin allowlist.
        const UNKNOWN_MINT: &str = "9XHRopERTd4LfQ8b6e3p9bN2WhxgQzDxFRtbq1XwQ4mP";
        let signer_pk = Pubkey::new_unique();
        let recipient = Pubkey::from_str(RECIPIENT).unwrap();
        let rpc = dummy_rpc();
        let md = MethodDetails {
            token_program: Some(programs::TOKEN_PROGRAM.to_string()),
            decimals: Some(6),
            ..Default::default()
        };
        let mut ixs = vec![];
        build_spl_instructions(
            &mut ixs,
            &signer_pk,
            &recipient,
            &rpc,
            UNKNOWN_MINT,
            &md,
            1_000_000,
            None,
            &[],
            None,
            false,
        )
        .unwrap();
        assert!(!ixs.is_empty());
    }

    #[test]
    fn build_spl_does_not_gate_known_token_2022_stablecoin() {
        // PYUSD is Token-2022 but in the known allowlist — gate must not
        // fire even with allow_unknown_token_2022 = false.
        let signer_pk = Pubkey::new_unique();
        let recipient = Pubkey::from_str(RECIPIENT).unwrap();
        let rpc = dummy_rpc();
        let md = MethodDetails {
            token_program: Some(programs::TOKEN_2022_PROGRAM.to_string()),
            decimals: Some(6),
            ..Default::default()
        };
        let mut ixs = vec![];
        build_spl_instructions(
            &mut ixs,
            &signer_pk,
            &recipient,
            &rpc,
            mints::PYUSD_MAINNET,
            &md,
            1_000_000,
            None,
            &[],
            None,
            false,
        )
        .unwrap();
        assert!(!ixs.is_empty());
    }

    #[test]
    fn build_spl_invalid_mint() {
        let signer_pk = Pubkey::new_unique();
        let recipient = Pubkey::new_unique();
        let rpc = dummy_rpc();
        let md = MethodDetails {
            token_program: Some(programs::TOKEN_PROGRAM.to_string()),
            ..Default::default()
        };
        let mut ixs = vec![];
        let err = build_spl_instructions(
            &mut ixs,
            &signer_pk,
            &recipient,
            &rpc,
            "not-a-mint!!!",
            &md,
            1_000_000,
            None,
            &[],
            None,
            false,
        );
        assert!(err.is_err());
        assert!(format!("{}", err.unwrap_err()).contains("Invalid mint"));
    }

    #[test]
    fn build_spl_invalid_split_recipient() {
        let signer_pk = Pubkey::new_unique();
        let recipient = Pubkey::from_str(RECIPIENT).unwrap();
        let rpc = dummy_rpc();
        let md = MethodDetails {
            token_program: Some(programs::TOKEN_PROGRAM.to_string()),
            decimals: Some(6),
            ..Default::default()
        };
        let splits = vec![Split {
            recipient: "not-a-pubkey!!!".to_string(),
            amount: "1000".to_string(),
            ata_creation_required: None,
            label: None,
            memo: None,
        }];
        let mut ixs = vec![];
        let err = build_spl_instructions(
            &mut ixs, &signer_pk, &recipient, &rpc, USDC_MINT, &md, 1_000_000, None, &splits, None,
            false,
        );
        assert!(err.is_err());
        assert!(format!("{}", err.unwrap_err()).contains("Invalid split recipient"));
    }

    #[test]
    fn build_spl_invalid_split_amount() {
        let signer_pk = Pubkey::new_unique();
        let recipient = Pubkey::from_str(RECIPIENT).unwrap();
        let split_recipient = Pubkey::new_unique();
        let rpc = dummy_rpc();
        let md = MethodDetails {
            token_program: Some(programs::TOKEN_PROGRAM.to_string()),
            decimals: Some(6),
            ..Default::default()
        };
        let splits = vec![Split {
            recipient: split_recipient.to_string(),
            amount: "not-a-number".to_string(),
            ata_creation_required: None,
            label: None,
            memo: None,
        }];
        let mut ixs = vec![];
        let err = build_spl_instructions(
            &mut ixs, &signer_pk, &recipient, &rpc, USDC_MINT, &md, 1_000_000, None, &splits, None,
            false,
        );
        assert!(err.is_err());
        assert!(format!("{}", err.unwrap_err()).contains("Invalid split amount"));
    }

    // ── build_credential_header ──

    #[tokio::test]
    async fn build_credential_header_sol_happy_path() {
        use crate::protocol::core::Base64UrlJson;
        use crate::protocol::intents::ChargeRequest;

        let signer = make_signer();
        let rpc = dummy_rpc();
        let request = ChargeRequest {
            amount: "1000000".to_string(),
            currency: "SOL".to_string(),
            recipient: Some(RECIPIENT.to_string()),
            method_details: Some(
                serde_json::to_value(MethodDetails {
                    recent_blockhash: Some(ZERO_HASH.to_string()),
                    ..Default::default()
                })
                .unwrap(),
            ),
            ..Default::default()
        };
        let request_b64 = Base64UrlJson::from_typed(&request).unwrap();
        let challenge =
            PaymentChallenge::new("test-id", "test-realm", "solana", "charge", request_b64);

        let header = build_credential_header(signer.as_ref(), &rpc, &challenge)
            .await
            .unwrap();
        assert!(header.starts_with("Payment "));
    }

    #[tokio::test]
    async fn build_credential_header_no_recipient_error() {
        use crate::protocol::core::Base64UrlJson;
        use crate::protocol::intents::ChargeRequest;

        let signer = make_signer();
        let rpc = dummy_rpc();
        let request = ChargeRequest {
            amount: "1000000".to_string(),
            currency: "SOL".to_string(),
            recipient: None, // missing
            method_details: Some(
                serde_json::to_value(MethodDetails {
                    recent_blockhash: Some(ZERO_HASH.to_string()),
                    ..Default::default()
                })
                .unwrap(),
            ),
            ..Default::default()
        };
        let request_b64 = Base64UrlJson::from_typed(&request).unwrap();
        let challenge =
            PaymentChallenge::new("test-id", "test-realm", "solana", "charge", request_b64);

        let err = build_credential_header(signer.as_ref(), &rpc, &challenge).await;
        assert!(err.is_err());
        assert!(format!("{}", err.unwrap_err()).contains("No recipient"));
    }

    // ── Audit #10: client-side policy gates ──

    #[tokio::test]
    async fn build_charge_transaction_rejects_amount_above_max() {
        let signer = make_signer();
        let rpc = dummy_rpc();
        let md = MethodDetails {
            recent_blockhash: Some(ZERO_HASH.to_string()),
            ..Default::default()
        };
        let err = build_charge_transaction_with_options(
            signer.as_ref(),
            &rpc,
            "5000000",
            "SOL",
            RECIPIENT,
            &md,
            BuildChargeTransactionOptions {
                max_amount_base_units: Some(1_000_000),
                ..Default::default()
            },
        )
        .await
        .err()
        .expect("amount above cap should be rejected");
        let msg = format!("{err}");
        assert!(
            msg.contains("exceeds client max_amount_base_units"),
            "unexpected error: {msg}"
        );
    }

    #[tokio::test]
    async fn build_charge_transaction_accepts_amount_at_max() {
        let signer = make_signer();
        let rpc = dummy_rpc();
        let md = MethodDetails {
            recent_blockhash: Some(ZERO_HASH.to_string()),
            ..Default::default()
        };
        build_charge_transaction_with_options(
            signer.as_ref(),
            &rpc,
            "1000000",
            "SOL",
            RECIPIENT,
            &md,
            BuildChargeTransactionOptions {
                max_amount_base_units: Some(1_000_000),
                ..Default::default()
            },
        )
        .await
        .expect("amount equal to cap should be allowed");
    }

    #[tokio::test]
    async fn build_charge_transaction_rejects_unexpected_network() {
        let signer = make_signer();
        let rpc = dummy_rpc();
        let md = MethodDetails {
            network: Some("mainnet".to_string()),
            recent_blockhash: Some(ZERO_HASH.to_string()),
            ..Default::default()
        };
        let err = build_charge_transaction_with_options(
            signer.as_ref(),
            &rpc,
            "1000000",
            "SOL",
            RECIPIENT,
            &md,
            BuildChargeTransactionOptions {
                expected_network: Some("devnet".to_string()),
                ..Default::default()
            },
        )
        .await
        .err()
        .expect("network mismatch should be rejected");
        let msg = format!("{err}");
        assert!(
            msg.contains("does not match client expected_network"),
            "unexpected error: {msg}"
        );
    }

    // Without the `confidential` feature, a well-formed confidential challenge
    // must NOT be settled as a plaintext transfer: the builder fails closed,
    // pointing at the missing feature rather than degrading to a cleartext tx.
    #[cfg(not(feature = "confidential"))]
    #[tokio::test]
    async fn build_charge_transaction_fails_closed_on_confidential() {
        let signer = make_signer();
        let rpc = dummy_rpc();
        let md = MethodDetails {
            network: Some("mainnet".to_string()),
            decimals: Some(6),
            token_program: Some(programs::TOKEN_2022_PROGRAM.to_string()),
            confidential: Some(true),
            auditor_elgamal_pubkey: Some("auditor-key".to_string()),
            recent_blockhash: Some(ZERO_HASH.to_string()),
            ..Default::default()
        };
        let err = build_charge_transaction_with_options(
            signer.as_ref(),
            &rpc,
            "1000000",
            crate::protocol::solana::mints::USDPT_MAINNET,
            RECIPIENT,
            &md,
            BuildChargeTransactionOptions::default(),
        )
        .await
        .err()
        .expect("confidential charge should fail closed");
        assert!(
            format!("{err}").contains("feature"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn build_charge_transaction_accepts_matching_network() {
        let signer = make_signer();
        let rpc = dummy_rpc();
        let md = MethodDetails {
            network: Some("devnet".to_string()),
            recent_blockhash: Some(ZERO_HASH.to_string()),
            ..Default::default()
        };
        build_charge_transaction_with_options(
            signer.as_ref(),
            &rpc,
            "1000000",
            "SOL",
            RECIPIENT,
            &md,
            BuildChargeTransactionOptions {
                expected_network: Some("devnet".to_string()),
                ..Default::default()
            },
        )
        .await
        .expect("matching network should be allowed");
    }

    #[tokio::test]
    async fn build_credential_header_rejects_expired_challenge() {
        use crate::protocol::core::Base64UrlJson;
        use crate::protocol::intents::ChargeRequest;

        let signer = make_signer();
        let rpc = dummy_rpc();
        let request = ChargeRequest {
            amount: "1000000".to_string(),
            currency: "SOL".to_string(),
            recipient: Some(RECIPIENT.to_string()),
            method_details: Some(
                serde_json::to_value(MethodDetails {
                    recent_blockhash: Some(ZERO_HASH.to_string()),
                    ..Default::default()
                })
                .unwrap(),
            ),
            ..Default::default()
        };
        let request_b64 = Base64UrlJson::from_typed(&request).unwrap();
        let mut challenge =
            PaymentChallenge::new("test-id", "test-realm", "solana", "charge", request_b64);
        // RFC3339 timestamp in the distant past.
        challenge.expires = Some("1970-01-01T00:00:00Z".to_string());

        let err = build_credential_header(signer.as_ref(), &rpc, &challenge)
            .await
            .err()
            .expect("expired challenge should be rejected");
        assert!(
            format!("{err}").contains("expired"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn build_credential_header_accepts_future_expiry() {
        use crate::protocol::core::Base64UrlJson;
        use crate::protocol::intents::ChargeRequest;

        let signer = make_signer();
        let rpc = dummy_rpc();
        let request = ChargeRequest {
            amount: "1000000".to_string(),
            currency: "SOL".to_string(),
            recipient: Some(RECIPIENT.to_string()),
            method_details: Some(
                serde_json::to_value(MethodDetails {
                    recent_blockhash: Some(ZERO_HASH.to_string()),
                    ..Default::default()
                })
                .unwrap(),
            ),
            ..Default::default()
        };
        let request_b64 = Base64UrlJson::from_typed(&request).unwrap();
        let mut challenge =
            PaymentChallenge::new("test-id", "test-realm", "solana", "charge", request_b64);
        challenge.expires = Some("2999-01-01T00:00:00Z".to_string());

        build_credential_header(signer.as_ref(), &rpc, &challenge)
            .await
            .expect("future expiry should be accepted");
    }

    // ── Audit #17: method/intent gate on the credential builder ──

    #[tokio::test]
    async fn build_credential_header_rejects_non_solana_method() {
        use crate::protocol::core::Base64UrlJson;
        use crate::protocol::intents::ChargeRequest;

        let signer = make_signer();
        let rpc = dummy_rpc();
        let request = ChargeRequest {
            amount: "1000000".to_string(),
            currency: "SOL".to_string(),
            recipient: Some(RECIPIENT.to_string()),
            method_details: Some(
                serde_json::to_value(MethodDetails {
                    recent_blockhash: Some(ZERO_HASH.to_string()),
                    ..Default::default()
                })
                .unwrap(),
            ),
            ..Default::default()
        };
        let request_b64 = Base64UrlJson::from_typed(&request).unwrap();
        // Wrong method — would otherwise be accepted by the builder.
        let challenge =
            PaymentChallenge::new("test-id", "test-realm", "stripe", "charge", request_b64);

        let err = build_credential_header(signer.as_ref(), &rpc, &challenge)
            .await
            .err()
            .expect("non-solana method should be rejected");
        let msg = format!("{err}");
        assert!(
            msg.contains("not a solana/charge challenge") && msg.contains("method=`stripe`"),
            "unexpected error: {msg}"
        );
    }

    #[tokio::test]
    async fn build_credential_header_rejects_non_charge_intent() {
        use crate::protocol::core::Base64UrlJson;
        use crate::protocol::intents::ChargeRequest;

        let signer = make_signer();
        let rpc = dummy_rpc();
        let request = ChargeRequest {
            amount: "1000000".to_string(),
            currency: "SOL".to_string(),
            recipient: Some(RECIPIENT.to_string()),
            method_details: Some(
                serde_json::to_value(MethodDetails {
                    recent_blockhash: Some(ZERO_HASH.to_string()),
                    ..Default::default()
                })
                .unwrap(),
            ),
            ..Default::default()
        };
        let request_b64 = Base64UrlJson::from_typed(&request).unwrap();
        // Wrong intent.
        let challenge =
            PaymentChallenge::new("test-id", "test-realm", "solana", "session", request_b64);

        let err = build_credential_header(signer.as_ref(), &rpc, &challenge)
            .await
            .err()
            .expect("non-charge intent should be rejected");
        let msg = format!("{err}");
        assert!(
            msg.contains("not a solana/charge challenge") && msg.contains("intent=`session`"),
            "unexpected error: {msg}"
        );
    }

    #[tokio::test]
    async fn build_credential_header_invalid_method_details() {
        use crate::protocol::core::Base64UrlJson;
        use crate::protocol::intents::ChargeRequest;

        let signer = make_signer();
        let rpc = dummy_rpc();
        // A JSON string instead of an object fails to deserialize as MethodDetails.
        let request = ChargeRequest {
            amount: "1000000".to_string(),
            currency: "SOL".to_string(),
            recipient: Some(RECIPIENT.to_string()),
            method_details: Some(serde_json::json!("this-is-a-string")),
            ..Default::default()
        };
        let request_b64 = Base64UrlJson::from_typed(&request).unwrap();
        let challenge =
            PaymentChallenge::new("test-id", "test-realm", "solana", "charge", request_b64);

        let err = build_credential_header(signer.as_ref(), &rpc, &challenge).await;
        assert!(err.is_err());
        assert!(format!("{}", err.unwrap_err()).contains("Invalid method details"));
    }
}
