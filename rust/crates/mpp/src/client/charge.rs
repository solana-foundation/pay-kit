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
use crate::protocol::solana::{programs, CredentialPayload, MethodDetails, Split};

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
}

/// Options for selecting one Solana charge challenge from a challenge set.
#[derive(Debug, Clone, Copy, Default)]
pub struct SelectChargeChallengeOptions<'a> {
    /// Currency symbol or mint address the client wants to pay with.
    pub currency: Option<&'a str>,
    /// Currency symbols or mint addresses in client preference order.
    pub currency_preferences: &'a [&'a str],
    /// Solana network identifier, e.g. "mainnet-beta", "devnet", or "localnet".
    pub network: Option<&'a str>,
}

/// Build a charge transaction from challenge parameters and additional client options.
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

    let splits = method_details.splits.as_deref().unwrap_or(&[]);
    if splits.len() > 8 {
        return Err(Error::TooManySplits);
    }

    let splits_total: u64 = splits
        .iter()
        .filter_map(|s| s.amount.parse::<u64>().ok())
        .sum();
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
    let blockhash = if let Some(bh) = &method_details.recent_blockhash {
        Hash::from_str(bh).map_err(|e| Error::Other(format!("Invalid blockhash: {e}")))?
    } else {
        rpc.get_latest_blockhash()
            .map_err(|e| Error::Rpc(e.to_string()))?
    };

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

    let payload = build_charge_transaction_with_options(
        signer,
        rpc,
        &request.amount,
        &request.currency,
        recipient,
        &method_details,
        BuildChargeTransactionOptions {
            external_id: request.external_id.clone(),
        },
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
) -> Result<(), Error> {
    let mint = Pubkey::from_str(spl).map_err(|e| Error::Other(format!("Invalid mint: {e}")))?;
    let token_program = resolve_token_program(rpc, &mint, method_details)?;
    let decimals = method_details.decimals.unwrap_or(6);

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
        add_spl_transfer(
            instructions,
            &split_recipient,
            split_amount,
            fee_payer.is_none() || split.ata_creation_required == Some(true),
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
    if data.len() > 566 {
        return Err(Error::Other("memo cannot exceed 566 bytes".into()));
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
/// Returns `None` for native SOL, or `Some(mint_address)` for SPL tokens.
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
    match network {
        None => true,
        Some(expected) => method_details.network.as_deref().unwrap_or("mainnet-beta") == expected,
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
            selection_challenge(
                "mainnet-usdc",
                "solana",
                mints::USDC_MAINNET,
                "mainnet-beta",
            ),
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
            selection_challenge(
                "usdc-mainnet",
                "solana",
                mints::USDC_MAINNET,
                "mainnet-beta",
            ),
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
        )
        .unwrap();
        assert_eq!(ixs.len(), 1);
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
        )
        .unwrap();
        assert_eq!(ixs.len(), 1);
    }

    #[test]
    fn build_spl_with_splits() {
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
        )
        .unwrap();
        // Primary recipient ATA creation is out of scope; split ATA creation is allowed.
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
        )
        .unwrap();

        assert_eq!(ixs.len(), 4);
        assert_eq!(
            ixs[3].program_id,
            Pubkey::from_str(programs::MEMO_PROGRAM).unwrap()
        );
        assert!(ixs[3].accounts.is_empty());
        assert_eq!(ixs[3].data, b"platform fee");
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
        )
        .unwrap();
        assert_eq!(ixs.len(), 2);
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
