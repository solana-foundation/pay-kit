use std::str::FromStr;

use solana_hash::Hash;
use solana_instruction::{AccountMeta, Instruction};
use solana_keychain::SolanaSigner;
use solana_message::{v0, VersionedMessage};
use solana_pubkey::Pubkey;
use solana_rpc_client::rpc_client::RpcClient;
use solana_signature::Signature;
use solana_system_interface::instruction as system_instruction;
use solana_transaction::versioned::VersionedTransaction;

use crate::{
    error::Error,
    protocol::schemes::exact::{
        caip2_network_for_cluster, cluster_for_caip2_network, default_token_program_for_currency,
        programs, resolve_stablecoin_mint, PaymentPayload, PaymentProof, PaymentRequiredEnvelope,
        PaymentRequirements, PaymentSignatureEnvelope, EXACT_SCHEME, MAX_MEMO_BYTES,
        SOLANA_MAINNET,
    },
    PAYMENT_REQUIRED_HEADER, SOLANA_NETWORK, X402_V1_PAYMENT_REQUIRED_HEADER, X402_VERSION_V1,
    X402_VERSION_V2,
};

/// Build a payment transaction from x402 payment requirements.
///
/// Returns a `PaymentPayload` ready to be wrapped in `PAYMENT-SIGNATURE`.
pub async fn build_payment(
    signer: &dyn SolanaSigner,
    rpc: &RpcClient,
    requirements: &PaymentRequirements,
) -> Result<PaymentPayload, Error> {
    let amount: u64 = requirements
        .amount
        .parse()
        .map_err(|_| Error::Other(format!("Invalid amount: {}", requirements.amount)))?;

    let signer_pubkey = signer.pubkey();

    let recipient = Pubkey::from_str(&requirements.recipient)
        .map_err(|e| Error::Other(format!("Invalid recipient: {e}")))?;

    let use_fee_payer =
        requirements.fee_payer.unwrap_or(false) && requirements.fee_payer_key.is_some();

    let fee_payer_pubkey = if use_fee_payer {
        let key = requirements.fee_payer_key.as_ref().unwrap();
        Some(Pubkey::from_str(key).map_err(|e| Error::Other(format!("Invalid fee payer: {e}")))?)
    } else {
        None
    };

    let mut instructions = Vec::new();

    // Compute budget. Canonical SVM exact validates these by index.
    instructions.push(compute_unit_limit_ix(20_000));
    instructions.push(compute_unit_price_ix(1));

    let cluster = requirements.cluster.as_deref();
    let mint = resolve_mint(&requirements.currency, cluster);

    if let Some(mint_str) = mint {
        build_spl_instructions(
            &mut instructions,
            &signer_pubkey,
            &recipient,
            mint_str,
            requirements,
            amount,
        )?;
    } else {
        build_sol_instructions(&mut instructions, &signer_pubkey, &recipient, amount)?;
    }

    instructions.push(memo_instruction(requirements)?);

    // Build and sign.
    let blockhash = if let Some(bh) = &requirements.recent_blockhash {
        Hash::from_str(bh).map_err(|e| Error::Other(format!("Invalid blockhash: {e}")))?
    } else {
        rpc.get_latest_blockhash()
            .map_err(|e| Error::Rpc(e.to_string()))?
    };

    let actual_fee_payer = fee_payer_pubkey.unwrap_or(signer_pubkey);
    let v0_message = v0::Message::try_compile(&actual_fee_payer, &instructions, &[], blockhash)
        .map_err(|e| Error::Other(format!("Failed to compile v0 message: {e}")))?;
    let versioned_message = VersionedMessage::V0(v0_message);
    let num_signers = versioned_message.header().num_required_signatures as usize;
    let mut tx = VersionedTransaction {
        signatures: vec![Signature::default(); num_signers],
        message: versioned_message,
    };

    let sig_bytes = signer
        .sign_message(&tx.message.serialize())
        .await
        .map_err(|e| Error::Other(format!("Signing failed: {e}")))?;
    let sig = Signature::from(<[u8; 64]>::from(sig_bytes));
    let signer_index = tx
        .message
        .static_account_keys()
        .iter()
        .position(|k| k == &signer_pubkey)
        .ok_or_else(|| Error::Other("Signer not found in transaction accounts".to_string()))?;
    tx.signatures[signer_index] = sig;

    let serialized =
        bincode::serialize(&tx).map_err(|e| Error::Other(format!("Serialization failed: {e}")))?;
    let encoded = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &serialized);

    Ok(PaymentPayload {
        network: requirements.network.clone(),
        proof: PaymentProof::Transaction {
            transaction: encoded,
        },
    })
}

/// Build a payment and return the base64-encoded `PAYMENT-SIGNATURE` header value,
/// ready to use directly with the x402 protocol.
///
/// This encodes the canonical v2 wire format expected by x402 facilitators:
/// `base64({ x402Version: X402_VERSION_V2, accepted, payload, resource? })`
pub async fn build_payment_header(
    signer: &dyn SolanaSigner,
    rpc: &RpcClient,
    requirements: &PaymentRequirements,
) -> Result<String, Error> {
    let payload = build_payment(signer, rpc, requirements).await?;
    let envelope = PaymentSignatureEnvelope {
        scheme: None,
        network: None,
        x402_version: X402_VERSION_V2,
        accepted: Some(requirements.to_accepted_value()),
        resource: requirements.resource_info(),
        payload: payload.proof,
    };

    encode_payment_envelope(&envelope)
}

/// Build a legacy v1 `X-PAYMENT` header value for older integrations.
pub async fn build_payment_header_v1(
    signer: &dyn SolanaSigner,
    rpc: &RpcClient,
    requirements: &PaymentRequirements,
) -> Result<String, Error> {
    let payload = build_payment(signer, rpc, requirements).await?;
    let envelope = PaymentSignatureEnvelope {
        scheme: Some(EXACT_SCHEME.to_string()),
        network: Some(v1_network_for_requirements(requirements).to_string()),
        x402_version: X402_VERSION_V1,
        accepted: None,
        resource: None,
        payload: payload.proof,
    };

    encode_payment_envelope(&envelope)
}

fn encode_payment_envelope(envelope: &PaymentSignatureEnvelope) -> Result<String, Error> {
    let json = serde_json::to_string(&envelope)
        .map_err(|e| Error::Other(format!("JSON serialization failed: {e}")))?;
    Ok(base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        json.as_bytes(),
    ))
}

/// Client-side preferences used when picking one offer from a server's
/// `accepts` list. Mirrors the MPP TS `SelectSolanaChargeChallengeOptions`.
#[derive(Debug, Clone, Default)]
pub struct ChallengeSelection<'a> {
    /// Solana network the client wants to pay on (cluster slug or CAIP-2).
    /// `None` defaults to mainnet.
    pub network: Option<&'a str>,
    /// Priority-ordered list of currencies the client is willing to pay in.
    /// Entries can be stablecoin symbols (`"USDC"`) or mint addresses; both
    /// resolve through `resolve_stablecoin_mint` so symbol/address are
    /// interchangeable. The first server offer matching the highest-priority
    /// currency wins. `None` falls back to "cheapest amount on the preferred
    /// network".
    pub currencies: Option<&'a [&'a str]>,
}

/// Parse an x402 challenge from response headers and/or body.
///
/// Checks for:
/// 1. `PAYMENT-REQUIRED` header containing base64-encoded JSON
/// 2. Response body with `{ "accepts": [...] }` (x402-express format)
///
/// Returns `None` if no Solana x402 challenge is found.
pub fn parse_x402_challenge(
    headers: &[(String, String)],
    body: Option<&str>,
) -> Option<PaymentRequirements> {
    parse_x402_challenge_with_selection(headers, body, &ChallengeSelection::default())
}

/// Parse an x402 challenge, preferring a specific SVM network.
pub fn parse_x402_challenge_for_network(
    headers: &[(String, String)],
    body: Option<&str>,
    preferred_network: Option<&str>,
) -> Option<PaymentRequirements> {
    parse_x402_challenge_with_selection(
        headers,
        body,
        &ChallengeSelection {
            network: preferred_network,
            currencies: None,
        },
    )
}

/// Parse an x402 challenge with full client-side selection preferences.
///
/// When `selection.currencies` is set, the first offer matching the
/// highest-priority currency is returned. When `None`, falls back to
/// cheapest-by-amount on the preferred network.
pub fn parse_x402_challenge_with_selection(
    headers: &[(String, String)],
    body: Option<&str>,
    selection: &ChallengeSelection<'_>,
) -> Option<PaymentRequirements> {
    if let Some(header) = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(PAYMENT_REQUIRED_HEADER))
    {
        if let Some(req) = parse_payment_required_header(&header.1, selection) {
            return Some(req);
        }
    }

    if let Some(header) = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(X402_V1_PAYMENT_REQUIRED_HEADER))
    {
        if let Ok(req) = serde_json::from_str::<PaymentRequirements>(&header.1) {
            return Some(req);
        }
    }

    if let Some(body) = body {
        if let Some(req) = parse_accepts_body(body, selection) {
            return Some(req);
        }
    }

    None
}

fn parse_payment_required_header(
    header: &str,
    selection: &ChallengeSelection<'_>,
) -> Option<PaymentRequirements> {
    let decoded =
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, header).ok()?;
    let envelope: PaymentRequiredEnvelope =
        serde_json::from_slice::<PaymentRequiredEnvelope>(&decoded)
            .ok()?
            .with_resource_on_accepts();
    select_requirement(envelope.accepts, selection)
}

/// Parse the x402-express body `{ "accepts": [...] }` into `PaymentRequirements`.
fn parse_accepts_body(
    body: &str,
    selection: &ChallengeSelection<'_>,
) -> Option<PaymentRequirements> {
    let envelope: PaymentRequiredEnvelope = serde_json::from_str::<PaymentRequiredEnvelope>(body)
        .ok()?
        .with_resource_on_accepts();
    select_requirement(envelope.accepts, selection)
}

fn select_requirement(
    accepts: Vec<PaymentRequirements>,
    selection: &ChallengeSelection<'_>,
) -> Option<PaymentRequirements> {
    let preferred_network = selection
        .network
        .map(caip2_network_for_cluster)
        .unwrap_or(SOLANA_MAINNET);

    fn amount(requirement: &PaymentRequirements) -> u64 {
        requirement.amount.parse::<u64>().unwrap_or(u64::MAX)
    }

    fn network_matches(requirement: &PaymentRequirements, preferred: &str) -> bool {
        requirement.network == preferred
            || (preferred == SOLANA_MAINNET && requirement.network == SOLANA_NETWORK)
            || requirement
                .cluster
                .as_deref()
                .map(caip2_network_for_cluster)
                .is_some_and(|network| network == preferred)
    }

    let solana_accepts: Vec<_> = accepts
        .into_iter()
        .filter(|requirement| cluster_for_caip2_network(&requirement.network).is_some())
        .collect();

    let on_preferred_network: Vec<&PaymentRequirements> = solana_accepts
        .iter()
        .filter(|requirement| network_matches(requirement, preferred_network))
        .collect();

    // Currency-preference path: iterate the client's accepted currencies in
    // priority order, returning the first server offer that matches.
    // Symbols and mint addresses are interchangeable — both resolve through
    // `resolve_stablecoin_mint`.
    if let Some(currencies) = selection.currencies {
        for accepted_currency in currencies {
            if let Some(matched) = on_preferred_network
                .iter()
                .find(|requirement| currencies_match(&requirement.currency, accepted_currency, requirement.cluster.as_deref()))
            {
                return Some((*matched).clone());
            }
        }
        // No accepted-currency match on the preferred network. Don't fall
        // back to cheapest — the client explicitly listed currencies it's
        // willing to pay; offering them anything else would be wrong.
        return None;
    }

    // No currency preference: pick cheapest on preferred network, falling
    // back to overall cheapest if the preferred network has no offers.
    on_preferred_network
        .into_iter()
        .min_by_key(|requirement| amount(requirement))
        .cloned()
        .or_else(|| solana_accepts.into_iter().min_by_key(amount))
}

/// Currency equivalence: `accepted` (client's preference, symbol or mint)
/// resolves to the same on-chain mint as `offered` (server's offer).
fn currencies_match(offered: &str, accepted: &str, cluster: Option<&str>) -> bool {
    let offered_mint = resolve_stablecoin_mint(offered, cluster).unwrap_or(offered);
    let accepted_mint = resolve_stablecoin_mint(accepted, cluster).unwrap_or(accepted);
    offered_mint == accepted_mint
}

fn memo_instruction(requirements: &PaymentRequirements) -> Result<Instruction, Error> {
    let data = if let Some(memo) = requirements
        .extra
        .as_ref()
        .and_then(|extra| extra.get("memo"))
        .and_then(|memo| memo.as_str())
    {
        let bytes = memo.as_bytes().to_vec();
        if bytes.len() > MAX_MEMO_BYTES {
            return Err(Error::Other(format!(
                "extra.memo exceeds maximum {MAX_MEMO_BYTES} bytes"
            )));
        }
        bytes
    } else {
        let mut nonce = [0u8; 16];
        getrandom::fill(&mut nonce)
            .map_err(|e| Error::Other(format!("Failed to generate nonce: {e}")))?;
        nonce
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
            .into_bytes()
    };

    Ok(Instruction {
        program_id: Pubkey::from_str(programs::MEMO_PROGRAM)
            .map_err(|e| Error::Other(e.to_string()))?,
        accounts: vec![],
        data,
    })
}

fn v1_network_for_requirements(requirements: &PaymentRequirements) -> &'static str {
    match requirements
        .cluster
        .as_deref()
        .unwrap_or(requirements.network.as_str())
    {
        "devnet" | "solana-devnet" | crate::protocol::schemes::exact::SOLANA_DEVNET => {
            "solana-devnet"
        }
        _ => SOLANA_NETWORK,
    }
}

// ── Compute budget instructions ──

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
    amount: u64,
) -> Result<(), Error> {
    instructions.push(system_instruction::transfer(
        signer_pubkey,
        recipient,
        amount,
    ));
    Ok(())
}

fn build_spl_instructions(
    instructions: &mut Vec<Instruction>,
    signer_pubkey: &Pubkey,
    recipient: &Pubkey,
    spl: &str,
    requirements: &PaymentRequirements,
    amount: u64,
) -> Result<(), Error> {
    let mint = Pubkey::from_str(spl).map_err(|e| Error::Other(format!("Invalid mint: {e}")))?;
    let token_program =
        Pubkey::from_str(requirements.token_program.as_deref().unwrap_or_else(|| {
            default_token_program_for_currency(
                &requirements.currency,
                requirements.cluster.as_deref(),
            )
        }))
        .map_err(|e| Error::Other(format!("Invalid token program: {e}")))?;
    let decimals = requirements.decimals.unwrap_or(6);

    let source_ata = get_associated_token_address(signer_pubkey, &mint, &token_program);
    let dest_ata = get_associated_token_address(recipient, &mint, &token_program);

    instructions.push(transfer_checked_ix(
        &token_program,
        &source_ata,
        &mint,
        &dest_ata,
        signer_pubkey,
        amount,
        decimals,
    ));

    Ok(())
}

/// Derive the Associated Token Account address (PDA).
fn get_associated_token_address(owner: &Pubkey, mint: &Pubkey, token_program: &Pubkey) -> Pubkey {
    let ata_program = Pubkey::from_str(programs::ASSOCIATED_TOKEN_PROGRAM).unwrap();
    let seeds = &[owner.as_ref(), token_program.as_ref(), mint.as_ref()];
    Pubkey::find_program_address(seeds, &ata_program).0
}

/// Build a TransferChecked instruction.
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
fn resolve_mint<'a>(currency: &'a str, cluster: Option<&str>) -> Option<&'a str> {
    resolve_stablecoin_mint(currency, cluster)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        protocol::schemes::exact::{mints, SOLANA_DEVNET},
        X402_VERSION_FIELD,
    };
    use async_trait::async_trait;
    use solana_keychain::{SignerError, SolanaSigner};
    use solana_transaction::Transaction as SolanaTransaction;

    struct MockSigner {
        pubkey: Pubkey,
        fail_sign: bool,
    }

    #[async_trait]
    impl SolanaSigner for MockSigner {
        fn pubkey(&self) -> solana_pubkey::Pubkey {
            self.pubkey
        }

        async fn sign_transaction(
            &self,
            _tx: &mut SolanaTransaction,
        ) -> Result<solana_keychain::SignTransactionResult, SignerError> {
            Err(SignerError::Other("unused".to_string()))
        }

        async fn sign_message(
            &self,
            _message: &[u8],
        ) -> Result<solana_signature::Signature, SignerError> {
            if self.fail_sign {
                Err(SignerError::SigningFailed("boom".to_string()))
            } else {
                Ok(Signature::from([7u8; 64]))
            }
        }

        async fn is_available(&self) -> bool {
            true
        }
    }

    fn test_requirements(currency: &str) -> PaymentRequirements {
        PaymentRequirements {
            network: SOLANA_DEVNET.to_string(),
            cluster: Some("devnet".to_string()),
            recipient: Pubkey::new_unique().to_string(),
            amount: "1000".to_string(),
            currency: currency.to_string(),
            decimals: if crate::protocol::schemes::exact::is_native_sol(currency) {
                None
            } else {
                Some(6)
            },
            token_program: None,
            resource: "/resource".to_string(),
            description: Some("test".to_string()),
            max_age: Some(60),
            recent_blockhash: Some(Hash::new_from_array([5u8; 32]).to_string()),
            fee_payer: None,
            fee_payer_key: None,
            extra: None,
            accepted: None,
            resource_info: None,
        }
    }

    fn decode_tx(encoded: &str) -> VersionedTransaction {
        let bytes =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, encoded).unwrap();
        bincode::deserialize(&bytes).unwrap()
    }

    fn memo_instruction_from_tx(
        tx: &VersionedTransaction,
    ) -> &solana_message::compiled_instruction::CompiledInstruction {
        let memo_program = Pubkey::from_str(programs::MEMO_PROGRAM).unwrap();
        tx.message
            .instructions()
            .iter()
            .find(|instruction| {
                tx.message
                    .static_account_keys()
                    .get(instruction.program_id_index as usize)
                    == Some(&memo_program)
            })
            .expect("memo instruction")
    }

    #[test]
    fn parse_x402_express_body() {
        let body = serde_json::json!({
            X402_VERSION_FIELD: X402_VERSION_V1,
            "error": "PAYMENT-SIGNATURE header is required",
            "accepts": [{
                "scheme": EXACT_SCHEME,
                "network": "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
                "maxAmountRequired": "1000",
                "resource": "http://localhost:3402/x402/joke",
                "description": "A random joke",
                "payTo": "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY",
                "maxTimeoutSeconds": 60,
                "asset": "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
                "extra": { "feePayer": "6AfzJJo1KfhNWKe56wa5EWszTNQ7B1W5Kfh5SY2JkRGQ" }
            }]
        })
        .to_string();

        let req = parse_accepts_body(&body, &ChallengeSelection::default()).unwrap();
        assert_eq!(req.amount, "1000");
        assert_eq!(
            req.recipient,
            "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY"
        );
        assert_eq!(
            req.cluster.as_deref(),
            Some(crate::protocol::schemes::exact::SOLANA_DEVNET)
        );
        assert_eq!(req.fee_payer, Some(true));
        assert_eq!(
            req.fee_payer_key.as_deref(),
            Some("6AfzJJo1KfhNWKe56wa5EWszTNQ7B1W5Kfh5SY2JkRGQ")
        );
        assert_eq!(req.currency, "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU");
    }

    #[test]
    fn parse_x402_express_body_no_solana() {
        let body = r#"{ "accepts": [{ "network": "foo:bar" }] }"#;
        assert!(parse_accepts_body(body, &ChallengeSelection::default()).is_none());
    }

    // ── Client-side selection ──────────────────────────────────────────────

    fn multi_currency_body() -> String {
        // Server offers USDC and PYUSD on devnet, plus a SOL fallback.
        serde_json::json!({
            X402_VERSION_FIELD: X402_VERSION_V2,
            "accepts": [
                {
                    "scheme": EXACT_SCHEME,
                    "network": SOLANA_DEVNET,
                    "amount": "1000000",
                    "asset": mints::USDC_DEVNET,
                    "payTo": "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY",
                    "maxTimeoutSeconds": 60,
                    "extra": { "decimals": 6 }
                },
                {
                    "scheme": EXACT_SCHEME,
                    "network": SOLANA_DEVNET,
                    "amount": "1000000",
                    "asset": mints::PYUSD_DEVNET,
                    "payTo": "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY",
                    "maxTimeoutSeconds": 60,
                    "extra": { "decimals": 6 }
                },
                {
                    "scheme": EXACT_SCHEME,
                    "network": SOLANA_DEVNET,
                    "amount": "5000",
                    "asset": "SOL",
                    "payTo": "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY",
                    "maxTimeoutSeconds": 60
                }
            ]
        })
        .to_string()
    }

    #[test]
    fn select_picks_first_in_preferred_currency_order() {
        // Client's first choice is PYUSD; the offer list contains both USDC
        // and PYUSD. The client must get PYUSD even though USDC is listed
        // first by the server.
        let body = multi_currency_body();
        let selection = ChallengeSelection {
            network: Some("devnet"),
            currencies: Some(&["PYUSD", "USDC"]),
        };
        let req = parse_x402_challenge_with_selection(&[], Some(&body), &selection).unwrap();
        assert_eq!(req.currency, mints::PYUSD_DEVNET);
    }

    #[test]
    fn select_falls_back_to_second_choice_when_first_unavailable() {
        // Client wants USDT first, then USDC. Server doesn't offer USDT.
        let body = multi_currency_body();
        let selection = ChallengeSelection {
            network: Some("devnet"),
            currencies: Some(&["USDT", "USDC"]),
        };
        let req = parse_x402_challenge_with_selection(&[], Some(&body), &selection).unwrap();
        assert_eq!(req.currency, mints::USDC_DEVNET);
    }

    #[test]
    fn select_returns_none_when_no_currency_matches_client_list() {
        // Client only accepts USDT; server offers USDC, PYUSD, SOL. No
        // match → return None (don't fall back to something the client
        // didn't list).
        let body = multi_currency_body();
        let selection = ChallengeSelection {
            network: Some("devnet"),
            currencies: Some(&["USDT"]),
        };
        assert!(parse_x402_challenge_with_selection(&[], Some(&body), &selection).is_none());
    }

    #[test]
    fn select_accepts_mint_addresses_as_currency_keys() {
        // Client passes the on-chain mint address instead of the symbol.
        // `currencies_match` should resolve both sides and accept the offer.
        let body = multi_currency_body();
        let selection = ChallengeSelection {
            network: Some("devnet"),
            currencies: Some(&[mints::USDC_DEVNET]),
        };
        let req = parse_x402_challenge_with_selection(&[], Some(&body), &selection).unwrap();
        assert_eq!(req.currency, mints::USDC_DEVNET);
    }

    #[test]
    fn select_no_preference_picks_cheapest() {
        // Backward-compat: when no currency preference is given, pick the
        // cheapest by amount on the preferred network. SOL costs 5000 base
        // units in the fixture, the stablecoins cost 1_000_000 — SOL wins.
        let body = multi_currency_body();
        let selection = ChallengeSelection {
            network: Some("devnet"),
            currencies: None,
        };
        let req = parse_x402_challenge_with_selection(&[], Some(&body), &selection).unwrap();
        assert_eq!(req.currency, "SOL");
    }

    #[test]
    fn parse_x402_header_format() {
        let json = serde_json::json!({
            X402_VERSION_FIELD: X402_VERSION_V1,
            "accepts": [{
                "scheme": EXACT_SCHEME,
                "network": "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
                "recipient": "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY",
                "amount": "10000",
                "currency": "USDC",
                "resource": "/api/v1/data",
                "decimals": 6
            }]
        });

        let headers = vec![(
            PAYMENT_REQUIRED_HEADER.to_string(),
            base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                json.to_string().as_bytes(),
            ),
        )];

        let req = parse_x402_challenge(&headers, None).unwrap();
        assert_eq!(req.amount, "10000");
        assert_eq!(req.currency, "USDC");
    }

    #[test]
    fn parse_x402_v2_auth_only_header_returns_none() {
        let json = serde_json::json!({
            X402_VERSION_FIELD: X402_VERSION_V2,
            "accepts": [],
            "extensions": {
                crate::SIGN_IN_WITH_X: {
                    "domain": "api.example.com",
                    "uri": "https://api.example.com",
                    "version": "1",
                    "nonce": "nonce-123",
                    "issuedAt": "2026-04-27T00:00:00Z",
                    "supportedChains": [{
                        "chainId": SOLANA_MAINNET,
                        "type": "ed25519",
                        "signatureScheme": "siws"
                    }]
                }
            }
        });
        let headers = vec![(
            PAYMENT_REQUIRED_HEADER.to_string(),
            base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                json.to_string().as_bytes(),
            ),
        )];

        assert!(parse_x402_challenge(&headers, None).is_none());
    }

    #[test]
    fn parse_x402_v2_header_preserves_selected_accepted_and_resource() {
        let selected = serde_json::json!({
            "scheme": EXACT_SCHEME,
            "network": "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
            "amount": "1000",
            "asset": mints::USDT_MAINNET,
            "payTo": "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY",
            "maxTimeoutSeconds": 300,
            "extra": {
                "feePayer": "6AfzJJo1KfhNWKe56wa5EWszTNQ7B1W5Kfh5SY2JkRGQ",
                "recentBlockhash": Hash::new_from_array([9u8; 32]).to_string(),
                "tokenProgram": programs::TOKEN_PROGRAM,
                "decimals": 6
            }
        });
        let json = serde_json::json!({
            X402_VERSION_FIELD: X402_VERSION_V2,
            "resource": { "url": "https://api.example.test/data", "description": "Data" },
            "accepts": [
                {
                    "scheme": EXACT_SCHEME,
                    "network": "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
                    "amount": "1",
                    "asset": "devnet-token",
                    "payTo": "devnet-recipient",
                    "maxTimeoutSeconds": 300,
                    "extra": {}
                },
                selected.clone()
            ]
        });
        let headers = vec![(
            PAYMENT_REQUIRED_HEADER.to_string(),
            base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                json.to_string().as_bytes(),
            ),
        )];

        let req = parse_x402_challenge(&headers, None).unwrap();
        assert_eq!(req.amount, "1000");
        assert_eq!(req.currency, mints::USDT_MAINNET);
        assert_eq!(req.accepted.as_ref(), Some(&selected));
        assert_eq!(
            req.resource_info
                .as_ref()
                .map(|resource| resource.url.as_str()),
            Some("https://api.example.test/data")
        );
    }

    #[test]
    fn parse_x402_challenge_from_body() {
        let body = serde_json::json!({
            X402_VERSION_FIELD: X402_VERSION_V1,
            "accepts": [{
                "scheme": EXACT_SCHEME,
                "network": "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
                "maxAmountRequired": "5000",
                "payTo": "abc123",
                "asset": "SOL",
                "resource": "/test"
            }]
        })
        .to_string();

        let headers: Vec<(String, String)> = vec![];
        let req = parse_x402_challenge(&headers, Some(&body)).unwrap();
        assert_eq!(req.amount, "5000");
        assert_eq!(req.recipient, "abc123");
        assert_eq!(
            req.cluster.as_deref(),
            Some(crate::protocol::schemes::exact::SOLANA_MAINNET)
        );
    }

    #[test]
    fn parse_x402_challenge_prefers_header() {
        let header_json = serde_json::json!({
            X402_VERSION_FIELD: X402_VERSION_V1,
            "accepts": [{
                "scheme": EXACT_SCHEME,
                "network": "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
                "recipient": "from-header",
                "amount": "100",
                "currency": "SOL",
                "resource": "/test"
            }]
        });
        let headers = vec![(
            PAYMENT_REQUIRED_HEADER.to_string(),
            base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                header_json.to_string().as_bytes(),
            ),
        )];
        let body = r#"{ "accepts": [{ "network": "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp", "payTo": "from-body", "maxAmountRequired": "999", "asset": "SOL", "resource": "/test" }] }"#;

        let req = parse_x402_challenge(&headers, Some(body)).unwrap();
        assert_eq!(req.recipient, "from-header");
        assert_eq!(req.amount, "100");
    }

    #[test]
    fn parse_invalid_returns_none() {
        assert!(parse_accepts_body("not json", &ChallengeSelection::default()).is_none());
        assert!(parse_x402_challenge(&[], None).is_none());
        assert!(parse_x402_challenge(&[], Some("garbage")).is_none());
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
        assert_eq!(resolve_mint("USDT", None), Some(mints::USDT_MAINNET));
        assert_eq!(resolve_mint("USDG", None), Some(mints::USDG_MAINNET));
        assert_eq!(
            resolve_mint("USDG", Some("devnet")),
            Some(mints::USDG_DEVNET)
        );
        assert_eq!(resolve_mint("PYUSD", None), Some(mints::PYUSD_MAINNET));
        assert_eq!(
            resolve_mint("PYUSD", Some("devnet")),
            Some(mints::PYUSD_DEVNET)
        );
        assert_eq!(resolve_mint("CASH", None), Some(mints::CASH_MAINNET));
    }

    #[test]
    fn resolve_mint_passthrough() {
        let addr = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
        assert_eq!(resolve_mint(addr, None), Some(addr));
    }

    #[tokio::test]
    async fn build_payment_for_sol_uses_recipient_and_memo() {
        let signer = MockSigner {
            pubkey: Pubkey::new_unique(),
            fail_sign: false,
        };
        let rpc = RpcClient::new("http://localhost:8899".to_string());
        let requirements = test_requirements("SOL");

        let payload = build_payment(&signer, &rpc, &requirements).await.unwrap();
        assert_eq!(payload.network, SOLANA_DEVNET);
        let PaymentProof::Transaction { transaction } = payload.proof else {
            panic!("expected transaction payload");
        };
        let tx = decode_tx(&transaction);
        assert!(tx.message.static_account_keys().contains(&signer.pubkey));
        assert_eq!(tx.message.instructions().len(), 4);
        let memo_ix = memo_instruction_from_tx(&tx);
        assert!(memo_ix.accounts.is_empty());
        assert_eq!(memo_ix.data.len(), 32);
        assert!(std::str::from_utf8(&memo_ix.data)
            .unwrap()
            .chars()
            .all(|ch| ch.is_ascii_hexdigit()));
    }

    #[tokio::test]
    async fn build_payment_for_spl_adds_token_instructions() {
        let signer = MockSigner {
            pubkey: Pubkey::new_unique(),
            fail_sign: false,
        };
        let rpc = RpcClient::new("http://localhost:8899".to_string());
        let requirements = test_requirements("USDC");

        let payload = build_payment(&signer, &rpc, &requirements).await.unwrap();
        let PaymentProof::Transaction { transaction } = payload.proof else {
            panic!("expected transaction payload");
        };
        let tx = decode_tx(&transaction);
        assert_eq!(tx.message.instructions().len(), 4);
        assert_eq!(tx.message.instructions()[0].data[0], 2);
        assert_eq!(tx.message.instructions()[1].data[0], 3);
        assert!(memo_instruction_from_tx(&tx).accounts.is_empty());
    }

    #[tokio::test]
    async fn build_payment_uses_server_requested_memo() {
        let signer = MockSigner {
            pubkey: Pubkey::new_unique(),
            fail_sign: false,
        };
        let rpc = RpcClient::new("http://localhost:8899".to_string());
        let mut requirements = test_requirements("USDC");
        requirements.extra = Some(serde_json::json!({ "memo": "order_12345" }));

        let payload = build_payment(&signer, &rpc, &requirements).await.unwrap();
        let PaymentProof::Transaction { transaction } = payload.proof else {
            panic!("expected transaction payload");
        };
        let tx = decode_tx(&transaction);
        let memo_ix = memo_instruction_from_tx(&tx);

        assert!(memo_ix.accounts.is_empty());
        assert_eq!(memo_ix.data, b"order_12345");
    }

    #[tokio::test]
    async fn build_payment_without_server_memo_generates_unique_nonce_memos() {
        let signer = MockSigner {
            pubkey: Pubkey::new_unique(),
            fail_sign: false,
        };
        let rpc = RpcClient::new("http://localhost:8899".to_string());
        let requirements = test_requirements("USDC");

        let first = build_payment(&signer, &rpc, &requirements).await.unwrap();
        let second = build_payment(&signer, &rpc, &requirements).await.unwrap();
        let PaymentProof::Transaction { transaction: first } = first.proof else {
            panic!("expected transaction payload");
        };
        let PaymentProof::Transaction {
            transaction: second,
        } = second.proof
        else {
            panic!("expected transaction payload");
        };
        let first_tx = decode_tx(&first);
        let second_tx = decode_tx(&second);
        let first_memo = std::str::from_utf8(&memo_instruction_from_tx(&first_tx).data).unwrap();
        let second_memo = std::str::from_utf8(&memo_instruction_from_tx(&second_tx).data).unwrap();

        assert_ne!(first, second);
        assert_ne!(first_memo, second_memo);
        assert_eq!(first_memo.len(), 32);
        assert_eq!(second_memo.len(), 32);
        assert!(first_memo.chars().all(|ch| ch.is_ascii_hexdigit()));
        assert!(second_memo.chars().all(|ch| ch.is_ascii_hexdigit()));
    }

    #[tokio::test]
    async fn build_payment_header_wraps_exact_envelope() {
        let signer = MockSigner {
            pubkey: Pubkey::new_unique(),
            fail_sign: false,
        };
        let rpc = RpcClient::new("http://localhost:8899".to_string());
        let requirements = test_requirements("SOL");

        let header = build_payment_header(&signer, &rpc, &requirements)
            .await
            .unwrap();
        let decoded =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, header).unwrap();
        let envelope: PaymentSignatureEnvelope = serde_json::from_slice(&decoded).unwrap();
        assert!(envelope.scheme.is_none());
        assert!(envelope.network.is_none());
        assert_eq!(envelope.x402_version, X402_VERSION_V2);
        assert!(envelope.accepted.is_some());
    }

    #[tokio::test]
    async fn build_payment_rejects_invalid_amount() {
        let signer = MockSigner {
            pubkey: Pubkey::new_unique(),
            fail_sign: false,
        };
        let rpc = RpcClient::new("http://localhost:8899".to_string());
        let mut requirements = test_requirements("SOL");
        requirements.amount = "abc".to_string();

        assert!(build_payment(&signer, &rpc, &requirements).await.is_err());
    }

    #[tokio::test]
    async fn build_payment_rejects_invalid_recipient() {
        let signer = MockSigner {
            pubkey: Pubkey::new_unique(),
            fail_sign: false,
        };
        let rpc = RpcClient::new("http://localhost:8899".to_string());
        let mut requirements = test_requirements("SOL");
        requirements.recipient = "not-a-pubkey".to_string();

        assert!(build_payment(&signer, &rpc, &requirements).await.is_err());
    }

    #[tokio::test]
    async fn build_payment_rejects_invalid_fee_payer() {
        let signer = MockSigner {
            pubkey: Pubkey::new_unique(),
            fail_sign: false,
        };
        let rpc = RpcClient::new("http://localhost:8899".to_string());
        let mut requirements = test_requirements("SOL");
        requirements.fee_payer = Some(true);
        requirements.fee_payer_key = Some("not-a-pubkey".to_string());

        assert!(build_payment(&signer, &rpc, &requirements).await.is_err());
    }

    #[tokio::test]
    async fn build_payment_rejects_invalid_blockhash() {
        let signer = MockSigner {
            pubkey: Pubkey::new_unique(),
            fail_sign: false,
        };
        let rpc = RpcClient::new("http://localhost:8899".to_string());
        let mut requirements = test_requirements("SOL");
        requirements.recent_blockhash = Some("bad-blockhash".to_string());

        assert!(build_payment(&signer, &rpc, &requirements).await.is_err());
    }

    #[tokio::test]
    async fn build_payment_rejects_oversized_seller_memo() {
        let signer = MockSigner {
            pubkey: Pubkey::new_unique(),
            fail_sign: false,
        };
        let rpc = RpcClient::new("http://localhost:8899".to_string());
        let mut requirements = test_requirements("USDC");
        requirements.extra = Some(serde_json::json!({
            "memo": "x".repeat(MAX_MEMO_BYTES + 1)
        }));

        let err = build_payment(&signer, &rpc, &requirements)
            .await
            .unwrap_err();
        assert!(matches!(err, Error::Other(message) if message.contains("extra.memo exceeds")));
    }

    #[tokio::test]
    async fn build_payment_propagates_signing_failure() {
        let signer = MockSigner {
            pubkey: Pubkey::new_unique(),
            fail_sign: true,
        };
        let rpc = RpcClient::new("http://localhost:8899".to_string());
        let requirements = test_requirements("SOL");

        assert!(build_payment(&signer, &rpc, &requirements).await.is_err());
    }

    #[test]
    fn private_helpers_build_expected_instructions() {
        let payer = Pubkey::new_unique();
        let recipient = Pubkey::new_unique();
        let mint = Pubkey::new_unique();
        let token_program = Pubkey::from_str(programs::TOKEN_PROGRAM).unwrap();

        let price_ix = compute_unit_price_ix(123);
        let limit_ix = compute_unit_limit_ix(456);
        assert_eq!(price_ix.data[0], 3);
        assert_eq!(limit_ix.data[0], 2);

        let ata = get_associated_token_address(&recipient, &mint, &token_program);

        let transfer_ix = transfer_checked_ix(&token_program, &ata, &mint, &ata, &payer, 999, 6);
        assert_eq!(transfer_ix.data[0], 12);
    }

    #[test]
    fn private_helpers_validate_sol_and_spl_builders() {
        let signer = Pubkey::new_unique();
        let recipient = Pubkey::new_unique();
        let mut instructions = Vec::new();
        build_sol_instructions(&mut instructions, &signer, &recipient, 100).unwrap();
        assert_eq!(instructions.len(), 1);

        let mut instructions = Vec::new();
        let requirements = test_requirements("USDC");
        build_spl_instructions(
            &mut instructions,
            &signer,
            &recipient,
            resolve_mint("USDC", Some("devnet")).unwrap(),
            &requirements,
            100,
        )
        .unwrap();
        assert_eq!(instructions.len(), 1);
    }
}
