//! Client-side payment building for the x402 `upto` scheme (payment-channel).
//!
//! The client opens a channel whose `deposit` is the authorized maximum, with
//! `authorized_signer = receiverAuthorizer` (the voucher signer) and
//! `payee = feePayer` — the facilitator's zero-share lifecycle seat, which also
//! sponsors the fee and rent. The client signs only the `open` transaction; the
//! fee payer broadcasts it and later submits the settlement carrying the
//! receiver authorizer's voucher for the metered amount.

use std::str::FromStr;

use solana_hash::Hash;
use solana_keychain::TransactionSigner;
use solana_pubkey::Pubkey;
use solana_rpc_client::rpc_client::RpcClient;

use crate::core::blockhash::CachedBlockhash;
use crate::core::payment_channels as pc;

use crate::x402::error::Error;
use crate::x402::protocol::schemes::upto::{
    Slot, UptoNonce, UptoPayload, UptoRequiredEnvelope, UptoRequirements, UptoSignatureEnvelope,
    UPTO_SCHEME,
};
use crate::x402::{PAYMENT_REQUIRED_HEADER, X402_VERSION_V2};

/// Build an `upto` payload for a `payment-channel` requirement.
///
/// `expires_at` is the voucher/authorization deadline (Unix seconds); `nonce`
/// identifies the logical request and seeds the channel salt, so rebuilding
/// the payment for the same request against the same challenge yields the
/// same channel rather than a second deposit. An empty `nonce` draws a random
/// salt. After an ambiguous outcome, resend the original header instead of
/// building a new one under a fresh nonce. The requirement SHOULD carry
/// `extra.recentBlockhash` and `extra.recentSlot` (the operator embeds both in
/// the 402 challenge so the client skips an RPC round-trip): the slot feeds
/// the program's `openSlot`, a channel-PDA seed the program only accepts
/// within a recent window. Both hints are optional per the upto spec — when
/// either is absent, a single `getLatestBlockhash` call against `rpc`
/// supplies the missing value(s). A `recentBlockhash` hint is signed only
/// once `rpc`, which serves the cluster the client pays on, confirms it is
/// live there: a hash from another cluster would open the channel on that
/// cluster instead.
pub async fn build_upto_payload(
    payer_signer: &dyn TransactionSigner,
    rpc: &RpcClient,
    requirements: &UptoRequirements,
    expires_at: i64,
    nonce: impl Into<String>,
    max_tx_version: Option<crate::core::tx::TxVersion>,
) -> Result<UptoPayload, Error> {
    let nonce = nonce.into();
    let max = requirements.max_amount()?;
    let mint = Pubkey::from_str(&requirements.asset)
        .map_err(|e| Error::Other(format!("invalid asset mint: {e}")))?;
    let fee_payer = Pubkey::from_str(&requirements.extra.fee_payer)
        .map_err(|e| Error::Other(format!("invalid feePayer: {e}")))?;
    let receiver_authorizer = Pubkey::from_str(&requirements.extra.receiver_authorizer)
        .map_err(|e| Error::Other(format!("invalid receiverAuthorizer: {e}")))?;
    if requirements.extra.withdraw_delay == 0 {
        return Err(Error::Other(
            "requirement missing extra.withdrawDelay".to_string(),
        ));
    }
    let beneficiary = Pubkey::from_str(&requirements.pay_to)
        .map_err(|e| Error::Other(format!("invalid payTo: {e}")))?;
    // Always explicit: the payee seat is held by the facilitator (fee payer)
    // with a zero implicit remainder, so 100% of settled funds must be
    // assigned to `payTo` through the recipients list.
    let recipients = vec![pc::Distribution {
        recipient: beneficiary,
        bps: pc::FULL_SHARE_BPS,
    }];
    let program_id = pc::default_program_id();
    let token_program = match &requirements.extra.token_program {
        Some(value) => Pubkey::from_str(value)
            .map_err(|e| Error::Other(format!("invalid tokenProgram: {e}")))?,
        None => Pubkey::from_str("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")
            .expect("valid token program"),
    };
    // Prefer the challenge-embedded hints (no RPC round-trip, and the operator
    // controls how fresh the `openSlot` seed is). Both are optional per the
    // upto spec, so fall back to one `getLatestBlockhash` call when either is
    // absent — its response context carries the current slot, covering both.
    let hint_blockhash = requirements.extra.recent_blockhash.as_deref();
    let hint_slot = requirements.extra.recent_slot.map(Slot::get);
    let fetched = match (hint_blockhash, hint_slot) {
        (Some(_), Some(_)) => None,
        _ => Some(fetch_blockhash_with_slot(rpc).await?),
    };
    let blockhash = match (hint_blockhash, &fetched) {
        (Some(hint), _) => verified_hint(rpc, hint).await?,
        (None, Some(fetched)) => Hash::from_str(&fetched.blockhash)
            .map_err(|e| Error::Other(format!("invalid recentBlockhash: {e}")))?,
        (None, None) => unreachable!("a missing blockhash hint fetches one"),
    };
    let open_slot = match (hint_slot, &fetched) {
        (Some(slot), _) => slot,
        (None, Some(fetched)) => fetched.slot,
        (None, None) => unreachable!("a missing slot hint fetches one"),
    };

    let salt = salt_for_nonce(&nonce);
    // “Clients MUST include a Memo instruction containing either the value
    // of extra.memo (when present) or a random nonce (at least 16 bytes,
    // hex-encoded)”: the memo keeps concurrent opens with identical
    // parameters distinct transactions.
    let memo = requirements
        .extra
        .memo
        .clone()
        .unwrap_or_else(random_memo_nonce);
    let options = pc::OpenTxOptions {
        memo: Some(memo),
        version: crate::core::tx::negotiate(
            requirements.extra.transaction_versions.as_deref(),
            max_tx_version,
        )?,
        ..Default::default()
    };
    let open = pc::build_open_payment_channel_tx_with_options(
        payer_signer,
        // Channel payee: the fee payer's zero-share lifecycle seat.
        &fee_payer,
        &mint,
        &receiver_authorizer,
        salt,
        open_slot,
        max,
        requirements.extra.withdraw_delay,
        recipients,
        &token_program,
        &program_id,
        &fee_payer,
        blockhash,
        &options,
    )
    .await?;

    Ok(UptoPayload {
        from: pc::pubkey_string(&payer_signer.pubkey()),
        max_amount: max.to_string(),
        expires_at,
        valid_after: requirements.extra.valid_after.unwrap_or(0),
        nonce: UptoNonce::new(salt),
        channel_id: pc::pubkey_string(&open.channel_id),
        deposit: max.to_string(),
        authorized_signer: pc::pubkey_string(&receiver_authorizer),
        open_slot: Slot::new(open_slot),
        open_transaction: Some(open.transaction),
    })
}

/// The latest blockhash and the slot it was observed at, in one
/// `getLatestBlockhash` call (its response context carries the slot).
async fn fetch_blockhash_with_slot(rpc: &RpcClient) -> Result<CachedBlockhash, Error> {
    use solana_rpc_client_api::{
        config::RpcContextConfig,
        request::RpcRequest,
        response::{Response, RpcBlockhash},
    };
    // Every call goes through the nonblocking client: mixing it with the
    // blocking one shares a connection pool across runtimes and can stall.
    let response: Response<RpcBlockhash> = rpc
        .get_inner_client()
        .send(
            RpcRequest::GetLatestBlockhash,
            serde_json::json!([RpcContextConfig {
                commitment: Some(rpc.commitment()),
                min_context_slot: None,
            }]),
        )
        .await
        .map_err(|e| Error::Rpc(e.to_string()))?;
    Ok(CachedBlockhash {
        blockhash: response.value.blockhash,
        last_valid_block_height: response.value.last_valid_block_height,
        slot: response.context.slot,
    })
}

/// The requirement's `recentBlockhash`, once the client's cluster knows it.
async fn verified_hint(rpc: &RpcClient, hint: &str) -> Result<Hash, Error> {
    // Only the nonblocking client is reachable here: a blocking call panics
    // on a current-thread runtime.
    crate::core::blockhash::resolve_challenge_blockhash(rpc.get_inner_client(), Some(hint))
        .await
        .map_err(|e| match e {
            crate::core::blockhash::ChallengeBlockhashError::Invalid(message) => {
                Error::Other(format!("invalid extra.recentBlockhash: {message}"))
            }
            crate::core::blockhash::ChallengeBlockhashError::Rpc(message) => Error::Rpc(message),
        })
}

/// The channel salt for a request `nonce`: derived from it, or random when the
/// caller supplied none.
fn salt_for_nonce(nonce: &str) -> u64 {
    if nonce.is_empty() {
        return pc::random_salt();
    }
    use sha2::{Digest, Sha256};
    let digest = Sha256::new()
        .chain_update(b"x402-upto-salt\0")
        .chain_update(nonce.as_bytes())
        .finalize();
    u64::from_le_bytes(digest[..8].try_into().expect("8-byte prefix"))
}

/// A fresh memo nonce: [`pc::MIN_MEMO_NONCE_BYTES`] CSPRNG bytes, hex encoded.
fn random_memo_nonce() -> String {
    let mut bytes = [0u8; pc::MIN_MEMO_NONCE_BYTES];
    getrandom::fill(&mut bytes).expect("getrandom CSPRNG failure");
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Wrap a payload in a `PAYMENT-SIGNATURE` envelope and base64-encode it.
pub fn encode_upto_header(
    requirements: &UptoRequirements,
    payload: UptoPayload,
) -> Result<String, Error> {
    // Emit the canonical x402 v2 shape: `{ x402Version, accepted, payload }`.
    // Per spec §5.2 the scheme/network live inside `accepted`, not at the
    // envelope level.
    let envelope = UptoSignatureEnvelope {
        x402_version: X402_VERSION_V2,
        accepted: serde_json::to_value(requirements)
            .map_err(|e| Error::Other(format!("upto accepted serialization failed: {e}")))?,
        payload,
    };
    let json = serde_json::to_string(&envelope)
        .map_err(|e| Error::Other(format!("upto envelope serialization failed: {e}")))?;
    Ok(base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        json.as_bytes(),
    ))
}

/// Build the full `PAYMENT-SIGNATURE` header value for an `upto` payment.
pub async fn build_upto_header(
    payer_signer: &dyn TransactionSigner,
    rpc: &RpcClient,
    requirements: &UptoRequirements,
    expires_at: i64,
    nonce: impl Into<String>,
    max_tx_version: Option<crate::core::tx::TxVersion>,
) -> Result<String, Error> {
    let payload = build_upto_payload(
        payer_signer,
        rpc,
        requirements,
        expires_at,
        nonce,
        max_tx_version,
    )
    .await?;
    encode_upto_header(requirements, payload)
}

/// Parse a 402 `upto` challenge from a `PAYMENT-REQUIRED` header value or body,
/// returning the first advertised `upto` requirement. Use [`parse_upto_accepts`]
/// to consider every advertised currency.
pub fn parse_upto_challenge(
    headers: &[(String, String)],
    body: Option<&str>,
) -> Option<UptoRequirements> {
    parse_upto_accepts(headers, body).into_iter().next()
}

/// Parse *all* `upto` requirements advertised on a 402 (every `scheme == "upto"`
/// `accepts` entry), so a balance- and cost-aware selector can choose among the
/// offered currencies — not just the first. Empty when none are present.
pub fn parse_upto_accepts(
    headers: &[(String, String)],
    body: Option<&str>,
) -> Vec<UptoRequirements> {
    let from_header = headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(PAYMENT_REQUIRED_HEADER))
        .and_then(|(_, value)| {
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, value).ok()
        })
        .and_then(|bytes| serde_json::from_slice::<UptoRequiredEnvelope>(&bytes).ok());

    let Some(envelope) = from_header
        .or_else(|| body.and_then(|b| serde_json::from_str::<UptoRequiredEnvelope>(b).ok()))
    else {
        return Vec::new();
    };

    envelope
        .accepts
        .into_iter()
        .filter(|req| req.scheme == UPTO_SCHEME)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::x402::protocol::schemes::upto::UptoExtra;

    const RECEIVER_AUTHORIZER: &str = "9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin";

    fn make_signer() -> Box<dyn TransactionSigner> {
        let sk = ed25519_dalek::SigningKey::from_bytes(&[42u8; 32]);
        let mut kp = [0u8; 64];
        kp[..32].copy_from_slice(sk.as_bytes());
        kp[32..].copy_from_slice(sk.verifying_key().as_bytes());
        Box::new(solana_keychain::MemorySigner::from_bytes(&kp).expect("valid keypair"))
    }

    fn requirements_without_hints() -> UptoRequirements {
        let mut req = requirements();
        req.extra.recent_blockhash = None;
        req.extra.recent_slot = None;
        req
    }

    fn requirements() -> UptoRequirements {
        UptoRequirements {
            scheme: UPTO_SCHEME.to_string(),
            network: "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1".to_string(),
            amount: "1000000".to_string(),
            asset: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v".to_string(),
            pay_to: "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY".to_string(),
            max_timeout_seconds: 300,
            extra: UptoExtra {
                token_program: None,
                fee_payer: RECEIVER_AUTHORIZER.to_string(),
                receiver_authorizer: RECEIVER_AUTHORIZER.to_string(),
                withdraw_delay: 900,
                recent_blockhash: Some(Hash::default().to_string()),
                last_valid_block_height: None,
                recent_slot: Some(Slot::new(314)),
                valid_after: None,
                memo: None,
                transaction_versions: None,
            },
        }
    }

    fn sample_payload() -> UptoPayload {
        UptoPayload {
            from: "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY".to_string(),
            max_amount: "1000000".to_string(),
            expires_at: 4_102_444_800,
            valid_after: 0,
            nonce: UptoNonce::new(7),
            channel_id: "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY".to_string(),
            deposit: "1000000".to_string(),
            authorized_signer: RECEIVER_AUTHORIZER.to_string(),
            open_slot: Slot::new(314),
            open_transaction: Some("tx".to_string()),
        }
    }

    #[test]
    fn encode_header_produces_upto_envelope() {
        let header = encode_upto_header(&requirements(), sample_payload()).unwrap();
        let bytes =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &header).unwrap();
        let envelope: UptoSignatureEnvelope = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            envelope.accepted.get("scheme").and_then(|s| s.as_str()),
            Some(UPTO_SCHEME)
        );
        assert_eq!(envelope.payload.max_amount, "1000000");
        assert_eq!(envelope.x402_version, X402_VERSION_V2);
        assert!(envelope.accepted.is_object());
    }

    #[test]
    fn parse_challenge_reads_payment_required_header() {
        let envelope = UptoRequiredEnvelope {
            x402_version: X402_VERSION_V2,
            resource: None,
            accepts: vec![requirements()],
            error: None,
        };
        let json = serde_json::to_string(&envelope).unwrap();
        let value =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, json.as_bytes());
        let headers = vec![(PAYMENT_REQUIRED_HEADER.to_string(), value)];

        let parsed = parse_upto_challenge(&headers, None).unwrap();
        assert_eq!(parsed.amount, "1000000");
        assert_eq!(parsed.extra.fee_payer, RECEIVER_AUTHORIZER);
        assert_eq!(parsed.extra.receiver_authorizer, RECEIVER_AUTHORIZER);
        assert_eq!(parsed.extra.withdraw_delay, 900);
    }

    #[test]
    fn parse_challenge_returns_none_without_upto_offer() {
        assert!(parse_upto_challenge(&[], None).is_none());
    }

    /// An RPC that knows every blockhash and serves `succeeds` otherwise.
    fn live_rpc() -> RpcClient {
        use solana_rpc_client::mock_sender::MocksMap;
        use solana_rpc_client_api::request::RpcRequest;
        let mut mocks = MocksMap::default();
        for _ in 0..8 {
            mocks.insert(
                RpcRequest::IsBlockhashValid,
                serde_json::json!({ "context": { "slot": 1 }, "value": true }),
            );
        }
        RpcClient::new_mock_with_mocks_map("succeeds", mocks)
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn build_payload_uses_challenge_hints_without_rpc() {
        let signer = make_signer();
        // Every other RPC method errors loudly: with both hints embedded, the
        // build only asks whether the hinted blockhash is live.
        let rpc = crate::core::blockhash::mock_blockhash_rpc(true);
        let payload =
            build_upto_payload(&*signer, &rpc, &requirements(), 4_102_444_800, "n-1", None)
                .await
                .expect("payload from embedded hints");
        assert_eq!(payload.open_slot, Slot::new(314));
        assert!(payload.open_transaction.is_some());
    }

    /// Rebuilding the payment for the same request against the same challenge
    /// names the same channel, so a retry cannot open a second deposit.
    #[tokio::test(flavor = "multi_thread")]
    async fn the_request_nonce_pins_the_channel() {
        let signer = make_signer();
        let rpc = crate::core::blockhash::mock_blockhash_rpc(true);
        let build = |nonce: &'static str| {
            let signer = &signer;
            let rpc = &rpc;
            async move {
                build_upto_payload(&**signer, rpc, &requirements(), 4_102_444_800, nonce, None)
                    .await
                    .unwrap()
            }
        };
        let first = build("request-7").await;
        let retry = build("request-7").await;
        assert_eq!(first.channel_id, retry.channel_id);
        assert_eq!(first.nonce, retry.nonce);
        assert_ne!(build("request-8").await.channel_id, first.channel_id);
        assert_ne!(build("").await.channel_id, build("").await.channel_id);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn build_payload_falls_back_to_rpc_when_hints_absent() {
        let signer = make_signer();
        let rpc = RpcClient::new_mock("succeeds".to_string());
        let payload = build_upto_payload(
            &*signer,
            &rpc,
            &requirements_without_hints(),
            4_102_444_800,
            "n-1",
            None,
        )
        .await
        .expect("payload from RPC fallback");
        // MockSender's getLatestBlockhash reports context slot 1.
        assert_eq!(payload.open_slot, Slot::new(1));
        assert!(payload.open_transaction.is_some());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn build_payload_fetches_missing_slot_keeping_hinted_blockhash() {
        let signer = make_signer();
        let rpc = live_rpc();
        let mut req = requirements();
        req.extra.recent_slot = None;
        let payload = build_upto_payload(&*signer, &rpc, &req, 4_102_444_800, "n-1", None)
            .await
            .expect("payload with fetched slot");
        assert_eq!(payload.open_slot, Slot::new(1));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn build_payload_emits_the_declared_memo_after_open() {
        // A seller that declares extra.memo requires exactly one matching Memo
        // after open, so the client emits it.
        let signer = make_signer();
        let rpc = crate::core::blockhash::mock_blockhash_rpc(true);
        let mut req = requirements();
        req.extra.memo = Some("order-4711".to_string());
        let payload = build_upto_payload(&*signer, &rpc, &req, 4_102_444_800, "n-1", None)
            .await
            .expect("payload with a declared memo");
        let tx = pc::decode_transaction(
            payload
                .open_transaction
                .as_deref()
                .expect("open transaction"),
        )
        .expect("decodable open transaction");
        let keys = tx.message.static_account_keys();
        let instructions = tx.message.instructions();
        assert_eq!(instructions.len(), 2);
        let memo = &instructions[1];
        assert_eq!(keys[memo.program_id_index as usize], pc::memo_program_id());
        assert_eq!(memo.data.as_slice(), b"order-4711");

        // Without a declared memo the client still emits one Memo carrying a
        // random hex nonce of at least 16 bytes, fresh on every build.
        let nonce_memo = |payload: &UptoPayload| {
            let tx = pc::decode_transaction(
                payload
                    .open_transaction
                    .as_deref()
                    .expect("open transaction"),
            )
            .expect("decodable open transaction");
            let keys = tx.message.static_account_keys().to_vec();
            let instructions = tx.message.instructions();
            assert_eq!(instructions.len(), 2);
            let memo = &instructions[1];
            assert_eq!(keys[memo.program_id_index as usize], pc::memo_program_id());
            String::from_utf8(memo.data.clone()).expect("utf-8 memo")
        };
        let first = build_upto_payload(&*signer, &rpc, &requirements(), 4_102_444_800, "n-1", None)
            .await
            .expect("payload without a declared memo");
        let second =
            build_upto_payload(&*signer, &rpc, &requirements(), 4_102_444_800, "n-1", None)
                .await
                .expect("payload without a declared memo");
        let (a, b) = (nonce_memo(&first), nonce_memo(&second));
        assert!(a.len() >= 2 * pc::MIN_MEMO_NONCE_BYTES, "{a}");
        assert!(a.bytes().all(|c| c.is_ascii_hexdigit()), "{a}");
        assert_ne!(a, b, "the nonce memo is random");
        assert_eq!(first.channel_id, second.channel_id);

        // An over-long memo fails at build time rather than at the facilitator.
        req.extra.memo = Some("x".repeat(pc::OPEN_MAX_MEMO_BYTES + 1));
        assert!(
            build_upto_payload(&*signer, &rpc, &req, 4_102_444_800, "n-1", None)
                .await
                .is_err()
        );
    }

    /// The hinted blockhash is the only thing binding the open to a
    /// cluster, so one the client's own cluster does not know is refused,
    /// with or without a slot hint.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_hinted_blockhash_the_client_cluster_does_not_know_is_refused() {
        let signer = make_signer();
        let foreign = crate::core::blockhash::mock_blockhash_rpc(false);
        let err = build_upto_payload(
            &*signer,
            &foreign,
            &requirements(),
            4_102_444_800,
            "n",
            None,
        )
        .await
        .expect_err("a foreign blockhash is refused");
        assert!(err.to_string().contains("not a live blockhash"), "{err}");

        let mut without_slot = requirements();
        without_slot.extra.recent_slot = None;
        let mut mocks = solana_rpc_client::mock_sender::MocksMap::default();
        mocks.insert(
            solana_rpc_client_api::request::RpcRequest::IsBlockhashValid,
            serde_json::json!({ "context": { "slot": 1 }, "value": false }),
        );
        let foreign = RpcClient::new_mock_with_mocks_map("succeeds", mocks);
        let err = build_upto_payload(&*signer, &foreign, &without_slot, 4_102_444_800, "n", None)
            .await
            .expect_err("a foreign blockhash is refused when the slot is fetched");
        assert!(err.to_string().contains("not a live blockhash"), "{err}");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn build_payload_errors_when_hints_absent_and_rpc_unavailable() {
        let signer = make_signer();
        let rpc = RpcClient::new_mock("fails".to_string());
        let err = build_upto_payload(
            &*signer,
            &rpc,
            &requirements_without_hints(),
            4_102_444_800,
            "n-1",
            None,
        )
        .await
        .expect_err("no hints and no RPC must fail");
        assert!(matches!(err, Error::Rpc(_)));
    }
}
