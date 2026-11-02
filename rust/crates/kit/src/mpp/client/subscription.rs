//! Client-side activation transaction builder for the Solana subscription intent.
//!
//! Builds the activation transaction defined by `draft-solana-subscription-00`:
//!
//!   `[compute_budget_*, create_ata_idempotent, subscribe,
//!     transfer_subscription, memo(externalId)?]`
//!
//! The builder works from the spec's request fields and the on-chain `Plan`
//! only. The challenge is parsed into [`SubscriptionTerms`], the Plan at
//! `methodDetails.planAddress` is read and checked against those terms
//! ([`VerifiedPlan::fetch`]), and the activation is built from the
//! [`VerifiedPlan`]: there is no way to sign an activation whose plan was
//! not read and matched (draft-solana-subscription-00 §Amount and Period
//! Verification: "Clients MUST NOT sign an activation transaction whose
//! on-chain Plan does not match the challenge.").
//!
//! A missing `SubscriptionAuthority` is initialized in its own transaction
//! first; servers reject it inside the activation transaction.
//!
//! The transaction is signed (or partially signed when the server is fee
//! payer) and returned as a `CredentialPayload::Transaction` ready to send
//! to the server.

use std::str::FromStr;

use crate::core::tx::TxVersion;
use solana_instruction::{AccountMeta, Instruction};
use solana_keychain::{SolanaSigner, TransactionSigner};
use solana_pubkey::Pubkey;
use solana_rpc_client::rpc_client::RpcClient;

use crate::mpp::error::Error;
use crate::mpp::program::subscriptions::{
    default_program_id, find_plan_pda, find_subscription_authority_pda, find_subscription_pda,
    plan_id_seed,
};
use crate::mpp::protocol::core::{PaymentChallenge, PaymentCredential};
use crate::mpp::protocol::intents::{
    ActivatePayload, ActivationFeePayer, SubscriptionAccessPayload, SubscriptionAuthentication,
    SubscriptionAuthenticationType, SubscriptionRequest, SubscriptionTerms,
};
use crate::mpp::protocol::solana::CredentialPayload;

/// Raw byte length of the on-chain `SubscriptionAuthority` PDA. Mirrors
/// `#[repr(C, packed)]` layout: discriminator(1) + user(32) + token_mint(32)
/// + payer(32) + bump(1) + init_id(8) = 106.
const SUBSCRIPTION_AUTHORITY_ACCOUNT_LEN: usize = 1 + 32 + 32 + 32 + 1 + 8;
/// Offset of `init_id` (i64, LE) inside a serialised `SubscriptionAuthority`.
const SUBSCRIPTION_AUTHORITY_INIT_ID_OFFSET: usize = 1 + 32 + 32 + 32 + 1;
/// `Plan` account discriminator.
const PLAN_DISCRIMINATOR: u8 = 1;
/// `PlanStatus::Active`.
const PLAN_STATUS_ACTIVE: u8 = 1;

pub use crate::mpp::protocol::intents::SubscriptionMethodDetails;

/// Options for building a Solana subscription activation transaction.
#[derive(Debug, Clone, Default)]
pub struct BuildSubscriptionActivationOptions {
    /// Highest message version the signer can sign, when that is below what
    /// the challenge accepts. The Ledger Solana app signs version 0 but not
    /// yet version 1. `None` takes the highest version the challenge accepts.
    pub max_tx_version: Option<crate::core::tx::TxVersion>,
    /// Compute unit limit. Defaults to 400,000 (activation includes up to
    /// three subscriptions-program instructions plus token transfers).
    pub compute_unit_limit: Option<u32>,
    /// Compute unit price in microlamports. Defaults to 1.
    pub compute_unit_price: Option<u64>,
    /// Pre-resolved `SubscriptionAuthority::init_id`. When set, the builder
    /// skips the on-chain SA lookup and the init-tx broadcast — useful for
    /// tests, and for callers that have already resolved the SA state.
    pub subscription_authority_init_id: Option<i64>,
}

/// The on-chain `Plan` a challenge names, read and checked against the
/// challenge's [`SubscriptionTerms`]. Only [`VerifiedPlan::fetch`] and
/// [`VerifiedPlan::verify`] produce one, and the activation builder takes
/// nothing else, so an activation is never built from an unchecked plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedPlan {
    terms: SubscriptionTerms,
    owner: Pubkey,
    plan_id: u64,
    bump: u8,
    created_at: i64,
}

impl VerifiedPlan {
    /// Read the Plan at `terms.plan_address()` and verify it.
    ///
    /// `trusted_program` is the subscriptions deployment the caller trusts;
    /// `None` trusts only the canonical
    /// [`SUBSCRIPTIONS_PROGRAM_ID`](crate::mpp::program::subscriptions::SUBSCRIPTIONS_PROGRAM_ID).
    /// A challenge naming any other program is refused before the RPC is
    /// asked for anything.
    pub fn fetch(
        rpc: &RpcClient,
        terms: SubscriptionTerms,
        trusted_program: Option<Pubkey>,
    ) -> Result<Self, Error> {
        check_trusted_program(&terms, trusted_program)?;
        let account = rpc.get_account(&terms.plan_address()).map_err(|e| {
            Error::Other(format!(
                "Plan account not found at methodDetails.planAddress {}: {e}",
                terms.plan_address()
            ))
        })?;
        Self::verify(terms, trusted_program, &account.owner, &account.data)
    }

    /// Verify a Plan account (its program owner and data) against `terms`
    /// (draft-solana-subscription-00 §Method Details and §Amount and Period
    /// Verification): owned by the pinned subscriptions program, active, at
    /// the PDA its owner and id derive, with the challenge's mint, amount and
    /// period, the puller as owner or listed puller, and exactly one non-zero
    /// destination equal to `recipient`.
    pub fn verify(
        terms: SubscriptionTerms,
        trusted_program: Option<Pubkey>,
        owner_program: &Pubkey,
        data: &[u8],
    ) -> Result<Self, Error> {
        use crate::generated::subscriptions::accounts::Plan;

        let program_id = check_trusted_program(&terms, trusted_program)?;
        let mismatch = |what: &str| {
            Error::Other(format!(
                "The on-chain Plan does not match the challenge: {what}"
            ))
        };
        if *owner_program != program_id {
            return Err(mismatch(
                "plan is not owned by methodDetails.subscriptionProgram",
            ));
        }
        let plan = Plan::from_bytes(data)
            .map_err(|e| Error::Other(format!("Invalid Plan account: {e}")))?;
        if plan.discriminator != PLAN_DISCRIMINATOR {
            return Err(mismatch("account is not a Plan"));
        }
        if plan.status != PLAN_STATUS_ACTIVE {
            return Err(mismatch("plan is not active"));
        }
        let owner = to_pubkey(&plan.owner);
        let (address, bump) = find_plan_pda(&owner, &plan_id_seed(plan.data.plan_id), &program_id);
        if address != terms.plan_address() || bump != plan.bump {
            return Err(mismatch("planAddress is not the plan's PDA"));
        }
        if to_pubkey(&plan.data.mint) != terms.mint() {
            return Err(mismatch("plan.mint differs from methodDetails.mint"));
        }
        if plan.data.terms.amount != terms.amount().get() {
            return Err(mismatch("plan amount differs from amount"));
        }
        if plan.data.terms.period_hours != terms.period().hours() {
            return Err(mismatch("plan period differs from the billing period"));
        }
        let puller = terms.puller();
        if puller != owner && !non_zero(&plan.data.pullers).any(|p| p == puller) {
            return Err(mismatch(
                "methodDetails.puller is neither plan.owner nor in plan.pullers",
            ));
        }
        let destinations: Vec<Pubkey> = non_zero(&plan.data.destinations).collect();
        if destinations != [terms.recipient()] {
            return Err(mismatch(
                "plan.destinations must be exactly one address equal to recipient",
            ));
        }
        Ok(Self {
            terms,
            owner,
            plan_id: plan.data.plan_id,
            bump: plan.bump,
            created_at: plan.data.terms.created_at,
        })
    }

    /// The challenge terms the plan was checked against.
    pub fn terms(&self) -> &SubscriptionTerms {
        &self.terms
    }

    /// `plan.owner`: the merchant who published the plan.
    pub fn owner(&self) -> Pubkey {
        self.owner
    }

    /// Kit tests only: a plan as if read and verified, for fixtures whose
    /// plan address is not a real PDA.
    #[cfg(test)]
    pub(crate) fn assume_verified(
        terms: SubscriptionTerms,
        owner: Pubkey,
        plan_id: u64,
        bump: u8,
        created_at: i64,
    ) -> Self {
        Self {
            terms,
            owner,
            plan_id,
            bump,
            created_at,
        }
    }
}

/// Kit tests only: the plan of `request`'s challenge, assumed verified, with
/// `owner` as the merchant (plan id 1, bump 255, created at 1_700_000_000).
#[cfg(test)]
pub(crate) fn assume_plan(request: &SubscriptionRequest, owner: Pubkey) -> VerifiedPlan {
    VerifiedPlan::assume_verified(
        request.terms().expect("valid request"),
        owner,
        1,
        255,
        1_700_000_000,
    )
}

fn to_pubkey(address: &solana_address::Address) -> Pubkey {
    Pubkey::new_from_array(address.to_bytes())
}

fn non_zero(list: &[solana_address::Address]) -> impl Iterator<Item = Pubkey> + '_ {
    list.iter()
        .filter(|address| address.to_bytes() != [0u8; 32])
        .map(to_pubkey)
}

/// Refuse a challenge whose `subscriptionProgram` the caller has not chosen
/// to trust: the program receives the subscriber's signature and token
/// account.
fn check_trusted_program(
    terms: &SubscriptionTerms,
    trusted: Option<Pubkey>,
) -> Result<Pubkey, Error> {
    let program_id = terms.subscription_program();
    let trusted = trusted.unwrap_or_else(default_program_id);
    if program_id != trusted {
        return Err(Error::Other(format!(
            "Untrusted subscription program {program_id} (expected {trusted})"
        )));
    }
    Ok(program_id)
}

/// Activation credential plus the reusable proof needed for later access.
#[derive(Debug, Clone)]
pub struct SubscriptionActivation {
    /// Credential sent to activate and pay the first period.
    pub credential: PaymentCredential,
    /// Proof that must be retained as a bearer secret for later access.
    pub authentication: SubscriptionAuthentication,
    /// Delegation PDA bound into `authentication`.
    pub subscription_delegation: String,
}

/// Sign the canonical reusable subscription authentication message.
pub async fn sign_subscription_authentication(
    signer: &dyn SolanaSigner,
    challenge_id: &str,
    subscription_delegation: &str,
) -> Result<SubscriptionAuthentication, Error> {
    let mut authentication = SubscriptionAuthentication {
        kind: SubscriptionAuthenticationType::Proof,
        challenge_id: challenge_id.to_string(),
        payer: signer.pubkey().to_string(),
        signature: String::new(),
    };
    let signature = signer
        .sign_message(&authentication.message_bytes(subscription_delegation)?)
        .await
        .map_err(|error| Error::Other(format!("Signing subscription proof failed: {error}")))?;
    authentication.signature = bs58::encode(signature.as_ref()).into_string();
    Ok(authentication)
}

/// Build a later-access credential from the proof retained at activation.
pub fn build_subscription_access_credential(
    challenge: &PaymentChallenge,
    subscription_delegation: impl Into<String>,
    authentication: SubscriptionAuthentication,
) -> PaymentCredential {
    PaymentCredential::new(
        challenge.to_echo(),
        SubscriptionAccessPayload {
            payload_type: SubscriptionAuthenticationType::Proof,
            subscription_delegation: subscription_delegation.into(),
            authentication,
        },
    )
}

/// Build the activation transaction for `challenge` and bind a reusable
/// proof to its delegation.
///
/// Parses the request ([`SubscriptionRequest::terms`]), reads and verifies
/// the on-chain Plan through `rpc` ([`VerifiedPlan::fetch`], trusting only
/// the canonical subscriptions program), then builds and signs.
pub async fn build_subscription_activation_credential(
    signer: &dyn TransactionSigner,
    rpc: &RpcClient,
    challenge: &PaymentChallenge,
) -> Result<SubscriptionActivation, Error> {
    let request: SubscriptionRequest = challenge.request.decode()?;
    let plan = VerifiedPlan::fetch(rpc, request.terms()?, None)?;
    let terms = plan.terms();
    let subscription_delegation = find_subscription_pda(
        &terms.plan_address(),
        &signer.pubkey(),
        &terms.subscription_program(),
    )
    .0
    .to_string();
    let transaction = build_subscription_activation_transaction(signer, rpc, &plan).await?;
    let authentication =
        sign_subscription_authentication(signer, &challenge.id, &subscription_delegation).await?;
    let CredentialPayload::Transaction { transaction } = transaction else {
        return Err(Error::Other(
            "Subscription activation builder returned an unexpected payload".into(),
        ));
    };
    let payload = ActivatePayload {
        payload_type: "transaction".into(),
        transaction: Some(transaction),
        signature: None,
        authentication: authentication.clone(),
    };
    let credential = PaymentCredential::with_source(
        challenge.to_echo(),
        PaymentCredential::solana_did(terms.network(), &signer.pubkey().to_string()),
        payload,
    );
    Ok(SubscriptionActivation {
        credential,
        authentication,
        subscription_delegation,
    })
}

/// Build the subscription activation transaction for a verified plan.
///
/// The returned payload is a `CredentialPayload::Transaction` carrying the
/// base64-encoded serialized transaction. When the challenge sets
/// `feePayer: true`, the transaction is partially signed; the server
/// completes the fee-payer signature before broadcasting.
pub async fn build_subscription_activation_transaction(
    signer: &dyn TransactionSigner,
    rpc: &RpcClient,
    plan: &VerifiedPlan,
) -> Result<CredentialPayload, Error> {
    build_subscription_activation_transaction_with_options(
        signer,
        rpc,
        plan,
        BuildSubscriptionActivationOptions::default(),
    )
    .await
}

/// Build the subscription activation transaction with additional options.
pub async fn build_subscription_activation_transaction_with_options(
    signer: &dyn TransactionSigner,
    rpc: &RpcClient,
    plan: &VerifiedPlan,
    options: BuildSubscriptionActivationOptions,
) -> Result<CredentialPayload, Error> {
    let terms = plan.terms();
    let program_id = terms.subscription_program();
    let subscriber = signer.pubkey();
    let mint = terms.mint();
    let token_program = terms.token_program().program_id();
    let plan_pda = terms.plan_address();
    let puller = terms.puller();
    let recipient = terms.recipient();
    let amount = terms.amount().get();
    let sponsor = match terms.fee_payer() {
        ActivationFeePayer::Server(key) => Some(key),
        ActivationFeePayer::Subscriber => None,
    };

    let (subscription_authority, _) =
        find_subscription_authority_pda(&subscriber, &mint, &program_id);
    let (subscription_pda, _) = find_subscription_pda(&plan_pda, &subscriber, &program_id);
    let (event_authority, _) =
        crate::mpp::program::subscriptions::find_event_authority_pda(&program_id);

    // ATA derivation: SPL Token associated-token program seeds are
    // `[owner, token_program, mint]`. Both SPL Token and Token-2022 share
    // the same associated-token-program ID.
    let associated_token_program =
        Pubkey::from_str_const(crate::mpp::program::subscriptions::ASSOCIATED_TOKEN_PROGRAM_ID);
    let (subscriber_ata, _) = Pubkey::find_program_address(
        &[subscriber.as_ref(), token_program.as_ref(), mint.as_ref()],
        &associated_token_program,
    );
    let (recipient_ata, _) = Pubkey::find_program_address(
        &[recipient.as_ref(), token_program.as_ref(), mint.as_ref()],
        &associated_token_program,
    );

    let mut instructions: Vec<Instruction> = Vec::new();

    // Compute budget: a ComputeBudget prefix on version 0, the header config
    // on version 1.
    let budget = crate::core::tx::ComputeBudget::new(
        options.compute_unit_limit.unwrap_or(400_000),
        options.compute_unit_price.unwrap_or(1),
    );

    // ATA bootstrap. The on-chain `init_subscription_authority` (and
    // every subsequent transfer) requires the subscriber's ATA to exist
    // and be owned by the token program. `CreateIdempotent` is a no-op
    // when the ATA is already in place, so we always prepend it. Rent is
    // paid by the fee payer when sponsorship is on, otherwise by the
    // subscriber.
    instructions.push(build_create_idempotent_ata_ix(
        sponsor.unwrap_or(subscriber),
        subscriber_ata,
        subscriber,
        mint,
        token_program,
        associated_token_program,
    ));

    // `methodDetails.recentBlockhash` when the server pre-fetched one,
    // otherwise the RPC's latest.
    let blockhash = match terms.recent_blockhash() {
        Some(hash) => hash,
        None => rpc
            .get_latest_blockhash()
            .map_err(|e| Error::Other(format!("Failed to fetch a recent blockhash: {e}")))?,
    };

    // The on-chain `Subscribe` instruction binds the subscriber's signature
    // to a specific `SubscriptionAuthority::init_id`, set from `Clock::slot`
    // at SA creation. If the SA is created in the same tx as `Subscribe`,
    // the client can't predict the landing slot — so SA must exist (and
    // we must read its `init_id`) before signing the activation tx. When
    // missing, broadcast a one-off init tx as the subscriber, paid by the
    // subscriber (~0.002 SOL rent + ~5k lamports fee).
    let expected_subscription_authority_init_id = match options.subscription_authority_init_id {
        Some(id) => id,
        None => {
            ensure_subscription_authority_init_id(
                signer,
                rpc,
                program_id,
                subscriber,
                mint,
                subscriber_ata,
                subscription_authority,
                token_program,
                &blockhash,
            )
            .await?
        }
    };

    instructions.push(crate::mpp::program::subscriptions::build_subscribe_ix(
        program_id,
        crate::mpp::program::subscriptions::SubscribeAccounts {
            subscriber,
            merchant: plan.owner,
            plan_pda,
            subscription_pda,
            subscription_authority_pda: subscription_authority,
            event_authority,
            // Rent payer for the delegation: the sponsor when configured,
            // otherwise the subscriber (no extra account meta).
            payer: sponsor,
        },
        // The terms the program checks against the live plan; every one
        // was read from the plan and matched to the challenge.
        &crate::mpp::program::subscriptions::SubscribeData {
            plan_id: plan.plan_id,
            plan_bump: plan.bump,
            expected_mint: mint,
            expected_amount: amount,
            expected_period_hours: terms.period().hours(),
            expected_created_at: plan.created_at,
            expected_subscription_authority_init_id,
        },
    ));

    instructions.push(
        crate::mpp::program::subscriptions::build_transfer_subscription_ix(
            program_id,
            crate::mpp::program::subscriptions::TransferSubscriptionAccounts {
                subscription_pda,
                plan_pda,
                subscription_authority,
                delegator_ata: subscriber_ata,
                receiver_ata: recipient_ata,
                caller: puller,
                token_mint: mint,
                token_program,
                event_authority,
            },
            &crate::mpp::program::subscriptions::TransferData {
                amount,
                delegator: subscriber,
                mint,
            },
        ),
    );

    if let Some(external_id) = terms.external_id() {
        instructions.push(build_memo_instruction(external_id));
    }

    let version = crate::core::tx::negotiate(terms.transaction_versions(), options.max_tx_version)?;
    let mut tx = crate::core::tx::build_unsigned(
        version,
        &sponsor.unwrap_or(subscriber),
        &instructions,
        blockhash,
        Some(&budget),
    )?;

    // Sign as subscriber; the server adds the puller and fee-payer
    // signatures. The subscriber is the only client-side signer; when fee
    // sponsorship is in play, the tx is broadcast partially signed.
    crate::core::signing::sign_versioned_transaction_slot(signer, &mut tx)
        .await
        .map_err(|e| Error::Other(format!("Subscriber signature failed: {e}")))?;

    let b64 = crate::core::tx::encode(&tx)?;
    Ok(CredentialPayload::Transaction { transaction: b64 })
}

/// Resolve the `SubscriptionAuthority::init_id` the activation tx must
/// reference, broadcasting a one-off subscriber-signed init tx when the SA
/// PDA hasn't been created yet.
///
/// The init tx is intentionally paid by the subscriber (no fee-payer
/// trailing account): the on-chain `init` records the funder as the rent
/// recipient on close, and we want that to be the subscriber so they get
/// their rent back when they tear the SA down later. Subscribers must
/// hold ~0.002 SOL the first time they subscribe with a given mint.
#[allow(clippy::too_many_arguments)]
// This is the live-RPC boundary. Pure instruction construction and account
// decoding are covered separately; CI has no deterministic validator here.
async fn ensure_subscription_authority_init_id(
    signer: &dyn TransactionSigner,
    rpc: &RpcClient,
    program_id: Pubkey,
    subscriber: Pubkey,
    mint: Pubkey,
    subscriber_ata: Pubkey,
    subscription_authority: Pubkey,
    token_program: Pubkey,
    blockhash: &solana_hash::Hash,
) -> Result<i64, Error> {
    if let Ok(account) = rpc.get_account(&subscription_authority) {
        if account.owner != program_id {
            return Err(Error::Other(format!(
                "SubscriptionAuthority {subscription_authority} is not owned by the subscriptions program"
            )));
        }
        return parse_subscription_authority_init_id(&account.data);
    }

    // SA doesn't exist — broadcast a subscriber-only-signed init tx so the
    // SA lands on-chain (and its `init_id` is recorded) before we sign the
    // activation tx.
    let init_ix = crate::mpp::program::subscriptions::build_initialize_subscription_authority_ix(
        program_id,
        crate::mpp::program::subscriptions::InitializeSubscriptionAuthorityAccounts {
            owner: subscriber,
            subscription_authority,
            token_mint: mint,
            user_ata: subscriber_ata,
            token_program,
        },
    );

    let mut tx =
        crate::core::tx::build_unsigned(TxVersion::V0, &subscriber, &[init_ix], *blockhash, None)?;
    crate::core::signing::sign_versioned_transaction_slot(signer, &mut tx)
        .await
        .map_err(|e| Error::Other(format!("SA init signature failed: {e}")))?;

    crate::core::rpc::send_and_confirm_transaction(rpc, &tx).map_err(|e| {
        Error::Other(format!(
            "Failed to broadcast SubscriptionAuthority init: {e}"
        ))
    })?;

    let account = rpc.get_account(&subscription_authority).map_err(|e| {
        Error::Other(format!(
            "SubscriptionAuthority still missing after init broadcast: {e}"
        ))
    })?;
    parse_subscription_authority_init_id(&account.data)
}

/// Extract `init_id` (i64 LE) from a serialised `SubscriptionAuthority`
/// account. The on-chain struct is `#[repr(C, packed)]` with `init_id` as
/// the last field, so it lives at offset 98 in a 106-byte account.
fn parse_subscription_authority_init_id(bytes: &[u8]) -> Result<i64, Error> {
    if bytes.len() != SUBSCRIPTION_AUTHORITY_ACCOUNT_LEN {
        return Err(Error::Other(format!(
            "Unexpected SubscriptionAuthority length: got {}, expected {SUBSCRIPTION_AUTHORITY_ACCOUNT_LEN}",
            bytes.len()
        )));
    }
    let raw: [u8; 8] = bytes
        [SUBSCRIPTION_AUTHORITY_INIT_ID_OFFSET..SUBSCRIPTION_AUTHORITY_INIT_ID_OFFSET + 8]
        .try_into()
        .expect("8-byte slice");
    Ok(i64::from_le_bytes(raw))
}

/// Build a `CreateIdempotent` instruction for the SPL Associated Token
/// Program. No-op when the ATA already exists; otherwise creates it and
/// charges rent to `funder`.
///
/// Account layout per the Associated Token Program spec:
///   0. funder (signer, writable)
///   1. ata (writable)
///   2. wallet (the ATA owner — readonly)
///   3. mint (readonly)
///   4. system_program (readonly)
///   5. token_program (readonly)
///
/// Instruction data: a single byte `1` (the `CreateIdempotent`
/// discriminator); the older `0` discriminator (`Create`) errors when
/// the ATA exists.
fn build_create_idempotent_ata_ix(
    funder: Pubkey,
    ata: Pubkey,
    wallet: Pubkey,
    mint: Pubkey,
    token_program: Pubkey,
    associated_token_program: Pubkey,
) -> Instruction {
    let system_program =
        Pubkey::from_str("11111111111111111111111111111111").expect("valid system program id");
    Instruction {
        program_id: associated_token_program,
        accounts: vec![
            AccountMeta::new(funder, true),
            AccountMeta::new(ata, false),
            AccountMeta::new_readonly(wallet, false),
            AccountMeta::new_readonly(mint, false),
            AccountMeta::new_readonly(system_program, false),
            AccountMeta::new_readonly(token_program, false),
        ],
        data: vec![1u8],
    }
}

fn build_memo_instruction(memo: &str) -> Instruction {
    let data = memo.as_bytes().to_vec();
    Instruction {
        program_id: Pubkey::from_str("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr")
            .expect("valid memo program id"),
        accounts: vec![],
        data,
    }
}

// ── Compute budget instructions (inline, no heavy dep) ──
//
// Mirror the inline builders used by `client::charge` to avoid pulling in
// `solana-compute-budget-interface`.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generated::subscriptions::accounts::Plan;
    use crate::generated::subscriptions::types::{PlanData, PlanTerms};
    use crate::mpp::program::subscriptions::{
        SubscribeData, INSTRUCTION_SUBSCRIBE, SUBSCRIPTIONS_PROGRAM_ID,
    };
    use crate::mpp::protocol::solana::programs::TOKEN_PROGRAM;
    use async_trait::async_trait;
    use solana_keychain::{SignTransactionResult, SignerError, SolanaSigner};
    use solana_rpc_client::mock_sender::MocksMap;
    use solana_rpc_client_api::request::RpcRequest;
    use solana_signature::Signature;

    const MINT: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
    const RECIPIENT: &str = "9xAXssX9j7vuK99c7cFwqbixzL3bFrzPy9PUhCtDPAYJ";
    const PLAN_ID: u64 = 7;
    const CREATED_AT: i64 = 1_700_000_000;

    fn merchant() -> Pubkey {
        Pubkey::new_from_array([21; 32])
    }

    fn program() -> Pubkey {
        Pubkey::from_str_const(SUBSCRIPTIONS_PROGRAM_ID)
    }

    fn plan_pda() -> (Pubkey, u8) {
        find_plan_pda(&merchant(), &plan_id_seed(PLAN_ID), &program())
    }

    /// A request carrying exactly the spec's fields: no kit extensions.
    fn spec_request() -> serde_json::Value {
        serde_json::json!({
            "amount": "10000000",
            "currency": MINT,
            "periodUnit": "day",
            "periodCount": "30",
            "recipient": RECIPIENT,
            "methodDetails": {
                "subscriptionProgram": SUBSCRIPTIONS_PROGRAM_ID,
                "planAddress": plan_pda().0.to_string(),
                "mint": MINT,
                "tokenProgram": TOKEN_PROGRAM,
                "decimals": 6,
                "puller": merchant().to_string(),
                "network": "devnet",
                "recentBlockhash": "11111111111111111111111111111111",
            },
        })
    }

    fn terms_of(request: &serde_json::Value) -> SubscriptionTerms {
        serde_json::from_value::<SubscriptionRequest>(request.clone())
            .unwrap()
            .terms()
            .unwrap()
    }

    fn address(key: &Pubkey) -> solana_address::Address {
        solana_address::Address::from(key.to_bytes())
    }

    fn padded(list: &[Pubkey]) -> [solana_address::Address; 4] {
        let mut out = [solana_address::Address::from([0u8; 32]); 4];
        for (slot, key) in out.iter_mut().zip(list) {
            *slot = address(key);
        }
        out
    }

    struct PlanFixture {
        mint: Pubkey,
        amount: u64,
        period_hours: u64,
        destinations: Vec<Pubkey>,
        pullers: Vec<Pubkey>,
        status: u8,
    }

    impl Default for PlanFixture {
        fn default() -> Self {
            Self {
                mint: Pubkey::from_str_const(MINT),
                amount: 10_000_000,
                period_hours: 720,
                destinations: vec![Pubkey::from_str_const(RECIPIENT)],
                pullers: vec![],
                status: PLAN_STATUS_ACTIVE,
            }
        }
    }

    impl PlanFixture {
        fn bytes(&self) -> Vec<u8> {
            borsh::to_vec(&Plan {
                discriminator: PLAN_DISCRIMINATOR,
                owner: address(&merchant()),
                bump: plan_pda().1,
                status: self.status,
                data: PlanData {
                    plan_id: PLAN_ID,
                    mint: address(&self.mint),
                    terms: PlanTerms {
                        amount: self.amount,
                        period_hours: self.period_hours,
                        created_at: CREATED_AT,
                    },
                    end_ts: 0,
                    destinations: padded(&self.destinations),
                    pullers: padded(&self.pullers),
                    metadata_uri: [0u8; 128],
                },
            })
            .unwrap()
        }

        fn verify(&self, request: &serde_json::Value) -> Result<VerifiedPlan, Error> {
            VerifiedPlan::verify(terms_of(request), None, &program(), &self.bytes())
        }
    }

    fn account_response(owner: &Pubkey, data: &[u8]) -> serde_json::Value {
        use base64::Engine;
        serde_json::json!({
            "context": {"slot": 1},
            "value": {
                "data": [base64::engine::general_purpose::STANDARD.encode(data), "base64"],
                "executable": false,
                "lamports": 1_000_000,
                "owner": owner.to_string(),
                "rentEpoch": 0,
                "space": data.len(),
            }
        })
    }

    /// An RPC whose successive `getAccountInfo` answers are `accounts`.
    fn rpc_serving(accounts: &[serde_json::Value]) -> RpcClient {
        let mut mocks = MocksMap::default();
        for account in accounts {
            mocks.insert(RpcRequest::GetAccountInfo, account.clone());
        }
        RpcClient::new_mock_with_mocks_map("succeeds".to_string(), mocks)
    }

    fn authority_bytes(init_id: i64) -> Vec<u8> {
        let mut data = vec![0u8; SUBSCRIPTION_AUTHORITY_ACCOUNT_LEN];
        data[SUBSCRIPTION_AUTHORITY_INIT_ID_OFFSET..].copy_from_slice(&init_id.to_le_bytes());
        data
    }

    fn make_signer() -> Box<dyn TransactionSigner> {
        let sk = ed25519_dalek::SigningKey::from_bytes(&[42u8; 32]);
        let mut kp = [0u8; 64];
        kp[..32].copy_from_slice(sk.as_bytes());
        kp[32..].copy_from_slice(sk.verifying_key().as_bytes());
        Box::new(solana_keychain::MemorySigner::from_bytes(&kp).expect("valid keypair"))
    }

    struct TransactionOnlySigner(Pubkey);

    #[async_trait]
    impl solana_keychain::SolanaSigner for TransactionOnlySigner {
        fn pubkey(&self) -> Pubkey {
            self.0
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

    #[async_trait]
    impl TransactionSigner for TransactionOnlySigner {
        async fn sign_transaction(
            &self,
            tx: &mut solana_transaction::versioned::VersionedTransaction,
        ) -> std::result::Result<SignTransactionResult, SignerError> {
            let index = tx
                .message
                .static_account_keys()
                .iter()
                .position(|key| key == &self.0)
                .ok_or_else(|| SignerError::Other("missing signer".into()))?;
            let signature = Signature::from([7u8; 64]);
            tx.signatures[index] = signature;
            Ok(SignTransactionResult::Partial((String::new(), signature)))
        }
    }

    fn pinned() -> BuildSubscriptionActivationOptions {
        BuildSubscriptionActivationOptions {
            subscription_authority_init_id: Some(77),
            ..Default::default()
        }
    }

    async fn build(
        signer: &dyn TransactionSigner,
        plan: &VerifiedPlan,
    ) -> solana_transaction::versioned::VersionedTransaction {
        let rpc = RpcClient::new_mock("succeeds".to_string());
        let CredentialPayload::Transaction { transaction } =
            build_subscription_activation_transaction_with_options(signer, &rpc, plan, pinned())
                .await
                .expect("activation tx")
        else {
            panic!("expected Transaction payload")
        };
        crate::core::tx::decode(&transaction).unwrap()
    }

    fn challenge_for(request: &serde_json::Value) -> PaymentChallenge {
        PaymentChallenge::new(
            "challenge-id",
            "realm",
            "solana",
            "subscription",
            crate::mpp::protocol::core::Base64UrlJson::from_value(request).unwrap(),
        )
    }

    // ── the plan is the source of the subscribe terms ──────────────────────

    // A spec-shaped challenge (no kit methodDetails extensions) builds: the
    // subscribe data and the merchant account come from the on-chain plan.
    #[tokio::test(flavor = "multi_thread")]
    async fn spec_shaped_challenge_builds_from_the_plan() {
        let signer = make_signer();
        let plan = PlanFixture::default().verify(&spec_request()).unwrap();
        let tx = build(signer.as_ref(), &plan).await;
        let keys = tx.message.static_account_keys();
        let subscribe = tx
            .message
            .instructions()
            .iter()
            .find(|ix| ix.data.first() == Some(&INSTRUCTION_SUBSCRIBE))
            .expect("subscribe");
        assert_eq!(
            subscribe.data,
            SubscribeData {
                plan_id: PLAN_ID,
                plan_bump: plan_pda().1,
                expected_mint: Pubkey::from_str_const(MINT),
                expected_amount: 10_000_000,
                expected_period_hours: 720,
                expected_created_at: CREATED_AT,
                expected_subscription_authority_init_id: 77,
            }
            .to_bytes()
        );
        assert_eq!(keys[subscribe.accounts[1] as usize], merchant());
    }

    // The credential path reads the plan and the authority through the RPC.
    #[tokio::test(flavor = "multi_thread")]
    async fn activation_credential_reads_the_plan_through_the_rpc() {
        let signer = make_signer();
        let rpc = rpc_serving(&[
            account_response(&program(), &PlanFixture::default().bytes()),
            account_response(&program(), &authority_bytes(77)),
        ]);
        let activation = build_subscription_activation_credential(
            signer.as_ref(),
            &rpc,
            &challenge_for(&spec_request()),
        )
        .await
        .unwrap();
        assert_eq!(
            activation.credential.source.as_deref(),
            Some(PaymentCredential::solana_did("devnet", &signer.pubkey().to_string()).as_str())
        );
        assert_eq!(
            activation.credential.payload["authentication"]["payer"],
            signer.pubkey().to_string()
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn activation_credential_refuses_a_missing_plan() {
        let signer = make_signer();
        let missing = serde_json::json!({"context": {"slot": 1}, "value": null});
        let rpc = rpc_serving(&[missing]);
        let err = build_subscription_activation_credential(
            signer.as_ref(),
            &rpc,
            &challenge_for(&spec_request()),
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("Plan account not found"), "{err}");
    }

    // draft-solana-subscription-00 §Amount and Period Verification, item 6.
    #[test]
    fn plan_that_does_not_match_the_challenge_is_refused() {
        let request = spec_request();
        let stranger = Pubkey::new_from_array([23; 32]);
        let attacker = Pubkey::new_from_array([24; 32]);
        let recipient = Pubkey::from_str_const(RECIPIENT);
        let cases = [
            (
                "amount",
                PlanFixture {
                    amount: 5_000_000,
                    ..Default::default()
                },
            ),
            (
                "period",
                PlanFixture {
                    period_hours: 168,
                    ..Default::default()
                },
            ),
            (
                "mint",
                PlanFixture {
                    mint: Pubkey::new_unique(),
                    ..Default::default()
                },
            ),
            (
                "no destination",
                PlanFixture {
                    destinations: vec![],
                    ..Default::default()
                },
            ),
            (
                "two destinations",
                PlanFixture {
                    destinations: vec![recipient, attacker],
                    ..Default::default()
                },
            ),
            (
                "other destination",
                PlanFixture {
                    destinations: vec![attacker],
                    ..Default::default()
                },
            ),
            (
                "sunset",
                PlanFixture {
                    status: 0,
                    ..Default::default()
                },
            ),
        ];
        for (what, plan) in cases {
            assert!(plan.verify(&request).is_err(), "{what}");
        }
        // Positive control.
        PlanFixture::default().verify(&request).unwrap();

        // A puller that is neither the owner nor listed.
        let mut unauthorized = request.clone();
        unauthorized["methodDetails"]["puller"] = stranger.to_string().into();
        let err = PlanFixture::default().verify(&unauthorized).unwrap_err();
        assert!(err.to_string().contains("puller"), "{err}");
        // Listed in plan.pullers: authorized.
        PlanFixture {
            pullers: vec![stranger],
            ..Default::default()
        }
        .verify(&unauthorized)
        .unwrap();
    }

    #[test]
    fn plan_owned_by_another_program_or_at_another_address_is_refused() {
        let request = spec_request();
        let bytes = PlanFixture::default().bytes();
        assert!(
            VerifiedPlan::verify(terms_of(&request), None, &Pubkey::new_unique(), &bytes).is_err()
        );
        let mut elsewhere = request.clone();
        elsewhere["methodDetails"]["planAddress"] = Pubkey::new_unique().to_string().into();
        assert!(VerifiedPlan::verify(terms_of(&elsewhere), None, &program(), &bytes).is_err());
    }

    // Kit-only methodDetails extensions never override the plan.
    #[tokio::test(flavor = "multi_thread")]
    async fn kit_extensions_are_ignored() {
        let signer = make_signer();
        let mut request = spec_request();
        let md = request["methodDetails"].as_object_mut().unwrap();
        md.insert("planIdNumeric".into(), 99.into());
        md.insert("expectedCreatedAt".into(), 1.into());
        md.insert("merchant".into(), Pubkey::new_unique().to_string().into());
        let with = build(
            signer.as_ref(),
            &PlanFixture::default().verify(&request).unwrap(),
        )
        .await;
        let without = build(
            signer.as_ref(),
            &PlanFixture::default().verify(&spec_request()).unwrap(),
        )
        .await;
        assert_eq!(with.message, without.message);
    }

    // ── request format reaches the builder only through SubscriptionTerms ──

    #[tokio::test(flavor = "multi_thread")]
    async fn malformed_requests_are_refused_before_any_rpc() {
        let signer = make_signer();
        let rpc = rpc_serving(&[]);
        for (pointer, value) in [
            ("/amount", serde_json::json!("010000000")),
            ("/amount", serde_json::json!("0")),
            ("/periodCount", serde_json::json!("030")),
            (
                "/methodDetails/tokenProgram",
                serde_json::json!("11111111111111111111111111111111"),
            ),
        ] {
            let mut request = spec_request();
            *request.pointer_mut(pointer).unwrap() = value.clone();
            assert!(
                build_subscription_activation_credential(
                    signer.as_ref(),
                    &rpc,
                    &challenge_for(&request)
                )
                .await
                .is_err(),
                "{pointer} = {value}"
            );
        }
        let mut no_decimals = spec_request();
        no_decimals["methodDetails"]
            .as_object_mut()
            .unwrap()
            .remove("decimals");
        assert!(build_subscription_activation_credential(
            signer.as_ref(),
            &rpc,
            &challenge_for(&no_decimals)
        )
        .await
        .is_err());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn activation_credential_rejects_currency_differing_from_mint() {
        let signer = make_signer();
        let mut request = spec_request();
        // Displayed as USDT while the transaction would authorize USDC.
        request["currency"] = "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB".into();
        let err = build_subscription_activation_credential(
            signer.as_ref(),
            &rpc_serving(&[]),
            &challenge_for(&request),
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("currency"), "{err}");
    }

    // ── program pin ────────────────────────────────────────────────────────

    #[test]
    fn untrusted_subscription_program_is_rejected_before_reading_the_plan() {
        let mut request = spec_request();
        request["methodDetails"]["subscriptionProgram"] = Pubkey::new_unique().to_string().into();
        // An RPC with nothing to serve: the pin refuses first.
        let err = VerifiedPlan::fetch(&rpc_serving(&[]), terms_of(&request), None).unwrap_err();
        assert!(
            err.to_string().contains("Untrusted subscription program"),
            "{err}"
        );
    }

    #[test]
    fn caller_trusted_subscription_program_does_not_trust_the_canonical_one() {
        let custom = Pubkey::new_unique();
        let err = VerifiedPlan::verify(
            terms_of(&spec_request()),
            Some(custom),
            &program(),
            &PlanFixture::default().bytes(),
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("Untrusted subscription program"),
            "{err}"
        );
    }

    // ── transaction shape ──────────────────────────────────────────────────

    #[tokio::test(flavor = "multi_thread")]
    async fn external_id_is_carried_as_a_trailing_memo() {
        let signer = make_signer();
        let mut request = spec_request();
        request["externalId"] = "order-42".into();
        let tx = build(
            signer.as_ref(),
            &PlanFixture::default().verify(&request).unwrap(),
        )
        .await;
        // [compute_price, compute_limit, ata_create_idempotent, subscribe,
        //  transfer, memo] = 6. Init runs as a separate pre-broadcast tx.
        assert_eq!(tx.message.instructions().len(), 6);
        let last = tx.message.instructions().last().unwrap();
        let memo_program_id =
            Pubkey::from_str("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr").unwrap();
        assert_eq!(
            tx.message.static_account_keys()[last.program_id_index as usize],
            memo_program_id
        );
        assert_eq!(last.data, b"order-42");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn sponsored_activation_names_the_fee_payer_key() {
        let signer = TransactionOnlySigner(Pubkey::new_unique());
        let fee_payer = Pubkey::new_unique();
        let mut request = spec_request();
        request["methodDetails"]["feePayer"] = true.into();
        request["methodDetails"]["feePayerKey"] = fee_payer.to_string().into();
        let tx = build(&signer, &PlanFixture::default().verify(&request).unwrap()).await;
        // In a sponsored transaction the fee payer is account_keys[0].
        assert_eq!(tx.message.static_account_keys()[0], fee_payer);
        let subscriber_index = tx
            .message
            .static_account_keys()
            .iter()
            .position(|key| key == &signer.pubkey())
            .expect("subscriber signer account");
        assert_ne!(subscriber_index, 0);
        assert_eq!(tx.signatures[0], Signature::default());
        assert_eq!(tx.signatures[subscriber_index], Signature::from([7u8; 64]));
    }

    #[test]
    fn subscription_authority_owned_by_another_program_is_refused() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let signer = make_signer();
        let rpc = rpc_serving(&[account_response(
            &Pubkey::new_unique(),
            &authority_bytes(77),
        )]);
        let err = rt
            .block_on(build_subscription_activation_transaction(
                signer.as_ref(),
                &rpc,
                &PlanFixture::default().verify(&spec_request()).unwrap(),
            ))
            .unwrap_err();
        assert!(err.to_string().contains("SubscriptionAuthority"), "{err}");
    }

    #[test]
    fn method_details_parse_required_fields() {
        let value = serde_json::json!({
            "planAddress": "8tWbqLkUJoYy7zXc5h2EvCRoaQEv2xnQjUuYhc3rzCgT",
            "mint": MINT,
            "tokenProgram": TOKEN_PROGRAM,
            "puller": "5fKb5cF22cFybZB1H4hLDydFhwoQy9JzKzRWaSbMkB6h",
            "feePayer": true,
            "feePayerKey": "5fKb5cF22cFybZB1H4hLDydFhwoQy9JzKzRWaSbMkB6h"
        });
        let md = SubscriptionMethodDetails::from_json(&value).unwrap();
        assert!(md.fee_payer);
        assert_eq!(
            md.fee_payer_key.as_deref(),
            Some("5fKb5cF22cFybZB1H4hLDydFhwoQy9JzKzRWaSbMkB6h")
        );
    }

    #[test]
    fn method_details_rejects_missing_required_field() {
        let value = serde_json::json!({ "mint": MINT });
        assert!(SubscriptionMethodDetails::from_json(&value).is_err());
    }

    #[test]
    fn build_memo_instruction_carries_payload() {
        let ix = build_memo_instruction("hello");
        assert_eq!(ix.data, b"hello");
        let memo = Pubkey::from_str("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr").unwrap();
        assert_eq!(ix.program_id, memo);
    }
}
