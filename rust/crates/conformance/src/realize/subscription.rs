//! Kit paths for `subscription` vectors: what `pkc fill` runs to realize a
//! case and what the build judge runs against an SDK's build.
//!
//! Vector inputs (one family per key; `harness/src/conformance/schema.ts`):
//!
//! - canonical bytes: `subscriptionAuthenticationMessage` (the bearer-proof
//!   JCS bytes), `subscriptionPeriod` (period to `period_hours`),
//!   `subscriptionPda` (delegation / authority PDA), `subscriptionInstruction`
//!   (subscribe / transfer_subscription data bytes), `subscriptionWire`
//!   (request or credential payload through the wire types, re-encoded);
//! - build (client): `subscriptionChallenge` + `signerSecretKey`, chain
//!   state (Plan, SubscriptionAuthority, mint) in `rpcFixtures`;
//! - verify (server): `subscriptionServer` (the route) with either
//!   `subscriptionAuthorization` (an activation credential, verified up to
//!   the broadcast), `subscriptionActive` (an on-chain delegation checked at
//!   `nowSeconds`) or `subscriptionProof` (a bearer proof against a
//!   delegation).
//!
//! Activation credentials are materialized here ([`Recipe`]): the kit's own
//! client builds the activation transaction against the fixture chain, the
//! case's single edit is applied, and the challenge is HMAC-bound under the
//! route's secret.

use std::sync::Arc;

use serde_json::{json, Map, Value};
use solana_instruction::{AccountMeta, Instruction};
use solana_pay_kit::mpp::client::{
    build_subscription_activation_credential, build_subscription_activation_transaction,
    sign_subscription_authentication, VerifiedPlan,
};
use solana_pay_kit::mpp::program::subscriptions::{
    self as program, find_subscription_authority_pda, find_subscription_pda, SubscribeData,
    TransferData, INSTRUCTION_SUBSCRIBE, INSTRUCTION_TRANSFER_SUBSCRIPTION,
};
use solana_pay_kit::mpp::protocol::core::{
    format_authorization, parse_authorization, Base64UrlJson, PaymentChallenge, PaymentCredential,
};
use solana_pay_kit::mpp::protocol::intents::{
    ActivatePayload, SubscriptionAccessPayload, SubscriptionAuthentication, SubscriptionPeriodUnit,
    SubscriptionRequest,
};
use solana_pay_kit::mpp::protocol::solana::CredentialPayload;
use solana_pay_kit::mpp::server::subscription::testkit::{
    verify_activation_pre_broadcast, verify_active_subscription_at, PreBroadcast,
};
use solana_pay_kit::mpp::server::subscription::{SubscriptionConfig, SubscriptionServer};
use solana_pay_kit::solana_keychain::memory::MemorySigner;
use solana_pay_kit::solana_keychain::SolanaSigner;
use solana_pubkey::Pubkey;

use super::{Observed, Output};
use crate::case::{Case, Expect, Intent, Mode, Provenance, RejectCode, Suite};
use crate::fixture_rpc::{self, Fixtures, HttpFixture};
use crate::keys::{self, pubkey, ATA_PROGRAM, SYSTEM_PROGRAM, TOKEN_PROGRAM};
use crate::run::judge::{compare_transactions, Failure};
use crate::run::vectors::Vector;
use crate::tx::{compile_v0, decode_b64, decompile, encode_b64, sign_slots};

/// The result field an accepted `subscription` build carries: the base64
/// activation transaction, signed by the subscriber only.
pub const BUILD_ARTIFACT: &str = "transaction";

// ── fixtures ───────────────────────────────────────────────────────────────

/// Deterministic actors, accounts and chain values shared by every case.
pub mod fx {
    use super::*;

    pub use solana_pay_kit::mpp::program::subscriptions::SUBSCRIPTIONS_PROGRAM_ID as PROGRAM;

    /// The subscriber is the vectors' client key ([`keys::CLIENT`]).
    pub const SUBSCRIBER: &str = keys::CLIENT;
    /// Merchant: plan owner and puller, seed `[21; 32]`.
    pub const MERCHANT_SEED: [u8; 32] = [21; 32];
    /// Server fee payer (sponsor): the x402 sponsor key.
    pub const SPONSOR_SEED: [u8; 32] = keys::X402_SERVER_FEE_PAYER_SEED;
    pub const SPONSOR: &str = keys::X402_SERVER_FEE_PAYER;
    /// Recipient of every charge.
    pub const RECIPIENT: &str = keys::SPLIT_RECIPIENT;
    /// An address that is neither the recipient nor any party.
    pub const ATTACKER: &str = keys::X402_OTHER_PAY_TO;
    /// A program that is not the subscriptions deployment.
    pub const FOREIGN_PROGRAM: &str = "Vote111111111111111111111111111111111111111";
    /// Another key that signs proofs it should not.
    pub const STRANGER_SEED: [u8; 32] = [23; 32];
    pub const MINT: &str = keys::MINT;
    pub const MINT_2022: &str = keys::MINT_2022;
    pub const DECIMALS: u8 = 6;
    pub const BLOCKHASH: &str = "EkSnNWid2cvwEVnVx9aBqawnmiCNiDgp3gUdkDPTKN1N";
    pub const PLAN_ID: u64 = 7;
    pub const CREATED_AT: i64 = 1_700_000_000;
    pub const INIT_ID: i64 = 77;
    pub const AMOUNT: &str = "10000000";
    pub const NETWORK: &str = "devnet";
    pub const REALM: &str = "api.example.com";
    pub const SECRET: &str = "subscription-conformance-binding-secret";
    pub const CHALLENGE_ID: &str = "qT8wErYuI3oPlKjH6gFdSa";
    /// The clock every time-dependent vector pins: 2030-03-17T17:46:40Z.
    pub const NOW: i64 = 1_900_000_000;

    pub fn merchant() -> String {
        keys::pubkey_of_seed(MERCHANT_SEED).to_string()
    }

    pub fn stranger() -> String {
        keys::pubkey_of_seed(STRANGER_SEED).to_string()
    }

    pub fn program() -> Pubkey {
        pubkey(PROGRAM)
    }

    /// The plan PDA `["plan", merchant, plan_id]` and its bump.
    pub fn plan_pda() -> (String, u8) {
        let (pda, bump) = program::find_plan_pda(
            &pubkey(&merchant()),
            &program::plan_id_seed(PLAN_ID),
            &program(),
        );
        (pda.to_string(), bump)
    }

    pub fn plan() -> String {
        plan_pda().0
    }

    pub fn delegation_of(plan: &str, subscriber: &str) -> String {
        find_subscription_pda(&pubkey(plan), &pubkey(subscriber), &program())
            .0
            .to_string()
    }

    pub fn delegation() -> String {
        delegation_of(&plan(), SUBSCRIBER)
    }

    pub fn authority_of(subscriber: &str, mint: &str) -> String {
        find_subscription_authority_pda(&pubkey(subscriber), &pubkey(mint), &program())
            .0
            .to_string()
    }

    /// RFC 3339 of a unix timestamp, seconds precision, UTC.
    pub fn rfc3339(secs: i64) -> String {
        time::OffsetDateTime::from_unix_timestamp(secs)
            .expect("timestamp in range")
            .format(&time::format_description::well_known::Rfc3339)
            .expect("formats")
    }

    fn address(text: &str) -> solana_address::Address {
        solana_address::Address::from(pubkey(text).to_bytes())
    }

    /// On-chain `Plan` terms.
    #[derive(Debug, Clone, PartialEq)]
    pub struct PlanSpec {
        pub mint: String,
        pub amount: u64,
        pub period_hours: u64,
        pub destinations: Vec<String>,
        pub pullers: Vec<String>,
    }

    impl Default for PlanSpec {
        fn default() -> Self {
            Self {
                mint: MINT.into(),
                amount: AMOUNT.parse().unwrap(),
                period_hours: 720,
                destinations: vec![RECIPIENT.into()],
                pullers: vec![],
            }
        }
    }

    fn padded(list: &[String]) -> [solana_address::Address; 4] {
        let mut out = [solana_address::Address::from([0u8; 32]); 4];
        for (slot, value) in out.iter_mut().zip(list) {
            *slot = address(value);
        }
        out
    }

    /// The Plan account bytes, encoded with the kit's generated type.
    pub fn plan_account(spec: &PlanSpec, owner_program: &str) -> Value {
        use solana_pay_kit::generated::subscriptions::accounts::Plan;
        use solana_pay_kit::generated::subscriptions::types::{PlanData, PlanTerms};
        let plan = Plan {
            discriminator: 1,
            owner: address(&merchant()),
            bump: plan_pda().1,
            status: 1,
            data: PlanData {
                plan_id: PLAN_ID,
                mint: address(&spec.mint),
                terms: PlanTerms {
                    amount: spec.amount,
                    period_hours: spec.period_hours,
                    created_at: CREATED_AT,
                },
                end_ts: 0,
                destinations: padded(&spec.destinations),
                pullers: padded(&spec.pullers),
                metadata_uri: [0u8; 128],
            },
        };
        account(owner_program, &borsh::to_vec(&plan).expect("plan encodes"))
    }

    /// The `SubscriptionAuthority` account for `(subscriber, mint)`.
    pub fn authority_account(subscriber: &str, mint: &str, init_id: i64) -> Value {
        use solana_pay_kit::generated::subscriptions::accounts::SubscriptionAuthority;
        let (_, bump) =
            find_subscription_authority_pda(&pubkey(subscriber), &pubkey(mint), &program());
        let authority = SubscriptionAuthority {
            discriminator: 0,
            user: address(subscriber),
            token_mint: address(mint),
            payer: address(subscriber),
            bump,
            init_id,
        };
        account(
            PROGRAM,
            &borsh::to_vec(&authority).expect("authority encodes"),
        )
    }

    /// On-chain `SubscriptionDelegation` state.
    #[derive(Debug, Clone, PartialEq)]
    pub struct DelegationSpec {
        pub plan: String,
        pub subscriber: String,
        pub init_id: i64,
        pub amount: u64,
        pub period_hours: u64,
        pub amount_pulled: u64,
        pub period_start: i64,
        pub expires_at: i64,
        pub version: u8,
    }

    impl Default for DelegationSpec {
        fn default() -> Self {
            Self {
                plan: plan(),
                subscriber: SUBSCRIBER.into(),
                init_id: INIT_ID,
                amount: AMOUNT.parse().unwrap(),
                period_hours: 720,
                amount_pulled: AMOUNT.parse().unwrap(),
                period_start: NOW - 3_600,
                expires_at: 0,
                version: 1,
            }
        }
    }

    pub fn delegation_account(spec: &DelegationSpec, owner_program: &str) -> Value {
        use solana_pay_kit::generated::subscriptions::accounts::SubscriptionDelegation;
        use solana_pay_kit::generated::subscriptions::types::{Header, PlanTerms};
        let (_, bump) =
            find_subscription_pda(&pubkey(&spec.plan), &pubkey(&spec.subscriber), &program());
        let delegation = SubscriptionDelegation {
            header: Header {
                discriminator: 4,
                version: spec.version,
                bump,
                delegator: address(&spec.subscriber),
                delegatee: address(&spec.plan),
                payer: address(&spec.subscriber),
                init_id: spec.init_id,
            },
            terms: PlanTerms {
                amount: spec.amount,
                period_hours: spec.period_hours,
                created_at: CREATED_AT,
            },
            amount_pulled_in_period: spec.amount_pulled,
            current_period_start_ts: spec.period_start,
            expires_at_ts: spec.expires_at,
        };
        account(
            owner_program,
            &borsh::to_vec(&delegation).expect("delegation encodes"),
        )
    }

    fn account(owner: &str, data: &[u8]) -> Value {
        use base64::Engine;
        json!({ "owner": owner, "data": base64::engine::general_purpose::STANDARD.encode(data) })
    }

    /// `rpcFixtures` with the plan, the subscriber's authority and the mint.
    pub fn chain(plan: &PlanSpec, plan_owner: &str, token_program: &str) -> Value {
        let mint = plan.mint.clone();
        let mut accounts = Map::new();
        accounts.insert(super::fx::plan(), plan_account(plan, plan_owner));
        accounts.insert(
            authority_of(SUBSCRIBER, &mint),
            authority_account(SUBSCRIBER, &mint, INIT_ID),
        );
        json!({
            "recentBlockhash": BLOCKHASH,
            "mints": { mint: { "owner": token_program, "decimals": DECIMALS } },
            "accounts": accounts,
        })
    }

    /// The spec-shaped request a server issues (draft-solana-subscription-00
    /// §Request Schema): shared fields plus the REQUIRED and the used
    /// OPTIONAL `methodDetails`.
    pub fn request() -> Value {
        json!({
            "amount": AMOUNT,
            "currency": MINT,
            "periodUnit": "day",
            "periodCount": "30",
            "recipient": RECIPIENT,
            "methodDetails": {
                "subscriptionProgram": PROGRAM,
                "planAddress": plan(),
                "mint": MINT,
                "tokenProgram": TOKEN_PROGRAM,
                "decimals": DECIMALS,
                "puller": merchant(),
                "network": NETWORK,
                "recentBlockhash": BLOCKHASH,
            },
        })
    }

    /// The kit server's `methodDetails` extensions (plan id, bump, terms,
    /// merchant, recipient, amount). Unknown fields every client ignores:
    /// the build cases carry them so a client that trusted them over the
    /// on-chain plan would sign the plan-mismatch cases.
    pub fn with_kit_extensions(mut request: Value) -> Value {
        let recipient = request_field(&request, "recipient");
        let amount = request_field(&request, "amount");
        let md = request["methodDetails"]
            .as_object_mut()
            .expect("methodDetails");
        md.insert("merchant".into(), json!(merchant()));
        md.insert("recipient".into(), recipient);
        md.insert("amount".into(), amount);
        md.insert("planIdNumeric".into(), json!(PLAN_ID));
        md.insert("planBump".into(), json!(plan_pda().1));
        md.insert("expectedPeriodHours".into(), json!(720));
        md.insert("expectedCreatedAt".into(), json!(CREATED_AT));
        request
    }

    fn request_field(request: &Value, key: &str) -> Value {
        request.get(key).cloned().unwrap_or(Value::Null)
    }

    /// The route a server is configured with (`subscriptionServer`).
    pub fn server() -> Value {
        json!({
            "realm": REALM,
            "secretKey": SECRET,
            "planAddress": plan(),
            "mint": MINT,
            "decimals": DECIMALS,
            "tokenProgram": TOKEN_PROGRAM,
            "puller": merchant(),
            "recipient": RECIPIENT,
            "periodUnit": "day",
            "periodCount": 30,
            "amount": AMOUNT,
            "network": NETWORK,
            "subscriptionProgram": PROGRAM,
        })
    }
}

// ── recipes (activation credentials) ───────────────────────────────────────

/// How a verify vector's input is produced.
#[derive(Debug, Clone, PartialEq)]
pub enum Recipe {
    Activation(Box<Activation>),
}

/// An activation credential: the kit's client builds the transaction from
/// `build_request` against `chain`, then the edits are applied and the
/// credential is bound to `issued_request` under the route's secret.
#[derive(Debug, Clone, PartialEq)]
pub struct Activation {
    /// The route (`subscriptionServer`).
    pub server: Value,
    /// Hold the sponsor's key on the server (fee sponsorship).
    pub sponsor: bool,
    /// The request the challenge carries.
    pub issued_request: Value,
    /// The request (with kit extensions) the activation is built from.
    pub build_request: Value,
    /// `rpcFixtures`.
    pub chain: Value,
    /// Challenge parameters: realm, method, intent, expires.
    pub realm: String,
    pub method: String,
    pub intent: String,
    pub expires: Option<String>,
    /// The echoed id is not the HMAC the route would compute.
    pub forged_id: bool,
    pub tx: Option<TxEdit>,
    pub auth: Option<AuthEdit>,
    pub payload: Option<PayloadEdit>,
    /// `source`; `None` omits it.
    pub source: Option<String>,
}

impl Activation {
    /// A well-formed, unsponsored activation of the default route.
    pub fn new() -> Self {
        Self {
            server: fx::server(),
            sponsor: false,
            issued_request: fx::request(),
            build_request: fx::with_kit_extensions(fx::request()),
            chain: fx::chain(&fx::PlanSpec::default(), fx::PROGRAM, TOKEN_PROGRAM),
            realm: fx::REALM.into(),
            method: "solana".into(),
            intent: "subscription".into(),
            expires: Some(fx::rfc3339(fx::NOW + 300)),
            forged_id: false,
            tx: None,
            auth: None,
            payload: None,
            source: Some(PaymentCredential::solana_did(fx::NETWORK, fx::SUBSCRIBER)),
        }
    }

    /// The same activation with the server as fee payer.
    pub fn sponsored() -> Self {
        let mut a = Self::new();
        a.sponsor = true;
        a.server["feePayerKey"] = json!(fx::SPONSOR);
        for request in [&mut a.issued_request, &mut a.build_request] {
            request["methodDetails"]["feePayer"] = json!(true);
            request["methodDetails"]["feePayerKey"] = json!(fx::SPONSOR);
        }
        a
    }

    pub fn tx(mut self, edit: TxEdit) -> Self {
        self.tx = Some(edit);
        self
    }

    pub fn auth(mut self, edit: AuthEdit) -> Self {
        self.auth = Some(edit);
        self
    }

    pub fn payload(mut self, edit: PayloadEdit) -> Self {
        self.payload = Some(edit);
        self
    }

    /// Set a field of both requests (the activation is built from what the
    /// challenge says).
    pub fn request_field(mut self, key: &str, value: Value) -> Self {
        for request in [&mut self.issued_request, &mut self.build_request] {
            set_path(request, key, value.clone());
        }
        self
    }

    /// Set a field of the issued request only.
    pub fn issued_field(mut self, key: &str, value: Value) -> Self {
        set_path(&mut self.issued_request, key, value);
        self
    }

    pub fn server_field(mut self, key: &str, value: Value) -> Self {
        set_path(&mut self.server, key, value);
        self
    }

    pub fn recipe(self) -> crate::case::Input {
        crate::case::Input::Subscription(Box::new(Recipe::Activation(Box::new(self))))
    }
}

impl Default for Activation {
    fn default() -> Self {
        Self::new()
    }
}

/// `a.b` paths; `Value::Null` removes the key.
fn set_path(target: &mut Value, path: &str, value: Value) {
    let mut parts: Vec<&str> = path.split('.').collect();
    let last = parts.pop().expect("non-empty path");
    let mut node = target;
    for part in parts {
        node = &mut node[part];
    }
    if value.is_null() {
        if let Some(obj) = node.as_object_mut() {
            obj.remove(last);
        }
    } else {
        node[last] = value;
    }
}

/// One edit of the kit-built activation transaction. Each operator is
/// paired with the reject code the server must produce ([`TxEdit::expected`]);
/// a generated reject case must declare that code.
#[derive(Debug, Clone, PartialEq)]
pub enum TxEdit {
    /// Append an instruction of `program` (no accounts, `data`).
    ExtraInstruction {
        program: &'static str,
        data: &'static [u8],
    },
    /// Append a System transfer of lamports from the subscriber.
    SystemTransfer,
    /// Append an SPL Token `Approve` of the subscriber's ATA to the attacker.
    TokenApprove,
    /// Point transfer_subscription's receiver ATA at `owner`'s ATA.
    ReceiverAta {
        owner: &'static str,
    },
    DropSubscribe,
    DropTransfer,
    DuplicateSubscribe,
    DuplicateTransfer,
    /// Move transfer_subscription before subscribe.
    TransferFirst,
    /// Run subscribe and transfer_subscription on another program.
    ForeignProgram,
    /// Add an idempotent ATA creation for `owner`.
    CreateAtaFor {
        owner: &'static str,
    },
    /// subscribe names another plan account.
    SubscribePlan {
        plan: &'static str,
    },
    /// Prepend initialize_subscription_authority for the subscriber and
    /// `mint` (an authority this activation does not use).
    InitAuthority {
        mint: &'static str,
    },
    /// The subscriber signs nothing (sponsored layout).
    DemoteSubscriber,
    /// transfer_subscription data amount changed by `delta`.
    TransferAmount {
        delta: i64,
    },
}

impl TxEdit {
    pub fn expected(&self) -> RejectCode {
        use RejectCode::*;
        match self {
            TxEdit::ExtraInstruction { .. }
            | TxEdit::SystemTransfer
            | TxEdit::TokenApprove
            | TxEdit::DuplicateSubscribe
            | TxEdit::DuplicateTransfer
            | TxEdit::ForeignProgram
            | TxEdit::CreateAtaFor { .. }
            | TxEdit::InitAuthority { .. } => UnexpectedInstruction,
            TxEdit::ReceiverAta { .. } => RecipientMismatch,
            TxEdit::DropSubscribe
            | TxEdit::DropTransfer
            | TxEdit::TransferFirst
            | TxEdit::SubscribePlan { .. }
            | TxEdit::TransferAmount { .. } => ActivationScope,
            TxEdit::DemoteSubscriber => InvalidPayload,
        }
    }

    pub fn describe(&self) -> String {
        match self {
            TxEdit::ExtraInstruction { program, data } => {
                format!("instruction of program {program} with data {data:?} appended")
            }
            TxEdit::SystemTransfer => "System transfer from the subscriber appended".into(),
            TxEdit::TokenApprove => {
                "SPL Token Approve of the subscriber's ATA to another delegate appended".into()
            }
            TxEdit::ReceiverAta { owner } => {
                format!("transfer_subscription receiver ATA set to {owner}'s ATA")
            }
            TxEdit::DropSubscribe => "subscribe removed".into(),
            TxEdit::DropTransfer => "transfer_subscription removed".into(),
            TxEdit::DuplicateSubscribe => "subscribe duplicated".into(),
            TxEdit::DuplicateTransfer => "transfer_subscription duplicated".into(),
            TxEdit::TransferFirst => "transfer_subscription moved before subscribe".into(),
            TxEdit::ForeignProgram => {
                format!(
                    "subscribe and transfer_subscription sent to {}",
                    fx::FOREIGN_PROGRAM
                )
            }
            TxEdit::CreateAtaFor { owner } => {
                format!("idempotent ATA creation for {owner} added")
            }
            TxEdit::SubscribePlan { plan } => format!("subscribe plan account set to {plan}"),
            TxEdit::InitAuthority { mint } => {
                format!("initialize_subscription_authority for mint {mint} prepended")
            }
            TxEdit::DemoteSubscriber => "the subscriber is no longer a signer".into(),
            TxEdit::TransferAmount { delta } => {
                format!("transfer_subscription amount changed by {delta}")
            }
        }
    }

    fn apply(&self, tx: &str) -> Result<String, String> {
        let decoded = decode_b64(tx)?;
        let mut d = decompile(&decoded.message)?;
        let program_id = fx::program();
        let position = |d: &crate::tx::Decompiled, disc: u8| {
            d.instructions
                .iter()
                .position(|ix| ix.program_id == program_id && ix.data.first() == Some(&disc))
                .ok_or_else(|| format!("activation has no instruction {disc}"))
        };
        let subscribe = position(&d, INSTRUCTION_SUBSCRIBE)?;
        let transfer = position(&d, INSTRUCTION_TRANSFER_SUBSCRIPTION)?;
        let subscriber = pubkey(fx::SUBSCRIBER);
        match self {
            TxEdit::ExtraInstruction { program, data } => {
                d.instructions.insert(
                    transfer + 1,
                    Instruction {
                        program_id: pubkey(program),
                        accounts: vec![],
                        data: data.to_vec(),
                    },
                );
            }
            TxEdit::SystemTransfer => {
                let mut data = 2u32.to_le_bytes().to_vec();
                data.extend_from_slice(&1_000u64.to_le_bytes());
                d.instructions.push(Instruction {
                    program_id: pubkey(SYSTEM_PROGRAM),
                    accounts: vec![
                        AccountMeta::new(subscriber, true),
                        AccountMeta::new(pubkey(fx::ATTACKER), false),
                    ],
                    data,
                });
            }
            TxEdit::TokenApprove => {
                let mut data = vec![4u8];
                data.extend_from_slice(&u64::MAX.to_le_bytes());
                d.instructions.push(Instruction {
                    program_id: pubkey(TOKEN_PROGRAM),
                    accounts: vec![
                        AccountMeta::new(keys::ata(fx::SUBSCRIBER, fx::MINT, TOKEN_PROGRAM), false),
                        AccountMeta::new_readonly(pubkey(fx::ATTACKER), false),
                        AccountMeta::new_readonly(subscriber, true),
                    ],
                    data,
                });
            }
            TxEdit::ReceiverAta { owner } => {
                d.instructions[transfer].accounts[4].pubkey =
                    keys::ata(owner, fx::MINT, TOKEN_PROGRAM);
            }
            TxEdit::DropSubscribe => {
                d.instructions.remove(subscribe);
            }
            TxEdit::DropTransfer => {
                d.instructions.remove(transfer);
            }
            TxEdit::DuplicateSubscribe => {
                let ix = d.instructions[subscribe].clone();
                d.instructions.insert(subscribe + 1, ix);
            }
            TxEdit::DuplicateTransfer => {
                let ix = d.instructions[transfer].clone();
                d.instructions.insert(transfer + 1, ix);
            }
            TxEdit::TransferFirst => {
                let ix = d.instructions.remove(transfer);
                d.instructions.insert(subscribe, ix);
            }
            TxEdit::ForeignProgram => {
                for index in [subscribe, transfer] {
                    d.instructions[index].program_id = pubkey(fx::FOREIGN_PROGRAM);
                }
            }
            TxEdit::CreateAtaFor { owner } => {
                d.instructions.insert(
                    subscribe,
                    Instruction {
                        program_id: pubkey(ATA_PROGRAM),
                        accounts: vec![
                            AccountMeta::new(d.fee_payer, true),
                            AccountMeta::new(keys::ata(owner, fx::MINT, TOKEN_PROGRAM), false),
                            AccountMeta::new_readonly(pubkey(owner), false),
                            AccountMeta::new_readonly(pubkey(fx::MINT), false),
                            AccountMeta::new_readonly(pubkey(SYSTEM_PROGRAM), false),
                            AccountMeta::new_readonly(pubkey(TOKEN_PROGRAM), false),
                        ],
                        data: vec![1],
                    },
                );
            }
            TxEdit::SubscribePlan { plan } => {
                d.instructions[subscribe].accounts[2].pubkey = pubkey(plan);
            }
            TxEdit::InitAuthority { mint } => {
                let ix = program::build_initialize_subscription_authority_ix(
                    program_id,
                    program::InitializeSubscriptionAuthorityAccounts {
                        owner: subscriber,
                        subscription_authority: find_subscription_authority_pda(
                            &subscriber,
                            &pubkey(mint),
                            &program_id,
                        )
                        .0,
                        token_mint: pubkey(mint),
                        user_ata: keys::ata(fx::SUBSCRIBER, mint, TOKEN_PROGRAM),
                        token_program: pubkey(TOKEN_PROGRAM),
                    },
                );
                d.instructions.insert(subscribe, ix);
            }
            TxEdit::DemoteSubscriber => {
                for ix in &mut d.instructions {
                    for meta in &mut ix.accounts {
                        if meta.pubkey == subscriber {
                            meta.is_signer = false;
                        }
                    }
                }
            }
            TxEdit::TransferAmount { delta } => {
                let data = &mut d.instructions[transfer].data;
                let amount = u64::from_le_bytes(data[1..9].try_into().unwrap());
                let bumped = amount
                    .checked_add_signed(*delta)
                    .ok_or("amount edit overflows")?;
                data[1..9].copy_from_slice(&bumped.to_le_bytes());
            }
        }
        let mut out = compile_v0(&d)?;
        sign_slots(&mut out, &[keys::CLIENT_SEED]);
        encode_b64(&out)
    }
}

/// One edit of the bearer proof in the activation payload.
#[derive(Debug, Clone, PartialEq)]
pub enum AuthEdit {
    /// No `authentication`.
    Missing,
    /// Signed over another challenge id (and echoing it).
    ChallengeId(&'static str),
    /// Signed over another delegation address.
    Delegation(&'static str),
    /// Signed by another key, which it names as payer.
    Signer([u8; 32]),
    /// One signature byte flipped.
    TamperSignature,
}

impl AuthEdit {
    pub fn describe(&self) -> String {
        match self {
            AuthEdit::Missing => "authentication removed".into(),
            AuthEdit::ChallengeId(id) => format!("proof bound to challenge {id}"),
            AuthEdit::Delegation(d) => format!("proof bound to delegation {d}"),
            AuthEdit::Signer(seed) => {
                format!("proof signed by {}", keys::pubkey_of_seed(*seed))
            }
            AuthEdit::TamperSignature => "proof signature tampered".into(),
        }
    }
}

/// One edit of the activation payload.
#[derive(Debug, Clone, PartialEq)]
pub enum PayloadEdit {
    /// `type` set to this value.
    Type(&'static str),
    /// `transaction` removed.
    NoTransaction,
    /// Push mode: `type="signature"` with the transaction's signature.
    PushSignature,
}

fn signer_of(seed: [u8; 32]) -> Result<MemorySigner, String> {
    MemorySigner::from_bytes(&keys::keypair_bytes(seed)).map_err(|e| e.to_string())
}

pub async fn materialize(case: &Case, recipe: &Recipe) -> Result<Value, String> {
    let Recipe::Activation(a) = recipe;
    if let (Some(edit), Provenance::Generated, Expect::Reject { code, .. }) =
        (&a.tx, &case.provenance, &case.expect)
    {
        if edit.expected() != *code {
            return Err(format!(
                "{edit:?} is paired with {} in {}, but the case declares {code}",
                edit.expected(),
                Suite::Subscription.as_str()
            ));
        }
    }
    let subscriber = signer_of(keys::CLIENT_SEED)?;
    let fixtures = Fixtures::from_input(&json!({ "rpcFixtures": a.chain }))?;
    let (rpc, _log) = fixture_rpc::rpc_client(&fixtures);
    let build: SubscriptionRequest = serde_json::from_value(a.build_request.clone())
        .map_err(|e| format!("build request: {e}"))?;
    let terms = build.terms().map_err(|e| format!("build request: {e}"))?;
    let plan = VerifiedPlan::fetch(&rpc, terms, None).map_err(|e| format!("build plan: {e}"))?;
    let transaction = match build_subscription_activation_transaction(&subscriber, &rpc, &plan)
        .await
        .map_err(|e| format!("kit activation build: {e}"))?
    {
        CredentialPayload::Transaction { transaction } => transaction,
        other => return Err(format!("unexpected payload {other:?}")),
    };
    let transaction = match &a.tx {
        Some(edit) => edit.apply(&transaction)?,
        None => transaction,
    };
    let secret = a.server["secretKey"].as_str().ok_or("server.secretKey")?;
    let encoded = Base64UrlJson::from_value(&a.issued_request).map_err(|e| e.to_string())?;
    let mut challenge = PaymentChallenge::with_challenge_binding_secret_full(
        secret,
        a.realm.as_str(),
        a.method.as_str(),
        a.intent.as_str(),
        encoded,
        a.expires.as_deref(),
        None,
        None,
        None,
    );
    if a.forged_id {
        challenge.id = fx::CHALLENGE_ID.into();
    }
    let plan = a.issued_request["methodDetails"]["planAddress"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    let delegation = fx::delegation_of(&plan, fx::SUBSCRIBER);
    let authentication = match &a.auth {
        None => Some(sign_proof(&subscriber, &challenge.id, &delegation).await?),
        Some(AuthEdit::Missing) => None,
        Some(AuthEdit::ChallengeId(id)) => Some(sign_proof(&subscriber, id, &delegation).await?),
        Some(AuthEdit::Delegation(other)) => {
            Some(sign_proof(&subscriber, &challenge.id, other).await?)
        }
        Some(AuthEdit::Signer(seed)) => {
            Some(sign_proof(&signer_of(*seed)?, &challenge.id, &delegation).await?)
        }
        Some(AuthEdit::TamperSignature) => {
            let mut proof = sign_proof(&subscriber, &challenge.id, &delegation).await?;
            let mut bytes = bs58::decode(&proof.signature)
                .into_vec()
                .map_err(|e| e.to_string())?;
            bytes[0] ^= 0x01;
            proof.signature = bs58::encode(bytes).into_string();
            Some(proof)
        }
    };
    // The payload as JSON: an edit may drop a field the kit's wire type
    // requires (`authentication`).
    let mut payload = json!({
        "type": "transaction",
        "transaction": transaction,
    });
    if let Some(authentication) = authentication {
        payload["authentication"] =
            serde_json::to_value(authentication).map_err(|e| e.to_string())?;
    }
    match &a.payload {
        None => {}
        Some(PayloadEdit::Type(kind)) => payload["type"] = json!(kind),
        Some(PayloadEdit::NoTransaction) => {
            payload
                .as_object_mut()
                .expect("object")
                .remove("transaction");
        }
        Some(PayloadEdit::PushSignature) => {
            let tx = decode_b64(&transaction)?;
            payload["type"] = json!("signature");
            payload
                .as_object_mut()
                .expect("object")
                .remove("transaction");
            payload["signature"] = json!(tx.signatures[0].to_string());
        }
    }
    let mut credential = PaymentCredential::new(challenge.to_echo(), payload);
    credential.source = a.source.clone();
    let authorization = format_authorization(&credential).map_err(|e| e.to_string())?;
    let mut input = json!({
        "nowSeconds": fx::NOW,
        "subscriptionServer": a.server,
        "subscriptionAuthorization": authorization,
        "rpcFixtures": a.chain,
    });
    if a.sponsor {
        input["subscriptionServerFeePayerSecretKey"] = keys::secret_json(fx::SPONSOR_SEED);
    }
    Ok(input)
}

async fn sign_proof(
    signer: &MemorySigner,
    challenge_id: &str,
    delegation: &str,
) -> Result<SubscriptionAuthentication, String> {
    sign_subscription_authentication(signer, challenge_id, delegation)
        .await
        .map_err(|e| e.to_string())
}

/// `subscriptionProof` for a proof signed by `seed` over the canonical
/// message (computed when the case is built: pure Ed25519).
pub fn proof(seed: [u8; 32], challenge_id: &str, delegation: &str) -> Value {
    use ed25519_dalek::Signer as _;
    let key = keys::signing_key(seed);
    let payer = keys::pubkey_of_seed(seed).to_string();
    let mut authentication = SubscriptionAuthentication {
        kind: solana_pay_kit::mpp::protocol::intents::SubscriptionAuthenticationType::Proof,
        challenge_id: challenge_id.into(),
        payer,
        signature: String::new(),
    };
    let message = authentication
        .message_bytes(delegation)
        .expect("message encodes");
    authentication.signature = bs58::encode(key.sign(&message).to_bytes()).into_string();
    serde_json::to_value(authentication).expect("proof encodes")
}

// ── classification ─────────────────────────────────────────────────────────

/// The shared reject category of a kit (or SDK) subscription error message.
/// Mirrored in the Rust and TypeScript testees' subscription modules.
pub fn classify(message: &str) -> Option<RejectCode> {
    use RejectCode::*;
    let m = message.to_ascii_lowercase();
    let has = |needle: &str| m.contains(needle);
    let code = if has("network does not match") || has("network mismatch") {
        WrongNetwork
    } else if has("hmac mismatch")
        || has("did not issue")
        || has("was not issued by this server")
        || has("does not match this server")
        || has("is not a subscription")
        || has("terms do not match")
        || has("does not match this route")
    {
        ChallengeMismatch
    } else if has("challenge has expired") || has("challenge expired") {
        ChallengeExpired
    } else if has("subscription has expired") || has("subscription expired") {
        SubscriptionExpired
    } else if has("authentication proof")
        || has("proof challengeid does not match")
        || has("proof payer does not match")
        || has("missing authentication")
        || has("authentication.type")
        || has("authentication is required")
    {
        AuthenticationInvalid
    } else if has("receiver does not match") || has("transfer_subscription accounts do not match") {
        RecipientMismatch
    } else if has("source") && (has("does not match") || has("did:pkh")) {
        SourceMismatch
    } else if has("fee payer must be")
        || has("fee payer pubkey not present")
        || has("fee-payer signer does not match")
    {
        FeePayerMismatch
    } else if has("compute unit limit exceeds") {
        ComputeLimitOverCap
    } else if has("compute unit price exceeds") {
        ComputePriceOverCap
    } else if has("unsupported program")
        || has("multiple subscribe")
        || has("multiple transfer_subscription")
        || has("multiple initialize_subscription_authority")
        || has("initialize_subscription_authority is not allowed")
        || has("idempotent")
        || has("ata creation")
        || has("unsupported subscriptions instruction")
        || has("unsupported compute-budget")
        || has("multiple memo")
        || has("multiple compute-unit")
    {
        UnexpectedInstruction
    } else if has("missing subscribe")
        || has("missing transfer_subscription")
        || has("subscribe must precede")
        || has("subscribe accounts do not match")
        || has("transfer_subscription data does not match")
        || has("transfer_subscription amount does not match")
        || has("transfer_subscription delegator does not match")
        || has("transfer_subscription mint does not match")
        || has("memo does not match")
        || has("missing challenge externalid memo")
        || has("signers must be exactly")
    {
        ActivationScope
    } else if has("not paid for the current billing period")
        || has("cancellation has taken effect")
        || has("authority has been invalidated")
        || has("subscriptionauthority account")
        || has("subscriptiondelegation account")
        || has("does not match the bound plan and payer")
        || has("owner mismatch")
        || has("subscriptiondelegation discriminator")
        || has("subscriptiondelegation length")
    {
        SubscriptionInactive
    } else if has("invalid subscription challenge")
        || has("requires feepayerkey")
        || has("feepayerkey is required")
        || has("untrusted subscription program")
        || has("currency must match")
        || has("must match amount")
        || has("must match recipient")
        || has("does not match the challenge")
        || has("plan owner does not match")
        || has("plan account not found")
        || has("invalid recentblockhash")
        || has("pubkey")
        || has("periodcount")
        || has("period_hours")
        || has("periodunit")
        || has("methoddetails")
        || has("invalid amount")
    {
        InvalidChallenge
    } else if has("push-mode")
        || has("unsupported payload type")
        || has("payload type")
        || has("missing `transaction`")
        || has("missing transaction")
        || has("failed to decode")
        || has("tx decode")
        || has("invalid transaction")
        || has("could not identify subscriber")
        || has("subscriber cannot")
        || has("does not verify")
        || has("cannot be used with fee sponsorship")
    {
        InvalidPayload
    } else {
        return None;
    };
    Some(code)
}

fn reject(message: impl Into<String>) -> Observed {
    let message = message.into();
    Observed::Reject {
        code: classify(&message).or_else(|| crate::classify::classify(&message)),
        message,
    }
}

fn reject_as(code: RejectCode, message: impl Into<String>) -> Observed {
    Observed::Reject {
        code: Some(code),
        message: message.into(),
    }
}

// ── kit drivers ────────────────────────────────────────────────────────────

pub async fn run(mode: Mode, input: &Value) -> Result<Observed, String> {
    match mode {
        Mode::CanonicalBytes => canonical(input),
        Mode::BuildTransaction => build(input).await,
        Mode::VerifyTransaction => {
            if input.get("subscriptionAuthorization").is_some() {
                verify_activation(input).await
            } else if input.get("subscriptionActive").is_some() {
                verify_active(input).await
            } else if input.get("subscriptionProof").is_some() {
                verify_proof(input)
            } else {
                Ok(Observed::NotExpressible(
                    "subscription verify input carries no credential".into(),
                ))
            }
        }
    }
}

fn exact(fields: Vec<(&str, Value)>) -> Observed {
    let mut exact = Map::new();
    for (k, v) in fields {
        exact.insert(k.to_string(), v);
    }
    Observed::Accept(Output {
        exact: Some(exact),
        ..Default::default()
    })
}

fn jcs(value: &Value) -> Result<Observed, String> {
    let (json, b64) = super::canonical_json(value)?;
    Ok(exact(vec![
        ("canonicalJson", json!(json)),
        ("base64Url", json!(b64)),
    ]))
}

fn canonical(input: &Value) -> Result<Observed, String> {
    if let Some(m) = input.get("subscriptionAuthenticationMessage") {
        let field = |k: &str| {
            m.get(k)
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string()
        };
        let authentication = SubscriptionAuthentication {
            kind: solana_pay_kit::mpp::protocol::intents::SubscriptionAuthenticationType::Proof,
            challenge_id: field("challengeId"),
            payer: field("payer"),
            signature: String::new(),
        };
        let bytes = authentication
            .message_bytes(&field("subscriptionDelegation"))
            .map_err(|e| e.to_string())?;
        let text = String::from_utf8(bytes.clone()).map_err(|e| e.to_string())?;
        return Ok(exact(vec![
            ("canonicalJson", json!(text)),
            (
                "base64Url",
                json!(solana_pay_kit::mpp::protocol::core::base64url_encode(
                    &bytes
                )),
            ),
        ]));
    }
    if let Some(p) = input.get("subscriptionPeriod") {
        let unit: SubscriptionPeriodUnit =
            match serde_json::from_value(p.get("periodUnit").cloned().unwrap_or(Value::Null)) {
                Ok(unit) => unit,
                Err(e) => {
                    return Ok(reject_as(
                        RejectCode::InvalidChallenge,
                        format!("invalid periodUnit: {e}"),
                    ))
                }
            };
        let request = SubscriptionRequest {
            period_unit: unit,
            period_count: p
                .get("periodCount")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
            ..Default::default()
        };
        return match request.period_hours() {
            Ok(hours) => jcs(&json!({ "periodHours": hours })),
            Err(e) => Ok(reject_as(RejectCode::InvalidChallenge, e.to_string())),
        };
    }
    if let Some(p) = input.get("subscriptionPda") {
        let field = |k: &str| p.get(k).and_then(Value::as_str).unwrap_or_default();
        let program_id = pubkey(field("subscriptionProgram"));
        let address = match field("kind") {
            "delegation" => {
                find_subscription_pda(
                    &pubkey(field("planAddress")),
                    &pubkey(field("subscriber")),
                    &program_id,
                )
                .0
            }
            "authority" => {
                find_subscription_authority_pda(
                    &pubkey(field("subscriber")),
                    &pubkey(field("mint")),
                    &program_id,
                )
                .0
            }
            other => return Err(format!("unknown subscriptionPda kind {other:?}")),
        };
        return jcs(&json!({ "address": address.to_string() }));
    }
    if let Some(ix) = input.get("subscriptionInstruction") {
        let str_of = |k: &str| ix.get(k).and_then(Value::as_str).unwrap_or_default();
        let num = |k: &str| -> Result<i128, String> {
            match ix.get(k) {
                Some(Value::String(s)) => s.parse().map_err(|_| format!("invalid {k}")),
                Some(Value::Number(n)) => n
                    .as_i64()
                    .map(i128::from)
                    .or_else(|| n.as_u64().map(i128::from))
                    .ok_or_else(|| format!("invalid {k}")),
                _ => Err(format!("missing {k}")),
            }
        };
        let bytes = match str_of("kind") {
            "subscribe" => SubscribeData {
                plan_id: num("planId")? as u64,
                plan_bump: num("planBump")? as u8,
                expected_mint: pubkey(str_of("mint")),
                expected_amount: num("amount")? as u64,
                expected_period_hours: num("periodHours")? as u64,
                expected_created_at: num("createdAt")? as i64,
                expected_subscription_authority_init_id: num("authorityInitId")? as i64,
            }
            .to_bytes(),
            "transfer" => TransferData {
                amount: num("amount")? as u64,
                delegator: pubkey(str_of("delegator")),
                mint: pubkey(str_of("mint")),
            }
            .to_bytes(INSTRUCTION_TRANSFER_SUBSCRIPTION),
            other => return Err(format!("unknown subscriptionInstruction kind {other:?}")),
        };
        return Ok(exact(vec![
            ("bytes", json!(bytes)),
            (
                "base64Url",
                json!(solana_pay_kit::mpp::protocol::core::base64url_encode(
                    &bytes
                )),
            ),
        ]));
    }
    if let Some(w) = input.get("subscriptionWire") {
        let value = w.get("value").cloned().unwrap_or(Value::Null);
        let (reencoded, code) = match w.get("shape").and_then(Value::as_str) {
            Some("request") => (
                serde_json::from_value::<SubscriptionRequest>(value).and_then(serde_json::to_value),
                RejectCode::InvalidChallenge,
            ),
            Some("activation") => (
                serde_json::from_value::<ActivatePayload>(value).and_then(serde_json::to_value),
                RejectCode::InvalidPayload,
            ),
            Some("access") => (
                serde_json::from_value::<SubscriptionAccessPayload>(value)
                    .and_then(serde_json::to_value),
                RejectCode::InvalidPayload,
            ),
            other => return Err(format!("unknown subscriptionWire shape {other:?}")),
        };
        return match reencoded {
            Ok(reencoded) => jcs(&reencoded),
            Err(e) => Ok(reject_as(
                code,
                format!("invalid subscription wire value: {e}"),
            )),
        };
    }
    super::canonical_bytes(input)
}

fn signer_from(input: &Value, key: &str) -> Result<MemorySigner, String> {
    let bytes: Vec<u8> = input
        .get(key)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("input.{key} missing"))?
        .iter()
        .map(|b| b.as_u64().and_then(|b| u8::try_from(b).ok()))
        .collect::<Option<_>>()
        .ok_or_else(|| format!("input.{key} must be bytes"))?;
    MemorySigner::from_bytes(&bytes).map_err(|e| format!("invalid {key}: {e}"))
}

/// The challenge a build vector carries, as the kit's client receives it.
fn challenge_of(input: &Value) -> Result<PaymentChallenge, String> {
    let c = input
        .get("subscriptionChallenge")
        .ok_or("input.subscriptionChallenge missing")?;
    let field = |k: &str| c.get(k).and_then(Value::as_str).unwrap_or_default();
    let request = Base64UrlJson::from_value(c.get("request").unwrap_or(&Value::Null))
        .map_err(|e| e.to_string())?;
    let mut challenge = PaymentChallenge::new(
        field("id"),
        field("realm"),
        field("method"),
        field("intent"),
        request,
    );
    challenge.expires = c.get("expires").and_then(Value::as_str).map(str::to_string);
    Ok(challenge)
}

/// The kit's client (`build_subscription_activation_credential`) against
/// the fixture chain.
async fn build(input: &Value) -> Result<Observed, String> {
    let signer = signer_from(input, "signerSecretKey")?;
    let challenge = challenge_of(input)?;
    let fixtures = Fixtures::from_input(input)?;
    let (rpc, _log) = fixture_rpc::rpc_client(&fixtures);
    Ok(
        match build_subscription_activation_credential(&signer, &rpc, &challenge).await {
            Ok(activation) => match activation.credential.payload.get("transaction") {
                Some(Value::String(transaction)) => Observed::Accept(Output {
                    transaction: Some(transaction.clone()),
                    ..Default::default()
                }),
                _ => return Err("activation credential carries no transaction".into()),
            },
            // Every refusal of the client builder is a refusal of the
            // challenge it was handed.
            Err(error) => reject_as(RejectCode::InvalidChallenge, error.to_string()),
        },
    )
}

/// `subscriptionServer` as the kit's route config.
fn server_config(input: &Value, rpc_url: String) -> Result<SubscriptionConfig, String> {
    let s = input
        .get("subscriptionServer")
        .ok_or("input.subscriptionServer missing")?;
    let field = |k: &str| {
        s.get(k)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string()
    };
    let period_unit: SubscriptionPeriodUnit =
        serde_json::from_value(s.get("periodUnit").cloned().unwrap_or(json!("day")))
            .map_err(|e| format!("server periodUnit: {e}"))?;
    let fee_payer_signer: Option<Arc<dyn solana_pay_kit::solana_keychain::TransactionSigner>> =
        match input.get("subscriptionServerFeePayerSecretKey") {
            Some(_) => Some(Arc::new(signer_from(
                input,
                "subscriptionServerFeePayerSecretKey",
            )?)),
            None => None,
        };
    let fee_payer_pubkey = s
        .get("feePayerKey")
        .and_then(Value::as_str)
        .map(str::to_string);
    Ok(SubscriptionConfig {
        plan_id: field("planAddress"),
        mint: field("mint"),
        decimals: s.get("decimals").and_then(Value::as_u64).unwrap_or(6) as u8,
        token_program: field("tokenProgram"),
        puller: field("puller"),
        recipient: field("recipient"),
        period_unit,
        period_count: s.get("periodCount").and_then(Value::as_u64).unwrap_or(0),
        amount_base_units: field("amount"),
        network: field("network"),
        program_id: s
            .get("subscriptionProgram")
            .and_then(Value::as_str)
            .map(str::to_string),
        rpc_url: Some(rpc_url),
        challenge_binding_secret: field("secretKey"),
        realm: field("realm"),
        fee_payer: fee_payer_pubkey.is_some(),
        fee_payer_signer,
        fee_payer_pubkey,
        ..Default::default()
    })
}

fn now_of(input: &Value) -> Result<i64, String> {
    input
        .get("nowSeconds")
        .and_then(Value::as_i64)
        .ok_or_else(|| "input.nowSeconds missing".into())
}

/// The kit server's activation checks up to the broadcast
/// (`mpp::server::subscription::testkit::verify_activation_pre_broadcast`).
async fn verify_activation(input: &Value) -> Result<Observed, String> {
    let fixtures = Fixtures::from_input(input)?;
    let fixture = HttpFixture::start(&fixtures).map_err(|e| e.to_string())?;
    let server = SubscriptionServer::new(server_config(input, fixture.url().to_string())?)
        .map_err(|e| format!("server config: {e}"))?;
    let header = input
        .get("subscriptionAuthorization")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let credential = match parse_authorization(header) {
        Ok(credential) => credential,
        Err(e) => return Ok(reject_as(RejectCode::InvalidPayload, e.to_string())),
    };
    Ok(
        match verify_activation_pre_broadcast(&server, &credential, now_of(input)?).await {
            Ok(PreBroadcast::Activation) => Observed::Accept(Output::default()),
            Ok(PreBroadcast::AccessProof) => Observed::NotExpressible(
                "a type=\"proof\" credential needs the binding a confirmed activation writes"
                    .into(),
            ),
            Err(error) => reject(error.message),
        },
    )
}

/// `verify_active_subscription` at the pinned clock against the fixture
/// delegation and authority.
async fn verify_active(input: &Value) -> Result<Observed, String> {
    let fixtures = Fixtures::from_input(input)?;
    let fixture = HttpFixture::start(&fixtures).map_err(|e| e.to_string())?;
    let server = SubscriptionServer::new(server_config(input, fixture.url().to_string())?)
        .map_err(|e| format!("server config: {e}"))?;
    let active = &input["subscriptionActive"];
    let subscriber = pubkey(active["subscriber"].as_str().unwrap_or_default());
    let amount = active["amount"].as_str().unwrap_or_default();
    Ok(
        match verify_active_subscription_at(&server, &subscriber, amount, now_of(input)?).await {
            Ok(_) => Observed::Accept(Output::default()),
            Err(error) => {
                let message = error.message;
                Observed::Reject {
                    code: classify(&message).or(Some(RejectCode::SubscriptionInactive)),
                    message,
                }
            }
        },
    )
}

/// `SubscriptionAuthentication::verify` against the delegation.
fn verify_proof(input: &Value) -> Result<Observed, String> {
    let p = &input["subscriptionProof"];
    let authentication: SubscriptionAuthentication =
        match serde_json::from_value(p["authentication"].clone()) {
            Ok(a) => a,
            Err(e) => {
                return Ok(reject_as(
                    RejectCode::AuthenticationInvalid,
                    format!("invalid authentication: {e}"),
                ))
            }
        };
    let delegation = p["subscriptionDelegation"].as_str().unwrap_or_default();
    Ok(match authentication.verify(delegation) {
        Ok(true) => Observed::Accept(Output::default()),
        Ok(false) => reject_as(
            RejectCode::AuthenticationInvalid,
            "the proof signature does not verify over the canonical message",
        ),
        Err(e) => reject_as(RejectCode::AuthenticationInvalid, e.to_string()),
    })
}

// ── build judge ────────────────────────────────────────────────────────────

/// The verify input that judges a built activation: the route the build
/// vector's challenge describes, the build bound to a fresh challenge under
/// a judge secret, the proof signed with the vector's subscriber key.
async fn verify_input_for_build(vector: &Vector, artifact: &str) -> Result<Value, String> {
    let input = vector.input();
    let request = input
        .pointer("/subscriptionChallenge/request")
        .ok_or("build vector has no challenge request")?;
    let md = &request["methodDetails"];
    let text = |v: &Value| v.as_str().unwrap_or_default().to_string();
    let sponsor = md["feePayer"].as_bool() == Some(true);
    let mut server = json!({
        "realm": fx::REALM,
        "secretKey": fx::SECRET,
        "planAddress": text(&md["planAddress"]),
        "mint": text(&md["mint"]),
        "decimals": md["decimals"].as_u64().unwrap_or(6),
        "tokenProgram": text(&md["tokenProgram"]),
        "puller": text(&md["puller"]),
        "recipient": text(&request["recipient"]),
        "periodUnit": text(&request["periodUnit"]),
        "periodCount": text(&request["periodCount"]).parse::<u64>().unwrap_or(0),
        "amount": text(&request["amount"]),
        "network": md["network"].as_str().unwrap_or("mainnet"),
        "subscriptionProgram": text(&md["subscriptionProgram"]),
    });
    if sponsor {
        server["feePayerKey"] = md["feePayerKey"].clone();
    }
    let encoded = Base64UrlJson::from_value(request).map_err(|e| e.to_string())?;
    let expires = fx::rfc3339(fx::NOW + 300);
    let challenge = PaymentChallenge::with_challenge_binding_secret_full(
        fx::SECRET,
        fx::REALM,
        "solana",
        "subscription",
        encoded,
        Some(&expires),
        None,
        None,
        None,
    );
    let signer = signer_from(input, "signerSecretKey")?;
    let delegation = fx::delegation_of(&text(&md["planAddress"]), &signer.pubkey().to_string());
    let authentication = sign_proof(&signer, &challenge.id, &delegation).await?;
    let credential = PaymentCredential::new(
        challenge.to_echo(),
        ActivatePayload {
            payload_type: "transaction".into(),
            transaction: Some(artifact.to_string()),
            signature: None,
            authentication,
        },
    );
    let mut out = json!({
        "nowSeconds": fx::NOW,
        "subscriptionServer": server,
        "subscriptionAuthorization": format_authorization(&credential).map_err(|e| e.to_string())?,
        "rpcFixtures": input.get("rpcFixtures").cloned().unwrap_or(json!({})),
    });
    if sponsor && md["feePayerKey"].as_str() == Some(fx::SPONSOR) {
        out["subscriptionServerFeePayerSecretKey"] = keys::secret_json(fx::SPONSOR_SEED);
    }
    Ok(out)
}

/// The SDK's `subscribe` data must carry exactly the terms the program
/// checks against the live plan and authority the vector serves: plan id
/// and bump, mint, amount, period, creation time and the authority's
/// `init_id`. Without them the activation cannot land on-chain.
fn check_subscribe_data(input: &Value, artifact: &str) -> Result<(), Failure> {
    use solana_pay_kit::generated::subscriptions::accounts::{Plan, SubscriptionAuthority};
    let md = &input["subscriptionChallenge"]["request"]["methodDetails"];
    let field = |k: &str| md[k].as_str().unwrap_or_default();
    let program_id = pubkey(field("subscriptionProgram"));
    let account = |address: &str| -> Result<Vec<u8>, Failure> {
        use base64::Engine;
        let data = input["rpcFixtures"]["accounts"][address]["data"]
            .as_str()
            .ok_or_else(|| Failure::new(format!("rpcFixtures has no account {address}")))?;
        base64::engine::general_purpose::STANDARD
            .decode(data)
            .map_err(|e| Failure::new(format!("account {address}: {e}")))
    };
    let plan = Plan::from_bytes(&account(field("planAddress"))?)
        .map_err(|e| Failure::new(format!("fixture plan: {e}")))?;
    let mint = Pubkey::new_from_array(plan.data.mint.to_bytes());
    let subscriber = pubkey(
        &signer_from(input, "signerSecretKey")
            .map_err(Failure::new)?
            .pubkey()
            .to_string(),
    );
    let (authority, _) = find_subscription_authority_pda(&subscriber, &mint, &program_id);
    let init_id = SubscriptionAuthority::from_bytes(&account(&authority.to_string())?)
        .map_err(|e| Failure::new(format!("fixture subscription authority: {e}")))?
        .init_id;
    let want = SubscribeData {
        plan_id: plan.data.plan_id,
        plan_bump: plan.bump,
        expected_mint: mint,
        expected_amount: plan.data.terms.amount,
        expected_period_hours: plan.data.terms.period_hours,
        expected_created_at: plan.data.terms.created_at,
        expected_subscription_authority_init_id: init_id,
    }
    .to_bytes();
    let tx = decode_b64(artifact).map_err(Failure::new)?;
    let d = decompile(&tx.message).map_err(Failure::new)?;
    let got = d
        .instructions
        .iter()
        .find(|ix| ix.program_id == program_id && ix.data.first() == Some(&INSTRUCTION_SUBSCRIBE))
        .map(|ix| ix.data.clone())
        .ok_or_else(|| Failure::new("the activation has no subscribe instruction"))?;
    if got != want {
        return Err(Failure {
            message: "subscribe data must carry the plan's id, bump and terms and the authority's init_id".into(),
            path: Some("subscribe.data".into()),
            expected: Some(json!(want)),
            actual: Some(json!(got)),
        });
    }
    Ok(())
}

/// Judge an accepted SDK build of a `subscription` vector: the kit server's
/// activation verification must accept it, and its fee payer, signer set
/// and instruction multiset must equal the kit's own build of the case
/// (skipped when the kit itself cannot build it: an authored case whose
/// divergence is recorded).
pub async fn judge_build(vector: &Vector, artifact: &str) -> Result<(), Failure> {
    let verify = verify_input_for_build(vector, artifact)
        .await
        .map_err(Failure::new)?;
    match verify_activation(&verify).await {
        Ok(Observed::Accept(_)) => {}
        Ok(other) => {
            return Err(Failure {
                message: format!(
                    "the Rust kit's activation verification refuses the SDK's build: {}",
                    other.summary()
                ),
                path: Some("verify".into()),
                expected: Some(json!("accept")),
                actual: Some(json!(other.summary())),
            })
        }
        Err(e) => return Err(Failure::new(e)),
    }
    match super::run(Intent::Subscription, Mode::BuildTransaction, vector.input()).await {
        Observed::Accept(Output {
            transaction: Some(reference),
            ..
        }) => compare_transactions(&reference, artifact, false),
        // No kit build to compare with: the verification above checks the
        // subscribe accounts, so pin its data to the fixture plan here.
        other if vector.raw["provenance"] == "authored" => {
            let _ = other;
            check_subscribe_data(vector.input(), artifact)
        }
        other => Err(Failure::new(format!(
            "the Rust kit cannot build this case ({}); the vector is wrong, file against the filler",
            other.summary()
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::run::vectors;

    fn vector(id: &str) -> Vector {
        vectors::load(&crate::repo_root().join("harness/vectors"))
            .unwrap()
            .into_iter()
            .find(|v| v.id == id)
            .unwrap()
    }

    /// The spec-request case has no kit build; the kit's build of the
    /// kit-shaped request on the same plan is a correct activation for it.
    fn activation(rt: &tokio::runtime::Runtime) -> String {
        let sibling = vector("subscription-build-activation");
        match rt.block_on(super::super::run(
            Intent::Subscription,
            Mode::BuildTransaction,
            sibling.input(),
        )) {
            Observed::Accept(Output {
                transaction: Some(tx),
                ..
            }) => tx,
            other => panic!("{}", other.summary()),
        }
    }

    // An authored case used to accept any build the kit's verification
    // accepts, and that verification checks the subscribe accounts and
    // discriminator but not its data. The kit now builds the spec-request
    // case, so the judge compares with its build; the subscribe-data check
    // remains the fallback for an authored case the kit cannot build.
    #[test]
    fn subscribe_data_off_the_plan_fails_the_authored_build_judge() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let v = vector("subscription-build-spec-request");
        let honest = activation(&rt);
        rt.block_on(judge_build(&v, &honest)).unwrap();
        check_subscribe_data(v.input(), &honest).unwrap();
        for data in [vec![INSTRUCTION_SUBSCRIBE], {
            let mut d = decompile(&decode_b64(&honest).unwrap().message).unwrap();
            let ix = d
                .instructions
                .iter_mut()
                .find(|ix| ix.data.first() == Some(&INSTRUCTION_SUBSCRIBE))
                .unwrap();
            ix.data[1] ^= 1;
            ix.data.clone()
        }] {
            let mut d = decompile(&decode_b64(&honest).unwrap().message).unwrap();
            d.instructions
                .iter_mut()
                .find(|ix| ix.data.first() == Some(&INSTRUCTION_SUBSCRIBE))
                .unwrap()
                .data = data;
            let mut tx = compile_v0(&d).unwrap();
            sign_slots(&mut tx, &[keys::CLIENT_SEED]);
            let tampered = encode_b64(&tx).unwrap();
            let failure = rt.block_on(judge_build(&v, &tampered)).unwrap_err();
            assert!(
                failure
                    .path
                    .as_deref()
                    .is_some_and(|p| p.ends_with(".data")),
                "{}",
                failure.message
            );
            let failure = check_subscribe_data(v.input(), &tampered).unwrap_err();
            assert_eq!(
                failure.path.as_deref(),
                Some("subscribe.data"),
                "{}",
                failure.message
            );
        }
    }
}
