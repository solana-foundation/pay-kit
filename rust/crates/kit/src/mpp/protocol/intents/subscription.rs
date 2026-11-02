//! Subscription intent request type and supporting payloads.
//!
//! The subscription intent represents a recurring fixed-amount payment
//! authorized once per billing period through an on-chain delegation.
//! Activation atomically creates the delegation and executes the first
//! billing-period charge; renewals are server-driven on-chain transactions
//! and do not produce HTTP credentials.

use std::num::NonZeroU64;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use solana_pubkey::Pubkey;

use crate::mpp::error::Error;
use crate::mpp::program::subscriptions::parse_pubkey;

/// Domain separator for reusable subscription authentication proofs.
pub const SUBSCRIPTION_AUTHENTICATION_DOMAIN: &str = "mpp-subscription-auth-v1";

/// Reusable payer proof bound to one activation challenge and delegation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SubscriptionAuthentication {
    /// Always `proof` on the wire.
    #[serde(rename = "type")]
    pub kind: SubscriptionAuthenticationType,
    /// Activation challenge identifier signed into the proof.
    pub challenge_id: String,
    /// Subscriber public key (base58).
    pub payer: String,
    /// Ed25519 signature over the canonical authentication message (base58).
    pub signature: String,
}

/// Discriminator for a reusable subscription proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SubscriptionAuthenticationType {
    /// An Ed25519 payer proof.
    Proof,
}

impl SubscriptionAuthentication {
    /// Return the RFC 8785/JCS message bytes signed by the subscriber.
    pub fn message_bytes(&self, subscription_delegation: &str) -> Result<Vec<u8>, Error> {
        let value = serde_json::json!({
            "domain": SUBSCRIPTION_AUTHENTICATION_DOMAIN,
            "payer": self.payer,
            "subscriptionChallengeId": self.challenge_id,
            "subscriptionDelegation": subscription_delegation,
        });
        serde_json_canonicalizer::to_vec(&value).map_err(|error| Error::Other(error.to_string()))
    }

    /// Verify this proof against its payer and bound delegation.
    pub fn verify(&self, subscription_delegation: &str) -> Result<bool, Error> {
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};

        let payer: [u8; 32] = bs58::decode(&self.payer)
            .into_vec()
            .map_err(|error| Error::Other(error.to_string()))?
            .try_into()
            .map_err(|_| Error::Other("payer must be 32 bytes".to_string()))?;
        let signature: [u8; 64] = bs58::decode(&self.signature)
            .into_vec()
            .map_err(|error| Error::Other(error.to_string()))?
            .try_into()
            .map_err(|_| Error::Other("signature must be 64 bytes".to_string()))?;
        let key =
            VerifyingKey::from_bytes(&payer).map_err(|error| Error::Other(error.to_string()))?;
        Ok(key
            .verify(
                &self.message_bytes(subscription_delegation)?,
                &Signature::from_bytes(&signature),
            )
            .is_ok())
    }
}

/// Billing period unit. The Solana profile supports `day` and `week` only;
/// `month` is rejected because the on-chain program uses fixed elapsed
/// seconds and cannot represent calendar-month cadence exactly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub enum SubscriptionPeriodUnit {
    #[default]
    Day,
    Week,
}

impl SubscriptionPeriodUnit {
    /// Map a `(unit, count)` pair to the subscriptions program's
    /// `period_hours` value.
    ///
    /// Returns an error if the count is out of range for the unit or if the
    /// resulting `period_hours` exceeds the program's `[1, 8760]` bound.
    pub fn to_period_hours(self, period_count: u64) -> Result<u64, Error> {
        if period_count == 0 {
            return Err(Error::Other(
                "periodCount must be a positive integer".into(),
            ));
        }
        match self {
            SubscriptionPeriodUnit::Day => {
                if period_count > 365 {
                    return Err(Error::Other(format!(
                        "periodCount={period_count} for periodUnit=\"day\" exceeds 365"
                    )));
                }
                Ok(period_count * 24)
            }
            SubscriptionPeriodUnit::Week => {
                if period_count > 52 {
                    return Err(Error::Other(format!(
                        "periodCount={period_count} for periodUnit=\"week\" exceeds 52"
                    )));
                }
                Ok(period_count * 168)
            }
        }
    }
}

/// Subscription request (for the `subscription` intent on Solana).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct SubscriptionRequest {
    /// Per-period token amount in base units.
    pub amount: String,

    /// Base58 SPL token mint address (canonical wire form). Implementations
    /// MUST treat this consistently with `methodDetails.mint`.
    pub currency: String,

    /// Billing period unit. The Solana profile supports `day` and `week`
    /// only; `month` is rejected at the schema layer.
    pub period_unit: SubscriptionPeriodUnit,

    /// Decimal string count of `period_unit` values per billing period.
    pub period_count: String,

    /// Primary recipient wallet pubkey (base58).
    pub recipient: String,

    /// Optional RFC3339 expiry of the recurring authorization.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subscription_expires: Option<String>,

    /// Human-readable description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Merchant reference.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_id: Option<String>,

    /// Solana-specific extension fields.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method_details: Option<serde_json::Value>,
}

impl SubscriptionRequest {
    /// Parse the request into [`SubscriptionTerms`]: the only form the
    /// activation builder accepts. Every field the profile constrains is
    /// checked here, once: the amount and period formats, the period
    /// mapping, `currency == methodDetails.mint`, the token program, the
    /// REQUIRED `methodDetails` and the addresses.
    pub fn terms(&self) -> Result<SubscriptionTerms, Error> {
        SubscriptionTerms::parse(self)
    }

    /// Parse `period_count`: a positive base-10 integer with no sign,
    /// leading zero, decimal point, exponent or whitespace.
    pub fn parse_period_count(&self) -> Result<u64, Error> {
        parse_positive_integer(&self.period_count, "periodCount").map(NonZeroU64::get)
    }

    /// Parse `amount`: a positive base-10 integer with no sign, leading
    /// zero, decimal point, exponent or whitespace.
    pub fn parse_amount(&self) -> Result<u64, Error> {
        SubscriptionAmount::from_str(&self.amount).map(SubscriptionAmount::get)
    }

    /// Compute the on-chain `period_hours` for this request, validating both
    /// the period mapping and the program-level bound `[1, 8760]`.
    pub fn period_hours(&self) -> Result<u64, Error> {
        BillingPeriod::parse(self.period_unit, &self.period_count).map(|period| period.hours())
    }
}

/// Parse a positive base-10 integer in the profile's canonical form
/// (draft-solana-subscription-00 §Optional Fields): ASCII digits only, no
/// sign, decimal point, exponent or surrounding whitespace, no leading zero.
fn parse_positive_integer(value: &str, field: &str) -> Result<NonZeroU64, Error> {
    let invalid = |why: &str| Error::Other(format!("Invalid {field} {value:?}: {why}"));
    if value.is_empty() {
        return Err(invalid("empty"));
    }
    if !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err(invalid(
            "must be a base-10 integer with no sign, decimal point, exponent or whitespace",
        ));
    }
    if value.starts_with('0') {
        return Err(invalid("must be positive with no leading zero"));
    }
    let parsed: u64 = value.parse().map_err(|_| invalid("out of range"))?;
    NonZeroU64::new(parsed).ok_or_else(|| invalid("must be positive"))
}

/// A per-period amount in base units: positive, parsed from its canonical
/// decimal form only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SubscriptionAmount(NonZeroU64);

impl SubscriptionAmount {
    /// The amount in base units.
    pub fn get(self) -> u64 {
        self.0.get()
    }
}

impl FromStr for SubscriptionAmount {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self, Error> {
        parse_positive_integer(value, "amount").map(Self)
    }
}

impl std::fmt::Display for SubscriptionAmount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

/// A billing period the Solana profile can represent exactly: `day` or
/// `week` units, mapped to `[1, 8760]` hours.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BillingPeriod {
    unit: SubscriptionPeriodUnit,
    count: u64,
    hours: u64,
}

impl BillingPeriod {
    /// Parse `periodCount` in its canonical form and map it to hours.
    pub fn parse(unit: SubscriptionPeriodUnit, count: &str) -> Result<Self, Error> {
        let count = parse_positive_integer(count, "periodCount")?.get();
        let hours = unit.to_period_hours(count)?;
        if hours == 0 || hours > 8760 {
            return Err(Error::Other(format!(
                "period_hours {hours} out of [1, 8760] range"
            )));
        }
        Ok(Self { unit, count, hours })
    }

    pub fn unit(&self) -> SubscriptionPeriodUnit {
        self.unit
    }

    pub fn count(&self) -> u64 {
        self.count
    }

    /// The program's `period_hours` for this period.
    pub fn hours(&self) -> u64 {
        self.hours
    }
}

/// The token programs `methodDetails.tokenProgram` may name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubscriptionTokenProgram {
    /// SPL Token.
    Token,
    /// SPL Token-2022.
    Token2022,
}

impl SubscriptionTokenProgram {
    /// Parse a base58 program id; anything but SPL Token or Token-2022 is
    /// refused.
    pub fn parse(value: &str) -> Result<Self, Error> {
        use crate::mpp::protocol::solana::programs::{TOKEN_2022_PROGRAM, TOKEN_PROGRAM};
        let program = parse_pubkey(value, "tokenProgram")?;
        if program == Pubkey::from_str_const(TOKEN_PROGRAM) {
            Ok(Self::Token)
        } else if program == Pubkey::from_str_const(TOKEN_2022_PROGRAM) {
            Ok(Self::Token2022)
        } else {
            Err(Error::Other(format!(
                "methodDetails.tokenProgram {value} is neither SPL Token nor Token-2022"
            )))
        }
    }

    pub fn program_id(self) -> Pubkey {
        use crate::mpp::protocol::solana::programs::{TOKEN_2022_PROGRAM, TOKEN_PROGRAM};
        match self {
            Self::Token => Pubkey::from_str_const(TOKEN_PROGRAM),
            Self::Token2022 => Pubkey::from_str_const(TOKEN_2022_PROGRAM),
        }
    }
}

/// Who pays the activation transaction's fees.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActivationFeePayer {
    /// The subscriber (`feePayer` absent or `false`).
    Subscriber,
    /// The server's `methodDetails.feePayerKey` (`feePayer: true`).
    Server(Pubkey),
}

/// A subscription request that passed every format and consistency check
/// of draft-solana-subscription-00 §Request Schema. Built only by
/// [`SubscriptionRequest::terms`]; it reads the spec's fields only, never
/// a server's `methodDetails` extensions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscriptionTerms {
    amount: SubscriptionAmount,
    mint: Pubkey,
    period: BillingPeriod,
    recipient: Pubkey,
    subscription_expires: Option<String>,
    external_id: Option<String>,
    plan_address: Pubkey,
    token_program: SubscriptionTokenProgram,
    decimals: u8,
    puller: Pubkey,
    subscription_program: Pubkey,
    network: String,
    fee_payer: ActivationFeePayer,
    recent_blockhash: Option<solana_hash::Hash>,
    transaction_versions: Option<Vec<crate::core::tx::TxVersion>>,
}

impl SubscriptionTerms {
    fn parse(request: &SubscriptionRequest) -> Result<Self, Error> {
        let amount = SubscriptionAmount::from_str(&request.amount)?;
        let period = BillingPeriod::parse(request.period_unit, &request.period_count)?;
        let recipient = parse_pubkey(&request.recipient, "recipient")?;
        let details = request
            .method_details
            .as_ref()
            .ok_or_else(|| Error::Other("Subscription request is missing methodDetails".into()))?;
        let details = SubscriptionMethodDetails::from_json(details)?;
        details.validate()?;
        let mint = parse_pubkey(&details.mint, "methodDetails.mint")?;
        if parse_pubkey(&request.currency, "currency")? != mint {
            return Err(Error::Other(
                "Subscription currency must match methodDetails.mint".into(),
            ));
        }
        let decimals = details
            .decimals
            .ok_or_else(|| Error::Other("methodDetails.decimals is required".into()))?;
        let fee_payer = if details.fee_payer {
            ActivationFeePayer::Server(parse_pubkey(
                details.fee_payer_key.as_deref().ok_or_else(|| {
                    Error::Other(
                        "methodDetails.feePayerKey is required when feePayer is true".into(),
                    )
                })?,
                "feePayerKey",
            )?)
        } else {
            ActivationFeePayer::Subscriber
        };
        let recent_blockhash = details
            .recent_blockhash
            .as_deref()
            .map(|value| {
                value
                    .parse::<solana_hash::Hash>()
                    .map_err(|e| Error::Other(format!("Invalid recentBlockhash: {e}")))
            })
            .transpose()?;
        Ok(Self {
            amount,
            mint,
            period,
            recipient,
            subscription_expires: request.subscription_expires.clone(),
            external_id: request.external_id.clone(),
            plan_address: parse_pubkey(&details.plan_address, "planAddress")?,
            token_program: SubscriptionTokenProgram::parse(&details.token_program)?,
            decimals,
            puller: parse_pubkey(&details.puller, "puller")?,
            subscription_program: parse_pubkey(
                details.subscription_program.as_deref().unwrap_or_default(),
                "subscriptionProgram",
            )?,
            network: details.network.unwrap_or_else(|| "mainnet".into()),
            fee_payer,
            recent_blockhash,
            transaction_versions: details.transaction_versions,
        })
    }

    pub fn amount(&self) -> SubscriptionAmount {
        self.amount
    }

    pub fn mint(&self) -> Pubkey {
        self.mint
    }

    pub fn period(&self) -> BillingPeriod {
        self.period
    }

    pub fn recipient(&self) -> Pubkey {
        self.recipient
    }

    pub fn subscription_expires(&self) -> Option<&str> {
        self.subscription_expires.as_deref()
    }

    pub fn external_id(&self) -> Option<&str> {
        self.external_id.as_deref()
    }

    pub fn plan_address(&self) -> Pubkey {
        self.plan_address
    }

    pub fn token_program(&self) -> SubscriptionTokenProgram {
        self.token_program
    }

    pub fn decimals(&self) -> u8 {
        self.decimals
    }

    pub fn puller(&self) -> Pubkey {
        self.puller
    }

    pub fn subscription_program(&self) -> Pubkey {
        self.subscription_program
    }

    /// `methodDetails.network`, `mainnet` when omitted.
    pub fn network(&self) -> &str {
        &self.network
    }

    pub fn fee_payer(&self) -> ActivationFeePayer {
        self.fee_payer
    }

    pub fn recent_blockhash(&self) -> Option<solana_hash::Hash> {
        self.recent_blockhash
    }

    pub fn transaction_versions(&self) -> Option<&[crate::core::tx::TxVersion]> {
        self.transaction_versions.as_deref()
    }
}

/// Single-action credential payload. The Solana subscription profile only
/// defines `activate`; renewals are server-driven and cancellations are
/// out-of-band on-chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "camelCase")]
pub enum SubscriptionAction {
    /// Activation: subscribe + first-period charge in one transaction.
    Activate(ActivatePayload),
}

/// Activation payload. Mirrors the Solana charge profile's two-mode shape:
/// `type="transaction"` (server broadcasts) or `type="signature"`
/// (client already broadcast).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ActivatePayload {
    /// Payload type discriminator: `"transaction"` or `"signature"`.
    #[serde(rename = "type")]
    pub payload_type: String,

    /// Standard base64 of the serialized activation transaction
    /// (when `type="transaction"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction: Option<String>,

    /// Base58 of the on-chain transaction signature (when `type="signature"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,

    /// Reusable subscriber proof bound to the activation challenge and
    /// resulting `SubscriptionDelegation` PDA. REQUIRED on the wire.
    pub authentication: SubscriptionAuthentication,
}

/// Credential payload for later access under an active subscription.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SubscriptionAccessPayload {
    /// Always `proof` on the wire.
    #[serde(rename = "type")]
    pub payload_type: SubscriptionAuthenticationType,
    /// Base58 `SubscriptionDelegation` PDA bound by the proof.
    pub subscription_delegation: String,
    /// Reusable subscriber proof retained from activation.
    pub authentication: SubscriptionAuthentication,
}

/// Extension fields placed on the standard Receipt's metadata for a
/// subscription activation or renewal.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct SubscriptionReceiptExtensions {
    /// Server-issued opaque base64url subscription identifier.
    pub subscription_id: String,
    /// Base58 address of the on-chain SubscriptionDelegation account.
    pub subscription_delegation: String,
    /// Decimal index of the billing period (0 for activation).
    pub period_index: u64,
    /// RFC3339 timestamp of the current period's start.
    pub period_start: String,
    /// RFC3339 timestamp of the current period's end (exclusive).
    pub period_end: String,
    /// RFC3339 effective subscription expiry, when set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
}

/// Typed `methodDetails` payload for the Solana subscription intent.
///
/// Serialised in camelCase per the spec wire form. The server (which
/// builds + HMAC-pins it into the 402 challenge) and the client (which
/// reads it back to construct the activation transaction) both use this
/// struct directly — no manual JSON pokery.
///
/// The `expected_*` and `plan_*` server-extension fields mirror the
/// immutable Plan terms the on-chain `Subscribe` instruction needs in
/// its `SubscribeData` payload. Including them in the challenge lets the
/// client build a settle-able activation transaction without an extra
/// RPC roundtrip to fetch the Plan account. When absent the client falls
/// back to RPC.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SubscriptionMethodDetails {
    /// Base58 address of the on-chain `Plan` account.
    pub plan_address: String,
    /// Base58 of the SPL token mint. MUST equal the on-chain `plan.mint`.
    pub mint: String,
    /// Base58 of the SPL Token / Token-2022 program id used for the
    /// per-period transfers.
    pub token_program: String,
    /// Decimal precision of the mint. Server-populated; clients use it
    /// to render the amount in human form.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decimals: Option<u8>,
    /// Base58 of the server's puller pubkey. MUST be `plan.owner` or
    /// appear in `plan.pullers`.
    pub puller: String,
    /// Base58 of the Plan's owner (the merchant who published it). The
    /// on-chain `Subscribe` instruction needs this as its second
    /// account meta and as part of the Plan PDA derivation. When unset,
    /// the client falls back to `puller` (correct only when the
    /// merchant published the plan AND is its own puller).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub merchant: Option<String>,
    /// Base58 of the recipient wallet — must be in `plan.destinations`
    /// (or the whitelist must be empty). The transfer_subscription
    /// instruction routes the first-period charge to this wallet's
    /// associated token account.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recipient: Option<String>,
    /// The per-period charge amount in base units (decimal string).
    /// Mirrors `SubscriptionRequest.amount` so the activation builder
    /// can fill `SubscribeData.expected_amount` + `TransferData.amount`
    /// without re-parsing the parent request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub amount: Option<String>,
    /// Base58 address of the subscriptions program deployment.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subscription_program: Option<String>,
    /// Solana network slug — `mainnet`, `devnet`, `testnet`,
    /// `localnet`. Servers MAY accept `mainnet-beta` as a legacy alias
    /// of `mainnet` but MUST emit `mainnet`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<String>,
    /// When `true`, the server pays activation transaction fees.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub fee_payer: bool,
    /// Base58 of the fee-payer pubkey. REQUIRED when `fee_payer` is
    /// true.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fee_payer_key: Option<String>,

    /// Transaction message versions the server accepts (`0`, `1`). Absent
    /// means `[0]`. See `core::tx`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transaction_versions: Option<Vec<crate::core::tx::TxVersion>>,
    /// Pre-fetched recent blockhash. When set, the client skips its own
    /// `getLatestBlockhash` RPC call.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recent_blockhash: Option<String>,
    /// On-chain `plan_id` (u64) the program reads from `SubscribeData`.
    /// The string `plan_id` above is the PDA derived from this number.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plan_id_numeric: Option<u64>,
    /// Plan PDA's bump seed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plan_bump: Option<u8>,
    /// Plan's `period_hours` — `period_count * 24` for day, `* 168` for
    /// week.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_period_hours: Option<u64>,
    /// Plan's `created_at` unix timestamp (set on-chain by the program
    /// at Plan creation, read back into the YAML by `pay server start`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_created_at: Option<i64>,
}

impl SubscriptionMethodDetails {
    /// Decode from the parsed `methodDetails` JSON value.
    pub fn from_json(value: &serde_json::Value) -> Result<Self, Error> {
        serde_json::from_value(value.clone())
            .map_err(|e| Error::Other(format!("Invalid methodDetails: {e}")))
    }

    /// Validate the spec's REQUIRED fields are non-empty. The struct
    /// can be deserialised with missing required fields (serde will
    /// supply defaults), so callers that need a settle-able activation
    /// must run this check.
    pub fn validate(&self) -> Result<(), Error> {
        if self.plan_address.is_empty() {
            return Err(Error::Other("methodDetails.planAddress is required".into()));
        }
        if self.mint.is_empty() {
            return Err(Error::Other("methodDetails.mint is required".into()));
        }
        if self.token_program.is_empty() {
            return Err(Error::Other(
                "methodDetails.tokenProgram is required".into(),
            ));
        }
        if self.puller.is_empty() {
            return Err(Error::Other("methodDetails.puller is required".into()));
        }
        if self.decimals.is_none() {
            return Err(Error::Other("methodDetails.decimals is required".into()));
        }
        if self
            .subscription_program
            .as_deref()
            .is_none_or(str::is_empty)
        {
            return Err(Error::Other(
                "methodDetails.subscriptionProgram is required".into(),
            ));
        }
        if self.fee_payer && self.fee_payer_key.is_none() {
            return Err(Error::Other(
                "methodDetails.feePayerKey is required when feePayer is true".into(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    #[test]
    fn subscription_authentication_uses_canonical_message_and_binds_delegation() {
        let signing_key = SigningKey::from_bytes(&[7; 32]);
        let payer = bs58::encode(signing_key.verifying_key().as_bytes()).into_string();
        let delegation = "8tWbqLkUJoYy7zXc5h2EvCRoaQEv2xnQjUuYhc3rzCgT";
        let mut authentication = SubscriptionAuthentication {
            kind: SubscriptionAuthenticationType::Proof,
            challenge_id: "challenge-1".into(),
            payer: payer.clone(),
            signature: String::new(),
        };
        let message = authentication.message_bytes(delegation).unwrap();
        assert_eq!(
            String::from_utf8(message.clone()).unwrap(),
            format!(
                "{{\"domain\":\"mpp-subscription-auth-v1\",\"payer\":\"{payer}\",\"subscriptionChallengeId\":\"challenge-1\",\"subscriptionDelegation\":\"{delegation}\"}}"
            )
        );
        authentication.signature =
            bs58::encode(signing_key.sign(&message).to_bytes()).into_string();
        assert!(authentication.verify(delegation).unwrap());
        assert!(!authentication
            .verify("9xAXssX9j7vuK99c7cFwqbixzL3bFrzPy9PUhCtDPAYJ")
            .unwrap());
    }

    #[test]
    fn day_period_maps_to_hours() {
        assert_eq!(SubscriptionPeriodUnit::Day.to_period_hours(1).unwrap(), 24);
        assert_eq!(
            SubscriptionPeriodUnit::Day.to_period_hours(30).unwrap(),
            720
        );
        assert_eq!(
            SubscriptionPeriodUnit::Day.to_period_hours(365).unwrap(),
            8760
        );
    }

    #[test]
    fn week_period_maps_to_hours() {
        assert_eq!(
            SubscriptionPeriodUnit::Week.to_period_hours(1).unwrap(),
            168
        );
        assert_eq!(
            SubscriptionPeriodUnit::Week.to_period_hours(52).unwrap(),
            8736
        );
    }

    #[test]
    fn period_count_out_of_range_errors() {
        assert!(SubscriptionPeriodUnit::Day.to_period_hours(366).is_err());
        assert!(SubscriptionPeriodUnit::Week.to_period_hours(53).is_err());
        assert!(SubscriptionPeriodUnit::Day.to_period_hours(0).is_err());
    }

    #[test]
    fn request_serializes_camel_case() {
        let req = SubscriptionRequest {
            amount: "10000000".into(),
            currency: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v".into(),
            period_unit: SubscriptionPeriodUnit::Day,
            period_count: "30".into(),
            recipient: "9xAXssX9j7vuK99c7cFwqbixzL3bFrzPy9PUhCtDPAYJ".into(),
            subscription_expires: Some("2026-07-14T12:00:00Z".into()),
            external_id: Some("order-42".into()),
            ..Default::default()
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("\"periodUnit\":\"day\""));
        assert!(json.contains("\"periodCount\":\"30\""));
        assert!(json.contains("\"subscriptionExpires\":\"2026-07-14T12:00:00Z\""));
        assert!(json.contains("\"externalId\":\"order-42\""));
    }

    #[test]
    fn rejects_unknown_period_unit_via_deserialization() {
        let json = r#"{"amount":"1","currency":"X","periodUnit":"month","periodCount":"1","recipient":"R"}"#;
        let parsed: Result<SubscriptionRequest, _> = serde_json::from_str(json);
        assert!(
            parsed.is_err(),
            "month must be rejected at the schema layer"
        );
    }

    #[test]
    fn period_hours_validates_range() {
        let req = SubscriptionRequest {
            period_unit: SubscriptionPeriodUnit::Day,
            period_count: "30".into(),
            ..Default::default()
        };
        assert_eq!(req.period_hours().unwrap(), 720);

        let too_big = SubscriptionRequest {
            period_unit: SubscriptionPeriodUnit::Day,
            period_count: "400".into(),
            ..Default::default()
        };
        assert!(too_big.period_hours().is_err());
    }

    #[test]
    fn activate_payload_pull_mode_roundtrip() {
        let action = SubscriptionAction::Activate(ActivatePayload {
            payload_type: "transaction".into(),
            transaction: Some("AQAAAA==".into()),
            signature: None,
            authentication: sample_authentication(),
        });
        let json = serde_json::to_string(&action).unwrap();
        assert!(json.contains("\"action\":\"activate\""));
        assert!(json.contains("\"type\":\"transaction\""));
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(value.get("signature").is_none());
        let _back: SubscriptionAction = serde_json::from_str(&json).unwrap();
    }

    #[test]
    fn activate_payload_push_mode_roundtrip() {
        let action = SubscriptionAction::Activate(ActivatePayload {
            payload_type: "signature".into(),
            transaction: None,
            signature: Some("5J8KKKKK".into()),
            authentication: sample_authentication(),
        });
        let json = serde_json::to_string(&action).unwrap();
        assert!(json.contains("\"type\":\"signature\""));
        assert!(json.contains("\"signature\":\"5J8KKKKK\""));
        let _back: SubscriptionAction = serde_json::from_str(&json).unwrap();
    }

    #[test]
    fn parse_amount_and_period_count() {
        let req = SubscriptionRequest {
            amount: "10000000".into(),
            period_count: "30".into(),
            ..Default::default()
        };
        assert_eq!(req.parse_amount().unwrap(), 10_000_000);
        assert_eq!(req.parse_period_count().unwrap(), 30);

        let bad_amount = SubscriptionRequest {
            amount: "not-a-number".into(),
            period_count: "30".into(),
            ..Default::default()
        };
        assert!(bad_amount.parse_amount().is_err());

        let bad_count = SubscriptionRequest {
            amount: "1".into(),
            period_count: "abc".into(),
            ..Default::default()
        };
        assert!(bad_count.parse_period_count().is_err());
    }

    #[test]
    fn period_hours_bound_check() {
        // day*365 = 8760 — at the upper bound, accepted.
        let at_bound = SubscriptionRequest {
            period_unit: SubscriptionPeriodUnit::Day,
            period_count: "365".into(),
            ..Default::default()
        };
        assert_eq!(at_bound.period_hours().unwrap(), 8760);

        // Bad period_count surfaces through period_hours().
        let bad = SubscriptionRequest {
            period_unit: SubscriptionPeriodUnit::Day,
            period_count: "not-a-number".into(),
            ..Default::default()
        };
        assert!(bad.period_hours().is_err());
    }

    fn sample_authentication() -> SubscriptionAuthentication {
        SubscriptionAuthentication {
            kind: SubscriptionAuthenticationType::Proof,
            challenge_id: "challenge-1".into(),
            payer: "9xAXssX9j7vuK99c7cFwqbixzL3bFrzPy9PUhCtDPAYJ".into(),
            signature: "5J8KKKKK".into(),
        }
    }

    // draft-solana-subscription-00 §Payload: `authentication` is REQUIRED.
    #[test]
    fn activate_payload_requires_authentication() {
        let without = serde_json::json!({"type": "transaction", "transaction": "AQAB"});
        assert!(serde_json::from_value::<ActivatePayload>(without).is_err());
        let mut with = serde_json::json!({"type": "transaction", "transaction": "AQAB"});
        with["authentication"] = serde_json::to_value(sample_authentication()).unwrap();
        assert!(serde_json::from_value::<ActivatePayload>(with).is_ok());
    }

    #[test]
    fn period_unit_default_is_day() {
        let unit = SubscriptionPeriodUnit::default();
        assert_eq!(unit, SubscriptionPeriodUnit::Day);
    }

    #[test]
    fn receipt_extensions_default() {
        let ext = SubscriptionReceiptExtensions::default();
        assert_eq!(ext.subscription_id, "");
        assert_eq!(ext.subscription_delegation, "");
        assert!(ext.expires_at.is_none());
    }

    #[test]
    fn receipt_extensions_serialize() {
        let ext = SubscriptionReceiptExtensions {
            subscription_id: "BXQGmO5VwTrl5RfFr6Y8XQZ4nPj9QqMOiKkRn3pZ4ZE".into(),
            subscription_delegation: "De1egation".into(),
            period_index: 0,
            period_start: "2026-01-15T12:03:10Z".into(),
            period_end: "2026-02-14T12:03:10Z".into(),
            expires_at: Some("2026-07-14T12:00:00Z".into()),
        };
        let json = serde_json::to_string(&ext).unwrap();
        assert!(json.contains("\"subscriptionId\""));
        assert!(json.contains("\"subscriptionDelegation\""));
        assert!(json.contains("\"periodIndex\":0"));
        assert!(json.contains("\"periodStart\""));
        assert!(json.contains("\"periodEnd\""));
        assert!(json.contains("\"expiresAt\""));
    }

    fn consistent_request() -> SubscriptionRequest {
        let mint = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
        let recipient = "9xAXssX9j7vuK99c7cFwqbixzL3bFrzPy9PUhCtDPAYJ";
        SubscriptionRequest {
            amount: "10000000".into(),
            currency: mint.into(),
            period_unit: SubscriptionPeriodUnit::Day,
            period_count: "30".into(),
            recipient: recipient.into(),
            method_details: Some(serde_json::json!({
                "planAddress": "8tWbqLkUJoYy7zXc5h2EvCRoaQEv2xnQjUuYhc3rzCgT",
                "mint": mint,
                "tokenProgram": "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
                "decimals": 6,
                "puller": "5fKb5cF22cFybZB1H4hLDydFhwoQy9JzKzRWaSbMkB6h",
                "subscriptionProgram": "De1egAFMkMWZSN5rYXRj9CAdheBamobVNubTsi9avR44",
            })),
            ..Default::default()
        }
    }

    fn with_detail(key: &str, value: serde_json::Value) -> SubscriptionRequest {
        let mut request = consistent_request();
        request.method_details.as_mut().unwrap()[key] = value;
        request
    }

    fn without_detail(key: &str) -> SubscriptionRequest {
        let mut request = consistent_request();
        request
            .method_details
            .as_mut()
            .unwrap()
            .as_object_mut()
            .unwrap()
            .remove(key);
        request
    }

    #[test]
    fn terms_accept_a_spec_shaped_request() {
        let terms = consistent_request().terms().unwrap();
        assert_eq!(terms.amount().get(), 10_000_000);
        assert_eq!(terms.period().hours(), 720);
        assert_eq!(terms.decimals(), 6);
        assert_eq!(terms.token_program(), SubscriptionTokenProgram::Token);
        assert_eq!(terms.fee_payer(), ActivationFeePayer::Subscriber);
        assert_eq!(terms.network(), "mainnet");
    }

    #[test]
    fn terms_reject_mint_differing_from_currency() {
        let request = with_detail(
            "mint",
            "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB".into(),
        );
        let err = request.terms().unwrap_err();
        assert!(err.to_string().contains("currency"), "{err}");
    }

    // draft-solana-subscription-00 §Optional Fields: amount and periodCount
    // are positive base-10 integers with no sign, leading zero, decimal
    // point, exponent or whitespace.
    #[test]
    fn terms_reject_non_canonical_amounts_and_period_counts() {
        for bad in [
            "010000000",
            "0",
            "+10000000",
            "-1",
            "1e7",
            "1.0",
            " 1",
            "1 ",
            "",
        ] {
            let mut request = consistent_request();
            request.amount = bad.into();
            assert!(request.terms().is_err(), "amount {bad:?}");
            assert!(request.parse_amount().is_err(), "amount {bad:?}");
        }
        for bad in ["030", "+30", "0", "30.0", "3e1", " 30", "30 ", ""] {
            let mut request = consistent_request();
            request.period_count = bad.into();
            assert!(request.terms().is_err(), "periodCount {bad:?}");
            assert!(request.period_hours().is_err(), "periodCount {bad:?}");
        }
    }

    #[test]
    fn terms_require_an_spl_token_program() {
        assert!(
            with_detail("tokenProgram", "11111111111111111111111111111111".into())
                .terms()
                .is_err()
        );
        let terms = with_detail(
            "tokenProgram",
            "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb".into(),
        )
        .terms()
        .unwrap();
        assert_eq!(terms.token_program(), SubscriptionTokenProgram::Token2022);
    }

    #[test]
    fn terms_require_every_required_method_detail() {
        for key in [
            "planAddress",
            "mint",
            "tokenProgram",
            "decimals",
            "puller",
            "subscriptionProgram",
        ] {
            assert!(without_detail(key).terms().is_err(), "{key}");
        }
    }

    #[test]
    fn terms_require_fee_payer_key_when_sponsored() {
        assert!(with_detail("feePayer", true.into()).terms().is_err());
        let mut request = with_detail("feePayer", true.into());
        request.method_details.as_mut().unwrap()["feePayerKey"] =
            "5fKb5cF22cFybZB1H4hLDydFhwoQy9JzKzRWaSbMkB6h".into();
        assert!(matches!(
            request.terms().unwrap().fee_payer(),
            ActivationFeePayer::Server(_)
        ));
    }

    // Kit-only methodDetails extensions are ignored, not required.
    #[test]
    fn terms_ignore_unknown_method_details() {
        let request = with_detail("expectedPeriodHours", 168.into());
        assert_eq!(request.terms().unwrap().period().hours(), 720);
    }
}
