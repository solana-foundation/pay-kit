//! Judge one testee result against its vector.
//!
//! [`judge_expect`] is `judgeVector` from the retired vitest driver
//! (`harness/test/conformance.test.ts`), assertion for assertion: outcome,
//! `rejectCode`, `exactBytes`, `x402EnvelopeShape` and `transactionShape`
//! (SPL destinations derived as the owner's ATA). [`judge_build`] adds what
//! the shape DSL could not see: every accepted build is decoded, run through
//! the kit's own verifier against the vector's request, and its instruction
//! multiset is compared with the kit's own build of the same case.

use std::collections::BTreeSet;

use base64::Engine;
use serde_json::{json, Value};

use crate::annotate;
use crate::case::{Intent, Mode};
use crate::keys::{self, ata};
use crate::realize::{self, Observed};
use crate::run::vectors::Vector;
use crate::tx::{decode_b64, decompile, signature_slots, Slot};

/// Why a case failed, with the decoded expected and actual values and the
/// first path where they diverge (DESIGN.md §6.2 element 3).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Failure {
    pub message: String,
    pub path: Option<String>,
    pub expected: Option<Value>,
    pub actual: Option<Value>,
}

impl Failure {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            ..Default::default()
        }
    }

    fn at(path: &str, expected: Option<&Value>, actual: Option<&Value>, message: String) -> Self {
        Self {
            message,
            path: Some(path.to_string()),
            expected: Some(expected.cloned().unwrap_or(Value::Null)),
            actual: Some(actual.cloned().unwrap_or(Value::Null)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Pass,
    Unsupported(String),
}

/// `toBe` across JSON: absent equals absent, numbers compare by value.
fn same(a: Option<&Value>, b: Option<&Value>) -> bool {
    match (a, b) {
        (None, None) => true,
        (Some(Value::Number(x)), Some(Value::Number(y))) => x.as_f64() == y.as_f64(),
        (Some(x), Some(y)) => x == y,
        (Some(Value::Null), None) | (None, Some(Value::Null)) => false,
        _ => false,
    }
}

fn show(v: Option<&Value>) -> String {
    v.map(Value::to_string)
        .unwrap_or_else(|| "undefined".into())
}

fn expect_same(
    path: &str,
    expected: Option<&Value>,
    actual: Option<&Value>,
) -> Result<(), Failure> {
    if same(expected, actual) {
        Ok(())
    } else {
        Err(Failure::at(
            path,
            expected,
            actual,
            format!(
                "{path}: expected {} but the runner emitted {}",
                show(expected),
                show(actual)
            ),
        ))
    }
}

/// `judgeVector`: the vector's `expect` block against the result.
pub fn judge_expect(vector: &Vector, result: &Value) -> Result<Verdict, Failure> {
    let actual_id = result.get("id");
    if actual_id.and_then(Value::as_str) != Some(vector.id.as_str()) {
        return Err(Failure::at(
            "id",
            Some(&json!(vector.id)),
            actual_id,
            format!("result id {} does not echo the vector id", show(actual_id)),
        ));
    }
    let outcome = result["outcome"].as_str().unwrap_or_default();
    let error = result["error"].as_str().unwrap_or_default();
    // A runner that cannot express a vector's mode for its SDK's role reports
    // `unsupported-mode`, or a reject whose error starts with it. The
    // reconciler decides whether that is allowed for this (SDK, vector).
    if outcome == "unsupported-mode"
        || (outcome == "reject" && error.starts_with("unsupported-mode"))
    {
        return Ok(Verdict::Unsupported(if error.is_empty() {
            "unsupported-mode".into()
        } else {
            error.to_string()
        }));
    }
    let expected_outcome = vector.expect_outcome();
    if outcome != expected_outcome {
        let mut failure = Failure::at(
            "outcome",
            Some(&json!(expected_outcome)),
            Some(&json!(outcome)),
            format!("expected {expected_outcome} but runner said {outcome}: {error}"),
        );
        if let Some(code) = vector.reject_code() {
            failure.expected = Some(json!({ "outcome": expected_outcome, "rejectCode": code }));
        }
        failure.actual = Some(json!({
            "outcome": outcome,
            "rejectCode": result.get("rejectCode"),
            "error": error,
        }));
        return Err(failure);
    }
    let expect = vector.expect();
    if expected_outcome == "reject" {
        // Pin WHY the SDK rejected, not just that it did.
        if let Some(code) = expect.get("rejectCode") {
            let got = result.get("rejectCode");
            if !same(Some(code), got) {
                return Err(Failure::at(
                    "rejectCode",
                    Some(code),
                    got,
                    format!(
                        "expected reject category {} but runner emitted {}: {error}",
                        code.as_str().unwrap_or_default(),
                        got.and_then(Value::as_str).unwrap_or("(none)")
                    ),
                ));
            }
        }
        return Ok(Verdict::Pass);
    }
    if vector.mode == "canonical-bytes" {
        let Some(wanted) = expect.get("exactBytes") else {
            return Err(Failure::new(
                "canonical-bytes vector missing expect.exactBytes",
            ));
        };
        for key in ["canonicalJson", "base64Url", "bytes"] {
            if let Some(want) = wanted.get(key) {
                let got = result.pointer(&format!("/exactBytes/{key}"));
                if got != Some(want) {
                    return Err(Failure::at(
                        &format!("exactBytes.{key}"),
                        Some(want),
                        got,
                        format!("exactBytes.{key} differs"),
                    ));
                }
            }
        }
        return Ok(Verdict::Pass);
    }
    if vector.intent == "x402-exact" {
        if let Some(shape) = expect.get("x402EnvelopeShape") {
            envelope_shape(shape, result.get("x402EnvelopeShape"))?;
        }
        return Ok(Verdict::Pass);
    }
    if let Some(shape) = expect.get("transactionShape") {
        transaction_shape(shape, result.get("transactionShape"))?;
    }
    Ok(Verdict::Pass)
}

/// `assertEnvelopeShape`. Only pinned fields are checked, except that
/// `scheme` / `network` are pinned by presence (v2 must not leak them).
fn envelope_shape(expected: &Value, actual: Option<&Value>) -> Result<(), Failure> {
    let Some(actual) = actual else {
        return Err(Failure::new("runner did not emit an x402EnvelopeShape"));
    };
    let p = |key: &str| format!("x402EnvelopeShape.{key}");
    for key in [
        "x402Version",
        "hasAccepted",
        "payloadHasTransaction",
        "scheme",
        "network",
    ] {
        expect_same(&p(key), expected.get(key), actual.get(key))?;
    }
    for key in [
        "acceptedScheme",
        "acceptedNetwork",
        "acceptedAsset",
        "acceptedPayTo",
        "acceptedAmount",
        "hasExtensions",
        "hasPaymentIdentifier",
        "paymentIdentifierRequired",
        "extensionKeys",
    ] {
        if let Some(want) = expected.get(key) {
            expect_same(&p(key), Some(want), actual.get(key))?;
        }
    }
    // A pinned id is asserted exactly; an unpinned-but-required id only
    // against the spec pattern (the runner generated it).
    if let Some(want) = expected.get("paymentIdentifierId") {
        expect_same(
            &p("paymentIdentifierId"),
            Some(want),
            actual.get("paymentIdentifierId"),
        )?;
    } else if truthy(expected.get("hasPaymentIdentifier"))
        && truthy(expected.get("paymentIdentifierRequired"))
    {
        let id = actual.get("paymentIdentifierId").and_then(Value::as_str);
        if !id.is_some_and(payment_identifier_shaped) {
            return Err(Failure::at(
                &p("paymentIdentifierId"),
                Some(&json!("^[A-Za-z0-9_-]{16,128}$")),
                actual.get("paymentIdentifierId"),
                "required id was not echoed".into(),
            ));
        }
    }
    Ok(())
}

fn truthy(v: Option<&Value>) -> bool {
    match v {
        None | Some(Value::Null) => false,
        Some(Value::Bool(b)) => *b,
        Some(Value::Number(n)) => n.as_f64().is_some_and(|f| f != 0.0),
        Some(Value::String(s)) => !s.is_empty(),
        Some(_) => true,
    }
}

fn payment_identifier_shaped(id: &str) -> bool {
    (16..=128).contains(&id.len())
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

fn big(value: Option<&Value>) -> Option<u128> {
    match value? {
        Value::String(s) => s.parse().ok(),
        Value::Number(n) => n.as_u64().map(u128::from),
        _ => None,
    }
}

/// `assertShape`.
fn transaction_shape(expected: &Value, actual: Option<&Value>) -> Result<(), Failure> {
    let Some(actual) = actual else {
        return Err(Failure::new("runner did not emit a transactionShape"));
    };
    if let Some(want) = expected.get("feePayer") {
        expect_same(
            "transactionShape.feePayer",
            Some(want),
            actual.get("feePayer"),
        )?;
    }
    if let Some(cap) = expected.get("maxComputeUnitLimit").and_then(Value::as_f64) {
        let got = actual.get("maxComputeUnitLimit");
        if !got.and_then(Value::as_f64).is_some_and(|g| g <= cap) {
            return Err(Failure::at(
                "transactionShape.maxComputeUnitLimit",
                expected.get("maxComputeUnitLimit"),
                got,
                format!("compute unit limit {} exceeds the cap {cap}", show(got)),
            ));
        }
    }
    if let Some(cap) = expected.get("maxComputeUnitPrice") {
        let got = big(actual.get("maxComputeUnitPrice")).unwrap_or(0);
        if big(Some(cap)).is_none_or(|cap| got > cap) {
            return Err(Failure::at(
                "transactionShape.maxComputeUnitPrice",
                Some(cap),
                actual.get("maxComputeUnitPrice"),
                format!("compute unit price {got} exceeds the cap {cap}"),
            ));
        }
    }
    let transfers: Vec<Value> = actual
        .get("transfers")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    for forbidden in expected
        .get("forbiddenPrograms")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        for transfer in &transfers {
            if transfer.get("tokenProgram") == Some(forbidden) {
                return Err(Failure::at(
                    "transactionShape.forbiddenPrograms",
                    Some(forbidden),
                    Some(transfer),
                    format!("forbidden program {forbidden} appeared in a transfer"),
                ));
            }
        }
    }
    if let Some(want) = expected.get("memo") {
        let set = |v: Option<&Value>| -> BTreeSet<String> {
            v.and_then(Value::as_array)
                .into_iter()
                .flatten()
                .map(Value::to_string)
                .collect()
        };
        if set(Some(want)) != set(actual.get("memo")) {
            return Err(Failure::at(
                "transactionShape.memo",
                Some(want),
                actual.get("memo"),
                "memo set differs".into(),
            ));
        }
    }
    if let Some(wanted) = expected.get("transfers").and_then(Value::as_array) {
        if actual
            .get("transfers")
            .and_then(Value::as_array)
            .map(Vec::len)
            != Some(wanted.len())
        {
            return Err(Failure::at(
                "transactionShape.transfers",
                expected.get("transfers"),
                actual.get("transfers"),
                format!(
                    "transfer count mismatch: expected {}, got {}",
                    wanted.len(),
                    transfers.len()
                ),
            ));
        }
        for (i, want) in wanted.iter().enumerate() {
            let s = |k: &str| want.get(k).and_then(Value::as_str);
            // SPL transfers land in the recipient's ATA: derive it from
            // destinationOwner + mint + tokenProgram.
            let destination = match (
                s("kind"),
                s("destinationOwner"),
                s("mint"),
                s("tokenProgram"),
            ) {
                (Some("spl"), Some(owner), Some(mint), Some(program)) => {
                    Some(ata(owner, mint, program).to_string())
                }
                _ => s("destination").map(str::to_string),
            };
            let matched = transfers.iter().any(|t| {
                t.get("kind") == want.get("kind")
                    && t.get("amount") == want.get("amount")
                    && destination
                        .as_deref()
                        .is_none_or(|d| t.get("destination").and_then(Value::as_str) == Some(d))
                    && ["mint", "decimals", "tokenProgram"]
                        .iter()
                        .all(|k| want.get(*k).is_none_or(|w| same(Some(w), t.get(*k))))
            });
            if !matched {
                return Err(Failure::at(
                    &format!("transactionShape.transfers[{i}]"),
                    Some(want),
                    actual.get("transfers"),
                    format!(
                        "no transfer matched {want} (dest {}); got {}",
                        destination.as_deref().unwrap_or("undefined"),
                        Value::Array(transfers.clone())
                    ),
                ));
            }
        }
    }
    Ok(())
}

// ── builds ─────────────────────────────────────────────────────────────────

/// CAIP-2 network of an x402 offer to the cluster name the kit's server
/// config takes.
pub fn cluster_for_caip2(network: &str) -> Option<&'static str> {
    ["devnet", "mainnet-beta", "testnet"]
        .into_iter()
        .find(|c| solana_pay_kit::x402::exact::caip2_network_for_cluster(c) == network)
}

/// The verify input for an x402 payment header built against `input`'s
/// offer: the route the offer advertises, served by the same fixtures.
pub fn x402_verify_input(build_input: &Value, header: &str) -> Result<Value, String> {
    let offer = build_input
        .get("x402Offer")
        .ok_or("build input has no x402Offer")?;
    let s = |k: &str| offer.get(k).and_then(Value::as_str).unwrap_or_default();
    let network = cluster_for_caip2(s("network"))
        .ok_or_else(|| format!("unknown offer network {}", s("network")))?;
    let mut input = json!({
        "x402PaymentHeader": header,
        "x402ServerNetwork": network,
        "x402ServerRecipient": s("payTo"),
        "x402ServerCurrency": s("asset"),
        "x402ServerAmount": s("amount"),
        "x402ServerFeePayer": offer.pointer("/extra/feePayer").cloned().unwrap_or(Value::Null),
        "rpcFixtures": build_input.get("rpcFixtures").cloned().unwrap_or(json!({})),
    });
    if let Some(memo) = offer.pointer("/extra/memo") {
        input["x402ServerMemo"] = memo.clone();
    }
    // Server SDKs configure their sponsor from its secret; the harness holds
    // the seeds of both sponsors the vectors use.
    let fee_payer = offer.pointer("/extra/feePayer").and_then(Value::as_str);
    for seed in [
        keys::X402_OFFER_FEE_PAYER_SEED,
        keys::X402_SERVER_FEE_PAYER_SEED,
    ] {
        if fee_payer == Some(keys::pubkey_of_seed(seed).to_string().as_str()) {
            input["x402ServerFeePayerSecretKey"] = keys::secret_json(seed);
        }
    }
    let required = build_input
        .pointer("/x402AdvertisedExtensions/payment-identifier/info/required")
        .and_then(Value::as_bool)
        == Some(true);
    if required {
        input["x402ServerRequiresPaymentIdentifier"] = json!(true);
    }
    Ok(input)
}

/// The verify-mode vector a build output turns into (also what `--cross`
/// feeds to every server SDK).
pub fn verify_input_for_build(vector: &Vector, artifact: &str) -> Result<Value, String> {
    match vector.intent.as_str() {
        "charge" => {
            let mut input = vector.input().clone();
            if let Some(obj) = input.as_object_mut() {
                obj.remove("rpcUrl");
            }
            input["transaction"] = json!(artifact);
            Ok(input)
        }
        "x402-exact" => x402_verify_input(vector.input(), artifact),
        other => Err(format!("no build verification for intent {other}")),
    }
}

/// The built artifact a build result must carry, per intent.
pub fn build_artifact(vector: &Vector, result: &Value) -> Result<Option<String>, Failure> {
    let field = match vector.intent.as_str() {
        "charge" => "transaction",
        "x402-exact" => "x402PaymentHeader",
        _ => return Ok(None),
    };
    match result.get(field).and_then(Value::as_str) {
        Some(artifact) => Ok(Some(artifact.to_string())),
        None => Err(Failure::new(format!(
            "an accepted {} build must carry the built `{field}` so the Rust verifier can judge it (testee ABI, harness/README.md)",
            vector.intent
        ))),
    }
}

fn header_transaction(header: &str) -> Result<String, String> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(header)
        .map_err(|e| format!("payment header base64: {e}"))?;
    let envelope: Value =
        serde_json::from_slice(&bytes).map_err(|e| format!("payment header JSON: {e}"))?;
    envelope
        .pointer("/payload/transaction")
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| "payment header has no payload.transaction".into())
}

/// One instruction as compared across SDKs: program, the SET of accounts
/// (SDKs may order accounts differently inside a signer/writable class) and
/// the data bytes. Each account carries its signer and writable flags
/// (`<pubkey>|<s or ->|<w or r>`): a read-only recipient executes
/// differently on-chain even with identical keys and data. Signatures never
/// enter the comparison.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Ix {
    pub program: String,
    pub accounts: BTreeSet<String>,
    pub data: String,
}

impl Ix {
    fn describe(&self) -> String {
        let accounts: Vec<String> = self
            .accounts
            .iter()
            .map(|a| {
                let mut parts = a.split('|');
                let key = parts.next().unwrap_or_default();
                let flags: String = parts.collect();
                format!("{}({flags})", annotate::address_name(key))
            })
            .collect();
        format!(
            "{} data={} accounts=[{}]",
            annotate::address_name(&self.program),
            self.data,
            accounts.join(", ")
        )
    }
}

/// Normalised view of a transaction: fee payer, signer set, instruction
/// multiset. `nonce_memo` replaces Memo data that is a random nonce (x402
/// without `extra.memo`: "a random nonce (at least 16 bytes, hex-encoded)")
/// by a placeholder, so two honest builds compare equal.
pub fn normalised(
    transaction: &str,
    nonce_memo: bool,
) -> Result<(String, BTreeSet<String>, Vec<Ix>), String> {
    let tx = decode_b64(transaction)?;
    let decompiled = decompile(&tx.message)?;
    let signed = tx.message.header().num_required_signatures as usize;
    let signers = tx
        .message
        .static_account_keys()
        .iter()
        .take(signed)
        .map(|k| k.to_string())
        .collect();
    let mut ixs: Vec<Ix> = decompiled
        .instructions
        .iter()
        .map(|ix| {
            let program = ix.program_id.to_string();
            let mut data: String = ix.data.iter().map(|b| format!("{b:02x}")).collect();
            if nonce_memo && program == keys::MEMO_PROGRAM {
                let text = String::from_utf8_lossy(&ix.data);
                if text.len() >= 32 && text.chars().all(|c| c.is_ascii_hexdigit()) {
                    data = "<hex nonce, at least 16 bytes>".into();
                }
            }
            Ix {
                program,
                accounts: ix
                    .accounts
                    .iter()
                    .map(|a| {
                        format!(
                            "{}|{}|{}",
                            a.pubkey,
                            if a.is_signer { "s" } else { "-" },
                            if a.is_writable { "w" } else { "r" }
                        )
                    })
                    .collect(),
                data,
            }
        })
        .collect();
    ixs.sort();
    Ok((decompiled.fee_payer.to_string(), signers, ixs))
}

/// Compare an SDK's transaction with the kit's: fee payer, signer set and
/// instruction multiset must be equal. Ordering differences are allowed.
pub fn compare_transactions(
    expected_tx: &str,
    actual_tx: &str,
    nonce_memo: bool,
) -> Result<(), Failure> {
    let (want_payer, want_signers, want) =
        normalised(expected_tx, nonce_memo).map_err(Failure::new)?;
    let (got_payer, got_signers, got) = normalised(actual_tx, nonce_memo)
        .map_err(|e| Failure::new(format!("the SDK's transaction does not decode: {e}")))?;
    let mut problems = Vec::new();
    if want_payer != got_payer {
        problems.push(format!(
            "fee payer {} (Rust: {})",
            annotate::address_name(&got_payer),
            annotate::address_name(&want_payer)
        ));
    }
    if want_signers != got_signers {
        problems.push(format!(
            "signers {:?} (Rust: {:?})",
            got_signers, want_signers
        ));
    }
    problems.extend(signature_problems(expected_tx, actual_tx)?);
    let mut missing = want.clone();
    let mut extra = Vec::new();
    for ix in &got {
        match missing.iter().position(|m| m == ix) {
            Some(at) => {
                missing.remove(at);
            }
            None => extra.push(ix.clone()),
        }
    }
    for ix in &missing {
        problems.push(format!("missing instruction {}", ix.describe()));
    }
    for ix in &extra {
        problems.push(format!("unexpected instruction {}", ix.describe()));
    }
    if problems.is_empty() {
        return Ok(());
    }
    let tree = |tx: &str| decode_b64(tx).map(|t| annotate::transaction_tree(&t)).ok();
    let (expected, actual) = (tree(expected_tx), tree(actual_tx));
    let path = match (&expected, &actual) {
        (Some(e), Some(a)) => crate::run::explain::first_divergence(e, a).map(|d| d.path),
        _ => None,
    };
    Err(Failure {
        message: format!(
            "the build differs from the Rust kit's build of the same case: {}",
            problems.join("; ")
        ),
        path,
        expected,
        actual,
    })
}

/// Every slot the SDK filled must hold a valid signature over the message,
/// and the SDK must fill exactly the slots the kit fills: a co-signer's slot
/// (the sponsoring fee payer, the x402 facilitator) stays empty.
fn signature_problems(expected_tx: &str, actual_tx: &str) -> Result<Vec<String>, Failure> {
    let want = signature_slots(&decode_b64(expected_tx).map_err(Failure::new)?);
    let got = signature_slots(
        &decode_b64(actual_tx)
            .map_err(|e| Failure::new(format!("the SDK's transaction does not decode: {e}")))?,
    );
    let mut problems = Vec::new();
    for (key, slot) in &got {
        let name = annotate::address_name(key);
        let reference = want.iter().find(|(k, _)| k == key).map(|(_, s)| *s);
        match (slot, reference) {
            (Slot::Invalid, _) => {
                problems.push(format!("signature slot of {name} does not verify"))
            }
            (Slot::Signed, Some(Slot::Empty)) => problems.push(format!(
                "signature slot of {name} is filled (Rust leaves it for the co-signer)"
            )),
            (Slot::Empty, Some(Slot::Signed)) => {
                problems.push(format!("signature slot of {name} is empty (Rust signs it)"))
            }
            _ => {}
        }
    }
    Ok(problems)
}

/// Judge an accepted build: the Rust verifier must accept it against the
/// vector's request, and its instruction multiset must equal the kit's own
/// build (DESIGN.md §3.2 "Judging a build").
pub async fn judge_build(vector: &Vector, artifact: &str) -> Result<(), Failure> {
    let intent = match vector.intent.as_str() {
        "charge" => Intent::Charge,
        "x402-exact" => Intent::X402Exact,
        _ => return Ok(()),
    };
    let verify_input = verify_input_for_build(vector, artifact).map_err(Failure::new)?;
    match realize::run(intent, Mode::VerifyTransaction, &verify_input).await {
        Observed::Accept(_) => {}
        other => {
            return Err(Failure::at(
                "verify",
                Some(&json!("accept")),
                Some(&json!(other.summary())),
                format!(
                    "the Rust kit's verifier refuses the SDK's build: {}",
                    other.summary()
                ),
            ))
        }
    }
    let reference = match realize::run(intent, Mode::BuildTransaction, vector.input()).await {
        Observed::Accept(output) => output,
        other => {
            return Err(Failure::new(format!(
                "the Rust kit cannot build this case ({}); the vector is wrong, file against the filler",
                other.summary()
            )))
        }
    };
    let (expected_tx, actual_tx, nonce_memo) = match intent {
        Intent::Charge => (
            reference.transaction.unwrap_or_default(),
            artifact.to_string(),
            false,
        ),
        _ => (
            header_transaction(&reference.header.unwrap_or_default()).map_err(Failure::new)?,
            header_transaction(artifact).map_err(Failure::new)?,
            vector.input().pointer("/x402Offer/extra/memo").is_none(),
        ),
    };
    compare_transactions(&expected_tx, &actual_tx, nonce_memo)
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

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap()
    }

    #[test]
    fn unsupported_mode_is_reported_not_judged() {
        let v = vector("charge-sol-native-build");
        let r = json!({"id": v.id, "outcome": "reject", "error": "unsupported-mode: server-only"});
        assert_eq!(
            judge_expect(&v, &r).unwrap(),
            Verdict::Unsupported("unsupported-mode: server-only".into())
        );
    }

    #[test]
    fn reject_code_is_pinned() {
        let v = vector("charge-verify-wrong-amount-reject");
        let code = v.reject_code().unwrap().to_string();
        let ok = json!({"id": v.id, "outcome": "reject", "rejectCode": code});
        assert_eq!(judge_expect(&v, &ok).unwrap(), Verdict::Pass);
        let wrong = json!({"id": v.id, "outcome": "reject", "rejectCode": "invalid-payload"});
        assert_eq!(
            judge_expect(&v, &wrong).unwrap_err().path.as_deref(),
            Some("rejectCode")
        );
        let accepted = json!({"id": v.id, "outcome": "accept"});
        assert_eq!(
            judge_expect(&v, &accepted).unwrap_err().path.as_deref(),
            Some("outcome")
        );
    }

    // Every accepted Rust build passes the Rust verifier and equals itself
    // (positive control for the build judge).
    #[test]
    fn the_kits_own_builds_pass_the_build_judge() {
        let rt = runtime();
        let all = vectors::load(&crate::repo_root().join("harness/vectors")).unwrap();
        let mut judged = 0;
        for v in all.iter().filter(|v| {
            v.mode == "build-transaction" && v.expect_outcome() == "accept" && v.intent != "session"
        }) {
            let intent = if v.intent == "charge" {
                Intent::Charge
            } else {
                Intent::X402Exact
            };
            let output = match rt.block_on(realize::run(intent, Mode::BuildTransaction, v.input()))
            {
                Observed::Accept(o) => o,
                other => panic!("{}: {}", v.id, other.summary()),
            };
            let artifact = output.transaction.or(output.header).unwrap();
            rt.block_on(judge_build(v, &artifact))
                .unwrap_or_else(|f| panic!("{}: {}", v.id, f.message));
            judged += 1;
        }
        assert!(judged >= 8, "{judged}");
    }

    // Planted lenient verifier (PLAN phase 2 success criterion): an extra
    // transfer that a lenient verifier would accept is caught by the
    // multiset comparison.
    #[test]
    fn an_extra_transfer_fails_the_multiset_comparison() {
        let rt = runtime();
        let v = vector("charge-sol-native-build");
        let built = match rt.block_on(realize::run(
            Intent::Charge,
            Mode::BuildTransaction,
            v.input(),
        )) {
            Observed::Accept(o) => o.transaction.unwrap(),
            other => panic!("{}", other.summary()),
        };
        let tx = decode_b64(&built).unwrap();
        let mut decompiled = decompile(&tx.message).unwrap();
        let transfer = decompiled
            .instructions
            .iter()
            .find(|ix| ix.program_id.to_string() == keys::SYSTEM_PROGRAM)
            .cloned()
            .unwrap();
        decompiled.instructions.push(transfer);
        let mut planted = crate::tx::compile_v0(&decompiled).unwrap();
        crate::tx::sign_slots(&mut planted, &[keys::CLIENT_SEED]);
        let planted = crate::tx::encode_b64(&planted).unwrap();
        let failure = compare_transactions(&built, &planted, false).unwrap_err();
        assert!(
            failure.message.contains("unexpected instruction"),
            "{}",
            failure.message
        );
        assert!(failure.path.is_some());
        // Control: the honest build compares equal to itself.
        compare_transactions(&built, &built, false).unwrap();
    }

    // A read-only recipient keeps keys and data identical but cannot be
    // credited on-chain; the comparison must see the writable flag.
    #[test]
    fn a_read_only_recipient_fails_the_multiset_comparison() {
        let rt = runtime();
        let v = vector("charge-sol-native-build");
        let built = match rt.block_on(realize::run(
            Intent::Charge,
            Mode::BuildTransaction,
            v.input(),
        )) {
            Observed::Accept(o) => o.transaction.unwrap(),
            other => panic!("{}", other.summary()),
        };
        let tx = decode_b64(&built).unwrap();
        let mut decompiled = decompile(&tx.message).unwrap();
        let transfer = decompiled
            .instructions
            .iter_mut()
            .find(|ix| ix.program_id.to_string() == keys::SYSTEM_PROGRAM)
            .unwrap();
        // System transfer accounts: [from (signer, writable), to (writable)].
        transfer.accounts[1].is_writable = false;
        let mut planted = crate::tx::compile_v0(&decompiled).unwrap();
        crate::tx::sign_slots(&mut planted, &[keys::CLIENT_SEED]);
        let planted = crate::tx::encode_b64(&planted).unwrap();
        let failure = compare_transactions(&built, &planted, false).unwrap_err();
        assert!(
            failure.message.contains("charge recipient)(-r)"),
            "{}",
            failure.message
        );
    }

    // charge-build-sponsored-fee-payer: the client signs only as transfer
    // authority. Copying its signature into the sponsor's slot, or sending a
    // signature that does not verify, fails the comparison.
    #[test]
    fn a_filled_sponsor_slot_or_a_bad_signature_fails_the_build_judge() {
        let rt = runtime();
        let v = vector("charge-build-sponsored-fee-payer");
        let built = match rt.block_on(realize::run(
            Intent::Charge,
            Mode::BuildTransaction,
            v.input(),
        )) {
            Observed::Accept(o) => o.transaction.unwrap(),
            other => panic!("{}", other.summary()),
        };
        compare_transactions(&built, &built, false).unwrap();
        let tx = decode_b64(&built).unwrap();
        let slots = signature_slots(&tx);
        let sponsor = slots.iter().position(|(_, s)| *s == Slot::Empty).unwrap();
        let client = slots.iter().position(|(_, s)| *s == Slot::Signed).unwrap();

        let mut copied = tx.clone();
        copied.signatures[sponsor] = copied.signatures[client];
        let failure = compare_transactions(&built, &crate::tx::encode_b64(&copied).unwrap(), false)
            .unwrap_err();
        assert!(
            failure.message.contains("does not verify"),
            "{}",
            failure.message
        );

        let mut corrupted = tx.clone();
        let mut bytes: [u8; 64] = corrupted.signatures[client].into();
        bytes[0] ^= 1;
        corrupted.signatures[client] = bytes.into();
        let failure =
            compare_transactions(&built, &crate::tx::encode_b64(&corrupted).unwrap(), false)
                .unwrap_err();
        assert!(
            failure.message.contains("does not verify"),
            "{}",
            failure.message
        );

        let mut unsigned = tx.clone();
        unsigned.signatures[client] = Default::default();
        let failure =
            compare_transactions(&built, &crate::tx::encode_b64(&unsigned).unwrap(), false)
                .unwrap_err();
        assert!(failure.message.contains("is empty"), "{}", failure.message);
    }

    #[test]
    fn caip2_round_trips() {
        assert_eq!(cluster_for_caip2(keys::DEVNET_CAIP2), Some("devnet"));
        assert_eq!(cluster_for_caip2(keys::MAINNET_CAIP2), Some("mainnet-beta"));
        assert_eq!(cluster_for_caip2("solana:nope"), None);
    }
}
