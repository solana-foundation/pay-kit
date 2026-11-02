//! Annotated views of filled vectors (`harness/vectors/annotated/<id>.txt`).
//!
//! Transactions are split into instructions with program names, named
//! accounts and decoded data (System transfer, SPL Token / Token-2022
//! TransferChecked, ATA CreateIdempotent, Memo, ComputeBudget limit and
//! price). Canonical-bytes vectors are split by offset and field. A PR that
//! changes a vector shows which field changed.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use base64::Engine;
use serde_json::Value;
use solana_transaction::versioned::VersionedTransaction;

use crate::keys::{self, ata};
use crate::tx::decode_b64;

/// Human names for the fixed addresses, and for their ATAs under every known
/// mint and token program.
fn labels() -> BTreeMap<String, String> {
    let mut labels = BTreeMap::new();
    let owners = [
        (keys::CLIENT, "client"),
        (
            keys::X402_SERVER_FEE_PAYER,
            "server fee payer / charge recipient",
        ),
        (keys::SPLIT_RECIPIENT, "split recipient"),
        (keys::SPLIT_RECIPIENT_2, "split recipient 2"),
        (keys::X402_PAY_TO, "x402 payTo"),
        (keys::X402_OTHER_PAY_TO, "x402 other payTo"),
        (keys::X402_OFFER_FEE_PAYER, "x402 offer fee payer"),
    ];
    let mints = [
        (keys::MINT, "mint"),
        (keys::OTHER_MINT, "other mint"),
        (keys::MINT_2022, "Token-2022 mint"),
        (keys::MAINNET_USDC, "mainnet USDC"),
    ];
    let programs = [
        (keys::SYSTEM_PROGRAM, "System Program"),
        (keys::TOKEN_PROGRAM, "SPL Token"),
        (keys::TOKEN_2022_PROGRAM, "Token-2022"),
        (keys::ATA_PROGRAM, "Associated Token Account"),
        (keys::MEMO_PROGRAM, "Memo"),
        (keys::COMPUTE_BUDGET_PROGRAM, "ComputeBudget"),
    ];
    for (address, name) in owners.iter().chain(mints.iter()).chain(programs.iter()) {
        labels
            .entry(address.to_string())
            .or_insert_with(|| name.to_string());
    }
    for (owner, owner_name) in owners {
        for (mint, mint_name) in mints {
            for (program, program_name) in [
                (keys::TOKEN_PROGRAM, "SPL Token"),
                (keys::TOKEN_2022_PROGRAM, "Token-2022"),
            ] {
                labels.insert(
                    ata(owner, mint, program).to_string(),
                    format!("ATA({owner_name}, {mint_name}, {program_name})"),
                );
            }
        }
    }
    labels
}

fn name(labels: &BTreeMap<String, String>, address: &str) -> String {
    match labels.get(address) {
        Some(label) => format!("{address} ({label})"),
        None => address.to_string(),
    }
}

fn le_u32(data: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(data.get(at..at + 4)?.try_into().ok()?))
}

fn le_u64(data: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(data.get(at..at + 8)?.try_into().ok()?))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn transaction(tx: &VersionedTransaction) -> String {
    let labels = labels();
    let keys = tx.message.static_account_keys();
    let header = tx.message.header();
    let signed = header.num_required_signatures as usize;
    let readonly_signed = header.num_readonly_signed_accounts as usize;
    let readonly_unsigned = header.num_readonly_unsigned_accounts as usize;
    let version = match &tx.message {
        solana_message::VersionedMessage::Legacy(_) => "legacy".to_string(),
        solana_message::VersionedMessage::V0(_) => "0".to_string(),
        _ => "1".to_string(),
    };
    let mut out = String::new();
    let _ = writeln!(out, "transaction version {version}");
    let _ = writeln!(out, "  recent blockhash {}", tx.message.recent_blockhash());
    if let Some(config) = crate::tx::v1_config(&tx.message) {
        let show = |v: Option<String>| v.unwrap_or_else(|| "absent".into());
        let _ = writeln!(
            out,
            "  config computeUnitLimit {} priorityFee {} loadedAccountsDataSizeLimit {}",
            show(config.compute_unit_limit.map(|v| v.to_string())),
            show(config.priority_fee.map(|v| format!("{v} lamports"))),
            show(
                config
                    .loaded_accounts_data_size_limit
                    .map(|v| v.to_string())
            ),
        );
    }
    if let Some(lookups) = tx.message.address_table_lookups().filter(|l| !l.is_empty()) {
        let _ = writeln!(out, "  address lookup tables {}", lookups.len());
    }
    let _ = writeln!(out, "  signatures");
    for (i, sig) in tx.signatures.iter().enumerate() {
        let state = if *sig == Default::default() {
            "empty"
        } else {
            "signed"
        };
        let key = keys.get(i).map(|k| k.to_string()).unwrap_or_default();
        let _ = writeln!(out, "    [{i}] {state:6} {}", name(&labels, &key));
    }
    let _ = writeln!(out, "  accounts");
    for (i, key) in keys.iter().enumerate() {
        let signer = i < signed;
        let writable = if signer {
            i < signed - readonly_signed
        } else {
            i < keys.len() - readonly_unsigned
        };
        let role = match (signer, writable) {
            (true, true) => "signer, writable",
            (true, false) => "signer",
            (false, true) => "writable",
            (false, false) => "readonly",
        };
        let fee_payer = if i == 0 { ", fee payer" } else { "" };
        let _ = writeln!(
            out,
            "    [{i}] {} [{role}{fee_payer}]",
            name(&labels, &key.to_string())
        );
    }
    let _ = writeln!(out, "  instructions");
    for (n, ix) in tx.message.instructions().iter().enumerate() {
        let (title, fields) = decode_instruction(&labels, keys, ix);
        let _ = writeln!(out, "    #{n} {title}");
        for (k, v) in fields {
            let _ = writeln!(out, "         {k:<14} {v}");
        }
    }
    out
}

/// The decoded transaction as a tree, for diffs that name the first
/// divergent field: fee payer, signer set, and every instruction's title and
/// decoded fields (accounts by name).
pub fn transaction_tree(tx: &VersionedTransaction) -> Value {
    let labels = labels();
    let keys = tx.message.static_account_keys();
    let signed = tx.message.header().num_required_signatures as usize;
    let instructions: Vec<Value> = tx
        .message
        .instructions()
        .iter()
        .map(|ix| {
            let (title, fields) = decode_instruction(&labels, keys, ix);
            let mut obj = serde_json::Map::new();
            obj.insert("instruction".into(), Value::String(title));
            for (k, v) in fields {
                obj.insert(k, Value::String(v));
            }
            Value::Object(obj)
        })
        .collect();
    serde_json::json!({
        "feePayer": keys.first().map(|k| name(&labels, &k.to_string())).unwrap_or_default(),
        "signers": keys.iter().take(signed).map(|k| name(&labels, &k.to_string())).collect::<Vec<_>>(),
        "recentBlockhash": tx.message.recent_blockhash().to_string(),
        "instructions": instructions,
    })
}

/// Human name of an address (`<address> (<label>)` for fixed addresses).
pub fn address_name(address: &str) -> String {
    name(&labels(), address)
}

/// One instruction as a title (program and instruction name) and its decoded
/// fields with named accounts.
fn decode_instruction(
    labels: &BTreeMap<String, String>,
    account_keys: &[solana_pubkey::Pubkey],
    ix: &solana_message::compiled_instruction::CompiledInstruction,
) -> (String, Vec<(String, String)>) {
    let program = account_keys
        .get(ix.program_id_index as usize)
        .map(|k| k.to_string())
        .unwrap_or_default();
    let account = |i: usize| -> String {
        ix.accounts
            .get(i)
            .and_then(|a| account_keys.get(*a as usize))
            .map(|k| name(labels, &k.to_string()))
            .unwrap_or_else(|| "<missing>".into())
    };
    let data = ix.data.as_slice();
    let mut fields: Vec<(String, String)> = Vec::new();
    let title = match program.as_str() {
        keys::COMPUTE_BUDGET_PROGRAM if data.first() == Some(&2) => {
            fields.push((
                "units".into(),
                le_u32(data, 1).map(|v| v.to_string()).unwrap_or_default(),
            ));
            "ComputeBudget SetComputeUnitLimit".to_string()
        }
        keys::COMPUTE_BUDGET_PROGRAM if data.first() == Some(&3) => {
            fields.push((
                "microLamports".into(),
                le_u64(data, 1).map(|v| v.to_string()).unwrap_or_default(),
            ));
            "ComputeBudget SetComputeUnitPrice".to_string()
        }
        keys::SYSTEM_PROGRAM if le_u32(data, 0) == Some(2) => {
            fields.push((
                "lamports".into(),
                le_u64(data, 4).map(|v| v.to_string()).unwrap_or_default(),
            ));
            fields.push(("from".into(), account(0)));
            fields.push(("to".into(), account(1)));
            "System Transfer".to_string()
        }
        keys::TOKEN_PROGRAM | keys::TOKEN_2022_PROGRAM if data.len() == 10 && data[0] == 12 => {
            fields.push((
                "amount".into(),
                le_u64(data, 1).map(|v| v.to_string()).unwrap_or_default(),
            ));
            fields.push(("decimals".into(), data[9].to_string()));
            fields.push(("source".into(), account(0)));
            fields.push(("mint".into(), account(1)));
            fields.push(("destination".into(), account(2)));
            fields.push(("authority".into(), account(3)));
            let program_name = if program == keys::TOKEN_PROGRAM {
                "SPL Token"
            } else {
                "Token-2022"
            };
            format!("{program_name} TransferChecked")
        }
        keys::ATA_PROGRAM if data == [1] => {
            for (i, role) in [
                "payer",
                "ata",
                "owner",
                "mint",
                "system program",
                "token program",
            ]
            .iter()
            .enumerate()
            {
                fields.push(((*role).into(), account(i)));
            }
            "Associated Token Account CreateIdempotent".to_string()
        }
        keys::MEMO_PROGRAM => {
            fields.push((
                "text".into(),
                format!("{:?}", String::from_utf8_lossy(data)),
            ));
            for i in 0..ix.accounts.len() {
                fields.push((format!("signer[{i}]"), account(i)));
            }
            "Memo".to_string()
        }
        _ => {
            fields.push(("data".into(), hex(data)));
            for i in 0..ix.accounts.len() {
                fields.push((format!("account[{i}]"), account(i)));
            }
            format!("unknown program {}", name(labels, &program))
        }
    };
    (title, fields)
}

fn bytes_of(expect: &Value) -> Option<Vec<u8>> {
    expect
        .pointer("/exactBytes/bytes")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|b| b.as_u64().map(|b| b as u8))
                .collect()
        })
}

fn canonical(input: &Value, expect: &Value) -> String {
    let mut out = String::new();
    if let Some(vp) = input.get("voucherPreimage") {
        let _ = writeln!(out, "session voucher preimage (50 bytes)");
        if let Some(bytes) = bytes_of(expect) {
            let field =
                |out: &mut String, range: std::ops::Range<usize>, label: &str, value: String| {
                    let _ = writeln!(
                        out,
                        "  [{:>2}..{:>2}] {label:<17} {} = {value}",
                        range.start,
                        range.end,
                        hex(&bytes[range.clone()])
                    );
                };
            if bytes.len() == 50 {
                field(&mut out, 0..2, "magic", "0x56 0x01".into());
                field(
                    &mut out,
                    2..34,
                    "channelId",
                    vp["channelId"].as_str().unwrap_or_default().into(),
                );
                field(
                    &mut out,
                    34..42,
                    "cumulative u64 LE",
                    le_u64(&bytes, 34).unwrap_or(0).to_string(),
                );
                field(
                    &mut out,
                    42..50,
                    "expiresAt i64 LE",
                    i64::from_le_bytes(bytes[42..50].try_into().unwrap()).to_string(),
                );
            }
        }
        return out;
    }
    if let Some(cid) = input.get("challengeId") {
        let _ = writeln!(out, "challenge id = base64url(HMAC-SHA256(secretKey, realm|method|intent|request|expires|digest|opaque))");
        let _ = writeln!(
            out,
            "  secretKey {:?}",
            cid["secretKey"].as_str().unwrap_or_default()
        );
        let mut offset = 0;
        for key in [
            "realm", "method", "intent", "request", "expires", "digest", "opaque",
        ] {
            let value = cid.get(key).and_then(Value::as_str).unwrap_or("");
            let _ = writeln!(
                out,
                "  [{offset:>3}..{:>3}] {key:<8} {value:?}",
                offset + value.len()
            );
            offset += value.len() + 1;
        }
    }
    if let Some(sw) = input.get("sessionWire") {
        let _ = writeln!(
            out,
            "session wire round trip, shape {}",
            sw["shape"].as_str().unwrap_or_default()
        );
    }
    if let Some(json) = expect
        .pointer("/exactBytes/canonicalJson")
        .and_then(Value::as_str)
    {
        let _ = writeln!(out, "  canonicalJson ({} bytes) {json}", json.len());
    }
    if let Some(b64) = expect
        .pointer("/exactBytes/base64Url")
        .and_then(Value::as_str)
    {
        let _ = writeln!(out, "  base64Url ({} chars) {b64}", b64.len());
    }
    if let Some(bytes) = bytes_of(expect) {
        let _ = writeln!(out, "  bytes ({}) {}", bytes.len(), hex(&bytes));
    }
    out
}

/// The annotated text for one vector, or `None` when it has nothing to
/// annotate. `reference_tx` is the kit's own build for build vectors (which
/// carry no transaction).
pub fn vector(vector: &Value, reference_tx: Option<&str>) -> Option<String> {
    let id = vector["id"].as_str().unwrap_or_default();
    let input = &vector["input"];
    let expect = &vector["expect"];
    let mut out = format!(
        "# {id} ({} {}, expect {})\n# generated by pkc fill; do not edit\n\n",
        vector["intent"].as_str().unwrap_or_default(),
        vector["mode"].as_str().unwrap_or_default(),
        expect["outcome"].as_str().unwrap_or_default()
    );
    let mut any = false;
    if let Some(header) = input.get("x402PaymentHeader").and_then(Value::as_str) {
        if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(header) {
            if let Ok(mut envelope) = serde_json::from_slice::<Value>(&bytes) {
                let tx = envelope
                    .pointer("/payload/transaction")
                    .and_then(Value::as_str)
                    .map(str::to_string);
                if let Some(payload) = envelope.get_mut("payload") {
                    payload["transaction"] = Value::String("<below>".into());
                }
                let _ = writeln!(
                    out,
                    "payment header (base64 JSON)\n{}\n",
                    serde_json::to_string_pretty(&envelope).unwrap_or_default()
                );
                any = true;
                if let Some(tx) = tx {
                    out.push_str(&match decode_b64(&tx) {
                        Ok(tx) => transaction(&tx),
                        Err(e) => format!("payload.transaction does not decode: {e}\n"),
                    });
                }
            }
        }
    }
    if let Some(credential) = input.pointer("/sessionServerVerify/credential") {
        let mut shown = credential.clone();
        let tx = credential
            .get("transaction")
            .and_then(Value::as_str)
            .map(str::to_string);
        if tx.is_some() {
            shown["transaction"] = Value::String("<below>".into());
        }
        let _ = writeln!(
            out,
            "session credential ({})\n{}\n",
            credential["action"].as_str().unwrap_or("?"),
            serde_json::to_string_pretty(&shown).unwrap_or_default()
        );
        any = true;
        if let Some(tx) = tx {
            out.push_str(&match decode_b64(&tx) {
                Ok(tx) => transaction(&tx),
                Err(e) => format!("credential.transaction does not decode: {e}\n"),
            });
        }
    }
    if let Some(tx) = input.get("transaction").and_then(Value::as_str) {
        any = true;
        out.push_str(&match decode_b64(tx) {
            Ok(tx) => transaction(&tx),
            Err(e) => format!("input.transaction does not decode: {e}\n"),
        });
    } else if let Some(tx) = reference_tx {
        any = true;
        out.push_str(
            "reference build by the Rust kit (not part of the vector; runners build their own)\n",
        );
        out.push_str(&match decode_b64(tx) {
            Ok(tx) => transaction(&tx),
            Err(e) => format!("reference build does not decode: {e}\n"),
        });
    }
    if vector["mode"] == "canonical-bytes" {
        any = true;
        out.push_str(&canonical(input, expect));
    }
    any.then_some(out)
}
