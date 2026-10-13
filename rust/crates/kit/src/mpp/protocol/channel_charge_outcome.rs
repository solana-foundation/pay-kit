//! Atomic execution evidence for channel-charge payouts (original SPL Token only).
use std::{collections::HashSet, str::FromStr};

use serde_json::Value;
use solana_pubkey::Pubkey;

use crate::mpp::error::{Error, Result};
use crate::mpp::protocol::solana::programs::{ASSOCIATED_TOKEN_PROGRAM, TOKEN_PROGRAM};

fn invalid(message: &str) -> Error {
    Error::Other(format!("Invalid channel charge outcome: {message}"))
}

fn pubkey(value: &str) -> Result<Pubkey> {
    Pubkey::from_str(value).map_err(|_| invalid("invalid public key"))
}

fn index(value: &Value, keys: &[String]) -> Result<usize> {
    value
        .as_u64()
        .and_then(|n| usize::try_from(n).ok())
        .filter(|n| *n < keys.len())
        .ok_or_else(|| invalid("missing or out-of-range account index"))
}

fn recipients(
    keys: &[String],
    mint: &str,
    expected: &[(String, String, u64)],
) -> Result<Vec<usize>> {
    let mint = pubkey(mint)?;
    let token = pubkey(TOKEN_PROGRAM)?;
    let ata_program = pubkey(ASSOCIATED_TOKEN_PROGRAM)?;
    let mut unique = HashSet::new();
    for key in keys {
        pubkey(key)?;
        if !unique.insert(key) {
            return Err(invalid("duplicate static key"));
        }
    }
    if expected.is_empty() {
        return Err(invalid("no expected payouts"));
    }
    let mut seen = HashSet::new();
    expected
        .iter()
        .map(|(ata, owner, amount)| {
            let owner = pubkey(owner)?;
            let derived = Pubkey::find_program_address(
                &[owner.as_ref(), token.as_ref(), mint.as_ref()],
                &ata_program,
            )
            .0;
            if pubkey(ata)? != derived || *amount == 0 || !seen.insert(ata) {
                return Err(invalid("invalid or duplicate payout leg"));
            }
            keys.iter()
                .position(|key| key == ata)
                .ok_or_else(|| invalid("recipient absent from static keys"))
        })
        .collect()
}

fn balances(
    meta: &Value,
    field: &str,
    keys: &[String],
    mint: &str,
    expected: &[(String, String, u64)],
    recipient_indices: &[usize],
) -> Result<Vec<u64>> {
    let rows = meta[field]
        .as_array()
        .ok_or_else(|| invalid("missing token balance snapshot"))?;
    let mut seen = HashSet::new();
    let mut result = vec![None; expected.len()];
    for row in rows {
        let account = index(&row["accountIndex"], keys)?;
        if !seen.insert(account) {
            return Err(invalid("duplicate token balance index"));
        }
        if let Some(leg) = recipient_indices.iter().position(|i| *i == account) {
            if row["mint"].as_str() != Some(mint)
                || row["owner"].as_str() != Some(expected[leg].1.as_str())
                || row["programId"].as_str() != Some(TOKEN_PROGRAM)
            {
                return Err(invalid("recipient token balance identity mismatch"));
            }
            let raw = row["uiTokenAmount"]["amount"]
                .as_str()
                .filter(|raw| !raw.is_empty() && raw.bytes().all(|b| b.is_ascii_digit()))
                .ok_or_else(|| invalid("missing raw token amount"))?;
            result[leg] = Some(
                raw.parse::<u64>()
                    .map_err(|_| invalid("invalid raw token amount"))?,
            );
        }
    }
    result
        .into_iter()
        .map(|amount| amount.ok_or_else(|| invalid("incomplete recipient snapshot")))
        .collect()
}

/// Exact net credits from one atomic simulation or confirmed execution.
/// Both snapshots must originate from that execution, never separate account
/// reads. Every beneficiary ATA must pre-exist; missing evidence fails closed.
pub fn validate_channel_charge_outcome(
    meta: &Value,
    static_keys: &[String],
    mint: &str,
    expected: &[(String, String, u64)],
) -> Result<()> {
    match meta.get("err") {
        Some(Value::Null) => (),
        Some(_) => return Err(invalid("execution failed")),
        None => return Err(invalid("missing execution status")),
    }
    let indices = recipients(static_keys, mint, expected)?;
    let before = balances(
        meta,
        "preTokenBalances",
        static_keys,
        mint,
        expected,
        &indices,
    )?;
    let after = balances(
        meta,
        "postTokenBalances",
        static_keys,
        mint,
        expected,
        &indices,
    )?;
    for ((before, after), (_, _, amount)) in before.iter().zip(after).zip(expected) {
        if after.checked_sub(*before) != Some(*amount) {
            return Err(invalid("recipient net credit mismatch"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    type Fixture = (Value, Vec<String>, String, Vec<(String, String, u64)>);
    fn fixture() -> Fixture {
        let mint = Pubkey::new_unique();
        let owner = Pubkey::new_unique();
        let ata = Pubkey::find_program_address(
            &[
                owner.as_ref(),
                pubkey(TOKEN_PROGRAM).unwrap().as_ref(),
                mint.as_ref(),
            ],
            &pubkey(ASSOCIATED_TOKEN_PROGRAM).unwrap(),
        )
        .0;
        let row = |amount: &str| {
            json!({
                "accountIndex": 0, "mint": mint.to_string(), "owner": owner.to_string(),
                "programId": TOKEN_PROGRAM, "uiTokenAmount": {"amount": amount, "decimals": 6}
            })
        };
        (
            json!({"err":null,"preTokenBalances":[row("100")],"postTokenBalances":[row("175")]}),
            vec![ata.to_string()],
            mint.to_string(),
            vec![(ata.to_string(), owner.to_string(), 75)],
        )
    }

    #[test]
    fn accepts_exact_atomic_evidence() {
        let (meta, keys, mint, expected) = fixture();
        validate_channel_charge_outcome(&meta, &keys, &mint, &expected).unwrap();
    }

    #[test]
    fn rejects_missing_failed_partial_and_duplicate_evidence() {
        let (meta, keys, mint, expected) = fixture();
        for field in ["err", "preTokenBalances", "postTokenBalances"] {
            let mut changed = meta.clone();
            changed.as_object_mut().unwrap().remove(field);
            assert!(validate_channel_charge_outcome(&changed, &keys, &mint, &expected).is_err());
        }
        let mut changed = meta.clone();
        changed["err"] = json!({"InstructionError":[1,"InvalidArgument"]});
        assert!(validate_channel_charge_outcome(&changed, &keys, &mint, &expected).is_err());
        changed["err"] = Value::Null;
        changed["postTokenBalances"] = json!([]);
        assert!(validate_channel_charge_outcome(&changed, &keys, &mint, &expected).is_err());
        changed["postTokenBalances"] =
            json!([meta["postTokenBalances"][0], meta["postTokenBalances"][0]]);
        assert!(validate_channel_charge_outcome(&changed, &keys, &mint, &expected).is_err());
    }

    #[test]
    fn rejects_snapshot_identity_amount_and_index_tampering() {
        let (meta, keys, mint, expected) = fixture();
        for field in ["mint", "owner", "programId"] {
            let mut changed = meta.clone();
            changed["postTokenBalances"][0][field] = json!(Pubkey::new_unique().to_string());
            assert!(validate_channel_charge_outcome(&changed, &keys, &mint, &expected).is_err());
        }
        for amount in ["99", "174", "176", "-1", "18446744073709551616", "1.0", ""] {
            let mut changed = meta.clone();
            changed["postTokenBalances"][0]["uiTokenAmount"]["amount"] = json!(amount);
            assert!(validate_channel_charge_outcome(&changed, &keys, &mint, &expected).is_err());
        }
        let mut changed = meta;
        changed["postTokenBalances"][0]["accountIndex"] = json!(255);
        assert!(validate_channel_charge_outcome(&changed, &keys, &mint, &expected).is_err());
    }
}
