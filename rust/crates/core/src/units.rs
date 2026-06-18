//! Canonical human-decimal → base-units conversion, shared by `solana-mpp`
//! and `solana-x402`.
//!
//! This is the audited implementation (previously duplicated in both protocol
//! crates): it caps `decimals`, uses checked arithmetic, and validates input
//! shape strictly.

use crate::{Error, Result};

/// Upper bound on the `decimals` argument to [`parse_units`].
///
/// Solana's SPL convention is 0–9. 18 gives ERC-20-style headroom while staying
/// well below the cliff at 39 where `10u128.pow(decimals)` overflows. The cap
/// gives a single rejection site so any callsite that hasn't validated
/// `decimals` upstream gets a clear error rather than a panic or wrap.
pub const MAX_DECIMALS: u8 = 18;

/// Convert a human-readable amount to base units.
///
/// Matches the TypeScript SDK's `parseUnits(amount, decimals)` — e.g.
/// `parse_units("1.5", 6)` → `"1500000"`.
///
/// Rejects `decimals > MAX_DECIMALS`, empty amounts, more than one `.`, empty
/// integer/fractional parts (`".5"`, `"1."`), non-ASCII-digit characters, and
/// excess fractional digits. The integer branch uses checked arithmetic so a
/// hostile or buggy caller cannot trigger a panic (debug) or silent overflow
/// (release).
pub fn parse_units(amount: &str, decimals: u8) -> Result<String> {
    if decimals > MAX_DECIMALS {
        return Err(Error::Other(format!(
            "Decimals {decimals} exceeds maximum {MAX_DECIMALS}"
        )));
    }
    if amount.is_empty() {
        return Err(Error::Other("Empty amount".into()));
    }
    if amount.matches('.').count() > 1 {
        return Err(Error::Other(format!(
            "Invalid amount `{amount}`: more than one decimal point"
        )));
    }
    let decimals = decimals as u32;

    if let Some((integer, fraction)) = amount.split_once('.') {
        if integer.is_empty() || fraction.is_empty() {
            return Err(Error::Other(format!(
                "Invalid amount `{amount}`: integer and fractional parts must both be non-empty"
            )));
        }
        if !integer.bytes().all(|b| b.is_ascii_digit())
            || !fraction.bytes().all(|b| b.is_ascii_digit())
        {
            return Err(Error::Other(format!(
                "Invalid amount `{amount}`: only ASCII digits and a single optional decimal point are allowed"
            )));
        }
        let frac_len = fraction.len() as u32;
        if frac_len > decimals {
            return Err(Error::Other(format!(
                "Too many decimal places: {frac_len} > {decimals}"
            )));
        }
        let padding = decimals - frac_len;
        let combined = format!("{integer}{fraction}{}", "0".repeat(padding as usize));
        let trimmed = combined.trim_start_matches('0');
        if trimmed.is_empty() {
            Ok("0".to_string())
        } else {
            Ok(trimmed.to_string())
        }
    } else {
        let value: u128 = amount
            .parse()
            .map_err(|_| Error::Other(format!("Invalid amount: {amount}")))?;
        let factor = 10u128
            .checked_pow(decimals)
            .ok_or_else(|| Error::Other(format!("10^{decimals} overflows u128 in parse_units")))?;
        let product = value.checked_mul(factor).ok_or_else(|| {
            Error::Other(format!(
                "{value} * 10^{decimals} overflows u128 in parse_units"
            ))
        })?;
        Ok(product.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integer_and_decimal() {
        assert_eq!(parse_units("1", 6).unwrap(), "1000000");
        assert_eq!(parse_units("0", 6).unwrap(), "0");
        assert_eq!(parse_units("1.5", 6).unwrap(), "1500000");
        assert_eq!(parse_units("0.000001", 6).unwrap(), "1");
        assert_eq!(parse_units("0.0", 6).unwrap(), "0");
    }

    #[test]
    fn rejects_malformed() {
        assert!(parse_units("", 6).is_err());
        assert!(parse_units(".5", 1).is_err());
        assert!(parse_units("1.", 0).is_err());
        assert!(parse_units("1.2.3", 6).is_err());
        assert!(parse_units("-1", 6).is_err());
        assert!(parse_units("1a.2", 6).is_err());
        assert!(parse_units("1.0000001", 6).is_err());
    }

    #[test]
    fn decimals_cap_and_overflow() {
        assert!(parse_units("1", MAX_DECIMALS + 1).is_err());
        assert_eq!(
            parse_units("1", MAX_DECIMALS).unwrap(),
            "1000000000000000000"
        );
        let huge = format!("1{}", "0".repeat(21));
        assert!(parse_units(&huge, MAX_DECIMALS).is_err());
    }
}
