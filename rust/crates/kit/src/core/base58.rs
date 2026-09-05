//! Fast fixed-size Base58 codecs for Solana keys, hashes, and signatures.

/// Encode a 32-byte value such as a public key, channel ID, or hash.
pub(crate) fn encode_32(bytes: &[u8; 32]) -> String {
    let mut output = [0_u8; five8::BASE58_ENCODED_32_MAX_LEN];
    let len = five8::encode_32(bytes, &mut output);
    core::str::from_utf8(&output[..usize::from(len)])
        .expect("five8 output uses the Base58 ASCII alphabet")
        .to_owned()
}

/// Encode a 64-byte Ed25519 signature.
pub(crate) fn encode_64(bytes: &[u8; 64]) -> String {
    let mut output = [0_u8; five8::BASE58_ENCODED_64_MAX_LEN];
    let len = five8::encode_64(bytes, &mut output);
    core::str::from_utf8(&output[..usize::from(len)])
        .expect("five8 output uses the Base58 ASCII alphabet")
        .to_owned()
}

/// Decode a Base58 value that must contain exactly 32 bytes.
pub(crate) fn decode_32(value: &str) -> Result<[u8; 32], five8::DecodeError> {
    let mut output = [0_u8; 32];
    five8::decode_32(value, &mut output)?;
    Ok(output)
}

/// Decode a Base58 value that must contain exactly 64 bytes.
pub(crate) fn decode_64(value: &str) -> Result<[u8; 64], five8::DecodeError> {
    let mut output = [0_u8; 64];
    five8::decode_64(value, &mut output)?;
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_size_codecs_match_bs58() {
        let key = [0x42_u8; 32];
        let signature = [0xa5_u8; 64];
        let key_string = bs58::encode(key).into_string();
        let signature_string = bs58::encode(signature).into_string();

        assert_eq!(encode_32(&key), key_string);
        assert_eq!(decode_32(&key_string).unwrap(), key);
        assert_eq!(encode_64(&signature), signature_string);
        assert_eq!(decode_64(&signature_string).unwrap(), signature);
    }

    #[test]
    fn fixed_size_decoders_reject_wrong_sizes_and_alphabet() {
        assert!(decode_32(&bs58::encode([1_u8; 31]).into_string()).is_err());
        assert!(decode_64(&bs58::encode([1_u8; 63]).into_string()).is_err());
        assert!(decode_32("0OIl").is_err());
        assert!(decode_64("0OIl").is_err());
    }
}
