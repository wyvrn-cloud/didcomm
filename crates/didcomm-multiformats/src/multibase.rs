//! Base64url encoding, matching `didcomm_messaging.multiformats.multibase.Base64UrlEncoder`.
//!
//! DIDComm's JWE envelopes use unpadded, URL-safe base64 everywhere (the `protected`
//! header, `iv`, `ciphertext`, `tag`, `encrypted_key`, embedded JWK fields, ...). This is
//! the one encoding this crate needs today; `base58btc` (used for multikey-encoded DID
//! material) is added alongside the rest of the multicodec table in a later milestone.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

/// Error decoding a base64url string.
#[derive(Debug, thiserror::Error)]
#[error("invalid base64url value: {0}")]
pub struct DecodeError(#[from] base64::DecodeError);

/// Encode bytes as unpadded, URL-safe base64.
pub fn encode(value: impl AsRef<[u8]>) -> String {
    URL_SAFE_NO_PAD.encode(value)
}

/// Decode an unpadded, URL-safe base64 string.
pub fn decode(value: impl AsRef<[u8]>) -> Result<Vec<u8>, DecodeError> {
    Ok(URL_SAFE_NO_PAD.decode(value)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_and_omits_padding() {
        let encoded = encode(b"Hello world!");
        assert_eq!(encoded, "SGVsbG8gd29ybGQh");
        assert!(!encoded.contains('='));
        assert_eq!(decode(&encoded).unwrap(), b"Hello world!");
    }
}
