//! Base64url encoding, matching `didcomm_messaging.multiformats.multibase.Base64UrlEncoder`.
//!
//! DIDComm's JWE envelopes use unpadded, URL-safe base64 everywhere (the `protected`
//! header, `iv`, `ciphertext`, `tag`, `encrypted_key`, embedded JWK fields, ...).
//!
//! Backed by the [`multibase`](https://github.com/multiformats/rust-multibase) crate --
//! the canonical Rust implementation maintained by the multiformats project itself (not
//! reimplemented here). Its top-level `encode`/`decode` functions are multibase-aware
//! (they read/write the leading base-identifier character, e.g. `u` for base64url), which
//! JWE fields don't use -- JWE base64url values have no such prefix. `Base::encode`/
//! `Base::decode` are the prefix-free per-encoding primitives the crate exposes for
//! exactly this case, so those are what this module wraps.
//!
//! `base58btc` is also here now (used for `did:peer:2`'s `alsoKnownAs`/did:peer:3
//! derivation, and later for multikey-encoded DID material generally) via the same
//! crate (`multibase::Base::Base58Btc`), not a separate library. (There is a standalone
//! `multicodec` crate on crates.io, but it's unmaintained since 2018; the multicodec
//! prefix table itself stays a small hand-rolled lookup, matching
//! `didcomm_messaging.multiformats.multicodec`.)

use multibase::Base;

/// Error decoding a base64url or base58btc string.
#[derive(Debug, thiserror::Error)]
#[error("invalid multibase value: {0}")]
pub struct DecodeError(#[from] multibase::Error);

/// Encode bytes as unpadded, URL-safe base64.
pub fn encode(value: impl AsRef<[u8]>) -> String {
    Base::Base64Url.encode(value)
}

/// Decode an unpadded, URL-safe base64 string.
pub fn decode(value: impl AsRef<str>) -> Result<Vec<u8>, DecodeError> {
    Ok(Base::Base64Url.decode(value)?)
}

/// Encode bytes as base58btc (no multibase prefix character).
pub fn encode_base58btc(value: impl AsRef<[u8]>) -> String {
    Base::Base58Btc.encode(value)
}

/// Decode a base58btc string (no multibase prefix character).
pub fn decode_base58btc(value: impl AsRef<str>) -> Result<Vec<u8>, DecodeError> {
    Ok(Base::Base58Btc.decode(value)?)
}

/// Decode a self-describing multibase string, e.g. a DID document's
/// `publicKeyMultibase` value, which (unlike a JWE field) does carry its leading
/// base-identifier character (`z` for base58btc, `u` for base64url, ...). Uses the
/// `multibase` crate's own top-level `decode`, which reads that character to pick the
/// encoding -- unlike this module's other functions, which are for contexts (JWE
/// fields) where the encoding is already known and no prefix character is present.
pub fn decode_self_describing(value: impl AsRef<str>) -> Result<Vec<u8>, DecodeError> {
    let (_base, bytes) = multibase::decode(value.as_ref())?;
    Ok(bytes)
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
