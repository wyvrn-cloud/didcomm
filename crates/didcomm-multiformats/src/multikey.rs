//! Multikey encoding: a multicodec-wrapped key, base58btc-encoded with its multibase
//! prefix -- the `"z6Mk..."`/`"z6LS..."` strings used in `publicKeyMultibase` fields and
//! `did:peer:2` key elements. Combines [`multicodec`] and [`multibase`] rather than
//! adding a third concept; there's no equivalent standalone module in
//! `didcomm_messaging` (Python inlines this same combination at each call site), but
//! enough call sites need exactly this pairing here to be worth naming.

use crate::{multibase, multicodec};

/// Error decoding a multikey string.
#[derive(Debug, thiserror::Error)]
pub enum MultikeyError {
    #[error(transparent)]
    Multibase(#[from] multibase::DecodeError),
    #[error(transparent)]
    Multicodec(#[from] multicodec::MulticodecError),
}

/// Encode a raw public key as a multikey string, e.g. `encode(multicodec::X25519_PUB,
/// &bytes)` -> `"z6LS..."`.
pub fn encode(codec: multicodec::Multicodec, key_bytes: &[u8]) -> String {
    format!("z{}", multibase::encode_base58btc(multicodec::wrap(codec, key_bytes)))
}

/// Decode a multikey string into its multicodec and the raw key bytes it wraps.
pub fn decode(multikey: &str) -> Result<(multicodec::Multicodec, Vec<u8>), MultikeyError> {
    let decoded = multibase::decode_self_describing(multikey)?;
    let (codec, key_bytes) = multicodec::unwrap(&decoded)?;
    Ok((codec, key_bytes.to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        let encoded = encode(multicodec::X25519_PUB, &[1, 2, 3]);
        let (codec, bytes) = decode(&encoded).unwrap();
        assert_eq!(codec, multicodec::X25519_PUB);
        assert_eq!(bytes, vec![1, 2, 3]);
    }
}
