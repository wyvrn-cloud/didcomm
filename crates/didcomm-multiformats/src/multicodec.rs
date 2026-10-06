//! Multicodec wrap/unwrap, mirroring `didcomm_messaging.multiformats.multicodec`.
//!
//! A multicodec-wrapped value is just a short byte prefix (identifying what the
//! remaining bytes are, e.g. "this is an Ed25519 public key") followed by the raw
//! value. Unlike a full multicodec implementation, this doesn't compute the prefix from
//! a general varint-encoded codec number -- it's the same small, fixed lookup table
//! Python uses, since that's all `didcomm_messaging` (and this port) actually needs.

/// A supported multicodec: its name and byte prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Multicodec {
    pub name: &'static str,
    pub code: &'static [u8],
}

/// The multicodec table `didcomm_messaging.multiformats.multicodec.SupportedCodecs`
/// covers -- key material only used by this library so far is uncommented in practice,
/// but the full table costs nothing to keep and avoids surprises later.
pub const ED25519_PUB: Multicodec = Multicodec { name: "ed25519-pub", code: &[0xed, 0x01] };
pub const ED25519_PRIV: Multicodec = Multicodec { name: "ed25519-priv", code: &[0x80, 0x26] };
pub const X25519_PUB: Multicodec = Multicodec { name: "x25519-pub", code: &[0xec, 0x01] };
pub const X25519_PRIV: Multicodec = Multicodec { name: "x25519-priv", code: &[0x82, 0x26] };
pub const BLS12381_G1_PUB: Multicodec = Multicodec { name: "bls12_381-g1-pub", code: &[0xea, 0x01] };
pub const BLS12381_G2_PUB: Multicodec = Multicodec { name: "bls12_381-g2-pub", code: &[0xeb, 0x01] };
pub const BLS12381_G1G2_PUB: Multicodec = Multicodec { name: "bls12_381-g1g2-pub", code: &[0xee, 0x01] };
pub const SECP256K1_PUB: Multicodec = Multicodec { name: "secp256k1-pub", code: &[0xe7, 0x01] };
/// Multicodec 0x1200 / 0x1201 as unsigned varints -- the prefixes real P-256/P-384
/// multikeys (`zDn...`/`z82...`) carry. (The raw code bytes `[0x12, 0x00]` this entry
/// used to have match no real key.)
pub const P256_PUB: Multicodec = Multicodec { name: "p256-pub", code: &[0x80, 0x24] };
pub const P384_PUB: Multicodec = Multicodec { name: "p384-pub", code: &[0x81, 0x24] };

const ALL: &[Multicodec] = &[
    ED25519_PUB,
    ED25519_PRIV,
    X25519_PUB,
    X25519_PRIV,
    BLS12381_G1_PUB,
    BLS12381_G2_PUB,
    BLS12381_G1G2_PUB,
    SECP256K1_PUB,
    P256_PUB,
    P384_PUB,
];

/// Error looking up or matching a multicodec.
#[derive(Debug, thiserror::Error)]
pub enum MulticodecError {
    #[error("unsupported multicodec: {0}")]
    UnknownName(String),
    #[error("unsupported multicodec prefix in data")]
    UnknownPrefix,
}

/// Look up a multicodec by name.
pub fn by_name(name: &str) -> Result<Multicodec, MulticodecError> {
    ALL.iter()
        .copied()
        .find(|c| c.name == name)
        .ok_or_else(|| MulticodecError::UnknownName(name.to_string()))
}

/// Prepend a multicodec's prefix to data.
pub fn wrap(codec: Multicodec, data: &[u8]) -> Vec<u8> {
    [codec.code, data].concat()
}

/// Prefixes accepted on decode only, mapped to the codec they were meant to be:
/// didcomm-messaging-python writes P-256 keys with the raw code bytes `12 00` instead
/// of the varint `80 24` (as this table also did, before). `12 00` names no key type in
/// the multicodec table, so reading it as P-256 is unambiguous; it is never written.
const DECODE_ALIASES: &[(&[u8], Multicodec)] = &[(&[0x12, 0x00], P256_PUB)];

/// Split a multicodec-wrapped value into its codec and the remaining (unwrapped) bytes.
pub fn unwrap(data: &[u8]) -> Result<(Multicodec, &[u8]), MulticodecError> {
    ALL.iter()
        .map(|c| (c.code, *c))
        .chain(DECODE_ALIASES.iter().map(|(code, c)| (*code, *c)))
        .find(|(code, _)| data.starts_with(code))
        .map(|(code, c)| (c, &data[code.len()..]))
        .ok_or(MulticodecError::UnknownPrefix)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wraps_and_unwraps() {
        let wrapped = wrap(X25519_PUB, &[1, 2, 3]);
        let (codec, data) = unwrap(&wrapped).unwrap();
        assert_eq!(codec, X25519_PUB);
        assert_eq!(data, &[1, 2, 3]);
    }

    #[test]
    fn decodes_the_did_key_spec_p256_and_p384_vectors() {
        // From the did:key method spec's test vectors.
        for (multikey, codec, len) in [
            ("zDnaerDaTF5BXEavCrfRZEk316dpbLsfPDZ3WJ5hRTPFU2169", P256_PUB, 33),
            ("z82Lm1MpAkeJcix9K8TMiLd5NMAhnwkjjCBeWHXyu3U4oT2MVJJKXkcVBgjGhnLBn2Kaau9", P384_PUB, 49),
        ] {
            let bytes = crate::multibase::decode_base58btc(&multikey[1..]).unwrap();
            let (found, key) = unwrap(&bytes).unwrap();
            assert_eq!(found, codec);
            assert_eq!(key.len(), len);
        }
    }

    #[test]
    fn reads_python_style_p256_prefix_but_writes_the_varint() {
        let key = [2u8; 33];
        let wrapped = [&[0x12, 0x00][..], &key].concat();
        let (codec, bytes) = unwrap(&wrapped).unwrap();
        assert_eq!(codec, P256_PUB);
        assert_eq!(bytes, key);
        assert_eq!(&wrap(P256_PUB, &key)[..2], &[0x80, 0x24]);
    }
}
