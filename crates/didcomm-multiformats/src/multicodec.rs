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
pub const P256_PUB: Multicodec = Multicodec { name: "p256-pub", code: &[0x12, 0x00] };

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

/// Split a multicodec-wrapped value into its codec and the remaining (unwrapped) bytes.
pub fn unwrap(data: &[u8]) -> Result<(Multicodec, &[u8]), MulticodecError> {
    ALL.iter()
        .copied()
        .find(|c| data.starts_with(c.code))
        .map(|c| (c, &data[c.code.len()..]))
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
}
