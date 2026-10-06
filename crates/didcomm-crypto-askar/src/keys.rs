//! Key-agreement keys on every curve DIDComm v2 uses: X25519 (required), P-384
//! (required), P-256 (deprecated, still interoperable). P-521 is optional in the spec
//! and not available in `askar-crypto`, so it isn't supported.
//!
//! Every ECDH operation here requires both sides to be on the same curve -- one
//! envelope's shared ephemeral key (see `ecdh_es_encrypt`/`ecdh_1pu_encrypt`) means
//! every recipient of it must be too. Parsing a NIST public key goes through
//! `askar-crypto`'s SEC1/JWK decoding, which rejects points that aren't on the curve
//! (the spec's MUST for invalid-curve attacks).

use askar_crypto::{
    alg::{p256::P256KeyPair, p384::P384KeyPair, x25519::X25519KeyPair},
    jwk::{FromJwk, ToJwk},
    kdf::{ecdh_1pu::Ecdh1PU, ecdh_es::EcdhEs, KeyDerivation, KeyExchange},
    repr::{KeyGen, KeyPublicBytes, KeySecretBytes},
};
use ciborium::{value::Integer, Value as CborValue};
use didcomm_multiformats::multibase;
use serde_json::Value;

use crate::CryptoError;

/// A key-agreement curve.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Curve {
    X25519,
    P256,
    P384,
}

impl Curve {
    /// The JWK/JWA `crv` name.
    pub fn name(self) -> &'static str {
        match self {
            Self::X25519 => "X25519",
            Self::P256 => "P-256",
            Self::P384 => "P-384",
        }
    }

    /// The `COSE_Key` `crv` value (RFC 9053 §7.1).
    fn cose_crv(self) -> i64 {
        match self {
            Self::P256 => 1,
            Self::P384 => 2,
            Self::X25519 => 4,
        }
    }
}

/// An X25519, P-256 or P-384 key pair (or public key).
#[derive(Debug, Clone)]
pub enum AgreementKey {
    X25519(X25519KeyPair),
    P256(P256KeyPair),
    P384(P384KeyPair),
}

impl From<X25519KeyPair> for AgreementKey {
    fn from(key: X25519KeyPair) -> Self {
        Self::X25519(key)
    }
}

impl From<P256KeyPair> for AgreementKey {
    fn from(key: P256KeyPair) -> Self {
        Self::P256(key)
    }
}

impl From<P384KeyPair> for AgreementKey {
    fn from(key: P384KeyPair) -> Self {
        Self::P384(key)
    }
}

/// Runs `$body` with `$a`/`$b` bound to the inner keys of two `AgreementKey`s on the
/// same curve, or fails with `CurveMismatch`.
macro_rules! same_curve {
    ($x:expr, $y:expr, |$a:ident, $b:ident| $body:expr) => {
        match ($x, $y) {
            (AgreementKey::X25519($a), AgreementKey::X25519($b)) => $body,
            (AgreementKey::P256($a), AgreementKey::P256($b)) => $body,
            (AgreementKey::P384($a), AgreementKey::P384($b)) => $body,
            (x, y) => return Err(CryptoError::CurveMismatch(x.curve().name(), y.curve().name())),
        }
    };
}

impl AgreementKey {
    pub fn curve(&self) -> Curve {
        match self {
            Self::X25519(_) => Curve::X25519,
            Self::P256(_) => Curve::P256,
            Self::P384(_) => Curve::P384,
        }
    }

    /// A fresh random key on `curve` (an ephemeral key, or a CEK-wrapping identity).
    pub fn generate(curve: Curve) -> Result<Self, CryptoError> {
        Ok(match curve {
            Curve::X25519 => Self::X25519(X25519KeyPair::random()?),
            Curve::P256 => Self::P256(P256KeyPair::random()?),
            Curve::P384 => Self::P384(P384KeyPair::random()?),
        })
    }

    /// A public key from its raw encoding: 32 bytes for X25519, a SEC1 point
    /// (compressed or not) for P-256/P-384.
    pub fn from_public_bytes(curve: Curve, bytes: &[u8]) -> Result<Self, CryptoError> {
        Ok(match curve {
            Curve::X25519 => Self::X25519(X25519KeyPair::from_public_bytes(bytes)?),
            Curve::P256 => Self::P256(P256KeyPair::from_public_bytes(bytes)?),
            Curve::P384 => Self::P384(P384KeyPair::from_public_bytes(bytes)?),
        })
    }

    /// A key pair from its raw secret scalar.
    pub fn from_secret_bytes(curve: Curve, bytes: &[u8]) -> Result<Self, CryptoError> {
        Ok(match curve {
            Curve::X25519 => Self::X25519(X25519KeyPair::from_secret_bytes(bytes)?),
            Curve::P256 => Self::P256(P256KeyPair::from_secret_bytes(bytes)?),
            Curve::P384 => Self::P384(P384KeyPair::from_secret_bytes(bytes)?),
        })
    }

    /// The raw public key (X25519 bytes, or a compressed SEC1 point).
    pub fn public_bytes(&self) -> Vec<u8> {
        match self {
            Self::X25519(k) => k.with_public_bytes(<[u8]>::to_vec),
            Self::P256(k) => k.with_public_bytes(<[u8]>::to_vec),
            Self::P384(k) => k.with_public_bytes(<[u8]>::to_vec),
        }
    }

    /// The public JWK (an `epk` header value).
    pub fn to_jwk_public(&self) -> Result<Value, CryptoError> {
        let jwk = match self {
            Self::X25519(k) => k.to_jwk_public(None)?,
            Self::P256(k) => k.to_jwk_public(None)?,
            Self::P384(k) => k.to_jwk_public(None)?,
        };
        Ok(serde_json::from_str(&jwk)?)
    }

    /// A public key from a JWK, dispatching on its `crv`.
    pub fn from_jwk(jwk: &Value) -> Result<Self, CryptoError> {
        let text = serde_json::to_string(jwk)?;
        Ok(match jwk["crv"].as_str() {
            Some("X25519") => Self::X25519(X25519KeyPair::from_jwk(&text)?),
            Some("P-256") => Self::P256(P256KeyPair::from_jwk(&text)?),
            Some("P-384") => Self::P384(P384KeyPair::from_jwk(&text)?),
            other => return Err(CryptoError::UnsupportedCurve(format!("{other:?}"))),
        })
    }

    /// The public key as a `COSE_Key` (RFC 9053 §7): OKP `{1: 1, -1: 4, -2: x}` for
    /// X25519, EC2 `{1: 2, -1: crv, -2: x, -3: y}` for the NIST curves.
    pub fn to_cose_key(&self) -> Result<CborValue, CryptoError> {
        let int = |v: i64| CborValue::Integer(Integer::from(v));
        let curve = self.curve();
        Ok(match self {
            Self::X25519(_) => didcomm_core::cose::x25519_cose_key(&self.public_bytes()),
            Self::P256(_) | Self::P384(_) => {
                let jwk = self.to_jwk_public()?;
                let coord = |name: &str| -> Result<CborValue, CryptoError> {
                    let text = jwk[name].as_str().ok_or(CryptoError::UnsupportedCurve(format!("JWK without {name}")))?;
                    Ok(CborValue::Bytes(
                        multibase::decode(text).map_err(|_| CryptoError::UnsupportedCurve("bad JWK coordinate".into()))?,
                    ))
                };
                CborValue::Map(vec![
                    (int(1), int(2)),
                    (int(-1), int(curve.cose_crv())),
                    (int(-2), coord("x")?),
                    (int(-3), coord("y")?),
                ])
            }
        })
    }

    /// A public key from a `COSE_Key` (OKP X25519, or EC2 P-256/P-384 with `y` as
    /// coordinate bytes or a compressed-point sign bit).
    pub fn from_cose_key(value: &CborValue) -> Result<Self, CryptoError> {
        let CborValue::Map(entries) = value else {
            return Err(CryptoError::UnsupportedCurve("COSE_Key is not a map".into()));
        };
        let get = |label: i64| {
            entries
                .iter()
                .find(|(k, _)| matches!(k, CborValue::Integer(i) if i128::from(*i) == label as i128))
                .map(|(_, v)| v)
        };
        let int_of = |label| match get(label) {
            Some(CborValue::Integer(i)) => Some(i128::from(*i)),
            _ => None,
        };
        let bytes_of = |label| match get(label) {
            Some(CborValue::Bytes(b)) => Some(b.clone()),
            _ => None,
        };
        let x = bytes_of(-2).ok_or(CryptoError::UnsupportedCurve("COSE_Key without x".into()))?;
        match (int_of(1), int_of(-1)) {
            (Some(1), Some(4)) => Self::from_public_bytes(Curve::X25519, &x),
            (Some(2), Some(crv @ (1 | 2))) => {
                let curve = if crv == 1 { Curve::P256 } else { Curve::P384 };
                let sec1 = match get(-3) {
                    Some(CborValue::Bytes(y)) => [&[0x04][..], &x, y].concat(),
                    Some(CborValue::Bool(odd)) => [&[if *odd { 0x03 } else { 0x02 }][..], &x].concat(),
                    _ => return Err(CryptoError::UnsupportedCurve("EC2 COSE_Key without y".into())),
                };
                Self::from_public_bytes(curve, &sec1)
            }
            (kty, crv) => Err(CryptoError::UnsupportedCurve(format!("COSE_Key kty {kty:?} crv {crv:?}"))),
        }
    }

    /// The raw ECDH shared secret `Z` with `other` (the x-coordinate, for NIST curves).
    pub fn ecdh(&self, other: &Self) -> Result<Vec<u8>, CryptoError> {
        same_curve!(self, other, |a, b| Ok(a.key_exchange_bytes(b)?.as_ref().to_vec()))
    }

    /// JOSE ECDH-ES key derivation (Concat KDF) of a 32-byte wrap key, between an
    /// ephemeral and a recipient key -- `receive` says which of the two holds a secret.
    pub(crate) fn ecdh_es_wrap_key(
        epk: &Self,
        recipient: &Self,
        alg: &[u8],
        apv: &[u8],
        receive: bool,
    ) -> Result<[u8; 32], CryptoError> {
        let mut out = [0u8; 32];
        same_curve!(epk, recipient, |e, r| EcdhEs::new(e, r, alg, b"", apv, receive).derive_key_bytes(&mut out)?);
        Ok(out)
    }

    /// JOSE ECDH-1PU key derivation of a 32-byte wrap key, binding the content tag.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn ecdh_1pu_wrap_key(
        epk: &Self,
        sender: &Self,
        recipient: &Self,
        alg: &[u8],
        apu: &[u8],
        apv: &[u8],
        tag: &[u8],
        receive: bool,
    ) -> Result<[u8; 32], CryptoError> {
        let mut out = [0u8; 32];
        match (epk, sender, recipient) {
            (Self::X25519(e), Self::X25519(s), Self::X25519(r)) => {
                Ecdh1PU::new(e, s, r, alg, apu, apv, tag, receive).derive_key_bytes(&mut out)?
            }
            (Self::P256(e), Self::P256(s), Self::P256(r)) => {
                Ecdh1PU::new(e, s, r, alg, apu, apv, tag, receive).derive_key_bytes(&mut out)?
            }
            (Self::P384(e), Self::P384(s), Self::P384(r)) => {
                Ecdh1PU::new(e, s, r, alg, apu, apv, tag, receive).derive_key_bytes(&mut out)?
            }
            (e, s, r) => {
                let other = if e.curve() != s.curve() { s } else { r };
                return Err(CryptoError::CurveMismatch(e.curve().name(), other.curve().name()));
            }
        }
        Ok(out)
    }

    pub(crate) fn has_secret(&self) -> bool {
        match self {
            Self::X25519(k) => k.with_secret_bytes(|b| b.is_some()),
            Self::P256(k) => k.with_secret_bytes(|b| b.is_some()),
            Self::P384(k) => k.with_secret_bytes(|b| b.is_some()),
        }
    }
}

/// The one curve every key in `keys` uses -- a single envelope can't mix them, since
/// its ephemeral key is shared by all recipients.
pub(crate) fn common_curve<'a>(keys: impl IntoIterator<Item = &'a AgreementKey>) -> Result<Curve, CryptoError> {
    let mut keys = keys.into_iter();
    let first = keys.next().ok_or(CryptoError::NoRecipients)?.curve();
    for key in keys {
        if key.curve() != first {
            return Err(CryptoError::CurveMismatch(first.name(), key.curve().name()));
        }
    }
    Ok(first)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cose_and_jwk_forms_round_trip_on_every_curve() {
        for curve in [Curve::X25519, Curve::P256, Curve::P384] {
            let key = AgreementKey::generate(curve).unwrap();
            let via_cose = AgreementKey::from_cose_key(&key.to_cose_key().unwrap()).unwrap();
            let via_jwk = AgreementKey::from_jwk(&key.to_jwk_public().unwrap()).unwrap();
            assert_eq!(via_cose.public_bytes(), key.public_bytes(), "{curve:?}");
            assert_eq!(via_jwk.public_bytes(), key.public_bytes(), "{curve:?}");
            assert!(!via_cose.has_secret());

            let other = AgreementKey::generate(curve).unwrap();
            assert_eq!(key.ecdh(&via_cose_of(&other)).unwrap(), other.ecdh(&via_cose_of(&key)).unwrap());
        }
    }

    fn via_cose_of(key: &AgreementKey) -> AgreementKey {
        AgreementKey::from_cose_key(&key.to_cose_key().unwrap()).unwrap()
    }

    #[test]
    fn mixing_curves_is_an_error() {
        let x = AgreementKey::generate(Curve::X25519).unwrap();
        let p = AgreementKey::generate(Curve::P384).unwrap();
        assert!(matches!(x.ecdh(&p), Err(CryptoError::CurveMismatch(..))));
        assert!(common_curve([&x, &p]).is_err());
    }

    #[test]
    fn an_off_curve_nist_point_is_rejected() {
        let key = AgreementKey::generate(Curve::P256).unwrap();
        let mut jwk = key.to_jwk_public().unwrap();
        let mut y = multibase::decode(jwk["y"].as_str().unwrap()).unwrap();
        y[31] ^= 1;
        jwk["y"] = Value::String(multibase::encode(y));
        assert!(AgreementKey::from_jwk(&jwk).is_err());
    }
}
