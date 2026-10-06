//! An encrypted DIDComm v2 envelope of either encoding -- a JWE ([`crate::jwe`]) or a
//! COSE_Encrypt ([`crate::cose`]) -- behind one read-only view of the header values
//! `PackagingService` validates before decrypting (algorithm, recipient kids, `apv`,
//! `apu`, `skid`). The two carry the same information under different names: see the
//! `cose` module docs for the label mapping.

use serde_json::Value;

use crate::cose::{label, Alg, CoseEncrypt};
use crate::crypto::Encoding;
use crate::jwe::{JweEnvelope, JweError};

/// A parsed encrypted envelope.
#[derive(Debug, Clone)]
pub enum EncryptedEnvelope {
    Jwe(JweEnvelope),
    Cose(CoseEncrypt),
}

impl EncryptedEnvelope {
    /// Parse either encoding, chosen by [`Encoding::detect`].
    pub fn from_encoded(message: &[u8]) -> Result<Self, JweError> {
        Ok(match Encoding::detect(message)? {
            Encoding::Json => Self::Jwe(JweEnvelope::from_json(message)?),
            Encoding::Cbor => Self::Cose(CoseEncrypt::from_cbor(message)?),
        })
    }

    pub fn encoding(&self) -> Encoding {
        match self {
            Self::Jwe(_) => Encoding::Json,
            Self::Cose(_) => Encoding::Cbor,
        }
    }

    /// The key-agreement algorithm as a JWA name (`ECDH-ES+A256KW`,
    /// `ECDH-1PU+A256KW`, ...): the JWE protected `alg`, or a COSE recipient's `alg`.
    /// COSE recipients must all agree, since the envelope has one sender and one mode.
    pub fn key_agreement_alg(&self) -> Option<String> {
        match self {
            Self::Jwe(jwe) => jwe.protected.get("alg").and_then(Value::as_str).map(str::to_string),
            Self::Cose(cose) => {
                let mut algs = cose.recipients.iter().map(|r| r.protected.alg());
                let first = algs.next()??;
                algs.all(|a| a == Some(first)).then(|| first.jwa_name().to_string())
            }
        }
    }

    /// Every recipient's `kid`, in wire order.
    pub fn recipient_key_ids(&self) -> Vec<String> {
        match self {
            Self::Jwe(jwe) => jwe.recipient_key_ids().map(str::to_string).collect(),
            Self::Cose(cose) => cose.recipients.iter().filter_map(|r| r.kid()).collect(),
        }
    }

    /// Every distinct `apv` the envelope carries: one for a JWE (protected header),
    /// one per recipient for COSE -- a well-formed envelope has exactly one value.
    pub fn apv_values(&self) -> Result<Vec<Vec<u8>>, JweError> {
        match self {
            Self::Jwe(jwe) => Ok(vec![jwe.apv_bytes()?]),
            Self::Cose(cose) => {
                let mut values: Vec<Vec<u8>> = Vec::new();
                for r in &cose.recipients {
                    let apv = r
                        .protected
                        .bytes(label::PARTY_V_IDENTITY)
                        .ok_or(JweError::Invalid("missing PartyV identity (apv) header"))?;
                    if !values.iter().any(|v| v == apv) {
                        values.push(apv.to_vec());
                    }
                }
                Ok(values)
            }
        }
    }

    /// `apu` (the sender kid's bytes), for ECDH-1PU -- every COSE recipient must carry
    /// the same one.
    pub fn apu_bytes(&self) -> Result<Vec<u8>, JweError> {
        match self {
            Self::Jwe(jwe) => jwe.apu_bytes(),
            Self::Cose(cose) => common(cose, |r| r.protected.bytes(label::PARTY_U_IDENTITY).map(<[u8]>::to_vec))
                .ok_or(JweError::Invalid("missing or inconsistent PartyU identity (apu) header")),
        }
    }

    /// `skid` (JWE) / `static key id` (COSE), if present.
    pub fn skid(&self) -> Option<String> {
        match self {
            Self::Jwe(jwe) => jwe.protected.get("skid").and_then(Value::as_str).map(str::to_string),
            Self::Cose(cose) => common(cose, |r| r.protected.kid_str(label::STATIC_KEY_ID)),
        }
    }

    /// The COSE content-encryption algorithm, if this is a COSE envelope.
    pub fn cose_content_alg(&self) -> Option<Alg> {
        match self {
            Self::Jwe(_) => None,
            Self::Cose(cose) => cose.content_alg(),
        }
    }
}

/// The value every COSE recipient agrees on, or `None` if any is missing or differs.
fn common<T: PartialEq>(cose: &CoseEncrypt, get: impl Fn(&crate::cose::CoseRecipient) -> Option<T>) -> Option<T> {
    let mut values = cose.recipients.iter().map(get);
    let first = values.next()??;
    for v in values {
        if v.as_ref() != Some(&first) {
            return None;
        }
    }
    Some(first)
}
