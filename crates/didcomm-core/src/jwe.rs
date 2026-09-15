//! JWE envelope parsing, mirroring `didcomm_messaging.crypto.jwe`.
//!
//! This only covers the general ("recipients" array) JSON Serialization today, since
//! that's the only form `didcomm-messaging-python`'s Askar backend ever produces (it
//! always builds `JweBuilder(with_flatten_recipients=False)`). The flattened
//! single-recipient form, protected-recipients variant, and the `JweBuilder` (for
//! encrypting, not just decrypting) are follow-up work for a later milestone -- see
//! `didcomm_messaging/crypto/jwe.py` for the full shape being ported.

use didcomm_multiformats::multibase;
use serde::Deserialize;
use serde_json::{Map, Value};

/// Errors parsing a JWE envelope.
#[derive(Debug, thiserror::Error)]
pub enum JweError {
    #[error("invalid JWE JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid base64url in JWE: {0}")]
    Base64(#[from] multibase::DecodeError),
    #[error("invalid JWE: {0}")]
    Invalid(&'static str),
    #[error("unknown recipient: {0}")]
    UnknownRecipient(String),
}

/// One entry of the JWE `recipients` array.
#[derive(Debug, Clone)]
pub struct JweRecipient {
    pub encrypted_key: Vec<u8>,
    pub header: Map<String, Value>,
}

#[derive(Deserialize)]
struct RawRecipient {
    encrypted_key: String,
    #[serde(default)]
    header: Map<String, Value>,
}

#[derive(Deserialize)]
struct RawJwe {
    protected: String,
    #[serde(default)]
    recipients: Vec<RawRecipient>,
    iv: String,
    ciphertext: String,
    tag: String,
    #[serde(default)]
    aad: Option<String>,
}

/// A parsed DIDComm v2 JWE envelope, as produced by `ecdh_es_encrypt`/`ecdh_1pu_encrypt`.
#[derive(Debug, Clone)]
pub struct JweEnvelope {
    /// The protected header, base64url-encoded exactly as it appeared on the wire --
    /// this exact string (not the decoded bytes) is what goes into the AEAD's AAD.
    pub protected_b64: String,
    /// The protected header, decoded and parsed as JSON.
    pub protected: Map<String, Value>,
    pub recipients: Vec<JweRecipient>,
    pub iv: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub tag: Vec<u8>,
    pub aad: Option<Vec<u8>>,
}

impl JweEnvelope {
    /// Parse a JWE envelope from its JSON serialization.
    pub fn from_json(message: impl AsRef<[u8]>) -> Result<Self, JweError> {
        let raw: RawJwe = serde_json::from_slice(message.as_ref())?;

        let protected_bytes = multibase::decode(&raw.protected)?;
        let protected: Map<String, Value> = serde_json::from_slice(&protected_bytes)?;

        if raw.recipients.is_empty() {
            return Err(JweError::Invalid(
                "flattened (single-recipient) JWE form is not supported yet",
            ));
        }

        let recipients = raw
            .recipients
            .into_iter()
            .map(|r| {
                Ok(JweRecipient {
                    encrypted_key: multibase::decode(&r.encrypted_key)?,
                    header: r.header,
                })
            })
            .collect::<Result<Vec<_>, JweError>>()?;

        Ok(Self {
            protected_b64: raw.protected,
            protected,
            recipients,
            iv: multibase::decode(&raw.iv)?,
            ciphertext: multibase::decode(&raw.ciphertext)?,
            tag: multibase::decode(&raw.tag)?,
            aad: raw.aad.map(|a| multibase::decode(&a)).transpose()?,
        })
    }

    /// The additional authenticated data covering the AEAD payload: the ASCII bytes of
    /// the base64url-encoded protected header, plus an optional detached `aad` value.
    pub fn combined_aad(&self) -> Vec<u8> {
        let mut aad = self.protected_b64.clone().into_bytes();
        if let Some(extra) = &self.aad {
            aad.push(b'.');
            aad.extend_from_slice(multibase::encode(extra).as_bytes());
        }
        aad
    }

    /// The raw (decoded) `apv` (Agreement PartyVInfo) value from the protected header.
    pub fn apv_bytes(&self) -> Result<Vec<u8>, JweError> {
        let apv = self
            .protected
            .get("apv")
            .and_then(Value::as_str)
            .ok_or(JweError::Invalid("missing apv header"))?;
        Ok(multibase::decode(apv)?)
    }

    /// Find a recipient by `kid`, with the recipient's own headers merged over the
    /// envelope's protected headers (matching `JweEnvelope.get_recipient` in Python).
    pub fn get_recipient(&self, kid: &str) -> Result<JweRecipient, JweError> {
        for recip in &self.recipients {
            if recip.header.get("kid").and_then(Value::as_str) == Some(kid) {
                let mut header: Map<String, Value> = self.protected.clone();
                header.extend(recip.header.clone());
                return Ok(JweRecipient {
                    encrypted_key: recip.encrypted_key.clone(),
                    header,
                });
            }
        }
        Err(JweError::UnknownRecipient(kid.to_string()))
    }

    /// The `kid` of every recipient, for looking up a matching secret key.
    pub fn recipient_key_ids(&self) -> impl Iterator<Item = &str> {
        self.recipients
            .iter()
            .filter_map(|r| r.header.get("kid").and_then(Value::as_str))
    }

    /// Serialize back to the general ("recipients" array) JSON form, matching
    /// `JweEnvelope.serialize()`/`to_json()` in Python. Field order doesn't need to match
    /// what Python would produce for the same inputs -- a decoder only needs the field
    /// values, not a canonical byte-for-byte layout -- so this doesn't try to reproduce
    /// Python's `OrderedDict` ordering.
    pub fn to_json(&self) -> Result<String, JweError> {
        let mut env = Map::new();
        env.insert("protected".into(), Value::String(self.protected_b64.clone()));
        env.insert(
            "recipients".into(),
            Value::Array(
                self.recipients
                    .iter()
                    .map(|r| {
                        let mut m = Map::new();
                        m.insert(
                            "encrypted_key".into(),
                            Value::String(multibase::encode(&r.encrypted_key)),
                        );
                        if !r.header.is_empty() {
                            m.insert("header".into(), Value::Object(r.header.clone()));
                        }
                        Value::Object(m)
                    })
                    .collect(),
            ),
        );
        env.insert("iv".into(), Value::String(multibase::encode(&self.iv)));
        env.insert(
            "ciphertext".into(),
            Value::String(multibase::encode(&self.ciphertext)),
        );
        env.insert("tag".into(), Value::String(multibase::encode(&self.tag)));
        if let Some(aad) = &self.aad {
            env.insert("aad".into(), Value::String(multibase::encode(aad)));
        }
        Ok(serde_json::to_string(&Value::Object(env))?)
    }
}

/// Base64url-encode a protected header, for building (not just parsing) an envelope.
/// The result is what both `JweEnvelope::protected_b64` and the AEAD's AAD must use.
pub fn encode_protected(protected: &Map<String, Value>) -> Result<String, JweError> {
    Ok(multibase::encode(serde_json::to_vec(&Value::Object(
        protected.clone(),
    ))?))
}

#[cfg(test)]
mod tests {
    use super::*;

    // A real "Hello world!" ECDH-ES envelope, produced by didcomm-messaging-python's
    // AskarCryptoService -- see /fixtures/wire-compat for the generating script and the
    // matching decrypt test in didcomm-crypto-askar.
    const FIXTURE: &str = include_str!("../../../fixtures/wire-compat/hello_world_es.json");

    #[test]
    fn parses_a_real_python_produced_envelope() {
        let fixture: Value = serde_json::from_str(FIXTURE).unwrap();
        let jwe_json = serde_json::to_string(&fixture["packed_jwe"]).unwrap();

        let jwe = JweEnvelope::from_json(jwe_json).unwrap();
        assert_eq!(jwe.protected["alg"], "ECDH-ES+A256KW");
        assert_eq!(jwe.protected["enc"], "XC20P");
        assert_eq!(
            jwe.recipient_key_ids().collect::<Vec<_>>(),
            vec![fixture["recipient_kid"].as_str().unwrap()]
        );
        assert!(jwe.apv_bytes().is_ok());
    }
}
