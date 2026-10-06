//! JWE envelope parsing, mirroring `didcomm_messaging.crypto.jwe`.
//!
//! Two JSON layouts are covered, matching the two `JweBuilder` configurations
//! `didcomm-messaging-python` actually uses:
//!
//! - The general ("recipients" array as a sibling field of the envelope) form, used by
//!   the v2 Askar backend (`JweBuilder(with_flatten_recipients=False)`) --
//!   [`JweEnvelope::from_json`]/[`to_json`](JweEnvelope::to_json).
//! - The "protected recipients" form, used by DIDComm v1's pack format
//!   (`JweBuilder(with_protected_recipients=True, with_flatten_recipients=False)`):
//!   the `recipients` array lives *inside* the decoded protected header instead --
//!   [`JweEnvelope::from_json_v1`]/[`to_json_v1`](JweEnvelope::to_json_v1).
//!
//! The flattened single-recipient form isn't covered -- neither of the above ever
//! produces it.
//!
//! JSON only: the `didcomm/v2+cbor` profile's encrypted envelope is a COSE_Encrypt
//! (see [`crate::cose`]), not a CBOR rendering of this one. [`peek_typ`] still reads
//! either, since callers use it on whatever arrived.

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
    #[error(transparent)]
    Cose(#[from] crate::cose::CoseError),
    #[error(transparent)]
    UnknownEncoding(#[from] crate::crypto::UnknownEncoding),
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

    /// The raw (decoded) `apu` (Agreement PartyUInfo) value from the protected header --
    /// only present for ECDH-1PU (authenticated encryption), where it carries the
    /// sender's kid.
    pub fn apu_bytes(&self) -> Result<Vec<u8>, JweError> {
        let apu = self
            .protected
            .get("apu")
            .and_then(Value::as_str)
            .ok_or(JweError::Invalid("missing apu header"))?;
        Ok(multibase::decode(apu)?)
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

    /// Parse a JWE using DIDComm v1's "protected recipients" layout: the `recipients`
    /// array lives inside the decoded protected header rather than as a sibling field
    /// of the envelope. Mirrors `JweEnvelope._deserialize`'s `IDENT_RECIPIENTS in
    /// protected` branch.
    pub fn from_json_v1(message: impl AsRef<[u8]>) -> Result<Self, JweError> {
        #[derive(Deserialize)]
        struct RawJweV1 {
            protected: String,
            iv: String,
            ciphertext: String,
            tag: String,
        }

        let raw: RawJweV1 = serde_json::from_slice(message.as_ref())?;
        let protected_bytes = multibase::decode(&raw.protected)?;
        let mut protected: Map<String, Value> = serde_json::from_slice(&protected_bytes)?;

        let recipients_json = protected
            .remove("recipients")
            .ok_or(JweError::Invalid("missing recipients in protected header"))?;
        let raw_recipients: Vec<RawRecipient> = serde_json::from_value(recipients_json)?;
        let recipients = raw_recipients
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
            aad: None,
        })
    }

    /// Serialize using DIDComm v1's "protected recipients" layout -- the inverse of
    /// [`from_json_v1`](Self::from_json_v1). Unlike [`to_json`](Self::to_json), there is
    /// no sibling `recipients` field: it's already embedded in `protected_b64`.
    pub fn to_json_v1(&self) -> Result<String, JweError> {
        let mut env = Map::new();
        env.insert("protected".into(), Value::String(self.protected_b64.clone()));
        env.insert("iv".into(), Value::String(multibase::encode(&self.iv)));
        env.insert(
            "ciphertext".into(),
            Value::String(multibase::encode(&self.ciphertext)),
        );
        env.insert("tag".into(), Value::String(multibase::encode(&self.tag)));
        Ok(serde_json::to_string(&Value::Object(env))?)
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

/// Reads the `typ` header out of a packed message's outer envelope without otherwise
/// parsing or validating it as a specific layout -- works equally for the v2 general
/// form, DIDComm v1's "protected recipients" form, a JWS, and (for the
/// `didcomm/v2+cbor` profile) a COSE_Encrypt or COSE_Sign1, whose `typ` is header
/// label 16. Dispatches on the first byte per #463's encoding detection rule
/// ([`Encoding::detect`](crate::crypto::Encoding::detect)).
///
/// `ecdh_es_encrypt`/`ecdh_1pu_encrypt` (`didcomm-crypto-askar`) set
/// `"application/didcomm-encrypted+json"`/`"application/didcomm+encrypted"` on JSON
/// envelopes (see `ecdh_1pu_encrypt`'s own comment on the latter), and
/// `"application/didcomm-encrypted+cbor"` on every COSE one; `didcomm-v1`'s packer
/// sets `"JWM/1.0"`. This is the one place that dispatch needs to happen for every
/// caller downstream (`wyvrn-mediator`'s `receive()`, `wyvrn-chat`'s `unpack()`) to
/// get it for free.
pub fn peek_typ(message: impl AsRef<[u8]>) -> Result<String, JweError> {
    let message = message.as_ref();
    match crate::crypto::Encoding::detect(message)? {
        crate::crypto::Encoding::Json => {
            #[derive(Deserialize)]
            struct RawEnvelopeProtected {
                protected: String,
            }
            let protected_b64 = match serde_json::from_slice::<RawEnvelopeProtected>(message) {
                Ok(raw) => raw.protected,
                // A general-form JWS keeps `protected` per signature.
                Err(_) => {
                    let value: Value = serde_json::from_slice(message)?;
                    value["signatures"][0]["protected"]
                        .as_str()
                        .ok_or(JweError::Invalid("missing protected field"))?
                        .to_string()
                }
            };
            let protected_bytes = multibase::decode(&protected_b64)?;
            let protected: Map<String, Value> = serde_json::from_slice(&protected_bytes)?;
            protected
                .get("typ")
                .and_then(Value::as_str)
                .map(str::to_string)
                .ok_or(JweError::Invalid("missing typ in protected header"))
        }
        crate::crypto::Encoding::Cbor => {
            use crate::cose::{classify, CoseEncrypt, CoseKind, CoseSign1};
            let typ = match classify(message)? {
                CoseKind::Encrypt => CoseEncrypt::from_cbor(message)?.typ().map(str::to_string),
                CoseKind::Sign1 => CoseSign1::from_cbor(message)?
                    .protected
                    .text(crate::cose::label::TYP)
                    .map(str::to_string),
                CoseKind::Plaintext => None,
            };
            typ.ok_or(JweError::Invalid("missing typ (label 16) in protected header"))
        }
    }
}

/// Base64url-encode a protected header, for building (not just parsing) an envelope.
/// The result is what both `JweEnvelope::protected_b64` and the AEAD's AAD must use.
pub fn encode_protected(protected: &Map<String, Value>) -> Result<String, JweError> {
    Ok(multibase::encode(serde_json::to_vec(&Value::Object(
        protected.clone(),
    ))?))
}

/// Base64url-encode a protected header for DIDComm v1's "protected recipients" layout:
/// `recipients` is embedded into a clone of `protected` before encoding, matching
/// `JweBuilder(with_protected_recipients=True).set_protected()`. `protected` itself is
/// left untouched -- callers keep using the clean (recipients-free) metadata for
/// `JweEnvelope::protected`, matching what [`JweEnvelope::from_json_v1`] hands back
/// after parsing.
pub fn encode_protected_v1(
    protected: &Map<String, Value>,
    recipients: &[JweRecipient],
) -> Result<String, JweError> {
    let mut protected = protected.clone();
    let recipients_json: Vec<Value> = recipients
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
        .collect();
    protected.insert("recipients".into(), Value::Array(recipients_json));
    Ok(multibase::encode(serde_json::to_vec(&Value::Object(
        protected,
    ))?))
}

#[cfg(test)]
mod tests {
    use super::*;

    // A real "Hello world!" ECDH-ES envelope, produced by didcomm-messaging-python's
    // AskarCryptoService -- see /fixtures/wire-compat for the generating script and the
    // matching decrypt test in didcomm-crypto-askar.
    const FIXTURE: &str = include_str!("../../../fixtures/wire-compat/hello_world_es.json");
    const FIXTURE_1PU: &str = include_str!("../../../fixtures/wire-compat/hello_world_1pu.json");
    const FIXTURE_V1: &str = include_str!("../../../fixtures/v1/fixture.json");

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

    #[test]
    fn peek_typ_reads_the_real_v2_anoncrypt_and_authcrypt_typ_values() {
        let es_fixture: Value = serde_json::from_str(FIXTURE).unwrap();
        let es_json = serde_json::to_string(&es_fixture["packed_jwe"]).unwrap();
        assert_eq!(peek_typ(es_json).unwrap(), "application/didcomm-encrypted+json");

        let pu_fixture: Value = serde_json::from_str(FIXTURE_1PU).unwrap();
        let pu_json = serde_json::to_string(&pu_fixture["packed_jwe"]).unwrap();
        assert_eq!(peek_typ(pu_json).unwrap(), "application/didcomm+encrypted");
    }

    #[test]
    fn peek_typ_reads_jwm_1_0_for_a_real_v1_envelope_of_either_alg() {
        let v1_fixture: Value = serde_json::from_str(FIXTURE_V1).unwrap();
        for alg in ["anoncrypt", "authcrypt"] {
            let json = serde_json::to_string(&v1_fixture[alg]).unwrap();
            assert_eq!(peek_typ(json).unwrap(), "JWM/1.0");
        }
    }

    #[test]
    fn peek_typ_rejects_a_message_with_no_protected_field_or_no_typ_at_all() {
        assert!(peek_typ(r#"{"not":"a jwe"}"#).is_err());
        let no_typ = multibase::encode(br#"{"alg":"ECDH-ES+A256KW"}"#);
        let body = format!(r#"{{"protected":"{no_typ}"}}"#);
        assert!(peek_typ(body).is_err());
    }
}
