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
//! A third, wyvrn-original layout -- [`JweEnvelope::to_cbor`]/[`from_cbor`](JweEnvelope::from_cbor)
//! -- covers the same general-form shape as `to_json`/`from_json`, CBOR-encoded instead
//! of JSON, with `iv`/`ciphertext`/`tag`/`recipients[].encrypted_key`/`aad` as real CBOR
//! byte strings rather than base64url text (the actual point of using it: no ~33%
//! base64 blowup on top of the ciphertext, encrypted key, and other binary fields).
//! `protected` stays base64url text either way -- it's the exact ASCII bytes that feed
//! the AEAD's AAD ([`JweEnvelope::combined_aad`]), so its *encoding* can't change
//! independently of the cryptography, only the envelope wrapping it.

use ciborium::Value as CborValue;
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
    #[error("invalid CBOR JWE envelope: {0}")]
    CborDecode(String),
    #[error("failed to encode a CBOR JWE envelope: {0}")]
    CborEncode(String),
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
    /// Parse a v2/v3/v4 (general-form) envelope of either encoding, sniffing which one
    /// from the message's first byte exactly as [`peek_typ`] does: `{` means
    /// [`from_json`](Self::from_json), anything else is attempted as
    /// [`from_cbor`](Self::from_cbor). This is the entry point real callers
    /// (`PackagingService::extract_packed_message_metadata`, and so every real unpack
    /// path) use instead of committing to one encoding up front -- a received message
    /// carries no separate out-of-band indicator of which one it is.
    pub fn from_encoded(message: impl AsRef<[u8]>) -> Result<Self, JweError> {
        let message = message.as_ref();
        if message.first() == Some(&b'{') {
            Self::from_json(message)
        } else {
            Self::from_cbor(message)
        }
    }

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

    /// Parse a JWE envelope from the `didcomm/v2+cbor` general-form CBOR encoding (see
    /// this module's own docs) -- the CBOR analog of [`from_json`](Self::from_json).
    pub fn from_cbor(message: impl AsRef<[u8]>) -> Result<Self, JweError> {
        let value: CborValue = ciborium::from_reader(message.as_ref())
            .map_err(|e| JweError::CborDecode(e.to_string()))?;
        let entries = cbor_map(&value).ok_or(JweError::Invalid("CBOR JWE envelope must be a map"))?;

        let protected_b64 = match cbor_get(entries, "protected") {
            Some(CborValue::Text(s)) => s.clone(),
            _ => return Err(JweError::Invalid("missing or invalid protected field")),
        };
        let protected_bytes = multibase::decode(&protected_b64)?;
        let protected: Map<String, Value> = serde_json::from_slice(&protected_bytes)?;

        let recipients = match cbor_get(entries, "recipients") {
            Some(CborValue::Array(items)) if !items.is_empty() => items
                .iter()
                .map(cbor_recipient)
                .collect::<Result<Vec<_>, JweError>>()?,
            _ => {
                return Err(JweError::Invalid(
                    "flattened (single-recipient) JWE form is not supported yet",
                ))
            }
        };

        let iv = cbor_bytes(entries, "iv")?;
        let ciphertext = cbor_bytes(entries, "ciphertext")?;
        let tag = cbor_bytes(entries, "tag")?;
        let aad = match cbor_get(entries, "aad") {
            Some(CborValue::Bytes(b)) => Some(b.clone()),
            Some(_) => return Err(JweError::Invalid("invalid aad field")),
            None => None,
        };

        Ok(Self {
            protected_b64,
            protected,
            recipients,
            iv,
            ciphertext,
            tag,
            aad,
        })
    }

    /// Serialize to the `didcomm/v2+cbor` general-form CBOR encoding (see this module's
    /// own docs) -- the CBOR analog of [`to_json`](Self::to_json), with binary fields as
    /// real CBOR byte strings instead of base64url text.
    pub fn to_cbor(&self) -> Result<Vec<u8>, JweError> {
        let recipients = self
            .recipients
            .iter()
            .map(|r| {
                let mut entry = vec![(
                    CborValue::Text("encrypted_key".into()),
                    CborValue::Bytes(r.encrypted_key.clone()),
                )];
                if !r.header.is_empty() {
                    let header = CborValue::serialized(&r.header)
                        .map_err(|e| JweError::CborEncode(e.to_string()))?;
                    entry.push((CborValue::Text("header".into()), header));
                }
                Ok(CborValue::Map(entry))
            })
            .collect::<Result<Vec<_>, JweError>>()?;

        let mut env = vec![
            (
                CborValue::Text("protected".into()),
                CborValue::Text(self.protected_b64.clone()),
            ),
            (CborValue::Text("recipients".into()), CborValue::Array(recipients)),
            (CborValue::Text("iv".into()), CborValue::Bytes(self.iv.clone())),
            (
                CborValue::Text("ciphertext".into()),
                CborValue::Bytes(self.ciphertext.clone()),
            ),
            (CborValue::Text("tag".into()), CborValue::Bytes(self.tag.clone())),
        ];
        if let Some(aad) = &self.aad {
            env.push((CborValue::Text("aad".into()), CborValue::Bytes(aad.clone())));
        }

        let mut bytes = Vec::new();
        ciborium::into_writer(&CborValue::Map(env), &mut bytes)
            .map_err(|e| JweError::CborEncode(e.to_string()))?;
        Ok(bytes)
    }
}

/// Look up a text-keyed entry in a CBOR map's raw `(key, value)` pairs, mirroring how
/// `serde_json::Map::get` works for the JSON encoding's equivalent object -- CBOR maps
/// have no such by-key lookup of their own since keys aren't restricted to text.
fn cbor_get<'a>(entries: &'a [(CborValue, CborValue)], key: &str) -> Option<&'a CborValue> {
    entries
        .iter()
        .find(|(k, _)| matches!(k, CborValue::Text(t) if t == key))
        .map(|(_, v)| v)
}

fn cbor_map(value: &CborValue) -> Option<&[(CborValue, CborValue)]> {
    match value {
        CborValue::Map(entries) => Some(entries),
        _ => None,
    }
}

fn cbor_bytes(entries: &[(CborValue, CborValue)], key: &'static str) -> Result<Vec<u8>, JweError> {
    match cbor_get(entries, key) {
        Some(CborValue::Bytes(b)) => Ok(b.clone()),
        _ => Err(JweError::Invalid(match key {
            "iv" => "missing or invalid iv field",
            "ciphertext" => "missing or invalid ciphertext field",
            "tag" => "missing or invalid tag field",
            _ => "missing or invalid field",
        })),
    }
}

fn cbor_recipient(value: &CborValue) -> Result<JweRecipient, JweError> {
    let entries = cbor_map(value).ok_or(JweError::Invalid("invalid recipient entry"))?;
    let encrypted_key = match cbor_get(entries, "encrypted_key") {
        Some(CborValue::Bytes(b)) => b.clone(),
        _ => return Err(JweError::Invalid("missing or invalid encrypted_key field")),
    };
    let header = match cbor_get(entries, "header") {
        Some(h) => h.deserialized().map_err(|e| JweError::CborDecode(e.to_string()))?,
        None => Map::new(),
    };
    Ok(JweRecipient { encrypted_key, header })
}

/// Reads the JOSE `typ` header out of a packed message's decoded protected header,
/// without otherwise parsing or validating it as a specific JWE layout -- works
/// equally for the v2 general form and DIDComm v1's "protected recipients" form,
/// since both carry a plain top-level `protected` field the same way (only where
/// `recipients` lives differs between them, which this never looks at, unlike
/// [`JweEnvelope::from_json`]/[`from_json_v1`](JweEnvelope::from_json_v1) which
/// each commit to one specific layout).
///
/// This is how a caller is meant to tell a v2/v3/v4 message from a legacy v1 one
/// *before* deciding which parser to even attempt (not an HTTP `Content-Type`
/// header, which nothing about the DIDComm wire format itself depends on).
/// `ecdh_es_encrypt`/ `ecdh_1pu_encrypt` (`didcomm-crypto-askar`) set `typ` to
/// `"application/didcomm-encrypted+json"`/`"application/didcomm+encrypted"`
/// (or their `+cbor` counterparts, when packed as `didcomm/v2+cbor`) respectively;
/// `didcomm-v1`'s packer sets it to `"JWM/1.0"`.
///
/// Transparently handles either outer envelope encoding via [`peek_protected_b64`]'s
/// "first byte" sniff -- a JSON envelope always starts with `{`, so anything else is
/// attempted as CBOR instead. This is the one place that dispatch needs to happen for
/// every caller downstream (`wyvrn-mediator`'s `receive()`, `wyvrn-chat`'s `unpack()`)
/// to get it for free.
pub fn peek_typ(message: impl AsRef<[u8]>) -> Result<String, JweError> {
    let protected_b64 = peek_protected_b64(message.as_ref())?;
    let protected_bytes = multibase::decode(&protected_b64)?;
    let protected: Map<String, Value> = serde_json::from_slice(&protected_bytes)?;
    protected
        .get("typ")
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or(JweError::Invalid("missing typ header"))
}

/// Extracts just the base64url-encoded `protected` header string from a packed
/// message's outer envelope, without otherwise parsing or committing to one specific
/// JWE layout. Dispatches on the message's first byte: `{` means JSON (this workspace's
/// only encoding until `didcomm/v2+cbor` existed), anything else is attempted as CBOR --
/// nothing about the DIDComm wire format carries an out-of-band content-type the way an
/// HTTP header would, so the bytes have to speak for themselves.
fn peek_protected_b64(message: &[u8]) -> Result<String, JweError> {
    if message.first() == Some(&b'{') {
        #[derive(Deserialize)]
        struct RawEnvelopeProtected {
            protected: String,
        }
        let raw: RawEnvelopeProtected = serde_json::from_slice(message)?;
        return Ok(raw.protected);
    }
    let value: CborValue =
        ciborium::from_reader(message).map_err(|e| JweError::CborDecode(e.to_string()))?;
    let entries = cbor_map(&value).ok_or(JweError::Invalid("CBOR JWE envelope must be a map"))?;
    match cbor_get(entries, "protected") {
        Some(CborValue::Text(s)) => Ok(s.clone()),
        _ => Err(JweError::Invalid("missing or invalid protected field")),
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

    #[test]
    fn cbor_round_trips_a_real_python_produced_envelope() {
        // Real crypto-produced data (not a synthetic envelope), parsed from JSON,
        // re-encoded as CBOR, and parsed back -- every field, binary or not, must
        // survive the round trip unchanged.
        let fixture: Value = serde_json::from_str(FIXTURE).unwrap();
        let jwe_json = serde_json::to_string(&fixture["packed_jwe"]).unwrap();
        let original = JweEnvelope::from_json(jwe_json).unwrap();

        let cbor_bytes = original.to_cbor().unwrap();
        let round_tripped = JweEnvelope::from_cbor(&cbor_bytes).unwrap();

        assert_eq!(round_tripped.protected_b64, original.protected_b64);
        assert_eq!(round_tripped.protected, original.protected);
        assert_eq!(round_tripped.iv, original.iv);
        assert_eq!(round_tripped.ciphertext, original.ciphertext);
        assert_eq!(round_tripped.tag, original.tag);
        assert_eq!(round_tripped.aad, original.aad);
        assert_eq!(round_tripped.recipients.len(), original.recipients.len());
        for (a, b) in round_tripped.recipients.iter().zip(&original.recipients) {
            assert_eq!(a.encrypted_key, b.encrypted_key);
            assert_eq!(a.header, b.header);
        }
        // combined_aad depends only on protected_b64/aad, both already asserted equal
        // above, but exercised directly here since it's the value crypto actually signs
        // over -- a subtly wrong round trip that happened to leave the asserted fields
        // superficially equal wouldn't be caught otherwise.
        assert_eq!(round_tripped.combined_aad(), original.combined_aad());
    }

    #[test]
    fn cbor_envelope_uses_real_byte_strings_not_base64_text_for_binary_fields() {
        // The actual point of the CBOR profile: iv/ciphertext/tag/encrypted_key must be
        // genuine CBOR byte strings, not base64url text re-wrapped in CBOR -- decoded
        // here with plain ciborium (not JweEnvelope::from_cbor) to check the wire shape
        // itself, independent of whether this crate's own decoder is lenient about it.
        let fixture: Value = serde_json::from_str(FIXTURE).unwrap();
        let jwe_json = serde_json::to_string(&fixture["packed_jwe"]).unwrap();
        let envelope = JweEnvelope::from_json(jwe_json).unwrap();
        let cbor_bytes = envelope.to_cbor().unwrap();

        let value: CborValue = ciborium::from_reader(cbor_bytes.as_slice()).unwrap();
        let entries = cbor_map(&value).unwrap();
        assert!(matches!(cbor_get(entries, "iv"), Some(CborValue::Bytes(_))));
        assert!(matches!(cbor_get(entries, "ciphertext"), Some(CborValue::Bytes(_))));
        assert!(matches!(cbor_get(entries, "tag"), Some(CborValue::Bytes(_))));
        assert!(matches!(cbor_get(entries, "protected"), Some(CborValue::Text(_))));

        let CborValue::Array(recipients) = cbor_get(entries, "recipients").unwrap() else {
            panic!("recipients must be a CBOR array");
        };
        let recipient_entries = cbor_map(&recipients[0]).unwrap();
        assert!(matches!(
            cbor_get(recipient_entries, "encrypted_key"),
            Some(CborValue::Bytes(_))
        ));
    }

    #[test]
    fn peek_typ_and_from_encoded_recognize_a_cbor_envelope_by_its_first_byte() {
        let fixture: Value = serde_json::from_str(FIXTURE).unwrap();
        let jwe_json = serde_json::to_string(&fixture["packed_jwe"]).unwrap();
        let envelope = JweEnvelope::from_json(jwe_json).unwrap();
        let cbor_bytes = envelope.to_cbor().unwrap();

        // A JSON envelope always starts with '{' (0x7b); a CBOR map of this envelope's
        // shape (5-6 text keys) never does -- it's a definite-length-map major-type byte
        // in the 0xa5-0xa6 range.
        assert_ne!(cbor_bytes[0], b'{');

        assert_eq!(peek_typ(&cbor_bytes).unwrap(), "application/didcomm-encrypted+json");
        let via_dispatch = JweEnvelope::from_encoded(&cbor_bytes).unwrap();
        assert_eq!(via_dispatch.ciphertext, envelope.ciphertext);
    }
}
