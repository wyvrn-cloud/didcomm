//! Plaintext message encoding: `application/didcomm-plain+json` or, for the
//! `didcomm/v2+cbor` profile, `application/didcomm-plain+cbor` -- "a CBOR mapping of
//! the same structure" (#463), with the same keys and value types.
//!
//! Messages are handled everywhere in this workspace as `serde_json::Value` (the
//! *JSON view*), whichever encoding they travel in. The two encodings differ in one
//! place: CBOR has a native byte string, JSON doesn't. The mapping between them:
//!
//! - CBOR -> JSON view: a byte string anywhere becomes its unpadded base64url text.
//! - JSON view -> CBOR: an attachment's `data.cbor` (base64url text in the JSON view)
//!   becomes a real byte string -- the one field this profile defines as binary.
//! - JSON view -> JSON wire: `data.cbor` is renamed to the spec's standard
//!   `data.base64` (same base64url value), since plain DIDComm v2 has no `data.cbor`.
//!
//! So code building a message (a `routing/2.0/forward`, a pickup `delivery`) that
//! carries an already-packed CBOR message just puts its base64url in `data.cbor`, and
//! it lands as raw bytes in a CBOR plaintext and as `data.base64` in a JSON one. Code
//! reading one should accept `data.cbor`, `data.base64` and `data.json` (see
//! [`attachment_bytes`]).

use ciborium::value::Integer;
use ciborium::Value as CborValue;
use didcomm_multiformats::multibase;
use serde_json::{Map, Number, Value};

use crate::crypto::Encoding;

pub const PLAIN_JSON_TYP: &str = "application/didcomm-plain+json";
pub const PLAIN_CBOR_TYP: &str = "application/didcomm-plain+cbor";

/// Errors encoding or decoding a plaintext message.
#[derive(Debug, thiserror::Error)]
pub enum PlaintextError {
    #[error("invalid plaintext JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid plaintext CBOR: {0}")]
    Cbor(String),
    #[error("invalid data.cbor attachment: not base64url")]
    AttachmentBase64,
    #[error("unrecognized message encoding (first byte {0:#04x})")]
    UnknownEncoding(u8),
}

/// Serialize a message in the given plaintext `encoding`. A top-level `typ` naming a
/// DIDComm plaintext media type is rewritten to match the encoding actually used.
pub fn encode(message: &Value, encoding: Encoding) -> Result<Vec<u8>, PlaintextError> {
    let mut message = message.clone();
    if let Some(Value::String(typ)) = message.get_mut("typ") {
        if typ == PLAIN_JSON_TYP || typ == PLAIN_CBOR_TYP {
            *typ = match encoding {
                Encoding::Json => PLAIN_JSON_TYP,
                Encoding::Cbor => PLAIN_CBOR_TYP,
            }
            .to_string();
        }
    }
    match encoding {
        Encoding::Json => {
            rename_cbor_attachments_to_base64(&mut message);
            Ok(serde_json::to_vec(&message)?)
        }
        Encoding::Cbor => {
            let value = json_to_cbor(&message, false)?;
            let mut out = Vec::new();
            ciborium::into_writer(&value, &mut out).map_err(|e| PlaintextError::Cbor(e.to_string()))?;
            Ok(out)
        }
    }
}

/// Parse a plaintext message of either encoding into its JSON view, also reporting
/// which encoding it was.
pub fn decode(bytes: &[u8]) -> Result<(Value, Encoding), PlaintextError> {
    match Encoding::detect(bytes).map_err(|_| PlaintextError::UnknownEncoding(bytes.first().copied().unwrap_or(0)))? {
        Encoding::Json => Ok((serde_json::from_slice(bytes)?, Encoding::Json)),
        Encoding::Cbor => {
            let value: CborValue = ciborium::from_reader(bytes).map_err(|e| PlaintextError::Cbor(e.to_string()))?;
            Ok((cbor_to_json(&value)?, Encoding::Cbor))
        }
    }
}

/// The payload bytes of an attachment, from `data.cbor`, `data.base64` (both base64 in
/// the JSON view; either alphabet, padded or not) or `data.json` (re-serialized as JSON).
pub fn attachment_bytes(attachment: &Value) -> Option<Vec<u8>> {
    let data = &attachment["data"];
    if let Some(b64) = data["cbor"].as_str().or_else(|| data["base64"].as_str()) {
        // Lenient: base64url or standard alphabet, padded or not -- other senders vary.
        let normalized: String = b64.chars().filter(|c| *c != '=').map(|c| match c {
            '+' => '-',
            '/' => '_',
            c => c,
        }).collect();
        return multibase::decode(normalized).ok();
    }
    if data["json"].is_object() {
        return serde_json::to_vec(&data["json"]).ok();
    }
    None
}

/// An attachment `data` object for an already-packed DIDComm message: `{"json": ...}`
/// for a JSON one, `{"cbor": <base64url>}` for a CBOR one (see the module docs for how
/// that serializes).
pub fn packed_message_attachment_data(packed: &[u8]) -> Result<(&'static str, Value), PlaintextError> {
    match Encoding::detect(packed).map_err(|_| PlaintextError::UnknownEncoding(packed.first().copied().unwrap_or(0)))? {
        Encoding::Json => Ok(("application/didcomm-encrypted+json", serde_json::json!({ "json": serde_json::from_slice::<Value>(packed)? }))),
        Encoding::Cbor => Ok(("application/didcomm-encrypted+cbor", serde_json::json!({ "cbor": multibase::encode(packed) }))),
    }
}

fn rename_cbor_attachments_to_base64(message: &mut Value) {
    let Some(Value::Array(attachments)) = message.get_mut("attachments") else {
        return;
    };
    for attachment in attachments {
        if let Some(Value::Object(data)) = attachment.get_mut("data") {
            if let Some(cbor) = data.remove("cbor") {
                data.entry("base64").or_insert(cbor);
            }
        }
    }
}

fn json_to_cbor(value: &Value, in_attachment_data: bool) -> Result<CborValue, PlaintextError> {
    Ok(match value {
        Value::Null => CborValue::Null,
        Value::Bool(b) => CborValue::Bool(*b),
        Value::Number(n) => {
            if let Some(u) = n.as_u64() {
                CborValue::Integer(Integer::from(u))
            } else if let Some(i) = n.as_i64() {
                CborValue::Integer(Integer::from(i))
            } else {
                CborValue::Float(n.as_f64().unwrap_or(f64::NAN))
            }
        }
        Value::String(s) => CborValue::Text(s.clone()),
        Value::Array(items) => {
            CborValue::Array(items.iter().map(|v| json_to_cbor(v, false)).collect::<Result<_, _>>()?)
        }
        Value::Object(map) => CborValue::Map(
            map.iter()
                .map(|(k, v)| {
                    let v = if in_attachment_data && k == "cbor" {
                        let b64 = v.as_str().ok_or(PlaintextError::AttachmentBase64)?;
                        CborValue::Bytes(multibase::decode(b64).map_err(|_| PlaintextError::AttachmentBase64)?)
                    } else if k == "attachments" {
                        attachments_to_cbor(v)?
                    } else {
                        json_to_cbor(v, false)?
                    };
                    Ok((CborValue::Text(k.clone()), v))
                })
                .collect::<Result<_, PlaintextError>>()?,
        ),
    })
}

/// `attachments` is the one place `data.cbor` is special-cased.
fn attachments_to_cbor(value: &Value) -> Result<CborValue, PlaintextError> {
    let Value::Array(items) = value else {
        return json_to_cbor(value, false);
    };
    Ok(CborValue::Array(
        items
            .iter()
            .map(|attachment| match attachment {
                Value::Object(fields) => Ok(CborValue::Map(
                    fields
                        .iter()
                        .map(|(k, v)| Ok((CborValue::Text(k.clone()), json_to_cbor(v, k == "data")?)))
                        .collect::<Result<_, PlaintextError>>()?,
                )),
                other => json_to_cbor(other, false),
            })
            .collect::<Result<_, _>>()?,
    ))
}

fn cbor_to_json(value: &CborValue) -> Result<Value, PlaintextError> {
    Ok(match value {
        CborValue::Null => Value::Null,
        CborValue::Bool(b) => Value::Bool(*b),
        CborValue::Integer(i) => {
            let i = i128::from(*i);
            if let Ok(u) = u64::try_from(i) {
                Value::Number(u.into())
            } else if let Ok(s) = i64::try_from(i) {
                Value::Number(s.into())
            } else {
                return Err(PlaintextError::Cbor("integer out of range".into()));
            }
        }
        CborValue::Float(f) => Number::from_f64(*f).map(Value::Number).unwrap_or(Value::Null),
        CborValue::Text(s) => Value::String(s.clone()),
        CborValue::Bytes(b) => Value::String(multibase::encode(b)),
        CborValue::Array(items) => Value::Array(items.iter().map(cbor_to_json).collect::<Result<_, _>>()?),
        CborValue::Map(entries) => {
            let mut map = Map::new();
            for (k, v) in entries {
                let CborValue::Text(k) = k else {
                    return Err(PlaintextError::Cbor("plaintext map keys must be text".into()));
                };
                map.insert(k.clone(), cbor_to_json(v)?);
            }
            Value::Object(map)
        }
        CborValue::Tag(_, inner) => cbor_to_json(inner)?,
        _ => return Err(PlaintextError::Cbor("unsupported CBOR value".into())),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn forward_with_cbor_attachment() -> Value {
        json!({
            "typ": PLAIN_JSON_TYP,
            "type": "https://didcomm.org/routing/2.0/forward",
            "id": "1",
            "to": ["did:example:mediator"],
            "created_time": 1_700_000_000u64,
            "body": {"next": "did:example:bob"},
            "attachments": [{
                "id": "a",
                "media_type": "application/didcomm-encrypted+cbor",
                "data": {"cbor": multibase::encode([0xd8, 0x60, 0x84, 0x00])},
            }],
        })
    }

    #[test]
    fn cbor_plaintext_carries_data_cbor_as_raw_bytes_and_round_trips() {
        let message = forward_with_cbor_attachment();
        let bytes = encode(&message, Encoding::Cbor).unwrap();
        assert!((0xa0..=0xbf).contains(&bytes[0]), "a CBOR map");

        let raw: CborValue = ciborium::from_reader(bytes.as_slice()).unwrap();
        let CborValue::Map(top) = &raw else { panic!() };
        let attachments = &top.iter().find(|(k, _)| k == &CborValue::Text("attachments".into())).unwrap().1;
        let CborValue::Array(attachments) = attachments else { panic!() };
        let CborValue::Map(att) = &attachments[0] else { panic!() };
        let data = &att.iter().find(|(k, _)| k == &CborValue::Text("data".into())).unwrap().1;
        let CborValue::Map(data) = data else { panic!() };
        assert_eq!(data[0], (CborValue::Text("cbor".into()), CborValue::Bytes(vec![0xd8, 0x60, 0x84, 0x00])));

        let (decoded, encoding) = decode(&bytes).unwrap();
        assert_eq!(encoding, Encoding::Cbor);
        assert_eq!(decoded["typ"], PLAIN_CBOR_TYP);
        assert_eq!(decoded["attachments"][0]["data"], message["attachments"][0]["data"]);
        assert_eq!(decoded["created_time"], 1_700_000_000u64);
        assert_eq!(attachment_bytes(&decoded["attachments"][0]).unwrap(), vec![0xd8, 0x60, 0x84, 0x00]);
    }

    #[test]
    fn json_plaintext_carries_data_cbor_as_standard_data_base64() {
        let bytes = encode(&forward_with_cbor_attachment(), Encoding::Json).unwrap();
        let (decoded, encoding) = decode(&bytes).unwrap();
        assert_eq!(encoding, Encoding::Json);
        let data = &decoded["attachments"][0]["data"];
        assert!(data.get("cbor").is_none());
        assert_eq!(attachment_bytes(&decoded["attachments"][0]).unwrap(), vec![0xd8, 0x60, 0x84, 0x00]);
    }
}
