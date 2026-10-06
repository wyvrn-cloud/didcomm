//! Plaintext message encoding: `application/didcomm-plain+json` or, for the
//! `didcomm/v2+cbor` profile, `application/didcomm-plain+cbor` -- "a CBOR mapping of
//! the same structure" (#463), with the same keys and value types.
//!
//! Messages are handled everywhere in this workspace as `serde_json::Value` (the
//! *JSON view*), whichever encoding they travel in. The two encodings differ in one
//! place: CBOR has a native byte string, JSON doesn't. Attachment data is where that
//! matters, so an attachment's bytes take whichever form its encoding carries best:
//!
//! - JSON wire and JSON view: `data.base64`, base64url text, as the spec defines it.
//! - CBOR wire: `data.binary`, a raw byte string. Encoding to CBOR turns every
//!   attachment's `data.base64` into `data.binary`; decoding turns it back.
//!
//! The two are the same field in two representations, so code above this module only
//! ever sees `data.base64`. A forward or pickup `delivery` carrying an already-packed
//! message, or a message carrying an image, puts the bytes in `data.base64` and gets
//! raw bytes on a CBOR wire for free. The attachment's `media_type` says what the bytes
//! are; the field name only says how they're represented. `data.binary` in a JSON view
//! (a caller building one by hand) is accepted and treated the same way. Any other CBOR
//! byte string decodes to its unpadded base64url text.

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
    #[error("invalid data.binary attachment: not a byte string")]
    AttachmentBinary,
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
            binary_attachments_to_base64(&mut message);
            Ok(serde_json::to_vec(&message)?)
        }
        Encoding::Cbor => {
            let value = json_to_cbor(&message)?;
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
            Ok((cbor_to_json(&value, false)?, Encoding::Cbor))
        }
    }
}

/// The payload bytes of an attachment, from `data.base64` (either alphabet, padded or
/// not), `data.binary` (base64url in a JSON view) or `data.json` (re-serialized as JSON).
pub fn attachment_bytes(attachment: &Value) -> Option<Vec<u8>> {
    let data = &attachment["data"];
    if let Some(b64) = data["base64"].as_str().or_else(|| data["binary"].as_str()) {
        return decode_lenient_base64(b64);
    }
    if data["json"].is_object() {
        return serde_json::to_vec(&data["json"]).ok();
    }
    None
}

/// An attachment `data` object for an already-packed DIDComm message: `{"json": ...}`
/// for a JSON one, `{"base64": <base64url>}` for a CBOR one, which a CBOR plaintext
/// carries as raw `data.binary` (see the module docs).
pub fn packed_message_attachment_data(packed: &[u8]) -> Result<(&'static str, Value), PlaintextError> {
    match Encoding::detect(packed).map_err(|_| PlaintextError::UnknownEncoding(packed.first().copied().unwrap_or(0)))? {
        Encoding::Json => Ok(("application/didcomm-encrypted+json", serde_json::json!({ "json": serde_json::from_slice::<Value>(packed)? }))),
        Encoding::Cbor => Ok(("application/didcomm-encrypted+cbor", serde_json::json!({ "base64": multibase::encode(packed) }))),
    }
}

/// Lenient: base64url or standard alphabet, padded or not -- other senders vary.
fn decode_lenient_base64(b64: &str) -> Option<Vec<u8>> {
    let normalized: String = b64
        .chars()
        .filter(|c| *c != '=')
        .map(|c| match c {
            '+' => '-',
            '/' => '_',
            c => c,
        })
        .collect();
    multibase::decode(normalized).ok()
}

/// A hand-built JSON view may say `data.binary`; plain DIDComm v2 only has `data.base64`.
fn binary_attachments_to_base64(message: &mut Value) {
    let Some(Value::Array(attachments)) = message.get_mut("attachments") else {
        return;
    };
    for attachment in attachments {
        if let Some(Value::Object(data)) = attachment.get_mut("data") {
            if let Some(binary) = data.remove("binary") {
                data.entry("base64").or_insert(binary);
            }
        }
    }
}

/// An attachment's `data` object for a CBOR plaintext: its bytes (`base64`, or
/// `binary` from a hand-built view) become a raw `binary` byte string. A `base64`
/// value that isn't base64 at all stays as it was, as text, rather than failing the
/// whole message.
fn attachment_data_to_cbor(data: &Map<String, Value>) -> Result<CborValue, PlaintextError> {
    let bytes = match data.get("binary").or_else(|| data.get("base64")) {
        Some(Value::String(b64)) => decode_lenient_base64(b64),
        Some(_) if data.contains_key("binary") => return Err(PlaintextError::AttachmentBinary),
        _ => None,
    };
    let mut entries = Vec::with_capacity(data.len());
    for (k, v) in data {
        match (k.as_str(), &bytes) {
            ("binary" | "base64", Some(_)) => continue,
            _ => entries.push((CborValue::Text(k.clone()), json_to_cbor(v)?)),
        }
    }
    if let Some(bytes) = bytes {
        entries.push((CborValue::Text("binary".into()), CborValue::Bytes(bytes)));
    }
    Ok(CborValue::Map(entries))
}

fn json_to_cbor(value: &Value) -> Result<CborValue, PlaintextError> {
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
        Value::Array(items) => CborValue::Array(items.iter().map(json_to_cbor).collect::<Result<_, _>>()?),
        Value::Object(map) => CborValue::Map(
            map.iter()
                .map(|(k, v)| {
                    let v = if k == "attachments" { attachments_to_cbor(v)? } else { json_to_cbor(v)? };
                    Ok((CborValue::Text(k.clone()), v))
                })
                .collect::<Result<_, PlaintextError>>()?,
        ),
    })
}

/// `attachments` is the one place attachment `data` is special-cased.
fn attachments_to_cbor(value: &Value) -> Result<CborValue, PlaintextError> {
    let Value::Array(items) = value else {
        return json_to_cbor(value);
    };
    Ok(CborValue::Array(
        items
            .iter()
            .map(|attachment| match attachment {
                Value::Object(fields) => Ok(CborValue::Map(
                    fields
                        .iter()
                        .map(|(k, v)| {
                            let v = match (k.as_str(), v) {
                                ("data", Value::Object(data)) => attachment_data_to_cbor(data)?,
                                _ => json_to_cbor(v)?,
                            };
                            Ok((CborValue::Text(k.clone()), v))
                        })
                        .collect::<Result<_, PlaintextError>>()?,
                )),
                other => json_to_cbor(other),
            })
            .collect::<Result<_, _>>()?,
    ))
}

/// `in_attachments` is true for the items of an `attachments` array, whose
/// `data.binary` comes back as `data.base64` (the inverse of [`attachments_to_cbor`]).
fn cbor_to_json(value: &CborValue, in_attachments: bool) -> Result<Value, PlaintextError> {
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
        CborValue::Array(items) => Value::Array(items.iter().map(|v| cbor_to_json(v, false)).collect::<Result<_, _>>()?),
        CborValue::Map(entries) => {
            let mut map = Map::new();
            for (k, v) in entries {
                let CborValue::Text(k) = k else {
                    return Err(PlaintextError::Cbor("plaintext map keys must be text".into()));
                };
                let v = match (k.as_str(), v) {
                    ("attachments", CborValue::Array(items)) => {
                        Value::Array(items.iter().map(|a| cbor_to_json(a, true)).collect::<Result<_, _>>()?)
                    }
                    ("data", _) if in_attachments => {
                        let mut data = cbor_to_json(v, false)?;
                        if let Value::Object(fields) = &mut data {
                            if let Some(binary) = fields.remove("binary") {
                                fields.entry("base64").or_insert(binary);
                            }
                        }
                        data
                    }
                    _ => cbor_to_json(v, false)?,
                };
                map.insert(k.clone(), v);
            }
            Value::Object(map)
        }
        CborValue::Tag(_, inner) => cbor_to_json(inner, in_attachments)?,
        _ => return Err(PlaintextError::Cbor("unsupported CBOR value".into())),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const PACKED: [u8; 4] = [0xd8, 0x60, 0x84, 0x00];

    fn forward_with_packed_cbor_attachment() -> Value {
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
                "data": packed_message_attachment_data(&PACKED).unwrap().1,
            }],
        })
    }

    fn cbor_attachment_data(bytes: &[u8], index: usize) -> Vec<(CborValue, CborValue)> {
        let raw: CborValue = ciborium::from_reader(bytes).unwrap();
        let CborValue::Map(top) = &raw else { panic!() };
        let attachments = &top.iter().find(|(k, _)| k == &CborValue::Text("attachments".into())).unwrap().1;
        let CborValue::Array(attachments) = attachments else { panic!() };
        let CborValue::Map(att) = &attachments[index] else { panic!() };
        let data = &att.iter().find(|(k, _)| k == &CborValue::Text("data".into())).unwrap().1;
        let CborValue::Map(data) = data else { panic!() };
        data.clone()
    }

    #[test]
    fn cbor_plaintext_carries_attachment_bytes_as_raw_data_binary_and_round_trips() {
        let message = forward_with_packed_cbor_attachment();
        assert_eq!(message["attachments"][0]["data"], json!({"base64": multibase::encode(PACKED)}));
        let bytes = encode(&message, Encoding::Cbor).unwrap();
        assert!((0xa0..=0xbf).contains(&bytes[0]), "a CBOR map");
        assert_eq!(
            cbor_attachment_data(&bytes, 0),
            vec![(CborValue::Text("binary".into()), CborValue::Bytes(PACKED.to_vec()))]
        );

        let (decoded, encoding) = decode(&bytes).unwrap();
        assert_eq!(encoding, Encoding::Cbor);
        assert_eq!(decoded["typ"], PLAIN_CBOR_TYP);
        assert_eq!(decoded["attachments"][0]["data"], message["attachments"][0]["data"]);
        assert_eq!(decoded["created_time"], 1_700_000_000u64);
        assert_eq!(attachment_bytes(&decoded["attachments"][0]).unwrap(), PACKED);
    }

    #[test]
    fn json_plaintext_keeps_standard_data_base64() {
        let bytes = encode(&forward_with_packed_cbor_attachment(), Encoding::Json).unwrap();
        let (decoded, encoding) = decode(&bytes).unwrap();
        assert_eq!(encoding, Encoding::Json);
        assert_eq!(decoded["attachments"][0]["data"], json!({"base64": multibase::encode(PACKED)}));
        assert_eq!(attachment_bytes(&decoded["attachments"][0]).unwrap(), PACKED);
    }

    /// Any binary attachment -- an image here, padded standard base64 as some senders
    /// write it -- goes raw in CBOR, keeping its other `data` fields; a hand-built
    /// `data.binary` is accepted and becomes `data.base64` on a JSON wire.
    #[test]
    fn every_binary_attachment_goes_raw_in_cbor() {
        let png = [0x89, b'P', b'N', b'G', 0xfb, 0xff];
        let message = json!({
            "type": "https://didcomm.org/user-profile/1.0/profile",
            "id": "1",
            "body": {},
            "attachments": [
                {"id": "pic", "media_type": "image/png", "data": {"base64": "iVBOR/v/", "hash": "zQm"}},
                {"id": "doc", "media_type": "application/json", "data": {"json": {"a": 1}}},
                {"id": "raw", "data": {"binary": multibase::encode(png)}},
            ],
        });
        let bytes = encode(&message, Encoding::Cbor).unwrap();
        let pic = cbor_attachment_data(&bytes, 0);
        assert!(pic.contains(&(CborValue::Text("binary".into()), CborValue::Bytes(png.to_vec()))));
        assert!(pic.contains(&(CborValue::Text("hash".into()), CborValue::Text("zQm".into()))));
        assert!(!pic.iter().any(|(k, _)| k == &CborValue::Text("base64".into())));

        let (decoded, _) = decode(&bytes).unwrap();
        for i in [0, 2] {
            assert_eq!(decoded["attachments"][i]["data"]["base64"], multibase::encode(png));
            assert!(decoded["attachments"][i]["data"].get("binary").is_none());
        }
        assert_eq!(decoded["attachments"][1]["data"], json!({"json": {"a": 1}}));

        let (json_view, _) = decode(&encode(&message, Encoding::Json).unwrap()).unwrap();
        assert_eq!(json_view["attachments"][2]["data"], json!({"base64": multibase::encode(png)}));
    }

    /// Text that isn't base64 can't become bytes; it stays as text rather than failing.
    #[test]
    fn undecodable_base64_stays_text() {
        let message = json!({"id": "1", "type": "t", "body": {}, "attachments": [{"data": {"base64": "not base64!"}}]});
        let (decoded, _) = decode(&encode(&message, Encoding::Cbor).unwrap()).unwrap();
        assert_eq!(decoded["attachments"][0]["data"], json!({"base64": "not base64!"}));
    }
}
