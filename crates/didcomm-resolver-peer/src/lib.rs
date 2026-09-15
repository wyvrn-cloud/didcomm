//! `did:peer:2` resolution, mirroring the `did_peer_2` Python package that
//! `didcomm-messaging-python` depends on for this DID method (`did:peer:4` and the
//! `DIDResolver` trait impl -- once `didcomm-core::resolver` exists -- follow later).
//!
//! `did:peer:2` encodes an entire DID Document into the identifier itself: a sequence of
//! `.`-separated elements, each either a multikey-encoded verification key tagged with a
//! purpose code (`A`ssertion, k`E`yAgreement, authentication`(V)`, capabilit`I`nvocation,
//! capability`D`elegation) or a base64url-encoded, abbreviated-JSON `S`ervice block. No
//! network resolution is needed -- it's pure string/JSON manipulation, which is why this
//! crate has no async in it at all.

use didcomm_multiformats::multibase;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

/// Errors resolving a `did:peer:2` DID.
#[derive(Debug, thiserror::Error)]
pub enum PeerError {
    #[error("invalid did:peer:2: {0}")]
    InvalidDid(String),
    #[error("invalid multibase value in did:peer:2 element: {0}")]
    Multibase(#[from] multibase::DecodeError),
    #[error("invalid JSON in did:peer:2 service element: {0}")]
    Json(#[from] serde_json::Error),
}

/// `didcomm_messaging.multiformats.multicodec`'s SHA-256 multihash prefix, used for the
/// `did:peer:3` derivation embedded in every `did:peer:2` resolution's `alsoKnownAs`.
const MULTIHASH_SHA256: [u8; 2] = [0x12, 0x20];

/// Check whether a string has the shape of a `did:peer:2` DID. Doesn't fully validate
/// every embedded key/service -- `resolve` does that as a side effect of decoding them.
pub fn is_did_peer_2(did: &str) -> bool {
    did.strip_prefix("did:peer:2")
        .is_some_and(|rest| parse_elements(rest).is_some())
}

/// Resolve a `did:peer:2` DID into its DID Document, as a `serde_json::Value` (matching
/// what `did_peer_2.resolve()`/`didcomm_messaging.resolver.peer.Peer2.resolve` return --
/// a plain dict/JSON value, not yet a typed model).
pub fn resolve(did: &str) -> Result<Value, PeerError> {
    let rest = did
        .strip_prefix("did:peer:2")
        .ok_or_else(|| PeerError::InvalidDid(did.to_string()))?;
    let elements =
        parse_elements(rest).ok_or_else(|| PeerError::InvalidDid(did.to_string()))?;

    let mut doc = Map::new();
    doc.insert(
        "@context".into(),
        json!([
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/multikey/v1",
        ]),
    );
    doc.insert("id".into(), Value::String(did.to_string()));

    let mut verification_methods = Vec::new();
    // (relationship name, verification method refs) in first-appearance order, mirroring
    // Python's dict.setdefault -- doesn't affect correctness (JSON object equality isn't
    // order-sensitive) but keeps a Rust-produced document looking like what a human
    // reading the Python output would expect.
    let mut relationships: Vec<(&'static str, Vec<Value>)> = Vec::new();
    let mut services = Vec::new();
    let mut unidentified_index = 0usize;

    for (purpose, value) in elements {
        if purpose == 'S' {
            let decoded = multibase::decode(value)?;
            let expanded = expand_service(serde_json::from_slice(&decoded)?);
            let mut service = match expanded {
                Value::Object(m) => m,
                _ => return Err(PeerError::InvalidDid(did.to_string())),
            };
            if !service.contains_key("id") {
                let id = if unidentified_index == 0 {
                    "#service".to_string()
                } else {
                    format!("#service-{unidentified_index}")
                };
                service.insert("id".into(), Value::String(id));
                unidentified_index += 1;
            }
            services.push(Value::Object(service));
        } else {
            let vm_id = format!("#key-{}", verification_methods.len() + 1);
            verification_methods.push(json!({
                "type": "Multikey",
                "id": vm_id,
                "controller": did,
                "publicKeyMultibase": value,
            }));
            let rel_name = verification_relationship(purpose);
            match relationships.iter_mut().find(|(name, _)| *name == rel_name) {
                Some((_, ids)) => ids.push(Value::String(vm_id)),
                None => relationships.push((rel_name, vec![Value::String(vm_id)])),
            }
        }
    }

    if !verification_methods.is_empty() {
        doc.insert("verificationMethod".into(), Value::Array(verification_methods));
    }
    for (name, ids) in relationships {
        doc.insert(name.into(), Value::Array(ids));
    }
    if !services.is_empty() {
        doc.insert("service".into(), Value::Array(services));
    }
    doc.insert("alsoKnownAs".into(), json!([peer2to3(did)?]));

    Ok(Value::Object(doc))
}

/// Derive a `did:peer:3` from a `did:peer:2` (a hash of everything after `did:peer:2`,
/// so it's stable across whatever new elements might be appended, and shorter to pass
/// around). Included so `resolve`'s `alsoKnownAs` matches the reference implementation
/// byte-for-byte, not because `did:peer:3` resolution itself is supported yet.
pub fn peer2to3(did: &str) -> Result<String, PeerError> {
    if !is_did_peer_2(did) {
        return Err(PeerError::InvalidDid(did.to_string()));
    }
    let digest = Sha256::digest(did["did:peer:2".len()..].as_bytes());
    let mut raw = MULTIHASH_SHA256.to_vec();
    raw.extend_from_slice(&digest);
    Ok(format!("did:peer:3z{}", multibase::encode_base58btc(&raw)))
}

fn verification_relationship(purpose: char) -> &'static str {
    match purpose {
        'A' => "assertionMethod",
        'E' => "keyAgreement",
        'V' => "authentication",
        'I' => "capabilityInvocation",
        'D' => "capabilityDelegation",
        _ => unreachable!("filtered by parse_elements"),
    }
}

/// Split the part of a did:peer:2 after the method-specific prefix into
/// `(purpose_char, value)` pairs, matching
/// `^(\.[AEVID]z[b58]+|\.S[urlsafe-b64]+)+$`. Returns `None` if the shape doesn't match
/// (mirroring `did_peer_2.PATTERN` failing to match, which Python surfaces as a
/// `ValueError` from `resolve`).
fn parse_elements(rest: &str) -> Option<Vec<(char, &str)>> {
    let mut elements = Vec::new();
    let mut remaining = rest;
    while !remaining.is_empty() {
        remaining = remaining.strip_prefix('.')?;
        let purpose = remaining.chars().next()?;
        if !matches!(purpose, 'A' | 'E' | 'V' | 'I' | 'D' | 'S') {
            return None;
        }
        let after_purpose = &remaining[purpose.len_utf8()..];
        // A value never contains '.', so the next one (if any) starts the next element.
        let end = after_purpose.find('.').unwrap_or(after_purpose.len());
        let value = &after_purpose[..end];
        let valid = match purpose {
            'S' => !value.is_empty() && value.bytes().all(is_urlsafe_b64_byte),
            _ => value
                .strip_prefix('z')
                .is_some_and(|b58| !b58.is_empty() && b58.bytes().all(is_base58_byte)),
        };
        if !valid {
            return None;
        }
        elements.push((purpose, value));
        remaining = &after_purpose[end..];
    }
    (!elements.is_empty()).then_some(elements)
}

fn is_base58_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() && !matches!(b, b'0' | b'O' | b'I' | b'l')
}

fn is_urlsafe_b64_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'-'
}

/// `didcomm_messaging`'s "Common String Abbreviations" for `did:peer:2` service blocks,
/// used to keep the encoded services short. `(full name, abbreviation)` pairs.
const SERVICE_ABBREVIATIONS: &[(&str, &str)] = &[
    ("type", "t"),
    ("DIDCommMessaging", "dm"),
    ("serviceEndpoint", "s"),
    ("routingKeys", "r"),
    ("accept", "a"),
];

fn expand_abbreviation(s: &str) -> String {
    SERVICE_ABBREVIATIONS
        .iter()
        .find(|(_, abbr)| *abbr == s)
        .map_or(s, |(full, _)| full)
        .to_string()
}

/// Recursively replace abbreviated keys (and the `type` value, if abbreviated) with
/// their full names, mirroring `ServiceEncoder._expand_service`.
fn expand_service(value: Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut expanded = Map::new();
            for (k, v) in map {
                expanded.insert(expand_abbreviation(&k), expand_service(v));
            }
            if let Some(Value::String(t)) = expanded.get("type") {
                let full = expand_abbreviation(t);
                expanded.insert("type".into(), Value::String(full));
            }
            Value::Object(expanded)
        }
        Value::Array(items) => Value::Array(items.into_iter().map(expand_service).collect()),
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A real did:peer:2, generated and resolved by the actual did_peer_2 Python
    // package's own generate()/resolve() -- see /fixtures/did-peer-2.
    const FIXTURE: &str = include_str!("../../../fixtures/did-peer-2/fixture.json");

    #[test]
    fn resolves_to_the_same_document_as_the_python_reference() {
        let fixture: Value = serde_json::from_str(FIXTURE).unwrap();
        let did = fixture["did"].as_str().unwrap();

        assert!(is_did_peer_2(did));

        let resolved = resolve(did).unwrap();
        assert_eq!(resolved, fixture["document"]);
    }

    #[test]
    fn rejects_obviously_invalid_dids() {
        assert!(!is_did_peer_2("did:peer:2"));
        assert!(!is_did_peer_2("did:peer:2.Xz6Mkp"));
        assert!(!is_did_peer_2("did:web:example.com"));
        assert!(resolve("did:peer:2").is_err());
    }
}
