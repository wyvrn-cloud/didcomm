//! `did:peer:4` resolution, mirroring the `did_peer_4` Python package.
//!
//! Unlike `did:peer:2`, a `did:peer:4` comes in two forms: the **long** form
//! (`did:peer:4<hash>:<encoded-document>`) embeds the whole document -- self-certifying
//! and resolvable on its own, exactly like `did:peer:2` -- while the **short** form
//! (`did:peer:4<hash>`) is just that hash, with no document attached. A short-form DID
//! genuinely *cannot* be resolved from the identifier alone (there's nothing to decode
//! -- that's the point, it's a stable, compact reference once you already have the
//! document from elsewhere), which is why `resolve` here only accepts the long form,
//! matching `did_peer_4.resolve`'s own restriction (and why `Peer4::is_resolvable`
//! accepting the short pattern too, matching `didcomm_messaging.resolver.peer.Peer4`,
//! is a real, faithfully-reproduced asymmetry rather than a bug: a party who's already
//! resolved the long form and cached the document under its short form can still route
//! by it, even though this resolver can't cold-resolve one on its own).
//!
//! Generation (`encode`/`encode_short`, and the input-document validation Python's
//! `validate_input_document` performs for it) isn't implemented here -- this workspace
//! doesn't need to *create* did:peer:4 DIDs anywhere yet (`didcomm-quickstart` generates
//! did:peer:2), only to resolve ones a counterparty presents.

use async_trait::async_trait;
use didcomm_core::resolver::{DIDResolver, ResolutionError};
use didcomm_multiformats::multibase;
use serde_json::Value;
use sha2::{Digest, Sha256};

/// `didcomm_messaging.multiformats.multicodec`'s SHA-256 multihash prefix -- the same
/// constant `peer2::peer2to3` uses, here for the long-form DID's embedded document hash.
const MULTIHASH_SHA256: [u8; 2] = [0x12, 0x20];
/// did_peer_4's `MULTICODEC_JSON` -- not one of `didcomm_multiformats::multicodec`'s key
/// codecs, so it's not in that shared table; this is the only place it's used.
const MULTICODEC_JSON: [u8; 2] = [0x80, 0x04];

const BASE58_ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Errors resolving a `did:peer:4` DID.
#[derive(Debug, thiserror::Error)]
pub enum Peer4Error {
    #[error("invalid did:peer:4: {0}")]
    InvalidDid(String),
    #[error("cannot decode a document from a short-form did:peer:4: {0}")]
    ShortForm(String),
    #[error("hash does not match the encoded document for did:peer:4: {0}")]
    HashMismatch(String),
    #[error("unsupported multicodec in did:peer:4 encoded document")]
    UnsupportedMulticodec,
    #[error("invalid multibase value in did:peer:4: {0}")]
    Multibase(#[from] multibase::DecodeError),
    #[error("invalid JSON in did:peer:4 encoded document: {0}")]
    Json(#[from] serde_json::Error),
}

fn is_base58(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| BASE58_ALPHABET.contains(&b))
}

/// Check whether a string has the shape of a short-form `did:peer:4`:
/// `did:peer:4zQm<44 base58 chars>`.
pub fn is_did_peer_4_short(did: &str) -> bool {
    did.strip_prefix("did:peer:4zQm")
        .is_some_and(|rest| rest.len() == 44 && is_base58(rest))
}

/// Check whether a string has the shape of a long-form `did:peer:4`:
/// `did:peer:4zQm<44 base58 chars>:z<6+ base58 chars>`.
pub fn is_did_peer_4_long(did: &str) -> bool {
    let Some(rest) = did.strip_prefix("did:peer:4zQm") else {
        return false;
    };
    let Some((hash, doc)) = rest.split_once(':') else {
        return false;
    };
    hash.len() == 44 && is_base58(hash) && doc.len() >= 7 && doc.starts_with('z') && is_base58(&doc[1..])
}

fn hash_encoded_doc(encoded_doc: &str) -> String {
    let digest = Sha256::digest(encoded_doc.as_bytes());
    let mut raw = MULTIHASH_SHA256.to_vec();
    raw.extend_from_slice(&digest);
    format!("z{}", multibase::encode_base58btc(raw))
}

fn decode_doc(encoded_doc: &str) -> Result<Value, Peer4Error> {
    let decoded = multibase::decode_self_describing(encoded_doc)?;
    let value = decoded
        .strip_prefix(MULTICODEC_JSON.as_slice())
        .ok_or(Peer4Error::UnsupportedMulticodec)?;
    Ok(serde_json::from_slice(value)?)
}

/// Decode a long-form `did:peer:4` into its (uncontextualized -- no `id` set yet)
/// document, mirroring `did_peer_4.decode`.
pub fn decode(did: &str) -> Result<Value, Peer4Error> {
    if !did.starts_with("did:peer:4") {
        return Err(Peer4Error::InvalidDid(did.to_string()));
    }
    if is_did_peer_4_short(did) {
        return Err(Peer4Error::ShortForm(did.to_string()));
    }
    if !is_did_peer_4_long(did) {
        return Err(Peer4Error::InvalidDid(did.to_string()));
    }

    let (hash, encoded_doc) = did["did:peer:4".len()..].split_once(':').unwrap();
    if hash_encoded_doc(encoded_doc) != hash {
        return Err(Peer4Error::HashMismatch(did.to_string()));
    }
    decode_doc(encoded_doc)
}

/// The short form of a long-form `did:peer:4` (everything up to the last `:`).
pub fn long_to_short(did: &str) -> Result<String, Peer4Error> {
    if !is_did_peer_4_long(did) {
        return Err(Peer4Error::InvalidDid(did.to_string()));
    }
    Ok(did[..did.rfind(':').unwrap()].to_string())
}

/// Set `id` (and `controller`, on every verification method that doesn't already have
/// one -- including ones embedded directly in a verification relationship array) to
/// `did`, mirroring `contextualize_document`.
fn contextualize_document(did: &str, mut document: Value) -> Value {
    let set_controller = |vm: &mut Value| {
        if let Value::Object(map) = vm {
            map.entry("controller").or_insert_with(|| Value::String(did.to_string()));
        }
    };

    if let Some(Value::Array(vms)) = document.get_mut("verificationMethod") {
        for vm in vms {
            set_controller(vm);
        }
    }
    for relationship in [
        "authentication",
        "assertionMethod",
        "keyAgreement",
        "capabilityInvocation",
        "capabilityDelegation",
    ] {
        if let Some(Value::Array(entries)) = document.get_mut(relationship) {
            for entry in entries {
                // Only embedded verification methods (objects) get a controller set;
                // plain string references are left alone, matching
                // _operate_on_embedded's ref/vm split in Python.
                set_controller(entry);
            }
        }
    }

    if let Value::Object(map) = &mut document {
        map.insert("id".to_string(), Value::String(did.to_string()));
    }
    document
}

/// Resolve a long-form `did:peer:4` into its DID Document, mirroring `did_peer_4.resolve`.
pub fn resolve(did: &str) -> Result<Value, Peer4Error> {
    let decoded = decode(did)?;
    let mut document = contextualize_document(did, decoded);
    let short = long_to_short(did)?;
    push_also_known_as(&mut document, short);
    Ok(document)
}

/// Resolve the short-form document variant of a long-form `did:peer:4` (the document
/// contextualized with the *short* DID as its `id`, with the long form recorded in
/// `alsoKnownAs` instead), mirroring `did_peer_4.resolve_short`.
pub fn resolve_short(did: &str) -> Result<Value, Peer4Error> {
    let decoded = decode(did)?;
    let short = long_to_short(did)?;
    let mut document = contextualize_document(&short, decoded);
    push_also_known_as(&mut document, did.to_string());
    Ok(document)
}

fn push_also_known_as(document: &mut Value, value: String) {
    if let Value::Object(map) = document {
        match map.get_mut("alsoKnownAs") {
            Some(Value::Array(existing)) => existing.push(Value::String(value)),
            _ => {
                map.insert("alsoKnownAs".to_string(), Value::Array(vec![Value::String(value)]));
            }
        }
    }
}

/// `did:peer:4` as a [`DIDResolver`](didcomm_core::resolver::DIDResolver). `resolve`
/// only succeeds for the long form -- see this module's docs for why that's not a
/// limitation of this port specifically.
#[derive(Debug, Default, Clone, Copy)]
pub struct Peer4;

// Split by target to match didcomm-core::resolver::DIDResolver's own signature
// there (`?Send` on wasm32) -- see that trait's doc comment. This resolver does no
// I/O so its own future is trivially Send either way, but the impl's macro-generated
// method signature still has to match the trait's exactly, not just be compatible.
#[cfg(not(target_arch = "wasm32"))]
#[async_trait]
impl DIDResolver for Peer4 {
    async fn resolve(&self, did: &str) -> Result<Value, ResolutionError> {
        resolve(did).map_err(|e| ResolutionError::Resolution(e.to_string()))
    }

    async fn is_resolvable(&self, did: &str) -> bool {
        is_did_peer_4_long(did) || is_did_peer_4_short(did)
    }
}

#[cfg(target_arch = "wasm32")]
#[async_trait(?Send)]
impl DIDResolver for Peer4 {
    async fn resolve(&self, did: &str) -> Result<Value, ResolutionError> {
        resolve(did).map_err(|e| ResolutionError::Resolution(e.to_string()))
    }

    async fn is_resolvable(&self, did: &str) -> bool {
        is_did_peer_4_long(did) || is_did_peer_4_short(did)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A real did:peer:4 (long and short form) and its resolved documents, produced by
    // the actual did_peer_4 Python package's own encode()/resolve()/resolve_short() --
    // see /fixtures/did-peer-4.
    const FIXTURE: &str = include_str!("../../../fixtures/did-peer-4/fixture.json");

    #[test]
    fn resolves_the_long_form_to_the_same_document_as_the_python_reference() {
        let fixture: Value = serde_json::from_str(FIXTURE).unwrap();
        let long_did = fixture["long_did"].as_str().unwrap();

        assert!(is_did_peer_4_long(long_did));
        assert!(!is_did_peer_4_short(long_did));
        assert_eq!(resolve(long_did).unwrap(), fixture["long_document"]);
    }

    #[test]
    fn resolves_short_to_the_same_document_as_the_python_reference() {
        let fixture: Value = serde_json::from_str(FIXTURE).unwrap();
        let long_did = fixture["long_did"].as_str().unwrap();

        assert_eq!(long_to_short(long_did).unwrap(), fixture["short_did"]);
        assert_eq!(resolve_short(long_did).unwrap(), fixture["short_document"]);
    }

    #[test]
    fn rejects_short_form_for_decode_and_resolve() {
        let fixture: Value = serde_json::from_str(FIXTURE).unwrap();
        let short_did = fixture["short_did"].as_str().unwrap();

        assert!(is_did_peer_4_short(short_did));
        assert!(matches!(decode(short_did), Err(Peer4Error::ShortForm(_))));
        assert!(resolve(short_did).is_err());
    }

    #[test]
    fn is_resolvable_accepts_both_forms_even_though_resolve_only_accepts_long() {
        let fixture: Value = serde_json::from_str(FIXTURE).unwrap();
        pollster::block_on(async {
            let resolver = Peer4;
            assert!(resolver.is_resolvable(fixture["long_did"].as_str().unwrap()).await);
            assert!(resolver.is_resolvable(fixture["short_did"].as_str().unwrap()).await);
            assert!(resolver.resolve(fixture["short_did"].as_str().unwrap()).await.is_err());
        });
    }
}
