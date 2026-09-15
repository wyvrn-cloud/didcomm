//! `did:jwk` resolution, mirroring `didcomm_messaging.resolver.jwk`.
//!
//! A `did:jwk` DID is just a base64url-encoded JWK -- resolving one means decoding that
//! JWK and wrapping it in a single-verification-method DID Document. No network
//! resolution needed, same as `did:peer:2`.

use async_trait::async_trait;
use didcomm_core::resolver::{DIDResolver, ResolutionError};
use didcomm_multiformats::multibase;
use serde_json::{json, Value};

/// Errors resolving a `did:jwk` DID.
#[derive(Debug, thiserror::Error)]
pub enum JwkResolverError {
    #[error("invalid did:jwk: {0}")]
    InvalidDid(String),
    #[error("invalid base64url in did:jwk: {0}")]
    Multibase(#[from] multibase::DecodeError),
    #[error("invalid JWK: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid JWK: not an object, or missing \"kty\"")]
    InvalidJwk,
}

/// Check whether a string has the shape of a `did:jwk` DID (a base64url payload after
/// the method-specific prefix). Doesn't validate that the payload decodes to a JWK --
/// `resolve` does that.
pub fn is_did_jwk(did: &str) -> bool {
    did.strip_prefix("did:jwk:")
        .is_some_and(|encoded| !encoded.is_empty() && encoded.bytes().all(is_urlsafe_b64_byte))
}

fn is_urlsafe_b64_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'-'
}

/// Resolve a `did:jwk` DID into its DID Document.
pub fn resolve(did: &str) -> Result<Value, JwkResolverError> {
    let encoded = did
        .strip_prefix("did:jwk:")
        .filter(|encoded| !encoded.is_empty() && encoded.bytes().all(is_urlsafe_b64_byte))
        .ok_or_else(|| JwkResolverError::InvalidDid(did.to_string()))?;

    let decoded = multibase::decode(encoded)?;
    let jwk: Value = serde_json::from_slice(&decoded)?;
    if !jwk.is_object() || jwk.get("kty").is_none() {
        return Err(JwkResolverError::InvalidJwk);
    }

    let vm_id = format!("{did}#0");
    let mut doc = json!({
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/jws-2020/v1",
        ],
        "id": did,
        "verificationMethod": [{
            "id": vm_id,
            "type": "JsonWebKey2020",
            "controller": did,
            "publicKeyJwk": jwk,
        }],
    });

    match jwk.get("use").and_then(Value::as_str) {
        Some("sig") => {
            let refs = json!([vm_id]);
            doc["assertionMethod"] = refs.clone();
            doc["authentication"] = refs.clone();
            doc["capabilityInvocation"] = refs.clone();
            doc["capabilityDelegation"] = refs;
        }
        Some("enc") => {
            doc["keyAgreement"] = json!([vm_id]);
        }
        _ => {}
    }

    Ok(doc)
}

/// `did:jwk` as a [`DIDResolver`](didcomm_core::resolver::DIDResolver), for use with
/// [`PrefixResolver`](didcomm_core::resolver::PrefixResolver).
#[derive(Debug, Default, Clone, Copy)]
pub struct JwkResolver;

#[async_trait]
impl DIDResolver for JwkResolver {
    async fn resolve(&self, did: &str) -> Result<Value, ResolutionError> {
        resolve(did).map_err(|e| ResolutionError::Resolution(e.to_string()))
    }

    async fn is_resolvable(&self, did: &str) -> bool {
        is_did_jwk(did)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A real did:jwk resolution, produced by didcomm_messaging.resolver.jwk's own
    // JWKResolver.resolve() -- see /fixtures/did-jwk.
    const FIXTURE: &str = include_str!("../../../fixtures/did-jwk/fixture.json");

    #[test]
    fn resolves_to_the_same_document_as_the_python_reference() {
        let fixture: Value = serde_json::from_str(FIXTURE).unwrap();
        let did = fixture["did"].as_str().unwrap();

        assert!(is_did_jwk(did));
        assert_eq!(resolve(did).unwrap(), fixture["document"]);
    }

    #[test]
    fn rejects_obviously_invalid_dids() {
        assert!(!is_did_jwk("did:jwk:"));
        assert!(!is_did_jwk("did:jwk:not valid base64!"));
        assert!(!is_did_jwk("did:peer:2.Vz6Mk"));
        assert!(resolve("did:jwk:").is_err());
    }

    #[test]
    fn resolves_and_dereferences_through_a_prefix_resolver() {
        use didcomm_core::resolver::PrefixResolver;

        let fixture: Value = serde_json::from_str(FIXTURE).unwrap();
        let did = fixture["did"].as_str().unwrap().to_string();

        let resolver =
            PrefixResolver::new(vec![("did:jwk:", Box::new(JwkResolver) as Box<dyn DIDResolver>)]);

        pollster::block_on(async {
            assert!(resolver.is_resolvable(&did).await);
            let doc = resolver.resolve_and_parse(&did).await.unwrap();
            let key_agreement = doc.default_key_agreement().expect("has a key agreement");
            assert_eq!(
                key_agreement.public_key_jwk.as_ref().unwrap()["x"],
                fixture["jwk"]["x"]
            );
        });
    }
}
