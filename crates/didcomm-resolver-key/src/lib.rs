//! `did:key` resolution, mirroring `didcomm_messaging.resolver.key`.
//!
//! A `did:key` DID is a self-describing, multicodec-tagged public key, multibase
//! (base58btc) encoded directly into the method-specific identifier -- resolving one
//! means decoding that key and wrapping it in a single-verification-method DID
//! Document. No network resolution needed, same as `did:peer:2`/`did:jwk`.
//!
//! Added to resolve a real gap found live: a real wallet's own `did:peer:4` document
//! listed its *own* mediator's routing key as a full `did:key:...#...` DID URL (not a
//! local `#fragment` reference into its own document), and this workspace had no
//! resolver registered for that prefix at all -- `V1DIDCommMessaging::pack`'s
//! `routing_key_to_kid` needs one for any non-local routing key, and `did:key` is by far
//! the most common shape a routing key takes in practice.
//!
//! Doesn't attempt the full W3C did:key spec's key-agreement derivation (deriving an
//! X25519 keyAgreement key from an Ed25519 base key via Edwards-to-Montgomery curve
//! conversion) -- out of scope for what this workspace actually needs a `did:key`
//! resolver for (resolving an already-typed key, whichever verification relationship it
//! turns out to serve), and a real added complexity/correctness surface this port
//! doesn't need to take on.

use async_trait::async_trait;
use didcomm_core::resolver::{DIDResolver, ResolutionError};
use didcomm_multiformats::{multibase, multicodec};
use serde_json::{json, Value};

/// Errors resolving a `did:key` DID.
#[derive(Debug, thiserror::Error)]
pub enum KeyResolverError {
    #[error("invalid did:key: {0}")]
    InvalidDid(String),
    #[error("invalid multibase value in did:key: {0}")]
    Multibase(#[from] multibase::DecodeError),
    #[error("unsupported multicodec in did:key: {0}")]
    Multicodec(#[from] multicodec::MulticodecError),
}

/// Check whether a string has the shape of a `did:key` DID: `did:key:` followed by a
/// self-describing multibase value. Doesn't validate that the payload decodes to a
/// supported multicodec -- `resolve` does that.
pub fn is_did_key(did: &str) -> bool {
    did.strip_prefix("did:key:").is_some_and(|suffix| !suffix.is_empty())
}

/// Resolve a `did:key` DID into its DID Document.
pub fn resolve(did: &str) -> Result<Value, KeyResolverError> {
    let suffix = did.strip_prefix("did:key:").ok_or_else(|| KeyResolverError::InvalidDid(did.to_string()))?;
    if suffix.is_empty() {
        return Err(KeyResolverError::InvalidDid(did.to_string()));
    }

    let decoded = multibase::decode_self_describing(suffix)?;
    let (codec, _key_bytes) = multicodec::unwrap(&decoded)?;

    let vm_id = format!("{did}#{suffix}");
    let mut doc = json!({
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/multikey/v1",
        ],
        "id": did,
        "verificationMethod": [{
            "id": vm_id,
            "type": "Multikey",
            "controller": did,
            "publicKeyMultibase": suffix,
        }],
    });

    // Ed25519 (and other signing-capable codecs) go in the signing relationships;
    // X25519 -- the one key-agreement-only codec this workspace's multicodec table
    // covers -- goes in `keyAgreement` instead. Doesn't attempt to synthesize the
    // *other* relationship from a key of the wrong shape (see module docs).
    if codec == multicodec::X25519_PUB {
        doc["keyAgreement"] = json!([vm_id]);
    } else {
        let refs = json!([vm_id]);
        doc["authentication"] = refs.clone();
        doc["assertionMethod"] = refs.clone();
        doc["capabilityInvocation"] = refs.clone();
        doc["capabilityDelegation"] = refs;
    }

    Ok(doc)
}

/// `did:key` as a [`DIDResolver`](didcomm_core::resolver::DIDResolver), for use with
/// [`PrefixResolver`](didcomm_core::resolver::PrefixResolver).
#[derive(Debug, Default, Clone, Copy)]
pub struct KeyResolver;

// Split by target to match didcomm-core::resolver::DIDResolver's own signature
// there (`?Send` on wasm32) -- see that trait's doc comment. This resolver does no
// I/O so its own future is trivially Send either way, but the impl's macro-generated
// method signature still has to match the trait's exactly, not just be compatible.
#[cfg(not(target_arch = "wasm32"))]
#[async_trait]
impl DIDResolver for KeyResolver {
    async fn resolve(&self, did: &str) -> Result<Value, ResolutionError> {
        resolve(did).map_err(|e| ResolutionError::Resolution(e.to_string()))
    }

    async fn is_resolvable(&self, did: &str) -> bool {
        is_did_key(did)
    }
}

#[cfg(target_arch = "wasm32")]
#[async_trait(?Send)]
impl DIDResolver for KeyResolver {
    async fn resolve(&self, did: &str) -> Result<Value, ResolutionError> {
        resolve(did).map_err(|e| ResolutionError::Resolution(e.to_string()))
    }

    async fn is_resolvable(&self, did: &str) -> bool {
        is_did_key(did)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A real did:key seen live: a wallet's own document listed this as its mediator's
    // routing key, as a full `did:key:...#...` DID URL -- the exact case that motivated
    // this crate (see module docs).
    const ED25519_DID: &str = "did:key:z6MkiAGAFumGbXRwNPA4paPEnCvBUS8C4yG65Kb1ig8GYX9S";

    #[test]
    fn resolves_an_ed25519_key_into_the_signing_relationships() {
        let doc = resolve(ED25519_DID).unwrap();
        let vm_id = format!("{ED25519_DID}#{}", ED25519_DID.strip_prefix("did:key:").unwrap());
        assert_eq!(doc["verificationMethod"][0]["id"], vm_id);
        assert_eq!(doc["verificationMethod"][0]["publicKeyMultibase"], "z6MkiAGAFumGbXRwNPA4paPEnCvBUS8C4yG65Kb1ig8GYX9S");
        assert_eq!(doc["authentication"][0], vm_id);
        assert!(doc.get("keyAgreement").is_none());
    }

    #[test]
    fn rejects_obviously_invalid_dids() {
        assert!(!is_did_key("did:key:"));
        assert!(!is_did_key("did:peer:2.Vz6Mk"));
        assert!(resolve("did:key:").is_err());
        assert!(resolve("did:key:not-valid-multibase!").is_err());
    }

    #[test]
    fn resolves_and_dereferences_through_a_prefix_resolver_by_full_url_with_fragment() {
        use didcomm_core::resolver::PrefixResolver;

        let resolver = PrefixResolver::new(vec![("did:key:", Box::new(KeyResolver) as Box<dyn DIDResolver>)]);
        let did_url = format!("{ED25519_DID}#{}", ED25519_DID.strip_prefix("did:key:").unwrap());

        pollster::block_on(async {
            assert!(resolver.is_resolvable(ED25519_DID).await);
            let vm = resolver.resolve_and_dereference_verification_method(&did_url).await.unwrap();
            assert_eq!(vm.public_key_multibase.as_deref(), Some("z6MkiAGAFumGbXRwNPA4paPEnCvBUS8C4yG65Kb1ig8GYX9S"));
        });
    }
}
