//! A key not in the document a resolver gave is asked for once more with
//! `resolve_fresh`: a resolver that keeps documents (did:webvh's) may hold one from
//! before the DID changed. One that has nothing fresher answers `None`, and the key
//! is not found, as before.

use std::sync::atomic::{AtomicUsize, Ordering};

use async_trait::async_trait;
use serde_json::{json, Value};

use didcomm_core::resolver::{DIDResolver, PrefixResolver, ResolutionError};

const DID: &str = "did:example:changed";

fn document(keys: &[&str]) -> Value {
    let methods: Vec<Value> = keys
        .iter()
        .map(|key| json!({ "id": format!("#{key}"), "type": "Multikey", "controller": DID, "publicKeyMultibase": "z6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc" }))
        .collect();
    json!({ "id": DID, "verificationMethod": methods, "keyAgreement": keys.iter().map(|key| format!("#{key}")).collect::<Vec<_>>() })
}

/// Holds a document from before `key-2` was added, and has the new one only when
/// asked again (if `fresher`).
struct Keeping {
    fresher: bool,
    asked_again: AtomicUsize,
}

#[async_trait]
impl DIDResolver for Keeping {
    async fn resolve(&self, _did: &str) -> Result<Value, ResolutionError> {
        Ok(document(&["key-1"]))
    }

    async fn resolve_fresh(&self, _did: &str) -> Result<Option<Value>, ResolutionError> {
        self.asked_again.fetch_add(1, Ordering::Relaxed);
        Ok(self.fresher.then(|| document(&["key-1", "key-2"])))
    }

    async fn is_resolvable(&self, did: &str) -> bool {
        did.starts_with("did:example:")
    }
}

#[test]
fn a_key_the_held_document_lacks_is_looked_for_in_a_fresh_one() {
    let resolver = Keeping { fresher: true, asked_again: AtomicUsize::new(0) };
    // A key the held document has: not asked again.
    pollster::block_on(resolver.resolve_and_dereference_verification_method(&format!("{DID}#key-1"))).unwrap();
    assert_eq!(resolver.asked_again.load(Ordering::Relaxed), 0);
    // One it lacks: asked again once, and found there.
    let found = pollster::block_on(resolver.resolve_and_dereference_verification_method(&format!("{DID}#key-2"))).unwrap();
    assert!(found.id.ends_with("key-2"));
    assert_eq!(resolver.asked_again.load(Ordering::Relaxed), 1);
}

#[test]
fn with_nothing_fresher_the_key_is_not_found() {
    let resolver = Keeping { fresher: false, asked_again: AtomicUsize::new(0) };
    let missing = pollster::block_on(resolver.resolve_and_dereference_verification_method(&format!("{DID}#key-2")));
    assert!(matches!(missing, Err(ResolutionError::NotFound(_))), "{missing:?}");
    assert_eq!(resolver.asked_again.load(Ordering::Relaxed), 1);
}

#[test]
fn a_prefix_resolver_passes_asking_again_to_the_resolver_for_the_method() {
    let resolver = PrefixResolver::new(vec![("did:example:", Box::new(Keeping { fresher: true, asked_again: AtomicUsize::new(0) }) as Box<dyn DIDResolver>)]);
    let found = pollster::block_on(resolver.resolve_and_dereference_verification_method(&format!("{DID}#key-2"))).unwrap();
    assert!(found.id.ends_with("key-2"));
}
