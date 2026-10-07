//! A minimal DID Document model, covering exactly the slice of `pydid` that
//! `didcomm-messaging-python` actually uses: parsing a resolved document, dereferencing
//! a DID URL to a verification method or service, and reading a `DIDCommMessaging`
//! service's endpoint. Not a general-purpose DID Core implementation -- see `PLAN.md`
//! §7 for why `ssi` (the closest full-featured Rust equivalent of `pydid`) was
//! deliberately not used here.

use serde::Deserialize;
use serde_json::Value;

/// Errors parsing or dereferencing a DID Document.
#[derive(Debug, thiserror::Error)]
pub enum DidDocError {
    #[error("invalid DID document: {0}")]
    Json(#[from] serde_json::Error),
    #[error("DID URL has no fragment to dereference: {0}")]
    NoFragment(String),
}

/// One verification method (a public key, in practice).
#[derive(Debug, Clone, Deserialize)]
pub struct VerificationMethod {
    pub id: String,
    #[serde(rename = "type")]
    pub type_: String,
    pub controller: String,
    #[serde(rename = "publicKeyMultibase")]
    pub public_key_multibase: Option<String>,
    #[serde(rename = "publicKeyBase58")]
    pub public_key_base58: Option<String>,
    #[serde(rename = "publicKeyJwk")]
    pub public_key_jwk: Option<Value>,
}

/// A service entry. `service_endpoint` is kept as raw JSON since the DID Core spec lets
/// it be a string, an object, or an array of either -- `didcomm_v2_endpoint` below is
/// the one shape this crate actually needs to read.
#[derive(Debug, Clone, Deserialize)]
pub struct Service {
    pub id: String,
    #[serde(rename = "type")]
    pub type_: String,
    #[serde(rename = "serviceEndpoint")]
    pub service_endpoint: Value,
    /// DIDComm v1 only (`pydid.service.DIDCommV1Service.recipient_keys`) -- DID URL
    /// references to verification methods, not yet dereferenced. Always empty on a v2
    /// `DIDCommMessaging` service, which has no such field.
    #[serde(default, rename = "recipientKeys")]
    pub recipient_keys: Vec<String>,
    /// DIDComm v1 only -- see `recipient_keys`. (v2 also has a `routingKeys` field, but
    /// nested inside its `serviceEndpoint` object instead of here at the top level --
    /// see [`DidCommV2ServiceEndpoint`].)
    #[serde(default, rename = "routingKeys")]
    pub routing_keys: Vec<String>,
}

/// The `accept` value every `DIDCommMessaging` service this workspace generates
/// advertises, in order of preference as the spec defines it: the `didcomm/v2+cbor`
/// profile proposed in
/// [decentralized-identity/didcomm-messaging#463](https://github.com/decentralized-identity/didcomm-messaging/pull/463)
/// (COSE envelopes and CBOR plaintext -- see `didcomm-core::cose`), then plain DIDComm
/// v2 (JSON-encoded JWE envelopes, which every peer understands). A sender picks the
/// first it supports (`didcomm-core`'s `Encoding::for_accept`), so peers without the
/// CBOR profile send JSON.
pub const DIDCOMM_V2_ACCEPT: &[&str] = &["didcomm/v2+cbor", "didcomm/v2"];

/// The `serviceEndpoint` shape of a `DIDCommMessaging` service, mirroring
/// `pydid.service.DIDCommV2Service`.
#[derive(Debug, Clone, Deserialize)]
pub struct DidCommV2ServiceEndpoint {
    pub uri: String,
    #[serde(default)]
    pub accept: Vec<String>,
    #[serde(default, rename = "routingKeys")]
    pub routing_keys: Vec<String>,
}

/// The shape of a DIDComm v1 service, mirroring `pydid.service.DIDCommV1Service`:
/// `serviceEndpoint` is a plain string here (unlike v2's object), and the recipient/
/// routing keys sit directly on the service rather than nested inside the endpoint.
#[derive(Debug, Clone)]
pub struct DidCommV1ServiceEndpoint {
    pub service_endpoint: String,
    /// DID URL references to verification methods -- not yet dereferenced to keys.
    pub recipient_keys: Vec<String>,
    pub routing_keys: Vec<String>,
}

impl Service {
    /// Parse this service's endpoint as a `DIDCommMessaging` (v2) endpoint, if it is
    /// one.
    pub fn didcomm_v2_endpoint(&self) -> Option<DidCommV2ServiceEndpoint> {
        if self.type_ != "DIDCommMessaging" {
            return None;
        }
        serde_json::from_value(self.service_endpoint.clone()).ok()
    }

    /// Parse this service as a DIDComm v1 endpoint, if it is one. `pydid` accepts
    /// `"IndyAgent"`, `"did-communication"`, or even `"DIDCommMessaging"` as a v1
    /// service `type` (the last one overlaps with v2's type string) -- since v1's
    /// `recipientKeys` field is what v2 services never have, requiring it non-empty is
    /// what actually distinguishes the two here rather than the type string alone.
    pub fn didcomm_v1_endpoint(&self) -> Option<DidCommV1ServiceEndpoint> {
        if !matches!(
            self.type_.as_str(),
            "IndyAgent" | "did-communication" | "DIDCommMessaging"
        ) {
            return None;
        }
        if self.recipient_keys.is_empty() {
            return None;
        }
        let service_endpoint = self.service_endpoint.as_str()?.to_string();
        Some(DidCommV1ServiceEndpoint {
            service_endpoint,
            recipient_keys: self.recipient_keys.clone(),
            routing_keys: self.routing_keys.clone(),
        })
    }
}

/// An entry of a verification relationship array (`authentication`, `keyAgreement`,
/// ...): either a reference to a verification method defined elsewhere in the document,
/// or one embedded directly. Mirrors `List[Union[DIDUrl, VerificationMethod]]` in pydid.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum VerificationRelationshipEntry {
    Reference(String),
    Embedded(VerificationMethod),
}

/// A resource a DID URL can dereference to.
#[derive(Debug, Clone)]
pub enum Resource {
    VerificationMethod(VerificationMethod),
    Service(Service),
}

/// A parsed DID Document.
#[derive(Debug, Clone, Deserialize)]
pub struct DidDocument {
    pub id: String,
    #[serde(default, rename = "verificationMethod")]
    pub verification_method: Vec<VerificationMethod>,
    #[serde(default)]
    pub authentication: Vec<VerificationRelationshipEntry>,
    #[serde(default, rename = "assertionMethod")]
    pub assertion_method: Vec<VerificationRelationshipEntry>,
    #[serde(default, rename = "keyAgreement")]
    pub key_agreement: Vec<VerificationRelationshipEntry>,
    #[serde(default, rename = "capabilityInvocation")]
    pub capability_invocation: Vec<VerificationRelationshipEntry>,
    #[serde(default, rename = "capabilityDelegation")]
    pub capability_delegation: Vec<VerificationRelationshipEntry>,
    #[serde(default)]
    pub service: Vec<Service>,
}

impl DidDocument {
    /// Parse a resolved DID Document (as returned by `DIDResolver::resolve`).
    pub fn deserialize(doc: Value) -> Result<Self, DidDocError> {
        Ok(serde_json::from_value(doc)?)
    }

    /// Dereference a DID URL (absolute, e.g. `did:example:abc#key-1`, or a bare
    /// fragment, e.g. `#key-1`) to the verification method or service it identifies.
    ///
    /// Per DID Core, a verification method doesn't have to live in the top-level
    /// `verificationMethod` array at all -- it can be embedded directly inside a
    /// verification relationship array (`authentication`, `keyAgreement`, ...) instead,
    /// with no top-level entry duplicating it. Confirmed live against a real wallet's
    /// own `did:peer:4` document (Credo/AFJ-family): its `#key-1` exists *only* embedded
    /// under `authentication`, no `verificationMethod` array at all, which an earlier
    /// version of this method -- checking only `self.verification_method` -- failed to
    /// dereference at all, breaking every outbound reply to that wallet.
    pub fn dereference(&self, did_url: &str) -> Option<Resource> {
        for vm in &self.verification_method {
            if self.id_matches(&vm.id, did_url) {
                return Some(Resource::VerificationMethod(vm.clone()));
            }
        }
        for relationship in [
            &self.authentication,
            &self.assertion_method,
            &self.key_agreement,
            &self.capability_invocation,
            &self.capability_delegation,
        ] {
            for entry in relationship {
                if let VerificationRelationshipEntry::Embedded(vm) = entry {
                    if self.id_matches(&vm.id, did_url) {
                        return Some(Resource::VerificationMethod(vm.clone()));
                    }
                }
            }
        }
        for service in &self.service {
            if self.id_matches(&service.id, did_url) {
                return Some(Resource::Service(service.clone()));
            }
        }
        None
    }

    /// Dereference a DID URL and require it to be a verification method (resolving
    /// through an embedded reference in a verification relationship array first, if
    /// `did_url` happens to match one of those instead of a top-level
    /// `verificationMethod` entry directly).
    pub fn dereference_verification_method(&self, did_url: &str) -> Option<VerificationMethod> {
        match self.dereference(did_url) {
            Some(Resource::VerificationMethod(vm)) => Some(vm),
            _ => None,
        }
    }

    /// The default key agreement verification method: the first entry of
    /// `keyAgreement`, dereferencing it if it's a reference rather than an embedded key.
    pub fn default_key_agreement(&self) -> Option<VerificationMethod> {
        self.key_agreement.first().and_then(|entry| self.dereference_key_agreement_entry(entry))
    }

    /// Every `keyAgreement` verification method, dereferencing any that are references
    /// rather than embedded keys (an entry that fails to dereference is skipped, not an
    /// error -- the same permissiveness [`Self::default_key_agreement`] already has for
    /// its one entry). Per
    /// [DIDComm Messaging v2.1](https://identity.foundation/didcomm-messaging/spec/v2.1/):
    /// "the default recipients of the envelope SHOULD include all the keyAgreement
    /// entries representing Bob... This allows Bob to decrypt his messages on any
    /// device he controls, without sharing keys across his devices" -- the real
    /// mechanism a multi-device identity needs, one independent key per device, rather
    /// than a single shared one.
    pub fn all_key_agreements(&self) -> Vec<VerificationMethod> {
        self.key_agreement
            .iter()
            .filter_map(|entry| self.dereference_key_agreement_entry(entry))
            .collect()
    }

    fn dereference_key_agreement_entry(
        &self,
        entry: &VerificationRelationshipEntry,
    ) -> Option<VerificationMethod> {
        match entry {
            VerificationRelationshipEntry::Embedded(vm) => Some(vm.clone()),
            VerificationRelationshipEntry::Reference(did_url) => {
                self.dereference_verification_method(did_url)
            }
        }
    }

    /// Find the absolute kid (`did:...#key-N`) of the verification method whose
    /// `publicKeyMultibase` exactly matches `public_key_multibase`, if any is listed in
    /// this document at all (in *any* verification relationship -- `authentication`,
    /// `keyAgreement`, or otherwise). A caller that just minted a document from its own
    /// already-known public key needs this to find out *which* kid that key ended up
    /// as -- `did:peer:4`'s numbering (`#key-1`, `#key-2`, ...) is positional in the
    /// list passed to generate it, so this avoids the caller having to duplicate that
    /// numbering rule itself (fragile the moment key ordering ever changes) by instead
    /// asking the actual resolved document directly.
    pub fn find_verification_method_id_by_public_key(&self, public_key_multibase: &str) -> Option<String> {
        self.verification_method
            .iter()
            .find(|vm| vm.public_key_multibase.as_deref() == Some(public_key_multibase))
            .map(|vm| {
                if vm.id.starts_with('#') {
                    format!("{}{}", self.id, vm.id)
                } else {
                    vm.id.clone()
                }
            })
    }

    /// True if `candidate_id` (a verification method or service `id`, which may be a
    /// bare fragment like `#key-1` or absolute like `did:example:abc#key-1`) is the
    /// same resource as `target` (a DID URL in either form).
    fn id_matches(&self, candidate_id: &str, target: &str) -> bool {
        if candidate_id == target {
            return true;
        }
        let candidate_absolute = if candidate_id.starts_with('#') {
            format!("{}{candidate_id}", self.id)
        } else {
            candidate_id.to_string()
        };
        let target_absolute = if target.starts_with('#') {
            format!("{}{target}", self.id)
        } else {
            target.to_string()
        };
        candidate_absolute == target_absolute
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sample_doc() -> DidDocument {
        DidDocument::deserialize(json!({
            "id": "did:example:abc",
            "verificationMethod": [
                {
                    "id": "#key-1",
                    "type": "Multikey",
                    "controller": "did:example:abc",
                    "publicKeyMultibase": "z6Mk...",
                },
            ],
            "authentication": ["#key-1"],
            "keyAgreement": ["#key-1"],
            "service": [
                {
                    "id": "#service",
                    "type": "DIDCommMessaging",
                    "serviceEndpoint": {
                        "uri": "https://example.com/didcomm",
                        "accept": ["didcomm/v2"],
                        "routingKeys": [],
                    },
                },
            ],
        }))
        .unwrap()
    }

    #[test]
    fn dereferences_by_bare_fragment_and_by_absolute_url() {
        let doc = sample_doc();
        assert!(doc.dereference_verification_method("#key-1").is_some());
        assert!(doc
            .dereference_verification_method("did:example:abc#key-1")
            .is_some());
        assert!(doc.dereference_verification_method("#nope").is_none());
    }

    #[test]
    fn resolves_default_key_agreement_through_a_reference() {
        let doc = sample_doc();
        let vm = doc.default_key_agreement().expect("has a key agreement");
        assert_eq!(vm.public_key_multibase.as_deref(), Some("z6Mk..."));
    }

    /// A real wallet's own `did:peer:4` document (Credo/AFJ-family, confirmed live):
    /// its key exists only *embedded* directly inside `authentication`, with no
    /// top-level `verificationMethod` array at all -- perfectly legal per DID Core,
    /// but broke every outbound reply to that wallet before `dereference` learned to
    /// look inside verification relationship arrays for embedded methods, not just
    /// the top-level list.
    #[test]
    fn dereferences_a_verification_method_embedded_only_in_authentication() {
        let doc = DidDocument::deserialize(json!({
            "id": "did:peer:4zQmExample:zExample",
            "service": [
                {
                    "id": "#inline-0",
                    "type": "did-communication",
                    "serviceEndpoint": "https://mediator.example/didcomm",
                    "recipientKeys": ["#key-1"],
                    "routingKeys": [],
                },
            ],
            "authentication": [
                {
                    "id": "#key-1",
                    "type": "Ed25519VerificationKey2018",
                    "controller": "did:peer:4zQmExample:zExample",
                    "publicKeyBase58": "6bZpV5dhMvatUMCwSMonQaEQRVBPRCNoovpZYMN6RsW4",
                },
            ],
        }))
        .unwrap();

        let vm = doc.dereference_verification_method("#key-1").expect("embedded-only key-1 must dereference");
        assert_eq!(vm.public_key_base58.as_deref(), Some("6bZpV5dhMvatUMCwSMonQaEQRVBPRCNoovpZYMN6RsW4"));
    }

    #[test]
    fn all_key_agreements_returns_every_entry_not_just_the_first() {
        // A multi-device identity's document: one independent keyAgreement entry per
        // device, mixing an embedded key and a by-reference one (both forms this type
        // already supports elsewhere) to prove both dereference correctly here too.
        let doc = DidDocument::deserialize(json!({
            "id": "did:example:multi-device",
            "verificationMethod": [
                {
                    "id": "#key-2",
                    "type": "Multikey",
                    "controller": "did:example:multi-device",
                    "publicKeyMultibase": "z6LSb...",
                },
            ],
            "keyAgreement": [
                {
                    "id": "#key-1",
                    "type": "Multikey",
                    "controller": "did:example:multi-device",
                    "publicKeyMultibase": "z6LSa...",
                },
                "#key-2",
            ],
        }))
        .unwrap();

        let vms = doc.all_key_agreements();
        assert_eq!(vms.len(), 2);
        assert_eq!(vms[0].public_key_multibase.as_deref(), Some("z6LSa..."));
        assert_eq!(vms[1].public_key_multibase.as_deref(), Some("z6LSb..."));
    }

    #[test]
    fn all_key_agreements_is_empty_for_a_document_with_none() {
        let doc = DidDocument::deserialize(json!({
            "id": "did:example:no-key-agreement",
            "verificationMethod": [],
        }))
        .unwrap();
        assert!(doc.all_key_agreements().is_empty());
    }

    #[test]
    fn finds_the_absolute_kid_for_a_known_public_key() {
        let doc = sample_doc();
        assert_eq!(
            doc.find_verification_method_id_by_public_key("z6Mk..."),
            Some("did:example:abc#key-1".to_string()),
        );
    }

    #[test]
    fn finds_none_for_a_public_key_the_document_does_not_list() {
        let doc = sample_doc();
        assert_eq!(doc.find_verification_method_id_by_public_key("z6NotListed..."), None);
    }

    #[test]
    fn reads_a_didcomm_v2_service_endpoint() {
        let doc = sample_doc();
        let endpoint = doc.service[0].didcomm_v2_endpoint().unwrap();
        assert_eq!(endpoint.uri, "https://example.com/didcomm");
        assert_eq!(endpoint.accept, vec!["didcomm/v2"]);
    }

    #[test]
    fn didcomm_v2_accept_advertises_plain_json_first_and_cbor_second() {
        // Order matters for anything that reports "the" preferred encoding by taking
        // the first entry -- plain didcomm/v2 (JSON) is always what every peer is
        // guaranteed to understand, so it stays first.
        assert_eq!(DIDCOMM_V2_ACCEPT, &["didcomm/v2+cbor", "didcomm/v2"]);
    }

    #[test]
    fn reads_a_didcomm_v1_service_endpoint_and_rejects_v2_as_v1() {
        let v1_doc = DidDocument::deserialize(json!({
            "id": "did:example:abc",
            "service": [{
                "id": "#service",
                "type": "did-communication",
                "serviceEndpoint": "https://example.com/didcomm",
                "recipientKeys": ["#key-1"],
                "routingKeys": [],
            }],
        }))
        .unwrap();
        let endpoint = v1_doc.service[0].didcomm_v1_endpoint().unwrap();
        assert_eq!(endpoint.service_endpoint, "https://example.com/didcomm");
        assert_eq!(endpoint.recipient_keys, vec!["#key-1"]);

        // A v2 service has no recipientKeys field at all, so it must not be
        // misidentified as a (malformed) v1 one.
        let v2_doc = sample_doc();
        assert!(v2_doc.service[0].didcomm_v1_endpoint().is_none());
    }
}
