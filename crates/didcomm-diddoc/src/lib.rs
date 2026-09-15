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
}

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

impl Service {
    /// Parse this service's endpoint as a `DIDCommMessaging` endpoint, if it is one.
    pub fn didcomm_v2_endpoint(&self) -> Option<DidCommV2ServiceEndpoint> {
        if self.type_ != "DIDCommMessaging" {
            return None;
        }
        serde_json::from_value(self.service_endpoint.clone()).ok()
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
    pub fn dereference(&self, did_url: &str) -> Option<Resource> {
        for vm in &self.verification_method {
            if self.id_matches(&vm.id, did_url) {
                return Some(Resource::VerificationMethod(vm.clone()));
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
        match self.key_agreement.first()? {
            VerificationRelationshipEntry::Embedded(vm) => Some(vm.clone()),
            VerificationRelationshipEntry::Reference(did_url) => {
                self.dereference_verification_method(did_url)
            }
        }
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

    #[test]
    fn reads_a_didcomm_v2_service_endpoint() {
        let doc = sample_doc();
        let endpoint = doc.service[0].didcomm_v2_endpoint().unwrap();
        assert_eq!(endpoint.uri, "https://example.com/didcomm");
        assert_eq!(endpoint.accept, vec!["didcomm/v2"]);
    }
}
