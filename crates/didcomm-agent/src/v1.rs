//! DIDComm v1 (the Aries "pack" envelope, RFC 0019) next to v2: the same [`Agent`]
//! sends and receives both. A message is v1 when it carries `@type` instead of `type`;
//! a packed message is v1 when its protected header says `"typ": "JWM/1.0"`.
//!
//! In v1 an agent is addressed by Ed25519 *verkeys* rather than DID URLs. This agent
//! has one: its identity's verification key ([`Agent::v1_verkey`]), and one v1 DID
//! ([`Agent::v1_did`]), a `did:peer:2` whose `did-communication` service lists that
//! key -- the same shape ACA-Py gives its own `did:peer:2`s. Peers are mostly reached
//! through [connections](crate::connections) (DID Exchange), whose records carry the
//! peer's keys and endpoint.

use askar_crypto::alg::ed25519::Ed25519KeyPair;
use askar_crypto::repr::KeyPublicBytes;
use askar_crypto::sign::KeySign;
use base64::Engine as _;
use didcomm_multiformats::{multibase, multicodec, multikey};
use didcomm_resolver_peer::{peer2, KeyPurpose};
use didcomm_v1::messaging::{PackTo, Target};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::agent::{did_of, Agent, AgentError, DidcommVersion, Received, NO_ENDPOINT};

/// The legacy prefix of v1 message types, equivalent to `https://didcomm.org/`.
pub const LEGACY_PREFIX: &str = "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/";
pub const PROBLEM_REPORT_V1: &str = "https://didcomm.org/report-problem/1.0/problem-report";
pub const TRUST_PING_V1: &str = "https://didcomm.org/trust_ping/1.0";
pub const TRUST_PING_V1_PING: &str = "https://didcomm.org/trust_ping/1.0/ping";
pub const TRUST_PING_V1_RESPONSE: &str = "https://didcomm.org/trust_ping/1.0/ping_response";
/// The `typ` of a packed v1 message's protected header.
pub const V1_TYP: &str = "JWM/1.0";
/// The media type v1 messages are POSTed with (RFC 0025).
pub const V1_CONTENT_TYPE: &str = "application/didcomm-envelope-enc";

/// `type` with the legacy `did:sov:...;spec/` prefix replaced by `https://didcomm.org/`,
/// so v1 types compare equal however a peer spells them.
pub fn normalize_type(message_type: &str) -> String {
    match message_type.strip_prefix(LEGACY_PREFIX) {
        Some(rest) => format!("https://didcomm.org/{rest}"),
        None => message_type.to_string(),
    }
}

/// Whether a packed message is DIDComm v1.
pub fn is_v1_packed(packed: &[u8]) -> bool {
    matches!(didcomm_core::jwe::peek_typ(packed), Ok(typ) if typ == V1_TYP)
}

/// Where and how to reach a v1 peer: its verkeys (bare base58), the verkeys of the
/// mediators in front of it, and its endpoint. Serializable, so connection records
/// survive restarts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct V1Service {
    pub recipient_keys: Vec<String>,
    #[serde(default)]
    pub routing_keys: Vec<String>,
    pub endpoint: String,
}

impl V1Service {
    pub(crate) fn target(&self) -> Target {
        Target {
            recipient_keys: self.recipient_keys.clone(),
            routing_keys: self.routing_keys.clone(),
            endpoint: self.endpoint.clone(),
        }
    }
}

/// The `did:key` for an Ed25519 verkey (bare base58).
pub fn verkey_to_did_key(verkey: &str) -> Result<String, AgentError> {
    let bytes = multibase::decode_base58btc(verkey).map_err(|e| AgentError::Key(e.to_string()))?;
    Ok(format!("did:key:{}", multikey::encode(multicodec::ED25519_PUB, &bytes)))
}

/// The verkey (bare base58) in a v1 key reference that needs no DID document: a bare
/// verkey, or a `did:key` (optionally with its `#fragment`). `None` for anything else.
pub fn verkey_from_key_ref(key_ref: &str) -> Option<String> {
    if let Some(rest) = key_ref.strip_prefix("did:key:") {
        let multikey = rest.split('#').next().unwrap_or(rest);
        let (codec, bytes) = multikey::decode(multikey).ok()?;
        return (codec == multicodec::ED25519_PUB).then(|| multibase::encode_base58btc(bytes));
    }
    if key_ref.contains(':') || key_ref.contains('#') {
        return None;
    }
    let bytes = multibase::decode_base58btc(key_ref).ok()?;
    (bytes.len() == 32).then(|| key_ref.to_string())
}

/// The verkey of a verification method (`publicKeyBase58`, an Ed25519 multikey, or a
/// legacy `Ed25519VerificationKey2020` multibase value).
fn verkey_of_method(method: &Value) -> Option<String> {
    if let Some(b58) = method["publicKeyBase58"].as_str() {
        return Some(b58.to_string());
    }
    let multibase_value = method["publicKeyMultibase"].as_str()?;
    if let Ok((codec, bytes)) = multikey::decode(multibase_value) {
        return (codec == multicodec::ED25519_PUB).then(|| multibase::encode_base58btc(bytes));
    }
    let bytes = multibase::decode_self_describing(multibase_value).ok()?;
    (bytes.len() == 32).then(|| multibase::encode_base58btc(bytes))
}

/// A verification method of `doc` by id, matching relative (`#key-1`) and absolute
/// (`did:...#key-1`) spellings on either side. Looks in `verificationMethod` and, for
/// legacy documents, `publicKey`.
fn find_method<'a>(doc: &'a Value, key_ref: &str) -> Option<&'a Value> {
    let fragment = key_ref.rsplit_once('#').map(|(_, f)| f)?;
    ["verificationMethod", "publicKey", "authentication"]
        .iter()
        .flat_map(|field| doc[*field].as_array().into_iter().flatten())
        .filter(|m| m.is_object())
        .find(|m| m["id"].as_str().and_then(|id| id.rsplit_once('#')).map(|(_, f)| f) == Some(fragment))
}

impl Agent {
    /// This agent's DIDComm v1 verkey: its identity's Ed25519 key, base58.
    pub fn v1_verkey(&self) -> String {
        didcomm_v1::kid_for_verkey(self.identity().verification_key())
    }

    /// [`v1_verkey`](Self::v1_verkey) as a `did:key`.
    pub fn v1_did_key(&self) -> String {
        verkey_to_did_key(&self.v1_verkey()).expect("the agent's own verkey is valid base58")
    }

    /// Where v1 peers reach this agent: its v1 mediator's endpoint and routing keys
    /// once [`mediate_v1`](Self::mediate_v1)d, otherwise its own endpoint (possibly
    /// [`NO_ENDPOINT`]: replies then only come back on the connection).
    pub fn v1_service(&self) -> V1Service {
        match self.v1_mediation() {
            Some(m) => V1Service {
                recipient_keys: vec![self.v1_verkey()],
                routing_keys: m.routing_keys,
                endpoint: m.endpoint,
            },
            None => V1Service {
                recipient_keys: vec![self.v1_verkey()],
                routing_keys: vec![],
                endpoint: self.endpoint().to_string(),
            },
        }
    }

    /// Whether v1 peers can send to this agent unprompted (a real endpoint, or a v1
    /// mediator).
    pub fn v1_reachable(&self) -> bool {
        let endpoint = self.v1_service().endpoint;
        endpoint != NO_ENDPOINT && (endpoint.starts_with("http") || endpoint.starts_with("ws"))
    }

    /// This agent's v1 DID: a `did:peer:2` with its Ed25519 key (`#key-1`), its X25519
    /// key (`#key-2`) and one `did-communication` service for [`v1_service`](Self::v1_service).
    /// Changes when the service does (after [`mediate_v1`](Self::mediate_v1)).
    pub fn v1_did(&self) -> String {
        let service = self.v1_service();
        let routing_keys: Vec<String> = service
            .routing_keys
            .iter()
            .filter_map(|k| verkey_to_did_key(k).ok())
            .map(|did| {
                let fragment = did.trim_start_matches("did:key:").to_string();
                format!("{did}#{fragment}")
            })
            .collect();
        let identity = self.identity();
        let verification = multikey::encode(
            multicodec::ED25519_PUB,
            &identity.verification_key().with_public_bytes(<[u8]>::to_vec),
        );
        let key_agreement = multikey::encode(
            multicodec::X25519_PUB,
            &identity.key_agreement_key().with_public_bytes(<[u8]>::to_vec),
        );
        peer2::generate(
            &[(KeyPurpose::Authentication, &verification), (KeyPurpose::KeyAgreement, &key_agreement)],
            &[json!({
                "id": "#didcomm-0",
                "type": "did-communication",
                "priority": 0,
                "recipientKeys": ["#key-1"],
                "routingKeys": routing_keys,
                "serviceEndpoint": service.endpoint,
            })],
        )
        .expect("a did:peer:2 of valid keys and a JSON service always encodes")
    }

    /// The v1 service in a DID document: the first `did-communication`, `IndyAgent` or
    /// `DIDCommMessaging` service with `recipientKeys` (lowest `priority` first), its
    /// key references dereferenced to verkeys.
    pub async fn v1_service_of_doc(&self, doc: &Value) -> Result<V1Service, AgentError> {
        let did = doc["id"].as_str().unwrap_or_default().to_string();
        let mut services: Vec<&Value> = doc["service"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|s| matches!(s["type"].as_str(), Some("did-communication" | "IndyAgent" | "DIDCommMessaging")))
            .filter(|s| s["recipientKeys"].as_array().is_some_and(|k| !k.is_empty()))
            .collect();
        services.sort_by_key(|s| s["priority"].as_i64().unwrap_or(0));
        let service = services.first().ok_or_else(|| AgentError::NoV1Service(did.clone()))?;

        let endpoint = match &service["serviceEndpoint"] {
            Value::String(uri) => uri.clone(),
            other => other["uri"].as_str().ok_or_else(|| AgentError::NoV1Service(did.clone()))?.to_string(),
        };
        let mut recipient_keys = Vec::new();
        for key_ref in service["recipientKeys"].as_array().into_iter().flatten().filter_map(Value::as_str) {
            recipient_keys.push(self.dereference_v1_key(doc, key_ref).await?);
        }
        let mut routing_keys = Vec::new();
        for key_ref in service["routingKeys"].as_array().into_iter().flatten().filter_map(Value::as_str) {
            routing_keys.push(self.dereference_v1_key(doc, key_ref).await?);
        }
        Ok(V1Service { recipient_keys, routing_keys, endpoint })
    }

    /// Resolve `did` and find its v1 service ([`v1_service_of_doc`](Self::v1_service_of_doc)).
    pub async fn resolve_v1_service(&self, did: &str) -> Result<V1Service, AgentError> {
        let doc = self.v1_messaging().resolver.resolve(did).await.map_err(|e| AgentError::Resolution(e.to_string()))?;
        self.v1_service_of_doc(&doc).await
    }

    async fn dereference_v1_key(&self, doc: &Value, key_ref: &str) -> Result<String, AgentError> {
        if let Some(verkey) = verkey_from_key_ref(key_ref) {
            return Ok(verkey);
        }
        let doc_did = doc["id"].as_str().unwrap_or_default();
        let unresolved = || AgentError::Key(format!("can't dereference key {key_ref}"));
        if key_ref.starts_with('#') || did_of(key_ref) == doc_did {
            return find_method(doc, key_ref).and_then(verkey_of_method).ok_or_else(unresolved);
        }
        let other = self
            .v1_messaging()
            .resolver
            .resolve(did_of(key_ref))
            .await
            .map_err(|e| AgentError::Resolution(e.to_string()))?;
        find_method(&other, key_ref).and_then(verkey_of_method).ok_or_else(unresolved)
    }

    /// Pack a v1 `message` from this agent's verkey for `service` (forward-wrapped for
    /// each routing key) and POST it. Returns what came back on the connection.
    /// Gives the message an `@id` if it has none (v1 messages must have one).
    pub async fn send_v1(&self, service: &V1Service, message: &Value) -> Result<Option<Received>, AgentError> {
        let mut message = message.clone();
        message
            .as_object_mut()
            .ok_or(AgentError::NotAnObject)?
            .entry("@id")
            .or_insert_with(|| json!(uuid::Uuid::new_v4().to_string()));
        let bytes = serde_json::to_vec(&message).map_err(|e| AgentError::Key(e.to_string()))?;
        let packed = self
            .v1_messaging()
            .pack(&bytes, PackTo::Target(service.target()), Some(&self.v1_verkey()))
            .await?;
        if !packed.target_endpoint.starts_with("http") {
            return Err(AgentError::NoHttpEndpoint(packed.target_endpoint));
        }
        self.post(&packed.target_endpoint, V1_CONTENT_TYPE, packed.message).await
    }

    /// Unpack a v1 message.
    pub(crate) async fn receive_v1(&self, packed: &[u8]) -> Result<Received, AgentError> {
        let unpacked = self.v1_messaging().unpack(packed).await?;
        let message = unpacked.message().map_err(|e| AgentError::Key(e.to_string()))?;
        let sender = match &unpacked.sender_kid {
            Some(key) => self.connection_by_key(key).and_then(|c| c.their_did),
            None => None,
        };
        let received = Received {
            message,
            sender,
            recipient_kid: unpacked.recipient_kid,
            version: DidcommVersion::V1,
            sender_key: unpacked.sender_kid,
        };
        self.note_activity(&received);
        Ok(received)
    }

    /// Pack a v1 reply straight to `received`'s sender key, for its connection.
    pub(crate) fn pack_reply_v1(&self, received: &Received, reply: &Value) -> Result<Vec<u8>, AgentError> {
        let to = received.sender_key.as_deref().ok_or(AgentError::NoReturnAddress)?;
        let to = Ed25519KeyPair::from_public_bytes(
            &multibase::decode_base58btc(to).map_err(|e| AgentError::Key(e.to_string()))?,
        )
        .map_err(|e| AgentError::Key(e.to_string()))?;
        let from = didcomm_v1::packaging::V1SecretKey::new(self.identity().verification_key().clone());
        let bytes = serde_json::to_vec(reply).map_err(|e| AgentError::Key(e.to_string()))?;
        Ok(self.v1_messaging().packaging.pack(&[to], Some(&from), &bytes)?)
    }

    /// An attachment of `data`, signed by this agent's verkey the way Aries signs
    /// `did_doc~attach` and `did_rotate~attach` (RFC 0017): a JWS over the base64url
    /// payload, with the key as a `did:key` `kid` and an `OKP` `jwk`.
    pub fn signed_attachment(&self, data: &[u8], mime_type: &str) -> Value {
        let did_key = self.v1_did_key();
        let key = self.identity().verification_key();
        let x = multibase::encode(key.with_public_bytes(<[u8]>::to_vec));
        let protected = json!({
            "alg": "EdDSA",
            "kid": did_key,
            "jwk": {"kty": "OKP", "crv": "Ed25519", "x": x, "kid": did_key},
        });
        let protected_b64 = multibase::encode(protected.to_string());
        let signing_input = format!("{protected_b64}.{}", multibase::encode(data));
        let signature = key
            .create_signature(signing_input.as_bytes(), None)
            .expect("an Ed25519 keypair with its secret always signs");
        json!({
            "@id": uuid::Uuid::new_v4().to_string(),
            "mime-type": mime_type,
            "data": {
                "base64": base64::engine::general_purpose::STANDARD.encode(data),
                "jws": {
                    "header": {"kid": did_key},
                    "protected": protected_b64,
                    "signature": multibase::encode(signature.as_ref()),
                },
            },
        })
    }
}

/// The data of an attachment (`data.base64`, `data.json`), checking its JWS if it has
/// one. With `signer`, the attachment must be signed, by that verkey. Returns the data
/// and the verkey that signed it, if any.
pub fn verify_attachment(attachment: &Value, signer: Option<&str>) -> Result<(Vec<u8>, Option<String>), AgentError> {
    let invalid = |why: &str| AgentError::Attachment(why.to_string());
    let data = &attachment["data"];
    let bytes = if data["json"].is_object() || data["json"].is_array() {
        serde_json::to_vec(&data["json"]).map_err(|e| invalid(&e.to_string()))?
    } else {
        let b64 = data["base64"].as_str().ok_or_else(|| invalid("no data.base64 or data.json"))?;
        decode_any_base64(b64).ok_or_else(|| invalid("data.base64 isn't base64"))?
    };

    let jws = &data["jws"];
    if !jws.is_object() {
        return match signer {
            Some(_) => Err(invalid("not signed")),
            None => Ok((bytes, None)),
        };
    }
    let protected_b64 = jws["protected"].as_str().ok_or_else(|| invalid("JWS without protected header"))?;
    let protected: Value = multibase::decode(protected_b64)
        .ok()
        .and_then(|p| serde_json::from_slice(&p).ok())
        .ok_or_else(|| invalid("JWS protected header isn't base64url JSON"))?;
    let verkey = [&jws["header"]["kid"], &protected["kid"]]
        .into_iter()
        .filter_map(Value::as_str)
        .find_map(verkey_from_key_ref)
        .or_else(|| {
            let x = multibase::decode(protected["jwk"]["x"].as_str()?).ok()?;
            Some(multibase::encode_base58btc(x))
        })
        .ok_or_else(|| invalid("JWS names no Ed25519 key"))?;
    if let Some(expected) = signer {
        if verkey != expected {
            return Err(invalid(&format!("signed by {verkey}, expected {expected}")));
        }
    }
    let key = Ed25519KeyPair::from_public_bytes(&multibase::decode_base58btc(&verkey).map_err(|e| invalid(&e.to_string()))?)
        .map_err(|e| invalid(&e.to_string()))?;
    let signature = multibase::decode(jws["signature"].as_str().ok_or_else(|| invalid("JWS without signature"))?)
        .map_err(|e| invalid(&e.to_string()))?;
    let signing_input = format!("{protected_b64}.{}", multibase::encode(&bytes));
    if !key.verify_signature(signing_input.as_bytes(), &signature) {
        return Err(invalid("bad signature"));
    }
    Ok((bytes, Some(verkey)))
}

/// Standard or URL-safe base64, padded or not.
pub(crate) fn decode_any_base64(value: &str) -> Option<Vec<u8>> {
    let url_safe: String = value.trim_end_matches('=').replace('+', "-").replace('/', "_");
    multibase::decode(url_safe).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Identity;

    #[test]
    fn legacy_types_normalize_to_didcomm_org() {
        assert_eq!(
            normalize_type("did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/trust_ping/1.0/ping"),
            TRUST_PING_V1_PING
        );
        assert_eq!(normalize_type(TRUST_PING_V1_PING), TRUST_PING_V1_PING);
    }

    #[test]
    fn key_refs_without_a_document() {
        let agent = Agent::new(Identity::generate().unwrap()).unwrap();
        let verkey = agent.v1_verkey();
        let did_key = agent.v1_did_key();
        let fragment = did_key.trim_start_matches("did:key:");
        assert_eq!(verkey_from_key_ref(&verkey).as_deref(), Some(verkey.as_str()));
        assert_eq!(verkey_from_key_ref(&did_key).as_deref(), Some(verkey.as_str()));
        assert_eq!(verkey_from_key_ref(&format!("{did_key}#{fragment}")).as_deref(), Some(verkey.as_str()));
        assert_eq!(verkey_from_key_ref("#key-1"), None);
    }

    #[test]
    fn signed_attachments_verify_and_name_their_signer() {
        let agent = Agent::new(Identity::generate().unwrap()).unwrap();
        let attachment = agent.signed_attachment(b"did:peer:2.example", "text/string");

        let (data, signer) = verify_attachment(&attachment, Some(&agent.v1_verkey())).unwrap();
        assert_eq!(data, b"did:peer:2.example");
        assert_eq!(signer.as_deref(), Some(agent.v1_verkey().as_str()));

        let other = Agent::new(Identity::generate().unwrap()).unwrap();
        assert!(verify_attachment(&attachment, Some(&other.v1_verkey())).is_err());

        let mut tampered = attachment.clone();
        tampered["data"]["base64"] = json!(base64::engine::general_purpose::STANDARD.encode(b"did:peer:2.other"));
        assert!(verify_attachment(&tampered, None).is_err());
    }

    #[tokio::test]
    async fn the_v1_did_resolves_to_the_agents_v1_service() {
        let agent = Agent::with_endpoint(Identity::generate().unwrap(), "https://agent.example/").unwrap();
        let service = agent.resolve_v1_service(&agent.v1_did()).await.unwrap();
        assert_eq!(service, agent.v1_service());
        assert_eq!(service.endpoint, "https://agent.example/");
        assert_eq!(service.recipient_keys, [agent.v1_verkey()]);
    }
}
