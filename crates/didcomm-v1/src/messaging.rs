//! `V1DIDCommMessaging`, mirroring `didcomm_messaging.v1.messaging`: the DID-based
//! layer on top of [`V1PackagingService`] -- resolving a recipient DID to its
//! `recipientKeys`/`routingKeys` (DIDComm v1's own service shape, see
//! [`didcomm_diddoc::Service::didcomm_v1_endpoint`]) and wrapping in
//! `routing/1.0/forward` envelopes per mediator hop, the v1 equivalent of what
//! [`didcomm_core::routing::RoutingService`] does for v2 (a different, older wire
//! format, but the same idea: wrap once per layer of mediation).

use askar_crypto::{alg::ed25519::Ed25519KeyPair, repr::KeyPublicBytes};
use didcomm_core::crypto::{multikey_bytes_from_verification_method, SecretsManager};
use didcomm_core::resolver::{DIDResolver, ResolutionError};
use didcomm_diddoc::{DidDocError, DidDocument, VerificationMethod};
use didcomm_multiformats::multibase;
use serde_json::{json, Value};

use crate::packaging::{V1PackagingService, V1SecretKey, V1UnpackResult};
use crate::V1Error;

/// Errors from [`V1DIDCommMessaging::pack`]/[`unpack`](V1DIDCommMessaging::unpack).
#[derive(Debug, thiserror::Error)]
pub enum V1MessagingError {
    #[error(transparent)]
    Resolution(#[from] ResolutionError),
    #[error(transparent)]
    DidDoc(#[from] DidDocError),
    #[error(transparent)]
    Crypto(#[from] didcomm_core::crypto::CryptoServiceError),
    #[error(transparent)]
    V1(#[from] V1Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Askar(#[from] askar_crypto::Error),
    #[error(transparent)]
    Multibase(#[from] multibase::DecodeError),
    #[error("unable to send message to DID {0}: no DIDComm v1 service found")]
    NoV1Service(String),
    #[error("unable to send message to endpoint {0}")]
    UnsupportedEndpoint(String),
    #[error("no sender key found for kid {0}")]
    NoSenderKey(String),
}

/// Resolved recipient information for sending a v1 message, mirroring `Target` in
/// Python. `recipient_keys`/`routing_keys` are already-dereferenced kids (bare base58
/// verkeys), not DID URLs.
#[derive(Debug, Clone)]
pub struct Target {
    pub recipient_keys: Vec<String>,
    pub routing_keys: Vec<String>,
    pub endpoint: String,
}

/// Either a DID to resolve, or an already-resolved [`Target`] (e.g. cached from an
/// earlier resolution) -- mirrors Python's `Union[str, Target]` parameter to `pack`.
pub enum PackTo<'a> {
    Did(&'a str),
    Target(Target),
}

/// The result of packing a v1 message: the bytes to send, and the endpoint to send
/// them to.
#[derive(Debug, Clone)]
pub struct V1PackResult {
    pub message: Vec<u8>,
    pub target_endpoint: String,
}

fn local_vm_ref_to_v1_kid(doc: &DidDocument, ref_: &str) -> Result<String, V1MessagingError> {
    let vm = doc
        .dereference_verification_method(ref_)
        .ok_or_else(|| V1MessagingError::NoV1Service(ref_.to_string()))?;
    vm_to_v1_kid(&vm)
}

fn vm_to_v1_kid(vm: &VerificationMethod) -> Result<String, V1MessagingError> {
    let key_bytes = multikey_bytes_from_verification_method(vm)
        .map_err(didcomm_core::crypto::CryptoServiceError::from)?;
    Ok(multibase::encode_base58btc(key_bytes))
}

async fn routing_key_to_kid(
    resolver: &dyn DIDResolver,
    doc: &DidDocument,
    routing_key: &str,
) -> Result<String, V1MessagingError> {
    let is_local = routing_key.starts_with('#')
        || routing_key.split('#').next() == Some(doc.id.as_str());
    let vm = if is_local {
        doc.dereference_verification_method(routing_key)
            .ok_or_else(|| V1MessagingError::NoV1Service(routing_key.to_string()))?
    } else {
        resolver
            .resolve_and_dereference_verification_method(routing_key)
            .await?
    };
    vm_to_v1_kid(&vm)
}

async fn did_to_target(resolver: &dyn DIDResolver, did: &str) -> Result<Target, V1MessagingError> {
    let doc = resolver.resolve_and_parse(did).await?;
    let service = doc
        .service
        .iter()
        .find_map(|s| s.didcomm_v1_endpoint())
        .ok_or_else(|| V1MessagingError::NoV1Service(did.to_string()))?;

    let recipient_keys = service
        .recipient_keys
        .iter()
        .map(|r| local_vm_ref_to_v1_kid(&doc, r))
        .collect::<Result<Vec<_>, _>>()?;

    let mut routing_keys = Vec::with_capacity(service.routing_keys.len());
    for routing_key in &service.routing_keys {
        routing_keys.push(routing_key_to_kid(resolver, &doc, routing_key).await?);
    }

    let endpoint = service.service_endpoint;
    if !endpoint.starts_with("http") && !endpoint.starts_with("ws") {
        return Err(V1MessagingError::UnsupportedEndpoint(endpoint));
    }

    Ok(Target {
        recipient_keys,
        routing_keys,
        endpoint,
    })
}

fn kid_to_public_key(kid: &str) -> Result<Ed25519KeyPair, V1MessagingError> {
    let bytes = multibase::decode_base58btc(kid)?;
    Ok(Ed25519KeyPair::from_public_bytes(&bytes)?)
}

fn forward_wrap(to: &str, message: &[u8]) -> Result<Vec<u8>, V1MessagingError> {
    let message_json: Value = serde_json::from_slice(message)?;
    let forward = json!({
        "@id": uuid::Uuid::new_v4().to_string(),
        "@type": "https://didcomm.org/routing/1.0/forward",
        "to": to,
        "msg": message_json,
    });
    Ok(serde_json::to_vec(&forward)?)
}

/// Main entry point for DIDComm v1 messaging, mirroring `V1DIDCommMessaging`: owns a
/// resolver and delegates crypto/secrets to a [`V1PackagingService`].
pub struct V1DIDCommMessaging<S: SecretsManager<SecretKey = V1SecretKey>> {
    pub secrets: S,
    pub resolver: Box<dyn DIDResolver>,
    pub packaging: V1PackagingService,
}

impl<S: SecretsManager<SecretKey = V1SecretKey>> V1DIDCommMessaging<S> {
    pub fn new(secrets: S, resolver: Box<dyn DIDResolver>) -> Self {
        Self {
            secrets,
            resolver,
            packaging: V1PackagingService,
        }
    }

    /// Pack a message for `to` (a DID to resolve, or an already-resolved [`Target`]),
    /// optionally authenticated by `frm` (a DID or a bare kid).
    pub async fn pack(
        &self,
        message: &[u8],
        to: PackTo<'_>,
        frm: Option<&str>,
    ) -> Result<V1PackResult, V1MessagingError> {
        let target = match to {
            PackTo::Did(did) => did_to_target(self.resolver.as_ref(), did).await?,
            PackTo::Target(target) => target,
        };

        let sender_kid = match frm {
            Some(frm) if frm.starts_with("did:") => {
                let sender_target = did_to_target(self.resolver.as_ref(), frm).await?;
                Some(
                    sender_target
                        .recipient_keys
                        .into_iter()
                        .next()
                        .ok_or_else(|| V1MessagingError::NoV1Service(frm.to_string()))?,
                )
            }
            Some(frm) => Some(frm.to_string()),
            None => None,
        };
        let sender_secret = match &sender_kid {
            Some(kid) => Some(
                self.secrets
                    .get_secret_by_kid(kid)
                    .await
                    .ok_or_else(|| V1MessagingError::NoSenderKey(kid.clone()))?,
            ),
            None => None,
        };

        let recipient_keys = target
            .recipient_keys
            .iter()
            .map(|k| kid_to_public_key(k))
            .collect::<Result<Vec<_>, _>>()?;
        let mut packed = self
            .packaging
            .pack(&recipient_keys, sender_secret.as_ref(), message)?;

        if !target.routing_keys.is_empty() {
            let mut forward_to = target.recipient_keys[0].clone();
            for routing_key in &target.routing_keys {
                let wrapped = forward_wrap(&forward_to, &packed)?;
                let key = kid_to_public_key(routing_key)?;
                packed = self.packaging.pack(&[key], None, &wrapped)?;
                forward_to = routing_key.clone();
            }
        }

        Ok(V1PackResult {
            message: packed,
            target_endpoint: target.endpoint,
        })
    }

    /// Unpack a received v1 message.
    pub async fn unpack(&self, encoded_message: &[u8]) -> Result<V1UnpackResult, V1MessagingError> {
        Ok(self.packaging.unpack(&self.secrets, encoded_message).await?)
    }
}
