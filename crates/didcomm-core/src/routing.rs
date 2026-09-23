//! `RoutingService`, mirroring `didcomm_messaging.routing`.
//!
//! Prepares a packed message for delivery through zero or more mediators: if a
//! recipient's DID document points straight at an HTTP(S)/etc. endpoint, nothing
//! changes; if it points at another DID (a mediator), the message gets wrapped in one
//! or more `routing/2.0/forward` envelopes, one per mediator, innermost first.

use didcomm_diddoc::DidCommV2ServiceEndpoint;
use serde_json::{json, Value};

use crate::crypto::{CryptoService, SecretsManager};
use crate::packaging::{PackagingError, PackagingService};
use crate::resolver::{DIDResolver, ResolutionError};

/// Errors preparing a message for forwarding.
#[derive(Debug, thiserror::Error)]
pub enum RoutingError {
    #[error(transparent)]
    Resolution(#[from] ResolutionError),
    #[error(transparent)]
    Packaging(#[from] PackagingError),
    #[error("no DIDCommV2 service endpoint found for {0}")]
    NoServiceEndpoint(String),
    #[error("invalid message JSON while wrapping a forward: {0}")]
    Json(#[from] serde_json::Error),
}

/// One hop of the resolved mediator chain: a DID and the `DIDCommMessaging` services
/// its document advertises.
struct ChainEntry {
    did: String,
    services: Vec<DidCommV2ServiceEndpoint>,
}

/// Prepares packed messages for delivery through mediators. Mirrors
/// `didcomm_messaging.routing.RoutingService`.
#[derive(Debug, Default, Clone, Copy)]
pub struct RoutingService;

impl RoutingService {
    /// Resolve `to`'s `DIDCommMessaging` service endpoints that advertise plain
    /// `didcomm/v2` support (any that don't are filtered out, matching what a sender
    /// could actually use them for). `pub` so `DIDCommMessaging::pack` can inspect the
    /// same resolved endpoint's `accept` list for content negotiation (choosing
    /// `didcomm/v2+cbor` over JSON) before this same resolution happens again as part
    /// of [`prepare_forward`](Self::prepare_forward) -- not merged into one call since
    /// `pack` needs the answer *before* packing, while forwarding only matters
    /// afterward.
    pub async fn resolve_services(
        &self,
        resolver: &dyn DIDResolver,
        to: &str,
    ) -> Result<Vec<DidCommV2ServiceEndpoint>, RoutingError> {
        if !resolver.is_resolvable(to).await {
            return Ok(Vec::new());
        }
        let doc = resolver.resolve_and_parse(to).await?;
        Ok(doc
            .service
            .iter()
            .filter_map(|s| s.didcomm_v2_endpoint())
            .filter(|e| e.accept.iter().any(|a| a == "didcomm/v2"))
            .collect())
    }

    /// Whether a service's URI is itself another DID we should forward through, rather
    /// than a final transport endpoint (http, ws, ...).
    async fn is_forwardable_service(
        &self,
        resolver: &dyn DIDResolver,
        service: &DidCommV2ServiceEndpoint,
    ) -> bool {
        resolver.is_resolvable(&service.uri).await
    }

    /// Wraps `message` (the already-packed bytes addressed to the real recipient, or an
    /// inner forward from an earlier hop) as a `routing/2.0/forward`'s attachment.
    /// `message` may be either encoding (JSON or CBOR) -- sniffed from its first byte,
    /// same convention as [`didcomm_core::jwe::peek_typ`] -- and embedded accordingly:
    /// `data.json` (parsed and inlined) when it's JSON, `data.base64` (the standard
    /// DIDComm attachment shape for an opaque binary payload) when it's CBOR, since a
    /// CBOR envelope generally isn't valid UTF-8 and can't be inlined as JSON at all.
    fn create_forward_message(
        &self,
        to: &str,
        next_target: &str,
        message: &[u8],
    ) -> Result<Vec<u8>, RoutingError> {
        let (media_type, data) = if message.first() == Some(&b'{') {
            let message_json: Value = serde_json::from_slice(message)?;
            ("application/didcomm-encrypted+json", json!({"json": message_json}))
        } else {
            (
                "application/didcomm-encrypted+cbor",
                json!({"base64": didcomm_multiformats::multibase::encode(message)}),
            )
        };
        let forward = json!({
            "typ": "application/didcomm-plain+json",
            "type": "https://didcomm.org/routing/2.0/forward",
            "id": uuid_v4(),
            "to": [to],
            "body": {"next": next_target},
            "attachments": [{
                "id": uuid_v4(),
                "media_type": media_type,
                "data": data,
            }],
        });
        Ok(serde_json::to_vec(&forward)?)
    }

    /// Prepare a message for forwarding, if necessary. Returns the (possibly
    /// forward-wrapped) message and the services to actually deliver it to.
    pub async fn prepare_forward<C, S>(
        &self,
        crypto: &C,
        packaging: &PackagingService,
        resolver: &dyn DIDResolver,
        secrets: &S,
        to: &str,
        encoded_message: &[u8],
    ) -> Result<(Vec<u8>, Vec<DidCommV2ServiceEndpoint>), RoutingError>
    where
        C: CryptoService,
        S: SecretsManager<SecretKey = C::SecretKey>,
    {
        let services = self.resolve_services(resolver, to).await?;
        // Python indexes services[0] unconditionally here and lets an empty list raise
        // an IndexError -- bailing cleanly instead, since that's an implementation
        // accident to reproduce, not part of the wire protocol.
        let Some(first) = services.first().cloned() else {
            return Err(RoutingError::NoServiceEndpoint(to.to_string()));
        };
        let mut chain = vec![ChainEntry {
            did: to.to_string(),
            services,
        }];

        let mut to_did = first.uri.clone();
        let mut found_forwardable = self.is_forwardable_service(resolver, &first).await;
        while found_forwardable {
            let services = self.resolve_services(resolver, &to_did).await?;
            found_forwardable = match services.first() {
                Some(s) => self.is_forwardable_service(resolver, s).await,
                None => false,
            };
            if let Some(first) = services.first() {
                let next_to_did = first.uri.clone();
                chain.push(ChainEntry {
                    did: to_did,
                    services,
                });
                to_did = next_to_did;
            }
        }

        if chain.last().is_some_and(|e| e.services.is_empty()) {
            return Err(RoutingError::NoServiceEndpoint(to.to_string()));
        }

        if chain.len() == 1 {
            return Ok((encoded_message.to_vec(), chain.pop().unwrap().services));
        }

        let final_destination = chain.remove(0);
        let mut next_target = final_destination.did;
        let mut packed_message = encoded_message.to_vec();

        for entry in &chain {
            // https://identity.foundation/didcomm-messaging/spec/#sender-process-to-enable-forwarding
            // Respect routing keys by adding the current DID to the front of the list,
            // then wrapping the message following routing key order (processed in
            // reverse, so the mediator's own DID -- prepended last -- wraps outermost).
            let mut routing_keys = entry.services[0].routing_keys.clone();
            routing_keys.insert(0, entry.did.clone());

            while let Some(key) = routing_keys.pop() {
                let forward = self.create_forward_message(&key, &next_target, &packed_message)?;
                // Same per-hop negotiation as DIDCommMessaging::pack, against this
                // specific forward's own recipient (`key`) -- the mediator's own
                // accept list, not the ultimate recipient's, and not necessarily the
                // same encoding `packed_message` (the payload being wrapped) already
                // used. `entry.services[0]` is already `key`'s resolved endpoint in the
                // common case (no extra `routingKeys`, so `key == entry.did`); anything
                // else gets resolved fresh, same fallback-to-JSON-on-failure as pack.
                let encoding = if key == entry.did {
                    crate::crypto::Encoding::for_accept(&entry.services[0].accept)
                } else {
                    self.resolve_services(resolver, &key)
                        .await
                        .ok()
                        .and_then(|services| {
                            services.first().map(|s| crate::crypto::Encoding::for_accept(&s.accept))
                        })
                        .unwrap_or_default()
                };
                packed_message = packaging
                    .pack(crypto, resolver, secrets, &forward, &[key.as_str()], None, encoding)
                    .await?;
                next_target = key;
            }
        }

        let target_services = chain.last().unwrap().services.clone();
        Ok((packed_message, target_services))
    }
}

fn uuid_v4() -> String {
    uuid::Uuid::new_v4().to_string()
}
