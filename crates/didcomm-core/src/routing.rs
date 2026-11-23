//! `RoutingService`, mirroring `didcomm_messaging.routing`.
//!
//! Prepares a packed message for delivery through zero or more mediators: if a
//! recipient's DID document points straight at an HTTP(S)/etc. endpoint, nothing
//! changes; if it points at another DID (a mediator), the message gets wrapped in one
//! or more `routing/2.0/forward` envelopes, one per mediator, innermost first.

use didcomm_diddoc::DidCommV2ServiceEndpoint;
use serde_json::json;

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
    /// The DIDs a message would be forwarded through go round in a circle, or on
    /// past `MAX_HOPS`: refused rather than followed for ever.
    #[error("the route to {0} loops, or passes through more than {MAX_HOPS} mediators")]
    RouteLoops(String),
    /// A mediator's service lists more than [`MAX_ROUTING_KEYS_PER_HOP`] distinct
    /// routing keys: refused before anything is wrapped (security review WYV-66).
    #[error("{did}'s service lists {count} routing keys; at most {MAX_ROUTING_KEYS_PER_HOP} are followed")]
    TooManyRoutingKeys { did: String, count: usize },
    /// The route to the recipient would wrap the message more than
    /// [`MAX_WRAP_LAYERS`] times: refused before anything is wrapped (WYV-66).
    #[error("the route to {did} wraps the message {layers} times; at most {MAX_WRAP_LAYERS} are made")]
    TooManyWrapLayers { did: String, layers: usize },
    #[error("invalid message JSON while wrapping a forward: {0}")]
    Json(#[from] serde_json::Error),
    #[error("encoding a forward: {0}")]
    Plaintext(#[from] crate::plaintext::PlaintextError),
}

/// The most mediators a message is forwarded through. One is usual, two is a
/// mediator behind another; more is a mistake or someone making a loop.
pub const MAX_HOPS: usize = 4;

/// The most distinct routing keys one hop's service may list. Each is one more
/// `forward` wrapped around the message, about 4/3 its size (security review
/// WYV-66); a real mediator lists none, one or two.
pub const MAX_ROUTING_KEYS_PER_HOP: usize = 4;

/// The most `forward` layers wrapped around one message, every hop's DID and
/// routing keys together: a mediator behind another, each with a couple of keys,
/// is well within it.
pub const MAX_WRAP_LAYERS: usize = 8;

/// The keys a hop wraps the message for, outermost first: the hop's own DID, then
/// its service's `routingKeys` in order, each once -- a repeated key is dropped (its
/// first place kept) rather than refused, since wrapping twice for one key only
/// costs a layer. More than [`MAX_ROUTING_KEYS_PER_HOP`] is refused.
fn hop_keys(did: &str, routing_keys: &[String]) -> Result<Vec<String>, RoutingError> {
    let mut keys = vec![did.to_string()];
    for key in routing_keys {
        if !keys.contains(key) {
            keys.push(key.clone());
        }
    }
    if keys.len() - 1 > MAX_ROUTING_KEYS_PER_HOP {
        return Err(RoutingError::TooManyRoutingKeys { did: did.to_string(), count: keys.len() - 1 });
    }
    Ok(keys)
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
    /// inner forward from an earlier hop) as a `routing/2.0/forward`'s attachment, and
    /// encodes the forward itself as `encoding`'s plaintext. `message` may be either
    /// encoding -- sniffed from its first byte -- and is embedded accordingly:
    /// `data.json` when it's JSON, `data.base64` when it's CBOR, which lands as a raw
    /// `data.binary` byte string in a CBOR forward (see [`crate::plaintext`]).
    fn create_forward_message(
        &self,
        to: &str,
        next_target: &str,
        message: &[u8],
        encoding: crate::crypto::Encoding,
    ) -> Result<Vec<u8>, RoutingError> {
        let (media_type, data) = crate::plaintext::packed_message_attachment_data(message)?;
        // `to` names the forward's recipient as a DID: the spec forbids a fragment
        // there, and a routing key is often a key-agreement DID URL (`did:...#key-1`).
        // `created_time` is the spec's "OPTIONAL but recommended" header, which every
        // other message this library packs gets too (see `HeaderPolicy`).
        let forward = json!({
            "typ": crate::plaintext::PLAIN_JSON_TYP,
            "type": "https://didcomm.org/routing/2.0/forward",
            "id": uuid_v4(),
            "to": [crate::messaging::did_of(to)],
            "created_time": crate::messaging::now_epoch_secs(),
            "body": {"next": next_target},
            "attachments": [{
                "id": uuid_v4(),
                "media_type": media_type,
                "data": data,
            }],
        });
        Ok(crate::plaintext::encode(&forward, encoding)?)
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
        // Each DID once, and only so many: a document naming itself as its own
        // endpoint, or two naming each other, would otherwise go round for ever.
        let mut visited = std::collections::HashSet::from([to.to_string()]);
        while found_forwardable {
            if !visited.insert(to_did.clone()) || chain.len() > MAX_HOPS {
                return Err(RoutingError::RouteLoops(to.to_string()));
            }
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

        let final_destination = chain.remove(0);
        // The recipient's own `routingKeys` (spec, Routing: "loops in reverse order over
        // all items in the routingKeys array of the service endpoint for the DID
        // document that corresponds to the intended recipient"): wrapped for first, so
        // innermost, whether its `uri` is a URL (the common did:peer:2 behind a
        // mediator: `{"uri": "https://...", "r": ["did:key:..."]}`) or a mediator's DID
        // (Endpoint Example 2: the forward to the routing key goes inside the one to
        // the mediator). Capped and de-duplicated like any hop's (WYV-66).
        let recipient_keys = hop_keys(to, &final_destination.services[0].routing_keys)?.split_off(1);
        if chain.is_empty() && recipient_keys.is_empty() {
            return Ok((encoded_message.to_vec(), final_destination.services));
        }

        // The recipient's `accept` is a promise about every publicly visible hop of its
        // inbound route (spec: Profiles), so a hop with no endpoint of its own to ask --
        // typically a `did:key` routing key -- inherits it rather than dropping to JSON.
        let route_encoding = crate::crypto::Encoding::for_accept(&final_destination.services[0].accept);
        let mut next_target = final_destination.did.clone();
        let mut packed_message = encoded_message.to_vec();

        // Every hop's keys, counted before anything is wrapped or resolved (WYV-66).
        let hops = chain
            .iter()
            .map(|entry| hop_keys(&entry.did, &entry.services[0].routing_keys))
            .collect::<Result<Vec<_>, _>>()?;
        let layers: usize = recipient_keys.len() + hops.iter().map(Vec::len).sum::<usize>();
        if layers > MAX_WRAP_LAYERS {
            return Err(RoutingError::TooManyWrapLayers { did: to.to_string(), layers });
        }

        let mut recipient_keys = recipient_keys;
        while let Some(key) = recipient_keys.pop() {
            let encoding = self
                .resolve_services(resolver, &key)
                .await
                .ok()
                .and_then(|services| services.first().map(|s| crate::crypto::Encoding::for_accept(&s.accept)))
                .unwrap_or(route_encoding);
            let forward = self.create_forward_message(&key, &next_target, &packed_message, encoding)?;
            packed_message = packaging
                .pack(crypto, resolver, secrets, &forward, &[key.as_str()], None, encoding)
                .await?;
            next_target = key;
        }
        if chain.is_empty() {
            return Ok((packed_message, final_destination.services));
        }

        for (entry, mut routing_keys) in chain.iter().zip(hops) {
            // https://identity.foundation/didcomm-messaging/spec/#sender-process-to-enable-forwarding
            // Respect routing keys by adding the current DID to the front of the list,
            // then wrapping the message following routing key order (processed in
            // reverse, so the mediator's own DID -- first in the list -- wraps outermost).
            while let Some(key) = routing_keys.pop() {
                // Same per-hop negotiation as DIDCommMessaging::pack, against this
                // specific forward's own recipient (`key`) -- the mediator's own
                // accept list, not the ultimate recipient's, and not necessarily the
                // same encoding `packed_message` (the payload being wrapped) already
                // used; the forward's plaintext uses the same encoding as its own
                // envelope. `entry.services[0]` is already `key`'s resolved endpoint in
                // the common case (no extra `routingKeys`, so `key == entry.did`);
                // anything else gets resolved fresh, falling back to the recipient's
                // own encoding when it has no endpoint to ask.
                let encoding = if key == entry.did {
                    crate::crypto::Encoding::for_accept(&entry.services[0].accept)
                } else {
                    self.resolve_services(resolver, &key)
                        .await
                        .ok()
                        .and_then(|services| {
                            services.first().map(|s| crate::crypto::Encoding::for_accept(&s.accept))
                        })
                        .unwrap_or(route_encoding)
                };
                let forward = self.create_forward_message(&key, &next_target, &packed_message, encoding)?;
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
