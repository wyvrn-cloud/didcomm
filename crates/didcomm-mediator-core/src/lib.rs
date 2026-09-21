//! A DIDComm v2 mediator *role* -- the receiving/server-side counterpart to
//! `didcomm_core::routing::RoutingService`, which only ever prepares a message to be
//! *sent through* a mediator. Neither this workspace nor the reference
//! `didcomm-messaging-python` library shipped any mediator-role implementation before
//! this crate; both only ever shipped client-side helpers for talking to one
//! (`didcomm_messaging.quickstart.setup_relay`/`fetch_relayed_messages`, mirrored by
//! nothing on this side until now).
//!
//! Implements enough of Aries RFC 0211 (Mediator Coordination) and RFC 0685 (Pickup
//! Protocol) -- specifically the exact message shapes `didcomm_messaging.quickstart`
//! already sends and expects, since that's the interop partner this crate is built to
//! work with -- for a mediated client to: request mediation, register a DID it wants
//! forwarded messages routed to, and poll for and retrieve them. Not implemented:
//! `mediate-deny`, live delivery over a websocket (`messagepickup/3.0/live-delivery-
//! change`), or forwarding through more than one layer of mediator.
//!
//! Transport-agnostic like `didcomm-core` itself: [`MediatorService::handle_message`]
//! takes and returns raw packed-message bytes, so it can be wrapped by any transport
//! (see `didcomm-peer-service` for the HTTP wrapper used in this workspace's own
//! interop testing).
//!
//! # Wire contract
//!
//! - `coordinate-mediation/3.0/mediate-request` (authenticated) -> `mediate-grant` with
//!   `body.routing_did: [<this mediator's DID>]`.
//! - `coordinate-mediation/3.0/recipient-update` (authenticated), `body.updates:
//!   [{recipient_did, action: "add"|"remove"}]` -> `recipient-update-response` with
//!   `body.updated: [{recipient_did, action, result: "success"}]`. Registrations are
//!   owned by whichever authenticated sender DID added them; only that same sender can
//!   remove one, and only that sender's registrations count for pickup below.
//! - `routing/2.0/forward`, `body.next` + `attachments[0].data.json` (the still-packed
//!   inner message, opaque to this crate -- a mediator never sees plaintext) -> queued
//!   for `next` if it's registered to someone, silently dropped otherwise. No reply.
//! - `messagepickup/3.0/status-request` (authenticated) -> `status` with
//!   `body.message_count` summed across all of the sender's registered recipient DIDs.
//! - `messagepickup/3.0/delivery-request` (authenticated), `body.limit` -> `delivery`
//!   with up to `limit` queued messages as `attachments: [{id, data: {json}}]`, oldest
//!   first, popped off the queue (not just peeked).
//! - `messagepickup/3.0/messages-received` (authenticated), `body.message_id_list` ->
//!   removes any already-delivered-but-unacked messages matching those ids. No reply.

use std::collections::HashMap;
use std::sync::RwLock;

use didcomm_core::crypto::{CryptoService, SecretsManager};
use didcomm_core::messaging::{DIDCommMessaging, MessagingError};
use serde_json::{json, Value};

/// Errors handling a message sent to a [`MediatorService`].
#[derive(Debug, thiserror::Error)]
pub enum MediatorError {
    #[error(transparent)]
    Messaging(#[from] MessagingError),
    #[error("invalid message JSON: {0}")]
    Json(#[from] serde_json::Error),
    /// Every message type this crate handles requires authentication (ECDH-1PU) --
    /// the mediator needs to know who it's talking to, both for authorization
    /// (whose registrations are whose) and to know where to send a reply.
    #[error("message must be authenticated (packed with a sender/frm)")]
    Unauthenticated,
    #[error("unsupported message type: {0}")]
    UnsupportedType(String),
    #[error("missing or invalid field: {0}")]
    MissingField(&'static str),
}

struct QueuedMessage {
    id: String,
    packed: Value,
}

#[derive(Default)]
struct State {
    /// recipient_did (a forward message's `body.next`) -> the bare DID of whichever
    /// authenticated sender registered it via `recipient-update`.
    registrations: HashMap<String, String>,
    /// recipient_did -> its pending queue, oldest first.
    queues: HashMap<String, Vec<QueuedMessage>>,
}

/// A DIDComm v2 mediator. Wraps a [`DIDCommMessaging`] (used for this mediator's own
/// pack/unpack, exactly like any other DIDComm participant) with the coordinate-
/// mediation/messagepickup protocol state and logic layered on top.
pub struct MediatorService<C: CryptoService, S: SecretsManager<SecretKey = C::SecretKey>> {
    did: String,
    dmp: DIDCommMessaging<C, S>,
    state: RwLock<State>,
}

impl<C, S> MediatorService<C, S>
where
    C: CryptoService,
    S: SecretsManager<SecretKey = C::SecretKey>,
{
    /// `did` is this mediator's own DID (must resolve to a document whose key
    /// agreement key matches a secret registered in `dmp`'s secrets manager, same as
    /// any other `DIDCommMessaging` participant) -- it's what gets handed out as
    /// `routing_did` in `mediate-grant` replies.
    pub fn new(did: impl Into<String>, dmp: DIDCommMessaging<C, S>) -> Self {
        Self {
            did: did.into(),
            dmp,
            state: RwLock::new(State::default()),
        }
    }

    /// Handle one incoming packed message, returning packed reply bytes if this
    /// message type has a synchronous reply (most do; `routing/2.0/forward` and
    /// `messagepickup/3.0/messages-received` don't).
    pub async fn handle_message(&self, encoded: &[u8]) -> Result<Option<Vec<u8>>, MediatorError> {
        let unpacked = self.dmp.unpack(encoded).await?;
        let message = unpacked.message()?;
        let msg_type = message.get("type").and_then(Value::as_str).unwrap_or_default();

        match msg_type {
            "https://didcomm.org/coordinate-mediation/3.0/mediate-request" => {
                let sender = self.require_sender(&unpacked)?;
                let reply = json!({
                    "type": "https://didcomm.org/coordinate-mediation/3.0/mediate-grant",
                    "body": {"routing_did": [self.did]},
                });
                Ok(Some(self.reply(&sender, reply).await?))
            }
            "https://didcomm.org/coordinate-mediation/3.0/recipient-update" => {
                let sender = self.require_sender(&unpacked)?;
                let updates = message["body"]["updates"]
                    .as_array()
                    .ok_or(MediatorError::MissingField("body.updates"))?;
                let results = self.apply_recipient_updates(&sender, updates)?;

                let reply = json!({
                    "type": "https://didcomm.org/coordinate-mediation/3.0/recipient-update-response",
                    "body": {"updated": results},
                });
                Ok(Some(self.reply(&sender, reply).await?))
            }
            "https://didcomm.org/routing/2.0/forward" => {
                let next = message["body"]["next"]
                    .as_str()
                    .ok_or(MediatorError::MissingField("body.next"))?;
                let packed = message["attachments"]
                    .get(0)
                    .and_then(|a| a["data"]["json"].as_object())
                    .ok_or(MediatorError::MissingField("attachments[0].data.json"))?
                    .clone();
                self.enqueue_forward(next, Value::Object(packed));
                Ok(None)
            }
            "https://didcomm.org/messagepickup/3.0/status-request" => {
                let sender = self.require_sender(&unpacked)?;
                let message_count = self.message_count_for(&sender);
                let reply = json!({
                    "type": "https://didcomm.org/messagepickup/3.0/status",
                    "body": {"message_count": message_count},
                });
                Ok(Some(self.reply(&sender, reply).await?))
            }
            "https://didcomm.org/messagepickup/3.0/delivery-request" => {
                let sender = self.require_sender(&unpacked)?;
                let limit = message["body"]["limit"].as_u64().unwrap_or(10) as usize;
                let attachments = self.take_deliverable(&sender, limit);

                let reply = json!({
                    "type": "https://didcomm.org/messagepickup/3.0/delivery",
                    "body": {},
                    "attachments": attachments,
                });
                Ok(Some(self.reply(&sender, reply).await?))
            }
            "https://didcomm.org/messagepickup/3.0/messages-received" => {
                let sender = self.require_sender(&unpacked)?;
                let ids: Vec<&str> = message["body"]["message_id_list"]
                    .as_array()
                    .map(|a| a.iter().filter_map(Value::as_str).collect())
                    .unwrap_or_default();
                self.ack_delivered(&sender, &ids);
                Ok(None)
            }
            other => Err(MediatorError::UnsupportedType(other.to_string())),
        }
    }

    // Each of the following is a plain synchronous function, deliberately not
    // `async`: `std::sync::RwLock`'s guards are `!Send` (releasing a lock from a
    // different OS thread than the one that acquired it is unsound on some
    // platforms), so a guard must never be alive across an `.await` point. Keeping
    // all lock-holding code inside ordinary function calls -- entirely off the stack
    // by the time the caller in `handle_message` reaches its own next `.await` --
    // sidesteps that rather than relying on precise cross-branch drop timing in one
    // big async match, which rustc's Send-auto-trait inference for generated
    // futures does not always get right (particularly through iterator/closure
    // chains over the guard, as was actually hit while first writing this).

    fn apply_recipient_updates(
        &self,
        sender: &str,
        updates: &[Value],
    ) -> Result<Vec<Value>, MediatorError> {
        let mut results = Vec::with_capacity(updates.len());
        let mut state = self.state.write().expect("lock poisoned");
        for update in updates {
            let recipient_did = update["recipient_did"]
                .as_str()
                .ok_or(MediatorError::MissingField("body.updates[].recipient_did"))?;
            let action = update["action"].as_str().unwrap_or_default();
            match action {
                "add" => {
                    state.registrations.insert(recipient_did.to_string(), sender.to_string());
                }
                "remove" => {
                    if state.registrations.get(recipient_did).map(String::as_str) == Some(sender) {
                        state.registrations.remove(recipient_did);
                    }
                }
                _ => {}
            }
            results.push(json!({
                "recipient_did": recipient_did,
                "action": action,
                "result": "success",
            }));
        }
        Ok(results)
    }

    fn enqueue_forward(&self, next: &str, packed: Value) {
        let mut state = self.state.write().expect("lock poisoned");
        // A recipient the mediator has no registration for is silently dropped --
        // the spec gives the mediator no synchronous reply channel to report that
        // back on anyway (the sender addressed the mediator, not the mediated
        // recipient, and gets no PackResult roundtrip here).
        if state.registrations.contains_key(next) {
            state.queues.entry(next.to_string()).or_default().push(QueuedMessage {
                id: uuid::Uuid::new_v4().to_string(),
                packed,
            });
        }
    }

    fn message_count_for(&self, sender: &str) -> usize {
        let state = self.state.read().expect("lock poisoned");
        state
            .registrations
            .iter()
            .filter(|(_, owner)| owner.as_str() == sender)
            .map(|(recipient_did, _)| state.queues.get(recipient_did).map_or(0, Vec::len))
            .sum()
    }

    fn take_deliverable(&self, sender: &str, limit: usize) -> Vec<Value> {
        let mut state = self.state.write().expect("lock poisoned");
        let owned: Vec<String> = state
            .registrations
            .iter()
            .filter(|(_, owner)| owner.as_str() == sender)
            .map(|(recipient_did, _)| recipient_did.clone())
            .collect();

        let mut attachments = Vec::new();
        for recipient_did in owned {
            if attachments.len() >= limit {
                break;
            }
            if let Some(queue) = state.queues.get_mut(&recipient_did) {
                while attachments.len() < limit && !queue.is_empty() {
                    let msg = queue.remove(0);
                    attachments.push(json!({
                        "id": msg.id,
                        "media_type": "application/didcomm-encrypted+json",
                        "data": {"json": msg.packed},
                    }));
                }
            }
        }
        attachments
    }

    fn ack_delivered(&self, sender: &str, ids: &[&str]) {
        let mut state = self.state.write().expect("lock poisoned");
        let owned: Vec<String> = state
            .registrations
            .iter()
            .filter(|(_, owner)| owner.as_str() == sender)
            .map(|(recipient_did, _)| recipient_did.clone())
            .collect();
        for recipient_did in owned {
            if let Some(queue) = state.queues.get_mut(&recipient_did) {
                queue.retain(|m| !ids.contains(&m.id.as_str()));
            }
        }
    }

    /// The authenticated sender's bare DID (the fragment-free part of `sender_kid`),
    /// or an error if the message wasn't authenticated at all -- every message type
    /// this crate handles needs one, to know whose registrations to act on/reply to.
    fn require_sender(
        &self,
        unpacked: &didcomm_core::messaging::UnpackResult,
    ) -> Result<String, MediatorError> {
        unpacked
            .sender_kid
            .as_deref()
            .map(|kid| kid.split('#').next().unwrap_or(kid).to_string())
            .ok_or(MediatorError::Unauthenticated)
    }

    async fn reply(&self, to: &str, message: Value) -> Result<Vec<u8>, MediatorError> {
        Ok(self.dmp.pack(&message, to, Some(&self.did)).await?.message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use askar_crypto::{
        alg::{ed25519::Ed25519KeyPair, x25519::X25519KeyPair},
        repr::{KeyGen, KeyPublicBytes},
    };
    use didcomm_multiformats::{multicodec, multikey};
    use didcomm_quickstart::{generate_did, setup_default, DefaultDIDCommMessaging, GeneratedDid};
    use didcomm_resolver_peer::KeyPurpose;
    use serde_json::json;

    /// Like `didcomm_quickstart::generate_did`, but with a caller-chosen service
    /// endpoint instead of the quickstart default's `"didcomm:transport/queue"` -- the
    /// same swap `didcomm-peer-service` makes for the same reason (its own doc comment
    /// invites exactly this): a mediated identity's endpoint needs to be the
    /// *mediator's* DID, so a sender's `RoutingService::prepare_forward` recognizes it
    /// as forwardable and wraps the message accordingly.
    fn generate_did_with_endpoint(endpoint_uri: &str) -> GeneratedDid {
        let verification_key = Ed25519KeyPair::random().unwrap();
        let key_agreement_key = X25519KeyPair::random().unwrap();
        let verification_material = multikey::encode(
            multicodec::ED25519_PUB,
            &verification_key.with_public_bytes(<[u8]>::to_vec),
        );
        let key_agreement_material = multikey::encode(
            multicodec::X25519_PUB,
            &key_agreement_key.with_public_bytes(<[u8]>::to_vec),
        );
        let did = didcomm_resolver_peer::generate(
            &[
                (KeyPurpose::Authentication, verification_material.as_str()),
                (KeyPurpose::KeyAgreement, key_agreement_material.as_str()),
            ],
            &[json!({
                "type": "DIDCommMessaging",
                "serviceEndpoint": {"uri": endpoint_uri, "accept": ["didcomm/v2"], "routingKeys": []},
            })],
        )
        .unwrap();
        GeneratedDid { did, verification_key, key_agreement_key }
    }

    fn add_key_agreement_secret(dmp: &DefaultDIDCommMessaging, generated: &GeneratedDid) {
        dmp.secrets.add_secret(didcomm_crypto_askar::AskarSecretKey::new(
            format!("{}#key-2", generated.did),
            generated.key_agreement_key.clone(),
        ));
    }

    #[test]
    fn mediates_a_message_end_to_end_preserving_encryption() {
        pollster::block_on(async {
            // The mediator itself: a normal DIDCommMessaging participant like any other.
            let mediator_generated = generate_did().unwrap();
            let mediator_did = mediator_generated.did.clone();
            let mediator = MediatorService::new(
                mediator_did.clone(),
                setup_default(&mediator_generated),
            );

            // Alice: the sender, entirely unaware a mediator is involved -- she just
            // packs to whatever DID Bob gives her.
            let alice_generated = generate_did().unwrap();
            let alice_dmp = setup_default(&alice_generated);

            // Bob: generates a *control* identity to talk to the mediator with (never
            // shared with Alice), gets mediation granted, then generates a *mediated*
            // identity (shared with Alice) whose endpoint is the mediator's DID.
            let bob_control_generated = generate_did().unwrap();
            let bob_control_did = bob_control_generated.did.clone();
            let bob_dmp = setup_default(&bob_control_generated);

            let mediate_request = json!({
                "type": "https://didcomm.org/coordinate-mediation/3.0/mediate-request",
                "body": {},
            });
            let packed = bob_dmp.pack(&mediate_request, &mediator_did, Some(&bob_control_did)).await.unwrap();
            let reply = mediator.handle_message(&packed.message).await.unwrap().expect("mediate-request gets a reply");
            let unpacked = bob_dmp.unpack(&reply).await.unwrap();
            let grant = unpacked.message().unwrap();
            assert_eq!(grant["type"], "https://didcomm.org/coordinate-mediation/3.0/mediate-grant");
            let routing_did = grant["body"]["routing_did"][0].as_str().unwrap();
            assert_eq!(routing_did, mediator_did);

            let bob_mediated = generate_did_with_endpoint(routing_did);
            let bob_mediated_did = bob_mediated.did.clone();
            add_key_agreement_secret(&bob_dmp, &bob_mediated);

            let recipient_update = json!({
                "type": "https://didcomm.org/coordinate-mediation/3.0/recipient-update",
                "body": {"updates": [{"recipient_did": bob_mediated_did, "action": "add"}]},
            });
            let packed = bob_dmp.pack(&recipient_update, &mediator_did, Some(&bob_control_did)).await.unwrap();
            let reply = mediator.handle_message(&packed.message).await.unwrap().expect("recipient-update gets a reply");
            let unpacked = bob_dmp.unpack(&reply).await.unwrap();
            let update_reply = unpacked.message().unwrap();
            assert_eq!(update_reply["body"]["updated"][0]["result"], "success");

            // Alice packs a real, authenticated message straight to Bob's mediated
            // DID -- she has no idea it's mediated. This should come back wrapped in a
            // routing/2.0/forward envelope, encrypted to the *mediator's* key, since
            // Bob's mediated DID's own service endpoint just points at the mediator.
            let hello = json!({
                "type": "https://didcomm.org/basicmessage/2.0/message",
                "body": {"content": "Hello world!"},
            });
            let packed = alice_dmp.pack(&hello, &bob_mediated_did, Some(&alice_generated.did)).await.unwrap();
            let forward_reply = mediator.handle_message(&packed.message).await.unwrap();
            assert!(forward_reply.is_none(), "a forward has no synchronous reply");

            // Bob checks his mailbox.
            let status_request = json!({
                "type": "https://didcomm.org/messagepickup/3.0/status-request",
                "body": {},
            });
            let packed = bob_dmp.pack(&status_request, &mediator_did, Some(&bob_control_did)).await.unwrap();
            let reply = mediator.handle_message(&packed.message).await.unwrap().unwrap();
            let unpacked = bob_dmp.unpack(&reply).await.unwrap();
            assert_eq!(unpacked.message().unwrap()["body"]["message_count"], 1);

            let delivery_request = json!({
                "type": "https://didcomm.org/messagepickup/3.0/delivery-request",
                "body": {"limit": 10},
            });
            let packed = bob_dmp.pack(&delivery_request, &mediator_did, Some(&bob_control_did)).await.unwrap();
            let reply = mediator.handle_message(&packed.message).await.unwrap().unwrap();
            let unpacked = bob_dmp.unpack(&reply).await.unwrap();
            let delivery = unpacked.message().unwrap();
            let attachments = delivery["attachments"].as_array().unwrap();
            assert_eq!(attachments.len(), 1);
            let delivered_id = attachments[0]["id"].as_str().unwrap().to_string();

            // The mediator only ever relayed an opaque JWE -- Bob decrypts it himself,
            // and the sender_kid proves it really was Alice who encrypted it, end to
            // end, with the mediator never able to see the plaintext.
            let inner_packed = serde_json::to_vec(&attachments[0]["data"]["json"]).unwrap();
            let inner_unpacked = bob_dmp.unpack(&inner_packed).await.unwrap();
            assert_eq!(
                inner_unpacked.message().unwrap()["body"]["content"],
                "Hello world!"
            );
            assert_eq!(
                inner_unpacked.sender_kid.as_deref(),
                Some(format!("{}#key-2", alice_generated.did).as_str())
            );
            assert_eq!(inner_unpacked.recipient_kid, format!("{}#key-2", bob_mediated_did));

            // Ack it, then confirm the mailbox is empty.
            let messages_received = json!({
                "type": "https://didcomm.org/messagepickup/3.0/messages-received",
                "body": {"message_id_list": [delivered_id]},
            });
            let packed = bob_dmp.pack(&messages_received, &mediator_did, Some(&bob_control_did)).await.unwrap();
            assert!(mediator.handle_message(&packed.message).await.unwrap().is_none());

            let packed = bob_dmp.pack(&status_request, &mediator_did, Some(&bob_control_did)).await.unwrap();
            let reply = mediator.handle_message(&packed.message).await.unwrap().unwrap();
            let unpacked = bob_dmp.unpack(&reply).await.unwrap();
            assert_eq!(unpacked.message().unwrap()["body"]["message_count"], 0);
        });
    }

    #[test]
    fn rejects_unauthenticated_control_messages() {
        pollster::block_on(async {
            let mediator_generated = generate_did().unwrap();
            let mediator_did = mediator_generated.did.clone();
            let mediator = MediatorService::new(mediator_did.clone(), setup_default(&mediator_generated));

            let anon_generated = generate_did().unwrap();
            let anon_dmp = setup_default(&anon_generated);

            let mediate_request = json!({
                "type": "https://didcomm.org/coordinate-mediation/3.0/mediate-request",
                "body": {},
            });
            // No `frm` -- anonymous ECDH-ES, not authenticated.
            let packed = anon_dmp.pack(&mediate_request, &mediator_did, None).await.unwrap();
            let err = mediator.handle_message(&packed.message).await.unwrap_err();
            assert!(matches!(err, MediatorError::Unauthenticated));
        });
    }

    #[test]
    fn silently_drops_a_forward_to_an_unregistered_recipient() {
        pollster::block_on(async {
            let mediator_generated = generate_did().unwrap();
            let mediator_did = mediator_generated.did.clone();
            let mediator = MediatorService::new(mediator_did.clone(), setup_default(&mediator_generated));

            let alice_generated = generate_did().unwrap();
            let alice_dmp = setup_default(&alice_generated);

            // Nobody ever registered this DID with the mediator.
            let stranger = generate_did_with_endpoint(&mediator_did);

            let hello = json!({"type": "https://didcomm.org/basicmessage/2.0/message", "body": {}});
            let packed = alice_dmp.pack(&hello, &stranger.did, Some(&alice_generated.did)).await.unwrap();
            let reply = mediator.handle_message(&packed.message).await.unwrap();
            assert!(reply.is_none());
        });
    }
}
