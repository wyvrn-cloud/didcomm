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
//! change`), or forwarding through more than one layer of mediator. This crate is
//! deliberately kept this minimal -- it exists to prove the wire protocol works end to
//! end and to back this workspace's own interop harness. A separate, full-featured
//! production mediator (SQL storage, WebSocket live delivery, additional protocol
//! versions, horizontal scaling) is built as its own project on top of the traits
//! below, rather than growing this crate into one.
//!
//! Transport-agnostic like `didcomm-core` itself: [`MediatorService::handle_message`]
//! takes and returns raw packed-message bytes, so it can be wrapped by any transport
//! (see `didcomm-peer-service` for the HTTP wrapper used in this workspace's own
//! interop testing).
//!
//! # Storage
//!
//! Registration and queue state live behind two `#[async_trait]` traits,
//! [`RegistrationStore`] and [`MessageQueueStore`] -- the same "swappable backend"
//! convention `didcomm-core` already uses for `DIDResolver`/`CryptoService`/
//! `SecretsManager`. [`MediatorService::new`] uses the in-memory implementations
//! included in this crate ([`InMemoryRegistrationStore`], [`InMemoryQueueStore`]);
//! [`MediatorService::with_stores`] accepts any other implementation (e.g. a
//! SQL-backed one), for anyone wanting persistent, shared-across-instances state
//! without forking this crate's protocol-handling logic.
//!
//! # Wire contract
//!
//! - `coordinate-mediation/3.0/mediate-request` (authenticated) -> `mediate-grant` with
//!   `body.routing_did: [<this mediator's DID>]`.
//! - `coordinate-mediation/3.0/recipient-update` (authenticated), `body.updates:
//!   [{recipient_did, action: "add"|"remove"}]` -> `recipient-update-response` with
//!   `body.updated: [{recipient_did, action, result: "success"|"failed"}]`.
//!   Registrations are owned by whichever authenticated sender DID added them; only
//!   that same sender can remove one, and only that sender's registrations count for
//!   pickup below. An `"add"` for a `recipient_did` already owned by a *different*
//!   sender is refused (`result: "failed"`), not silently reassigned -- a
//!   `recipient_did` is a public address (handed out to contacts), not a secret, so
//!   nothing else stops an unrelated authenticated sender from claiming someone
//!   else's already-registered one otherwise.
//! - `routing/2.0/forward`, `body.next` + `attachments[0].data.json` or `.data.base64`
//!   (the still-packed inner message, JSON or the wyvrn-original `didcomm/v2+cbor`
//!   profile respectively, opaque to this crate either way -- a mediator never sees
//!   plaintext) -> queued for `next` if it's registered to someone, silently dropped
//!   otherwise. No reply.
//! - `messagepickup/3.0/status-request` (authenticated) -> `status` with
//!   `body.message_count` summed across all of the sender's registered recipient DIDs.
//! - `messagepickup/3.0/delivery-request` (authenticated), `body.limit` -> `delivery`
//!   with up to `limit` queued messages as `attachments: [{id, data: {json} or
//!   {base64}}]` (same encoding-dependent shape as the forward above), oldest first,
//!   popped off the queue (not just peeked).
//! - `messagepickup/3.0/messages-received` (authenticated), `body.message_id_list` ->
//!   removes any already-delivered-but-unacked messages matching those ids. No reply.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use async_trait::async_trait;
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
    #[error(transparent)]
    Store(#[from] StoreError),
}

/// An error from a [`RegistrationStore`] or [`MessageQueueStore`] implementation
/// (e.g. a database error from a persistent backend). The in-memory implementations
/// in this crate never actually produce one.
#[derive(Debug)]
pub struct StoreError(Box<dyn std::error::Error + Send + Sync>);

impl StoreError {
    pub fn other(err: impl std::error::Error + Send + Sync + 'static) -> Self {
        StoreError(Box::new(err))
    }
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for StoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.0.as_ref())
    }
}

/// One queued forward message, as stored for/returned by a [`MessageQueueStore`].
/// `packed` is the exact wire bytes of the still-packed inner message (JSON or CBOR --
/// see `didcomm-core::jwe`'s module docs), opaque to this crate either way.
#[derive(Debug, Clone)]
pub struct QueuedMessage {
    pub id: String,
    pub packed: Vec<u8>,
}

/// The result of a [`RegistrationStore::register`] attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegisterOutcome {
    /// `recipient_did` was unclaimed, or already owned by this same `owner` -- it's
    /// now registered (or renewed) to `owner`.
    Registered,
    /// `recipient_did` is already owned by a *different* sender. Registration
    /// refused; the existing owner's claim is untouched.
    AlreadyOwnedByOther,
}

/// Tracks which authenticated sender DID owns (registered) each recipient DID a
/// forward message might name in `body.next`. Registrations are per-owner: only the
/// sender who added one can remove it, and only that sender's registrations count
/// toward their own pickup operations.
#[async_trait]
pub trait RegistrationStore: Send + Sync {
    /// Register `recipient_did` as owned by `owner`, unless it's already owned by a
    /// *different* sender -- a `recipient_did` is a public address (handed out to
    /// contacts), not a secret, so without this check any authenticated sender could
    /// silently steal someone else's already-registered one. Re-registering your own
    /// existing `recipient_did` is a renewal, not a conflict, and succeeds (clearing
    /// any TTL previously set via [`Self::touch`] -- callers wanting one re-establish
    /// it afterward).
    async fn register(&self, owner: &str, recipient_did: &str) -> Result<RegisterOutcome, StoreError>;
    /// Remove a registration, but only if `owner` actually owns it -- a no-op
    /// otherwise (including if it doesn't exist at all).
    async fn unregister(&self, owner: &str, recipient_did: &str) -> Result<(), StoreError>;
    /// The owner of `recipient_did`, if it's registered to anyone.
    async fn owner_of(&self, recipient_did: &str) -> Result<Option<String>, StoreError>;
    /// Every recipient DID currently registered to `owner`.
    async fn registered_to(&self, owner: &str) -> Result<Vec<String>, StoreError>;

    /// Set `recipient_did`'s expiry to `ttl_ms` from now, for a store that
    /// tracks contact lifecycle -- a no-op (not an error) if `recipient_did`
    /// isn't registered, or if this implementation doesn't track TTLs at all
    /// (the default here). Meant to be called on registration and on other
    /// signs of activity from the owning sender, to keep an active contact's
    /// registration alive.
    async fn touch(&self, _recipient_did: &str, _ttl_ms: i64) -> Result<(), StoreError> {
        Ok(())
    }
    /// Remove every registration whose TTL (set via [`Self::touch`]) has
    /// passed; returns how many were removed. A no-op returning `0` for a
    /// store that doesn't track TTLs (the default here). Meant to be driven
    /// by a periodic sweep task, not called on every read.
    async fn sweep_expired(&self) -> Result<usize, StoreError> {
        Ok(0)
    }
}

/// Per-recipient-DID queues of forward messages waiting to be picked up.
/// `didcomm-mediator-core` never inspects `packed` -- it's an opaque, still-encrypted
/// inner message, exactly as received in the forward's attachment.
#[async_trait]
pub trait MessageQueueStore: Send + Sync {
    /// Append a message to `recipient_did`'s queue, assigning it a fresh id.
    async fn enqueue(&self, recipient_did: &str, packed: Vec<u8>) -> Result<(), StoreError>;
    /// How many messages are currently queued for `recipient_did`.
    async fn count(&self, recipient_did: &str) -> Result<usize, StoreError>;
    /// Remove and return up to `limit` messages for `recipient_did`, oldest first.
    async fn take(
        &self,
        recipient_did: &str,
        limit: usize,
    ) -> Result<Vec<QueuedMessage>, StoreError>;
    /// Remove any of `recipient_did`'s queued messages matching one of `ids` (a
    /// `messagepickup/3.0/messages-received` ack for already-delivered messages).
    async fn ack(&self, recipient_did: &str, ids: &[&str]) -> Result<(), StoreError>;
}

struct RegistrationEntry {
    owner: String,
    expires_at_ms: Option<i64>,
}

/// The default, in-memory [`RegistrationStore`] -- this crate's original
/// storage, plus [`RegistrationStore::touch`]/[`RegistrationStore::sweep_expired`]
/// support (tracked alongside each entry, not a separate/parallel structure that
/// could drift out of sync with it). Not persistent, not shared across
/// instances; fine for tests and the minimal interop harness this crate is
/// built for.
#[derive(Default)]
pub struct InMemoryRegistrationStore {
    registrations: RwLock<HashMap<String, RegistrationEntry>>,
}

#[async_trait]
impl RegistrationStore for InMemoryRegistrationStore {
    async fn register(&self, owner: &str, recipient_did: &str) -> Result<RegisterOutcome, StoreError> {
        let mut registrations = self.registrations.write().expect("lock poisoned");
        if let Some(existing) = registrations.get(recipient_did) {
            if existing.owner != owner {
                return Ok(RegisterOutcome::AlreadyOwnedByOther);
            }
        }
        registrations.insert(
            recipient_did.to_string(),
            RegistrationEntry {
                owner: owner.to_string(),
                expires_at_ms: None,
            },
        );
        Ok(RegisterOutcome::Registered)
    }

    async fn unregister(&self, owner: &str, recipient_did: &str) -> Result<(), StoreError> {
        let mut registrations = self.registrations.write().expect("lock poisoned");
        if registrations.get(recipient_did).map(|e| e.owner.as_str()) == Some(owner) {
            registrations.remove(recipient_did);
        }
        Ok(())
    }

    async fn owner_of(&self, recipient_did: &str) -> Result<Option<String>, StoreError> {
        Ok(self
            .registrations
            .read()
            .expect("lock poisoned")
            .get(recipient_did)
            .map(|e| e.owner.clone()))
    }

    async fn registered_to(&self, owner: &str) -> Result<Vec<String>, StoreError> {
        Ok(self
            .registrations
            .read()
            .expect("lock poisoned")
            .iter()
            .filter(|(_, e)| e.owner.as_str() == owner)
            .map(|(recipient_did, _)| recipient_did.clone())
            .collect())
    }

    async fn touch(&self, recipient_did: &str, ttl_ms: i64) -> Result<(), StoreError> {
        if let Some(entry) = self
            .registrations
            .write()
            .expect("lock poisoned")
            .get_mut(recipient_did)
        {
            entry.expires_at_ms = Some(now_ms() + ttl_ms);
        }
        Ok(())
    }

    async fn sweep_expired(&self) -> Result<usize, StoreError> {
        let now = now_ms();
        let mut registrations = self.registrations.write().expect("lock poisoned");
        let before = registrations.len();
        registrations.retain(|_, entry| entry.expires_at_ms.is_none_or(|e| e > now));
        Ok(before - registrations.len())
    }
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock is before the unix epoch")
        .as_millis() as i64
}

/// One client's current FCM push-registration state -- see
/// `push-notifications-fcm/1.0` (Aries RFC 0734, adopted as-is; verified directly
/// against the OpenWallet Foundation's `didcomm-mediator-credo` reference
/// implementation, not just the RFC text -- see `wyvrn-protocols`' own copy of this
/// protocol's readme for the full reasoning). Both fields are `None` together
/// (unregistered) or `Some` together -- never one without the other, mirroring the
/// wire protocol's own both-or-neither-null rule on `set-device-info`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FcmDeviceInfo {
    pub device_token: Option<String>,
    pub device_platform: Option<String>,
}

/// Tracks each recipient DID's current FCM registration -- a much smaller surface
/// than [`RegistrationStore`] (no ownership/TTL concerns; a client can only ever set
/// its own registration in the first place, since it's keyed by the same
/// authenticated sender the message itself already establishes).
#[async_trait]
pub trait FcmDeviceStore: Send + Sync {
    /// Replaces whatever was stored for `recipient_did` -- last-write-wins, per the
    /// protocol's own "one registration per client, not a fan-out" design. Passing
    /// [`FcmDeviceInfo::default()`] (both fields `None`) clears any existing
    /// registration, the wire protocol's own unregister convention.
    async fn set(&self, recipient_did: &str, info: FcmDeviceInfo) -> Result<(), StoreError>;
    /// The current registration for `recipient_did`, or the default (both fields
    /// `None`) if it was never set or has since been cleared.
    async fn get(&self, recipient_did: &str) -> Result<FcmDeviceInfo, StoreError>;
}

/// The default, in-memory [`FcmDeviceStore`]. Not persistent, not shared across
/// instances -- fine for tests; `wyvrn-mediator-storage-sea` provides the real,
/// persistent implementation a production deployment actually needs.
#[derive(Default)]
pub struct InMemoryFcmDeviceStore {
    devices: RwLock<HashMap<String, FcmDeviceInfo>>,
}

#[async_trait]
impl FcmDeviceStore for InMemoryFcmDeviceStore {
    async fn set(&self, recipient_did: &str, info: FcmDeviceInfo) -> Result<(), StoreError> {
        self.devices
            .write()
            .expect("lock poisoned")
            .insert(recipient_did.to_string(), info);
        Ok(())
    }

    async fn get(&self, recipient_did: &str) -> Result<FcmDeviceInfo, StoreError> {
        Ok(self
            .devices
            .read()
            .expect("lock poisoned")
            .get(recipient_did)
            .cloned()
            .unwrap_or_default())
    }
}

/// The default, in-memory [`MessageQueueStore`] -- exactly this crate's original
/// storage, just behind the trait now.
#[derive(Default)]
pub struct InMemoryQueueStore {
    queues: RwLock<HashMap<String, Vec<QueuedMessage>>>,
}

#[async_trait]
impl MessageQueueStore for InMemoryQueueStore {
    async fn enqueue(&self, recipient_did: &str, packed: Vec<u8>) -> Result<(), StoreError> {
        self.queues
            .write()
            .expect("lock poisoned")
            .entry(recipient_did.to_string())
            .or_default()
            .push(QueuedMessage {
                id: uuid::Uuid::new_v4().to_string(),
                packed,
            });
        Ok(())
    }

    async fn count(&self, recipient_did: &str) -> Result<usize, StoreError> {
        Ok(self
            .queues
            .read()
            .expect("lock poisoned")
            .get(recipient_did)
            .map_or(0, Vec::len))
    }

    async fn take(
        &self,
        recipient_did: &str,
        limit: usize,
    ) -> Result<Vec<QueuedMessage>, StoreError> {
        let mut queues = self.queues.write().expect("lock poisoned");
        Ok(match queues.get_mut(recipient_did) {
            Some(queue) => {
                let n = limit.min(queue.len());
                queue.drain(0..n).collect()
            }
            None => Vec::new(),
        })
    }

    async fn ack(&self, recipient_did: &str, ids: &[&str]) -> Result<(), StoreError> {
        if let Some(queue) = self
            .queues
            .write()
            .expect("lock poisoned")
            .get_mut(recipient_did)
        {
            queue.retain(|m| !ids.contains(&m.id.as_str()));
        }
        Ok(())
    }
}

/// Extracts the raw packed bytes from an attachment's `data`, in either shape a sender
/// might use: `data.json` (a parsed JSON object, re-serialized back to bytes) for a
/// JSON-encoded inner message, or `data.base64` (multibase/base64url-decoded directly,
/// matching how `didcomm_core::routing::RoutingService::create_forward_message` encodes
/// it) for a CBOR-encoded one -- a CBOR envelope generally isn't valid UTF-8 and can't
/// be inlined as `data.json` at all. Used both for `routing/2.0/forward`'s own
/// attachment and, symmetrically, for building a pickup `delivery` reply's attachments
/// (see [`build_delivery_attachment`]).
fn extract_attachment_payload(attachment: &Value) -> Option<Vec<u8>> {
    if let Some(obj) = attachment["data"]["json"].as_object() {
        return serde_json::to_vec(obj).ok();
    }
    if let Some(b64) = attachment["data"]["base64"].as_str() {
        return didcomm_multiformats::multibase::decode(b64).ok();
    }
    None
}

/// The inverse of [`extract_attachment_payload`]: builds one pickup `delivery` (or
/// forward) attachment for already-packed `bytes`, sniffing their first byte the same
/// way `didcomm_core::jwe::peek_typ` does to choose `data.json` (JSON) or `data.base64`
/// (CBOR).
fn build_delivery_attachment(id: &str, bytes: &[u8]) -> Value {
    let (media_type, data) = if bytes.first() == Some(&b'{') {
        let parsed: Value = serde_json::from_slice(bytes).unwrap_or(Value::Null);
        ("application/didcomm-encrypted+json", json!({"json": parsed}))
    } else {
        (
            "application/didcomm-encrypted+cbor",
            json!({"base64": didcomm_multiformats::multibase::encode(bytes)}),
        )
    };
    json!({"id": id, "media_type": media_type, "data": data})
}

/// A DIDComm v2 mediator. Wraps a [`DIDCommMessaging`] (used for this mediator's own
/// pack/unpack, exactly like any other DIDComm participant) with the coordinate-
/// mediation/messagepickup protocol state and logic layered on top.
pub struct MediatorService<C: CryptoService, S: SecretsManager<SecretKey = C::SecretKey>> {
    did: String,
    dmp: DIDCommMessaging<C, S>,
    registrations: Arc<dyn RegistrationStore>,
    queues: Arc<dyn MessageQueueStore>,
}

impl<C, S> MediatorService<C, S>
where
    C: CryptoService,
    S: SecretsManager<SecretKey = C::SecretKey>,
{
    /// `did` is this mediator's own DID (must resolve to a document whose key
    /// agreement key matches a secret registered in `dmp`'s secrets manager, same as
    /// any other `DIDCommMessaging` participant) -- it's what gets handed out as
    /// `routing_did` in `mediate-grant` replies. Uses the in-memory stores; see
    /// [`Self::with_stores`] to plug in a different backend.
    pub fn new(did: impl Into<String>, dmp: DIDCommMessaging<C, S>) -> Self {
        Self::with_stores(
            did,
            dmp,
            Arc::new(InMemoryRegistrationStore::default()),
            Arc::new(InMemoryQueueStore::default()),
        )
    }

    /// Like [`Self::new`], but with explicit [`RegistrationStore`]/
    /// [`MessageQueueStore`] implementations -- for a persistent, shared-across-
    /// instances backend instead of the in-memory default.
    pub fn with_stores(
        did: impl Into<String>,
        dmp: DIDCommMessaging<C, S>,
        registrations: Arc<dyn RegistrationStore>,
        queues: Arc<dyn MessageQueueStore>,
    ) -> Self {
        Self {
            did: did.into(),
            dmp,
            registrations,
            queues,
        }
    }

    /// Handle one incoming packed message, returning packed reply bytes if this
    /// message type has a synchronous reply (most do; `routing/2.0/forward` and
    /// `messagepickup/3.0/messages-received` don't).
    pub async fn handle_message(&self, encoded: &[u8]) -> Result<Option<Vec<u8>>, MediatorError> {
        let unpacked = self.dmp.unpack(encoded).await?;
        let message = unpacked.message()?;
        let msg_type = message
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or_default();

        match msg_type {
            "https://didcomm.org/coordinate-mediation/3.0/mediate-request" => {
                let sender = self.require_sender(&unpacked)?;
                let reply = json!({
                    "type": "https://didcomm.org/coordinate-mediation/3.0/mediate-grant",
                    "body": {"routing_did": [self.did]},
                });
                Ok(Some(self.reply(&sender, &message, reply).await?))
            }
            "https://didcomm.org/coordinate-mediation/3.0/recipient-update" => {
                let sender = self.require_sender(&unpacked)?;
                let updates = message["body"]["updates"]
                    .as_array()
                    .ok_or(MediatorError::MissingField("body.updates"))?;

                let mut results = Vec::with_capacity(updates.len());
                for update in updates {
                    let recipient_did = update["recipient_did"]
                        .as_str()
                        .ok_or(MediatorError::MissingField("body.updates[].recipient_did"))?;
                    let action = update["action"].as_str().unwrap_or_default();
                    let result = match action {
                        "add" => match self.registrations.register(&sender, recipient_did).await? {
                            RegisterOutcome::Registered => "success",
                            RegisterOutcome::AlreadyOwnedByOther => "failed",
                        },
                        "remove" => {
                            self.registrations
                                .unregister(&sender, recipient_did)
                                .await?;
                            "success"
                        }
                        _ => "success",
                    };
                    results.push(json!({
                        "recipient_did": recipient_did,
                        "action": action,
                        "result": result,
                    }));
                }

                let reply = json!({
                    "type": "https://didcomm.org/coordinate-mediation/3.0/recipient-update-response",
                    "body": {"updated": results},
                });
                Ok(Some(self.reply(&sender, &message, reply).await?))
            }
            "https://didcomm.org/routing/2.0/forward" => {
                let next = message["body"]["next"]
                    .as_str()
                    .ok_or(MediatorError::MissingField("body.next"))?;
                let attachment = message["attachments"]
                    .get(0)
                    .ok_or(MediatorError::MissingField("attachments[0]"))?;
                let packed = extract_attachment_payload(attachment)
                    .ok_or(MediatorError::MissingField("attachments[0].data.json or .data.base64"))?;
                // A recipient the mediator has no registration for is silently
                // dropped -- the spec gives the mediator no synchronous reply
                // channel to report that back on anyway (the sender addressed the
                // mediator, not the mediated recipient, and gets no PackResult
                // roundtrip here).
                if self.registrations.owner_of(next).await?.is_some() {
                    self.queues.enqueue(next, packed).await?;
                }
                Ok(None)
            }
            "https://didcomm.org/messagepickup/3.0/status-request" => {
                let sender = self.require_sender(&unpacked)?;
                let mut message_count = 0;
                for recipient_did in self.registrations.registered_to(&sender).await? {
                    message_count += self.queues.count(&recipient_did).await?;
                }
                let reply = json!({
                    "type": "https://didcomm.org/messagepickup/3.0/status",
                    "body": {"message_count": message_count},
                });
                Ok(Some(self.reply(&sender, &message, reply).await?))
            }
            "https://didcomm.org/messagepickup/3.0/delivery-request" => {
                let sender = self.require_sender(&unpacked)?;
                let limit = message["body"]["limit"].as_u64().unwrap_or(10) as usize;

                let mut attachments = Vec::new();
                for recipient_did in self.registrations.registered_to(&sender).await? {
                    if attachments.len() >= limit {
                        break;
                    }
                    let remaining = limit - attachments.len();
                    for msg in self.queues.take(&recipient_did, remaining).await? {
                        attachments.push(build_delivery_attachment(&msg.id, &msg.packed));
                    }
                }

                let reply = json!({
                    "type": "https://didcomm.org/messagepickup/3.0/delivery",
                    "body": {},
                    "attachments": attachments,
                });
                Ok(Some(self.reply(&sender, &message, reply).await?))
            }
            "https://didcomm.org/messagepickup/3.0/messages-received" => {
                let sender = self.require_sender(&unpacked)?;
                let ids: Vec<&str> = message["body"]["message_id_list"]
                    .as_array()
                    .map(|a| a.iter().filter_map(Value::as_str).collect())
                    .unwrap_or_default();
                for recipient_did in self.registrations.registered_to(&sender).await? {
                    self.queues.ack(&recipient_did, &ids).await?;
                }
                Ok(None)
            }
            other => Err(MediatorError::UnsupportedType(other.to_string())),
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

    /// Pack `reply` to `to`, threaded onto `request`'s thread (its `thid`, or its `id`
    /// if it started the thread) -- the spec requires a message continuing a thread to
    /// carry `thid`.
    async fn reply(&self, to: &str, request: &Value, mut reply: Value) -> Result<Vec<u8>, MediatorError> {
        if let Some(thid) = request.get("thid").or_else(|| request.get("id")).filter(|v| v.is_string()) {
            reply["thid"] = thid.clone();
        }
        Ok(self.dmp.pack(&reply, to, Some(&self.did)).await?.message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use didcomm_quickstart::{
        generate_did, generate_did_with_endpoint, setup_default, DefaultDIDCommMessaging, GeneratedDid,
    };
    use serde_json::json;

    fn add_key_agreement_secret(dmp: &DefaultDIDCommMessaging, generated: &GeneratedDid) {
        dmp.secrets
            .add_secret(didcomm_crypto_askar::AskarSecretKey::new(
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
            let mediator =
                MediatorService::new(mediator_did.clone(), setup_default(&mediator_generated));

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
            let packed = bob_dmp
                .pack(&mediate_request, &mediator_did, Some(&bob_control_did))
                .await
                .unwrap();
            let reply = mediator
                .handle_message(&packed.message)
                .await
                .unwrap()
                .expect("mediate-request gets a reply");
            let unpacked = bob_dmp.unpack(&reply).await.unwrap();
            let grant = unpacked.message().unwrap();
            assert_eq!(
                grant["type"],
                "https://didcomm.org/coordinate-mediation/3.0/mediate-grant"
            );
            let routing_did = grant["body"]["routing_did"][0].as_str().unwrap();
            assert_eq!(routing_did, mediator_did);

            let bob_mediated = generate_did_with_endpoint(routing_did).unwrap();
            let bob_mediated_did = bob_mediated.did.clone();
            add_key_agreement_secret(&bob_dmp, &bob_mediated);

            let recipient_update = json!({
                "type": "https://didcomm.org/coordinate-mediation/3.0/recipient-update",
                "body": {"updates": [{"recipient_did": bob_mediated_did, "action": "add"}]},
            });
            let packed = bob_dmp
                .pack(&recipient_update, &mediator_did, Some(&bob_control_did))
                .await
                .unwrap();
            let reply = mediator
                .handle_message(&packed.message)
                .await
                .unwrap()
                .expect("recipient-update gets a reply");
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
            let packed = alice_dmp
                .pack(&hello, &bob_mediated_did, Some(&alice_generated.did))
                .await
                .unwrap();
            let forward_reply = mediator.handle_message(&packed.message).await.unwrap();
            assert!(
                forward_reply.is_none(),
                "a forward has no synchronous reply"
            );

            // Bob checks his mailbox.
            let status_request = json!({
                "type": "https://didcomm.org/messagepickup/3.0/status-request",
                "body": {},
            });
            let packed = bob_dmp
                .pack(&status_request, &mediator_did, Some(&bob_control_did))
                .await
                .unwrap();
            let reply = mediator
                .handle_message(&packed.message)
                .await
                .unwrap()
                .unwrap();
            let unpacked = bob_dmp.unpack(&reply).await.unwrap();
            assert_eq!(unpacked.message().unwrap()["body"]["message_count"], 1);

            let delivery_request = json!({
                "type": "https://didcomm.org/messagepickup/3.0/delivery-request",
                "body": {"limit": 10},
            });
            let packed = bob_dmp
                .pack(&delivery_request, &mediator_did, Some(&bob_control_did))
                .await
                .unwrap();
            let reply = mediator
                .handle_message(&packed.message)
                .await
                .unwrap()
                .unwrap();
            let unpacked = bob_dmp.unpack(&reply).await.unwrap();
            let delivery = unpacked.message().unwrap();
            let attachments = delivery["attachments"].as_array().unwrap();
            assert_eq!(attachments.len(), 1);
            let delivered_id = attachments[0]["id"].as_str().unwrap().to_string();

            // The mediator only ever relayed an opaque JWE -- Bob decrypts it himself,
            // and the sender_kid proves it really was Alice who encrypted it, end to
            // end, with the mediator never able to see the plaintext. Bob's own
            // generated identity advertises didcomm/v2+cbor, so Alice's direct pack to
            // him negotiates it -- the attachment lands in data.base64, not data.json,
            // hence reusing the real extraction helper rather than assuming a shape.
            let inner_packed = extract_attachment_payload(&attachments[0]).unwrap();
            let inner_unpacked = bob_dmp.unpack(&inner_packed).await.unwrap();
            assert_eq!(
                inner_unpacked.message().unwrap()["body"]["content"],
                "Hello world!"
            );
            assert_eq!(
                inner_unpacked.sender_kid.as_deref(),
                Some(format!("{}#key-2", alice_generated.did).as_str())
            );
            assert_eq!(
                inner_unpacked.recipient_kid,
                format!("{}#key-2", bob_mediated_did)
            );

            // Ack it, then confirm the mailbox is empty.
            let messages_received = json!({
                "type": "https://didcomm.org/messagepickup/3.0/messages-received",
                "body": {"message_id_list": [delivered_id]},
            });
            let packed = bob_dmp
                .pack(&messages_received, &mediator_did, Some(&bob_control_did))
                .await
                .unwrap();
            assert!(mediator
                .handle_message(&packed.message)
                .await
                .unwrap()
                .is_none());

            let packed = bob_dmp
                .pack(&status_request, &mediator_did, Some(&bob_control_did))
                .await
                .unwrap();
            let reply = mediator
                .handle_message(&packed.message)
                .await
                .unwrap()
                .unwrap();
            let unpacked = bob_dmp.unpack(&reply).await.unwrap();
            assert_eq!(unpacked.message().unwrap()["body"]["message_count"], 0);
        });
    }

    #[test]
    fn rejects_unauthenticated_control_messages() {
        pollster::block_on(async {
            let mediator_generated = generate_did().unwrap();
            let mediator_did = mediator_generated.did.clone();
            let mediator =
                MediatorService::new(mediator_did.clone(), setup_default(&mediator_generated));

            let anon_generated = generate_did().unwrap();
            let anon_dmp = setup_default(&anon_generated);

            let mediate_request = json!({
                "type": "https://didcomm.org/coordinate-mediation/3.0/mediate-request",
                "body": {},
            });
            // No `frm` -- anonymous ECDH-ES, not authenticated.
            let packed = anon_dmp
                .pack(&mediate_request, &mediator_did, None)
                .await
                .unwrap();
            let err = mediator.handle_message(&packed.message).await.unwrap_err();
            assert!(matches!(err, MediatorError::Unauthenticated));
        });
    }

    #[test]
    fn silently_drops_a_forward_to_an_unregistered_recipient() {
        pollster::block_on(async {
            let mediator_generated = generate_did().unwrap();
            let mediator_did = mediator_generated.did.clone();
            let mediator =
                MediatorService::new(mediator_did.clone(), setup_default(&mediator_generated));

            let alice_generated = generate_did().unwrap();
            let alice_dmp = setup_default(&alice_generated);

            // Nobody ever registered this DID with the mediator.
            let stranger = generate_did_with_endpoint(&mediator_did).unwrap();

            let hello = json!({"type": "https://didcomm.org/basicmessage/2.0/message", "body": {}});
            let packed = alice_dmp
                .pack(&hello, &stranger.did, Some(&alice_generated.did))
                .await
                .unwrap();
            let reply = mediator.handle_message(&packed.message).await.unwrap();
            assert!(reply.is_none());
        });
    }

    #[test]
    fn touch_and_sweep_expired_remove_only_expired_registrations() {
        pollster::block_on(async {
            let store = InMemoryRegistrationStore::default();
            store.register("alice", "did:example:r1").await.unwrap();
            store.register("alice", "did:example:r2").await.unwrap();

            // Not yet touched at all -- no TTL set, never swept.
            assert_eq!(store.sweep_expired().await.unwrap(), 0);
            assert_eq!(
                store.owner_of("did:example:r1").await.unwrap(),
                Some("alice".to_string())
            );

            // r1 expires in the past, r2 far in the future.
            store.touch("did:example:r1", -1000).await.unwrap();
            store.touch("did:example:r2", 60_000).await.unwrap();

            assert_eq!(store.sweep_expired().await.unwrap(), 1);
            assert_eq!(store.owner_of("did:example:r1").await.unwrap(), None);
            assert_eq!(
                store.owner_of("did:example:r2").await.unwrap(),
                Some("alice".to_string())
            );

            // Idempotent -- nothing left to sweep.
            assert_eq!(store.sweep_expired().await.unwrap(), 0);
        });
    }

    #[test]
    fn touch_on_an_unregistered_did_is_a_no_op() {
        pollster::block_on(async {
            let store = InMemoryRegistrationStore::default();
            store
                .touch("did:example:never-registered", 60_000)
                .await
                .unwrap();
            assert_eq!(
                store
                    .owner_of("did:example:never-registered")
                    .await
                    .unwrap(),
                None
            );
        });
    }

    #[test]
    fn register_refuses_to_steal_a_did_already_owned_by_someone_else() {
        pollster::block_on(async {
            let store = InMemoryRegistrationStore::default();
            assert_eq!(
                store.register("alice", "did:example:shared").await.unwrap(),
                RegisterOutcome::Registered
            );

            // A stranger trying to claim Alice's already-registered (and not at all
            // secret -- it's her public address) recipient_did is refused, not
            // silently handed ownership.
            assert_eq!(
                store.register("mallory", "did:example:shared").await.unwrap(),
                RegisterOutcome::AlreadyOwnedByOther
            );
            assert_eq!(
                store.owner_of("did:example:shared").await.unwrap(),
                Some("alice".to_string())
            );
        });
    }

    #[test]
    fn register_lets_the_real_owner_renew_their_own_registration() {
        pollster::block_on(async {
            let store = InMemoryRegistrationStore::default();
            assert_eq!(
                store.register("alice", "did:example:mine").await.unwrap(),
                RegisterOutcome::Registered
            );
            // Re-registering your own DID (e.g. to refresh a TTL via touch()
            // afterward) is a renewal, not a conflict.
            assert_eq!(
                store.register("alice", "did:example:mine").await.unwrap(),
                RegisterOutcome::Registered
            );
            assert_eq!(
                store.owner_of("did:example:mine").await.unwrap(),
                Some("alice".to_string())
            );
        });
    }

    #[test]
    fn register_still_allows_one_owner_to_claim_several_different_dids() {
        pollster::block_on(async {
            // The legitimate coordinate-mediation/3.0 use case this fix must not
            // break: one relationship registering several distinct pairwise DIDs.
            let store = InMemoryRegistrationStore::default();
            assert_eq!(
                store.register("alice", "did:example:r1").await.unwrap(),
                RegisterOutcome::Registered
            );
            assert_eq!(
                store.register("alice", "did:example:r2").await.unwrap(),
                RegisterOutcome::Registered
            );
            assert_eq!(
                store.registered_to("alice").await.unwrap().len(),
                2
            );
        });
    }

    #[test]
    fn fcm_device_store_defaults_to_unregistered() {
        pollster::block_on(async {
            let store = InMemoryFcmDeviceStore::default();
            assert_eq!(
                store.get("did:example:never-set").await.unwrap(),
                FcmDeviceInfo::default()
            );
        });
    }

    #[test]
    fn fcm_device_store_round_trips_a_registration() {
        pollster::block_on(async {
            let store = InMemoryFcmDeviceStore::default();
            let info = FcmDeviceInfo {
                device_token: Some("abc123".to_string()),
                device_platform: Some("android".to_string()),
            };
            store.set("did:example:alice", info.clone()).await.unwrap();
            assert_eq!(store.get("did:example:alice").await.unwrap(), info);
        });
    }

    #[test]
    fn fcm_device_store_set_with_defaults_clears_a_registration() {
        pollster::block_on(async {
            let store = InMemoryFcmDeviceStore::default();
            store
                .set(
                    "did:example:alice",
                    FcmDeviceInfo {
                        device_token: Some("abc123".to_string()),
                        device_platform: Some("android".to_string()),
                    },
                )
                .await
                .unwrap();
            // The wire protocol's own unregister convention: set both fields null.
            store.set("did:example:alice", FcmDeviceInfo::default()).await.unwrap();
            assert_eq!(
                store.get("did:example:alice").await.unwrap(),
                FcmDeviceInfo::default()
            );
        });
    }
}
