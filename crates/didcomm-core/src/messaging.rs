//! `DIDCommMessaging`, mirroring `didcomm_messaging.messaging` -- the main entry point
//! tying `PackagingService` and `RoutingService` together: `pack` a message straight to
//! a recipient DID (getting back the bytes to send *and* where to send them), `unpack`
//! a received one.
//!
//! Unlike `didcomm_messaging.messaging` (which packs whatever plaintext it's handed,
//! byte-for-byte), `pack` completes a message's standard headers by default -- see
//! [`HeaderPolicy`] -- and `unpack` checks an authcrypted message's `from` against the
//! key that actually encrypted it.

use std::borrow::Cow;
use std::sync::atomic::{AtomicBool, Ordering};

use didcomm_diddoc::DidCommV2ServiceEndpoint;
use serde_json::Value;

use crate::crypto::{CryptoService, SecretKey as _, SecretsManager};
use crate::packaging::{PackagingError, PackagingService};
use crate::resolver::DIDResolver;
use crate::routing::{RoutingError, RoutingService};

/// Errors from `DIDCommMessaging::pack`/`unpack`.
#[derive(Debug, thiserror::Error)]
pub enum MessagingError {
    #[error(transparent)]
    Packaging(#[from] PackagingError),
    #[error(transparent)]
    Routing(#[from] RoutingError),
    #[error("invalid message JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Plaintext(#[from] crate::plaintext::PlaintextError),
    #[error(transparent)]
    Signed(#[from] crate::signed::SignedError),
    /// [`DIDCommMessaging::unpack`] found a signed message; only
    /// [`DIDCommMessaging::unpack_verified`] (which needs a `SigningService`) can check
    /// its signature, and an unchecked one is never returned as if it were plaintext.
    #[error("message is signed; unpack it with unpack_verified")]
    SignedNeedsVerification,
    /// A plaintext header contradicts the `pack` call (or, on `unpack`, the key that
    /// actually authenticated the message).
    #[error("invalid `{header}` header: {reason}")]
    Header { header: &'static str, reason: String },
}

/// How [`DIDCommMessaging::pack`] (and [`pack_as`](DIDCommMessaging::pack_as) /
/// [`pack_direct`](DIDCommMessaging::pack_direct)) treat a message's standard
/// [plaintext headers](https://identity.foundation/didcomm-messaging/spec/v2.1/#message-headers).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HeaderPolicy {
    /// The default. Fill in whichever of these is missing (absent or `null`), never
    /// overwriting one the caller set:
    ///
    /// - `id`: a fresh UUIDv4.
    /// - `from`: the sender's DID (`frm` without any `#fragment`), only when
    ///   authcrypting -- the spec makes `from` REQUIRED there, and real
    ///   implementations (e.g. the Indicio public mediator) reject an authcrypted
    ///   message without it.
    /// - `to`: `[<recipient DID>]` (`to` without any `#fragment`).
    /// - `created_time`: now, in UTC epoch seconds.
    ///
    /// And refuse to pack a message that contradicts the call: a `from` that isn't the
    /// authcrypting sender's DID, or a `to` that isn't an array listing the recipient.
    /// Only applies to JSON-object messages; anything else is packed as given.
    #[default]
    Complete,
    /// Pack the message exactly as given -- the same plaintext
    /// `didcomm-messaging-python` would produce. For callers that need byte-for-byte
    /// parity with it (wire-compat fixtures, drop-in-replacement use of the bindings).
    Verbatim,
}

/// The result of packing a message: the (possibly forward-wrapped) bytes to send, and
/// the service(s) to send them to.
#[derive(Debug, Clone)]
pub struct PackResult {
    pub message: Vec<u8>,
    pub target_services: Vec<DidCommV2ServiceEndpoint>,
}

impl PackResult {
    /// The first matching endpoint URI for a given protocol (e.g. `"http"`, `"ws"`).
    pub fn get_endpoint(&self, protocol: &str) -> Option<&str> {
        self.get_service(protocol).map(|s| s.uri.as_str())
    }

    /// The first matching service for a given protocol.
    pub fn get_service(&self, protocol: &str) -> Option<&DidCommV2ServiceEndpoint> {
        self.filter_services_by_protocol(protocol).into_iter().next()
    }

    /// All services whose URI starts with the given protocol prefix.
    pub fn filter_services_by_protocol(&self, protocol: &str) -> Vec<&DidCommV2ServiceEndpoint> {
        self.target_services
            .iter()
            .filter(|s| s.uri.starts_with(protocol))
            .collect()
    }
}

/// The result of unpacking a message.
#[derive(Debug, Clone)]
pub struct UnpackResult {
    /// The plaintext message, always as JSON bytes -- a `didcomm-plain+cbor` plaintext
    /// is converted to its JSON view (see [`crate::plaintext`]), so callers handle one
    /// shape whichever encoding arrived; `plaintext_encoding` says which one that was.
    pub unpacked: Vec<u8>,
    pub encrypted: bool,
    pub authenticated: bool,
    pub recipient_kid: String,
    pub sender_kid: Option<String>,
    /// The kid that signed the message, for a signed one ([`DIDCommMessaging::unpack_verified`]).
    pub signer_kid: Option<String>,
    pub plaintext_encoding: crate::crypto::Encoding,
}

impl UnpackResult {
    /// The unpacked message, parsed as JSON.
    pub fn message(&self) -> Result<serde_json::Value, serde_json::Error> {
        serde_json::from_slice(&self.unpacked)
    }
}

/// Main entry point for DIDComm v2 messaging: owns a crypto backend, secrets manager,
/// and resolver, and packs/unpacks messages by DID.
pub struct DIDCommMessaging<C: CryptoService, S: SecretsManager<SecretKey = C::SecretKey>> {
    pub crypto: C,
    pub secrets: S,
    pub resolver: Box<dyn DIDResolver>,
    pub packaging: PackagingService,
    pub routing: RoutingService,
    /// `true` = [`HeaderPolicy::Verbatim`]. Atomic so the policy can change through a
    /// shared reference (e.g. a binding holding this behind an `Arc`/`Rc`); see
    /// [`header_policy`](Self::header_policy).
    verbatim_headers: AtomicBool,
}

impl<C, S> DIDCommMessaging<C, S>
where
    C: CryptoService,
    S: SecretsManager<SecretKey = C::SecretKey>,
{
    pub fn new(crypto: C, secrets: S, resolver: Box<dyn DIDResolver>) -> Self {
        Self {
            crypto,
            secrets,
            resolver,
            packaging: PackagingService,
            routing: RoutingService,
            verbatim_headers: AtomicBool::new(false),
        }
    }

    /// How `pack` treats standard headers; see [`HeaderPolicy`]. Defaults to
    /// [`HeaderPolicy::Complete`].
    pub fn header_policy(&self) -> HeaderPolicy {
        if self.verbatim_headers.load(Ordering::Relaxed) {
            HeaderPolicy::Verbatim
        } else {
            HeaderPolicy::Complete
        }
    }

    /// Change the [`header_policy`](Self::header_policy), e.g. to
    /// [`HeaderPolicy::Verbatim`] to opt out. Takes `&self`, so it works on a shared
    /// instance; messages already being packed keep the policy they started with.
    pub fn set_header_policy(&self, header_policy: HeaderPolicy) {
        self.verbatim_headers.store(header_policy == HeaderPolicy::Verbatim, Ordering::Relaxed);
    }

    /// Builder-style [`set_header_policy`](Self::set_header_policy).
    pub fn with_header_policy(self, header_policy: HeaderPolicy) -> Self {
        self.set_header_policy(header_policy);
        self
    }

    /// `message` with its standard headers completed and checked per
    /// [`header_policy`](Self::header_policy) -- borrowed unchanged under
    /// [`HeaderPolicy::Verbatim`] or for a non-object message.
    pub fn complete_headers<'m>(
        &self,
        message: &'m Value,
        to: &str,
        frm: Option<&str>,
    ) -> Result<Cow<'m, Value>, MessagingError> {
        if self.header_policy() == HeaderPolicy::Verbatim || !message.is_object() {
            return Ok(Cow::Borrowed(message));
        }
        let mut message = message.clone();
        let headers = message.as_object_mut().expect("checked is_object above");
        // A header set to `null` counts as missing.
        let present = |v: Option<&Value>| v.filter(|v| !v.is_null()).cloned();

        if present(headers.get("id")).is_none() {
            headers.insert("id".into(), Value::String(uuid::Uuid::new_v4().to_string()));
        }

        if let Some(frm) = frm {
            let sender = did_of(frm);
            match present(headers.get("from")) {
                None => {
                    headers.insert("from".into(), Value::String(sender.to_string()));
                }
                Some(Value::String(from)) if did_of(&from) == sender => {}
                Some(other) => {
                    return Err(MessagingError::Header {
                        header: "from",
                        reason: format!("{other} is not the authcrypting sender {sender}"),
                    })
                }
            }
        }

        let recipient = did_of(to);
        match present(headers.get("to")) {
            None => {
                headers.insert("to".into(), Value::Array(vec![Value::String(recipient.to_string())]));
            }
            Some(Value::Array(list)) => {
                if !list.iter().any(|d| d.as_str().map(did_of) == Some(recipient)) {
                    return Err(MessagingError::Header {
                        header: "to",
                        reason: format!("does not list the recipient {recipient}"),
                    });
                }
            }
            Some(other) => {
                return Err(MessagingError::Header {
                    header: "to",
                    reason: format!("must be an array of DIDs, got {other}"),
                })
            }
        }

        if present(headers.get("created_time")).is_none() {
            headers.insert("created_time".into(), Value::from(now_epoch_secs()));
        }

        Ok(Cow::Owned(message))
    }

    /// Pack a message to a recipient DID (or DID URL to a specific verification
    /// method), optionally authenticated by a sender.
    ///
    /// Chooses the `didcomm/v2+cbor` profile (COSE envelope, CBOR plaintext) over plain JSON iff `to`'s
    /// own resolved `DIDCommMessaging` service endpoint advertises it (the same
    /// endpoint [`RoutingService::prepare_forward`] resolves again immediately
    /// afterward for delivery/forwarding -- not shared with this call since the
    /// encoding decision has to happen *before* packing, while forwarding only matters
    /// once packing is already done). Resolution failing here (or `to` simply having no
    /// resolvable service endpoint at all, e.g. a bare key-agreement DID URL) falls back
    /// to JSON rather than erroring -- this is an optimization, not a requirement, and
    /// the real failure (if `to` truly can't be resolved at all) surfaces on its own
    /// moments later from the packing/key-resolution this wraps.
    pub async fn pack(
        &self,
        message: &serde_json::Value,
        to: &str,
        frm: Option<&str>,
    ) -> Result<PackResult, MessagingError> {
        let encoding = self
            .routing
            .resolve_services(self.resolver.as_ref(), to)
            .await
            .ok()
            .and_then(|services| services.first().map(|s| crate::crypto::Encoding::for_accept(&s.accept)))
            .unwrap_or_default();
        self.pack_as(message, to, frm, encoding).await
    }

    /// Like [`pack`](Self::pack), but skips content negotiation entirely and always
    /// uses `encoding` -- for a caller who knows their message must use a specific
    /// encoding regardless of what the recipient might otherwise support. The one real
    /// case so far: a message a client sends directly over a raw WebSocket connection
    /// (bypassing HTTP) to its mediator has to stay JSON no matter what, since
    /// `wyvrn-mediator-socketdock`'s inbound webhook relay (matching the real
    /// SocketDock's own contract, which this doesn't control or get to change) encodes
    /// the message as a JSON string field, lossily re-decoding it as UTF-8 text on the
    /// way -- fine for JSON, silently corrupting for a binary `didcomm/v2+cbor`
    /// envelope, which negotiation would otherwise happily choose since the mediator's
    /// own diddoc advertises it.
    pub async fn pack_as(
        &self,
        message: &serde_json::Value,
        to: &str,
        frm: Option<&str>,
        encoding: crate::crypto::Encoding,
    ) -> Result<PackResult, MessagingError> {
        let message = self.complete_headers(message, to, frm)?;
        let message_bytes = crate::plaintext::encode(message.as_ref(), encoding)?;
        self.encrypt_and_route(&message_bytes, to, frm, encoding).await
    }

    /// Encrypt an already-encoded plaintext (or signed message) to `to` in `encoding`,
    /// then forward-wrap it for `to`'s mediator chain -- the shared second half of
    /// [`pack_as`](Self::pack_as) and `pack_signed`.
    async fn encrypt_and_route(
        &self,
        message_bytes: &[u8],
        to: &str,
        frm: Option<&str>,
        encoding: crate::crypto::Encoding,
    ) -> Result<PackResult, MessagingError> {
        let encoded = self
            .packaging
            .pack(
                &self.crypto,
                self.resolver.as_ref(),
                &self.secrets,
                message_bytes,
                &[to],
                frm,
                encoding,
            )
            .await?;
        let (forward, target_services) = self
            .routing
            .prepare_forward(
                &self.crypto,
                &self.packaging,
                self.resolver.as_ref(),
                &self.secrets,
                to,
                &encoded,
            )
            .await?;
        Ok(PackResult {
            message: forward,
            target_services,
        })
    }

    /// Pack a message directly to `to`, bypassing forward-wrapping even if `to`'s own
    /// resolved service endpoint points at another DID (a mediator) rather than a real
    /// transport URI. For a caller replying synchronously to whoever it's already
    /// talking to over an already-open channel (the same HTTP request/response, or a
    /// live WebSocket) -- exactly [`pack`](Self::pack)'s own "0-hop" case, forced,
    /// since "forward this to a mediator" makes no sense for a reply going straight
    /// back down the leg it arrived on. Needed specifically because a self-mediated
    /// identity's own document legitimately advertises the mediator's DID as its
    /// endpoint (so *other* senders correctly route through it) -- but when the
    /// mediator itself is the one replying, resolving that same endpoint would
    /// otherwise make it wrap its own reply in a `routing/2.0/forward` addressed back
    /// to itself, which [`prepare_forward`](crate::routing::RoutingService::prepare_forward)
    /// has no way to distinguish from a real, different next hop. Chooses encoding the
    /// same way `pack` does (negotiated against `to`'s own advertised accept list).
    /// `target_services` on the result is always empty -- irrelevant here, since the
    /// caller already knows how it's delivering this (the connection it's replying
    /// over), not resolving one fresh.
    pub async fn pack_direct(
        &self,
        message: &serde_json::Value,
        to: &str,
        frm: Option<&str>,
    ) -> Result<PackResult, MessagingError> {
        let encoding = self
            .routing
            .resolve_services(self.resolver.as_ref(), to)
            .await
            .ok()
            .and_then(|services| services.first().map(|s| crate::crypto::Encoding::for_accept(&s.accept)))
            .unwrap_or_default();
        let message = self.complete_headers(message, to, frm)?;
        let message_bytes = crate::plaintext::encode(message.as_ref(), encoding)?;
        let encoded = self
            .packaging
            .pack(&self.crypto, self.resolver.as_ref(), &self.secrets, &message_bytes, &[to], frm, encoding)
            .await?;
        Ok(PackResult { message: encoded, target_services: Vec::new() })
    }

    /// Unpack a received message: decrypt it, and parse its plaintext (either
    /// encoding) into the JSON view [`UnpackResult::unpacked`] carries.
    ///
    /// For an authcrypted message whose plaintext carries a `from` header, `from` must
    /// be the DID that owns the sender key: the spec requires recipients to verify that
    /// the sender key is authorized by `from` (`didcomm-messaging-python` doesn't). A
    /// missing `from` is still accepted, since peers built on that library routinely
    /// omit it. Applies regardless of [`header_policy`](Self::header_policy), which only
    /// governs what *this* side sends.
    ///
    /// A signed payload (`anoncrypt(sign(plaintext))`) is refused with
    /// [`MessagingError::SignedNeedsVerification`] -- use
    /// [`unpack_verified`](Self::unpack_verified).
    pub async fn unpack(&self, encoded_message: &[u8]) -> Result<UnpackResult, MessagingError> {
        let (unpacked, metadata) = self
            .packaging
            .unpack(&self.crypto, self.resolver.as_ref(), &self.secrets, encoded_message)
            .await?;
        if crate::signed::is_signed(&unpacked) {
            return Err(MessagingError::SignedNeedsVerification);
        }
        let (message, plaintext_encoding) = crate::plaintext::decode(&unpacked)?;
        if let Some(sender_kid) = &metadata.sender_kid {
            check_from(&message, sender_kid, "sender")?;
        }
        Ok(UnpackResult {
            unpacked: serde_json::to_vec(&message)?,
            // Matches Python's `bool(metadata.method)`, which is always true in
            // practice -- extract_packed_message_metadata either determines a method
            // or returns an error, it never leaves it unset.
            encrypted: true,
            authenticated: metadata.sender_kid.is_some(),
            recipient_kid: metadata.recip_key.kid().to_string(),
            sender_kid: metadata.sender_kid,
            signer_kid: None,
            plaintext_encoding,
        })
    }
}

impl<C, S> DIDCommMessaging<C, S>
where
    C: CryptoService + crate::crypto::SigningService,
    S: SecretsManager<SecretKey = <C as CryptoService>::SecretKey>,
{
    /// Pack a signed message: `anoncrypt(sign(plaintext))`, the spec's combination for
    /// adding non-repudiation, signed with `signing_key` (one of the sender's
    /// `authentication` keys) and forward-wrapped like [`pack`](Self::pack). The
    /// plaintext, signature and envelope all use the encoding negotiated against
    /// `to`'s `accept` list (a JWS in a JWE, or a COSE_Sign1 in a COSE_Encrypt). `to`
    /// is always set, since the spec requires it on a signed-then-encrypted message.
    pub async fn pack_signed(
        &self,
        message: &serde_json::Value,
        to: &str,
        signing_key: &<C as crate::crypto::SigningService>::SigningKey,
    ) -> Result<PackResult, MessagingError> {
        let encoding = self
            .routing
            .resolve_services(self.resolver.as_ref(), to)
            .await
            .ok()
            .and_then(|services| services.first().map(|s| crate::crypto::Encoding::for_accept(&s.accept)))
            .unwrap_or_default();
        let signer = crate::crypto::SigningKey::kid(signing_key);
        let mut message = self.complete_headers(message, to, None)?.into_owned();
        if let Value::Object(headers) = &mut message {
            if headers.get("to").map_or(true, Value::is_null) {
                headers.insert("to".into(), Value::Array(vec![Value::String(did_of(to).to_string())]));
            }
            if headers.get("from").map_or(true, Value::is_null) {
                headers.insert("from".into(), Value::String(did_of(signer).to_string()));
            }
        }
        check_from(&message, signer, "signer")?;
        let plaintext = crate::plaintext::encode(&message, encoding)?;
        let signed = crate::signed::sign(&self.crypto, signing_key, &plaintext, encoding).await?;
        self.encrypt_and_route(&signed, to, None, encoding).await
    }

    /// Like [`unpack`](Self::unpack), but also accepts signed messages -- a bare one
    /// (`application/didcomm-signed+*`) or one inside encryption -- verifying the
    /// signature against the signer's resolved `kid` and requiring a plaintext `from`
    /// to be the signer's DID.
    pub async fn unpack_verified(&self, encoded_message: &[u8]) -> Result<UnpackResult, MessagingError> {
        let (inner, encrypted) = if crate::signed::is_signed(encoded_message) {
            (encoded_message.to_vec(), None)
        } else {
            let (inner, metadata) = self
                .packaging
                .unpack(&self.crypto, self.resolver.as_ref(), &self.secrets, encoded_message)
                .await?;
            (inner, Some(metadata))
        };
        let (plaintext, signer_kid) = if crate::signed::is_signed(&inner) {
            let verified = crate::signed::verify(&self.crypto, self.resolver.as_ref(), &inner).await?;
            (verified.payload, Some(verified.signer_kid))
        } else {
            (inner, None)
        };
        let (message, plaintext_encoding) = crate::plaintext::decode(&plaintext)?;
        if let Some(signer_kid) = &signer_kid {
            check_from(&message, signer_kid, "signer")?;
        }
        let sender_kid = encrypted.as_ref().and_then(|m| m.sender_kid.clone());
        if let Some(sender_kid) = &sender_kid {
            check_from(&message, sender_kid, "sender")?;
            // authcrypt(sign(plaintext)): the spec requires an error when the signer
            // isn't the authcrypt sender -- whether or not a `from` header says so.
            if let Some(signer_kid) = &signer_kid {
                if did_of(signer_kid) != did_of(sender_kid) {
                    return Err(MessagingError::Header {
                        header: "from",
                        reason: format!("signer {signer_kid} is not the authcrypt sender {sender_kid}"),
                    });
                }
            }
        }
        Ok(UnpackResult {
            unpacked: serde_json::to_vec(&message)?,
            encrypted: encrypted.is_some(),
            authenticated: sender_kid.is_some() || signer_kid.is_some(),
            recipient_kid: encrypted
                .as_ref()
                .map(|m| m.recip_key.kid().to_string())
                .unwrap_or_default(),
            sender_kid,
            signer_kid,
            plaintext_encoding,
        })
    }
}

/// A plaintext `from`, when present, must be the DID owning `kid` (the authcrypt
/// sender's or the signer's key).
fn check_from(message: &Value, kid: &str, role: &str) -> Result<(), MessagingError> {
    match message.get("from") {
        None | Some(Value::Null) => Ok(()),
        Some(Value::String(from)) if did_of(from) == did_of(kid) => Ok(()),
        Some(other) => Err(MessagingError::Header {
            header: "from",
            reason: format!("{other} does not own the {role} key {kid}"),
        }),
    }
}

/// The DID part of a DID or DID URL (everything before any `#fragment`).
pub(crate) fn did_of(did_or_url: &str) -> &str {
    did_or_url.split('#').next().unwrap_or(did_or_url)
}

/// Seconds since the Unix epoch -- `std::time::SystemTime` panics on
/// `wasm32-unknown-unknown`, so go through JS there (same split as
/// `didcomm-resolver-web`'s `now_ms`).
#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn now_epoch_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before 1970")
        .as_secs()
}

#[cfg(target_arch = "wasm32")]
pub(crate) fn now_epoch_secs() -> u64 {
    (js_sys::Date::now() / 1000.0) as u64
}
