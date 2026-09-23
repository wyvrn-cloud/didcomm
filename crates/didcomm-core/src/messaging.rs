//! `DIDCommMessaging`, mirroring `didcomm_messaging.messaging` -- the main entry point
//! tying `PackagingService` and `RoutingService` together: `pack` a message straight to
//! a recipient DID (getting back the bytes to send *and* where to send them), `unpack`
//! a received one.

use didcomm_diddoc::DidCommV2ServiceEndpoint;

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
    pub unpacked: Vec<u8>,
    pub encrypted: bool,
    pub authenticated: bool,
    pub recipient_kid: String,
    pub sender_kid: Option<String>,
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
        }
    }

    /// Pack a message to a recipient DID (or DID URL to a specific verification
    /// method), optionally authenticated by a sender.
    ///
    /// Chooses the wyvrn-original `didcomm/v2+cbor` profile over plain JSON iff `to`'s
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
        let message_bytes = serde_json::to_vec(message)?;
        let encoded = self
            .packaging
            .pack(
                &self.crypto,
                self.resolver.as_ref(),
                &self.secrets,
                &message_bytes,
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

    /// Unpack a received message.
    pub async fn unpack(&self, encoded_message: &[u8]) -> Result<UnpackResult, MessagingError> {
        let (unpacked, metadata) = self
            .packaging
            .unpack(&self.crypto, self.resolver.as_ref(), &self.secrets, encoded_message)
            .await?;
        Ok(UnpackResult {
            unpacked,
            // Matches Python's `bool(metadata.method)`, which is always true in
            // practice -- extract_packed_message_metadata either determines a method
            // or returns an error, it never leaves it unset.
            encrypted: true,
            authenticated: metadata.sender_kid.is_some(),
            recipient_kid: metadata.recip_key.kid().to_string(),
            sender_kid: metadata.sender_kid,
        })
    }
}
