//! Node.js (napi-rs) bindings for `wyvrn-didcomm`, published as `didcomm-node` -- the
//! Node-side equivalent of `didcomm-quickstart`'s "hit the ground running" flow:
//!
//! ```js
//! const { generateDid, DidcommMessaging } = require("didcomm-node");
//!
//! const me = generateDid();
//! const dmp = DidcommMessaging.setupDefault(me);
//!
//! const packed = await dmp.pack({ type: "https://didcomm.org/basicmessage/2.0/message", body: { content: "hi" } }, someOtherDid);
//! // packed.message is a Buffer ready to send; packed.targetServices tells you where
//!
//! const unpacked = await dmp.unpack(receivedBytes);
//! console.log(unpacked.message); // a plain JS object, not a JSON string
//! ```
//!
//! Like the Rust `didcomm-quickstart` crate this wraps, the point isn't that this is the
//! *only* way to use the library from Node -- napi-rs's generated `.d.ts` covers this
//! crate's full public surface, so once an application's needs outgrow
//! `generateDid`/`setupDefault`'s fixed defaults, its `DidcommMessaging` methods
//! (`pack`/`unpack`) work the same way against a resolver/secrets setup built by hand in
//! Rust and exposed the same way, if this crate grows that surface later.
//!
//! Unlike `didcomm-wasm`, this is a native addon (no wasm32 Send-future limitation, no
//! wasm-targeting bug in `didwebvh-rs`), so it depends on `didcomm-quickstart` with its
//! default features -- `did:web` and `did:webvh` both work here.

use std::sync::Arc;

use askar_crypto::{
    alg::{ed25519::Ed25519KeyPair, x25519::X25519KeyPair},
    jwk::{FromJwk, ToJwk},
};
use didcomm_quickstart::{DefaultDIDCommMessaging, GeneratedDid as CoreGeneratedDid};
use napi::bindgen_prelude::*;
use napi_derive::napi;

fn to_napi_err(e: impl std::fmt::Display) -> napi::Error {
    napi::Error::from_reason(e.to_string())
}

/// A freshly generated `did:peer:2` and its raw key material (as JWK JSON strings, so
/// they're plain, storable data rather than opaque handles) -- the Node-facing mirror of
/// [`didcomm_quickstart::GeneratedDid`].
#[napi]
pub struct GeneratedDid {
    did: String,
    verification_secret_jwk: String,
    key_agreement_secret_jwk: String,
}

#[napi]
impl GeneratedDid {
    #[napi(getter)]
    pub fn did(&self) -> String {
        self.did.clone()
    }

    #[napi(getter, js_name = "verificationSecretJwk")]
    pub fn verification_secret_jwk(&self) -> String {
        self.verification_secret_jwk.clone()
    }

    #[napi(getter, js_name = "keyAgreementSecretJwk")]
    pub fn key_agreement_secret_jwk(&self) -> String {
        self.key_agreement_secret_jwk.clone()
    }
}

/// Generate a fresh `did:peer:2`, ready to hand to
/// [`DidcommMessaging.setupDefault`](DidcommMessaging::setup_default). Mirrors
/// `didcomm_quickstart::generate_did`.
#[napi(js_name = "generateDid")]
pub fn generate_did() -> napi::Result<GeneratedDid> {
    let generated = didcomm_quickstart::generate_did().map_err(to_napi_err)?;
    let verification_secret_jwk = generated
        .verification_key
        .to_jwk_secret(None)
        .map_err(to_napi_err)?;
    let key_agreement_secret_jwk = generated
        .key_agreement_key
        .to_jwk_secret(None)
        .map_err(to_napi_err)?;
    Ok(GeneratedDid {
        did: generated.did,
        verification_secret_jwk: String::from_utf8(verification_secret_jwk.to_vec())
            .map_err(to_napi_err)?,
        key_agreement_secret_jwk: String::from_utf8(key_agreement_secret_jwk.to_vec())
            .map_err(to_napi_err)?,
    })
}

/// One entry of [`PackResult::target_services`]: a resolved DIDComm v2 service endpoint
/// to actually deliver the packed message to.
#[napi(object)]
pub struct TargetService {
    pub uri: String,
    pub accept: Vec<String>,
    #[napi(js_name = "routingKeys")]
    pub routing_keys: Vec<String>,
}

/// Return value of [`DidcommMessaging::pack`].
#[napi(object)]
pub struct PackResult {
    pub message: Buffer,
    #[napi(js_name = "targetServices")]
    pub target_services: Vec<TargetService>,
}

/// Return value of [`DidcommMessaging::unpack`].
#[napi(object)]
pub struct UnpackResult {
    /// A plain JS value (not a JSON string).
    pub message: serde_json::Value,
    pub encrypted: bool,
    pub authenticated: bool,
    #[napi(js_name = "recipientKid")]
    pub recipient_kid: String,
    #[napi(js_name = "senderKid")]
    pub sender_kid: Option<String>,
}

/// A ready-to-use DIDComm v2 messaging instance. Mirrors
/// `didcomm_core::messaging::DIDCommMessaging`, specialized to the `askar-crypto` backend
/// and the default resolver set (`did:peer:2`, `did:peer:4`, `did:jwk`, `did:web`,
/// `did:webvh`).
#[napi]
pub struct DidcommMessaging {
    inner: Arc<DefaultDIDCommMessaging>,
}

#[napi]
impl DidcommMessaging {
    /// Wire up a default `DidcommMessaging` from a [`GeneratedDid`]. Mirrors
    /// `didcomm_quickstart::setup_default`.
    #[napi(factory, js_name = "setupDefault")]
    pub fn setup_default(generated: &GeneratedDid) -> napi::Result<DidcommMessaging> {
        let key_agreement_key = X25519KeyPair::from_jwk(&generated.key_agreement_secret_jwk)
            .map_err(to_napi_err)?;
        let verification_key =
            Ed25519KeyPair::from_jwk(&generated.verification_secret_jwk).map_err(to_napi_err)?;
        let core_generated = CoreGeneratedDid {
            did: generated.did.clone(),
            verification_key,
            key_agreement_key,
        };
        let dmp = didcomm_quickstart::setup_default(&core_generated);
        Ok(DidcommMessaging { inner: Arc::new(dmp) })
    }

    /// Pack a message (a plain JS value, not a JSON string) to a recipient DID,
    /// optionally authenticated by a sender DID/kid.
    #[napi]
    pub async fn pack(
        &self,
        message: serde_json::Value,
        to: String,
        frm: Option<String>,
    ) -> napi::Result<PackResult> {
        let inner = self.inner.clone();
        let result = inner
            .pack(&message, &to, frm.as_deref())
            .await
            .map_err(to_napi_err)?;

        Ok(PackResult {
            message: result.message.into(),
            target_services: result
                .target_services
                .into_iter()
                .map(|service| TargetService {
                    uri: service.uri,
                    accept: service.accept,
                    routing_keys: service.routing_keys,
                })
                .collect(),
        })
    }

    /// Unpack a received message.
    #[napi]
    pub async fn unpack(&self, encoded: Buffer) -> napi::Result<UnpackResult> {
        let inner = self.inner.clone();
        let result = inner.unpack(encoded.as_ref()).await.map_err(to_napi_err)?;
        let message = result.message().map_err(to_napi_err)?;

        Ok(UnpackResult {
            message,
            encrypted: result.encrypted,
            authenticated: result.authenticated,
            recipient_kid: result.recipient_kid,
            sender_kid: result.sender_kid,
        })
    }
}
