//! wasm/TypeScript bindings for `wyvrn-didcomm` -- the JS-side equivalent of
//! `didcomm-quickstart`'s "hit the ground running" flow:
//!
//! ```js
//! import init, { generateDid, DidcommMessaging } from "wyvrn-didcomm";
//!
//! await init();
//! const me = generateDid();
//! const dmp = DidcommMessaging.setupDefault(me);
//!
//! const packed = await dmp.pack({ type: "https://didcomm.org/basicmessage/2.0/message", body: { content: "hi" } }, someOtherDid);
//! // packed.message is a Uint8Array ready to send; packed.targetServices tells you where
//!
//! const unpacked = await dmp.unpack(receivedBytes);
//! console.log(unpacked.message); // a plain JS object, not a JSON string
//! ```
//!
//! Like the Rust `didcomm-quickstart` crate this wraps, the point isn't that this is
//! the *only* way to use the library from JS -- `wasm-bindgen`'s generated `.d.ts`
//! covers this crate's full public surface, so once an application's needs outgrow
//! `generateDid`/`setupDefault`'s fixed defaults, its `DidcommMessaging` methods
//! (`pack`/`unpack`) work the same way against a resolver/secrets setup built by hand
//! in Rust and exposed the same way, if this crate grows that surface later.
//!
//! `did:web` and `did:webvh` aren't available here (unlike the native `didcomm-quickstart`
//! default) -- see `didcomm-quickstart`'s `Cargo.toml` for why (a `DIDResolver` Send-future
//! limitation for the former, an upstream `didwebvh-rs` wasm bug for the latter). This
//! wasm build covers `did:peer:2`, `did:peer:4`, and `did:jwk`.

use std::rc::Rc;

use askar_crypto::{
    alg::{ed25519::Ed25519KeyPair, x25519::X25519KeyPair},
    jwk::{FromJwk, ToJwk},
};
use didcomm_quickstart::{DefaultDIDCommMessaging, GeneratedDid as CoreGeneratedDid};
use serde::Serialize;
use serde_json::Value;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::future_to_promise;

fn to_js_error(e: impl std::fmt::Display) -> JsValue {
    JsValue::from_str(&e.to_string())
}

/// A freshly generated `did:peer:2` and its raw key material (as JWK JSON strings, so
/// they're plain, storable data rather than opaque handles) -- the wasm-facing mirror
/// of [`didcomm_quickstart::GeneratedDid`].
#[wasm_bindgen]
pub struct GeneratedDid {
    did: String,
    verification_secret_jwk: String,
    key_agreement_secret_jwk: String,
}

#[wasm_bindgen]
impl GeneratedDid {
    #[wasm_bindgen(getter)]
    pub fn did(&self) -> String {
        self.did.clone()
    }

    #[wasm_bindgen(getter, js_name = verificationSecretJwk)]
    pub fn verification_secret_jwk(&self) -> String {
        self.verification_secret_jwk.clone()
    }

    #[wasm_bindgen(getter, js_name = keyAgreementSecretJwk)]
    pub fn key_agreement_secret_jwk(&self) -> String {
        self.key_agreement_secret_jwk.clone()
    }
}

/// Generate a fresh `did:peer:2`, ready to hand to
/// [`DidcommMessaging.setupDefault`](DidcommMessaging::setup_default). Mirrors
/// `didcomm_quickstart::generate_did`.
#[wasm_bindgen(js_name = generateDid)]
pub fn generate_did() -> Result<GeneratedDid, JsValue> {
    generated_did_from_core(didcomm_quickstart::generate_did().map_err(to_js_error)?)
}

/// Generate a fresh `did:peer:2` with a caller-chosen service endpoint (e.g. a
/// mediator's granted `routing_did`) instead of the default `didcomm:transport/queue`
/// placeholder. Mirrors `didcomm_quickstart::generate_did_with_endpoint`.
#[wasm_bindgen(js_name = generateDidWithEndpoint)]
pub fn generate_did_with_endpoint(endpoint_uri: String) -> Result<GeneratedDid, JsValue> {
    generated_did_from_core(
        didcomm_quickstart::generate_did_with_endpoint(&endpoint_uri).map_err(to_js_error)?,
    )
}

fn generated_did_from_core(generated: CoreGeneratedDid) -> Result<GeneratedDid, JsValue> {
    let verification_secret_jwk = generated
        .verification_key
        .to_jwk_secret(None)
        .map_err(to_js_error)?;
    let key_agreement_secret_jwk = generated
        .key_agreement_key
        .to_jwk_secret(None)
        .map_err(to_js_error)?;
    Ok(GeneratedDid {
        did: generated.did,
        verification_secret_jwk: String::from_utf8(verification_secret_jwk.to_vec())
            .map_err(to_js_error)?,
        key_agreement_secret_jwk: String::from_utf8(key_agreement_secret_jwk.to_vec())
            .map_err(to_js_error)?,
    })
}

/// A ready-to-use DIDComm v2 messaging instance. Mirrors
/// `didcomm_core::messaging::DIDCommMessaging`, specialized to the `askar-crypto`
/// backend and the default resolver set (see this module's docs for what's included).
#[wasm_bindgen]
pub struct DidcommMessaging {
    inner: Rc<DefaultDIDCommMessaging>,
}

#[wasm_bindgen]
impl DidcommMessaging {
    /// Wire up a default `DidcommMessaging` from a [`GeneratedDid`]. Mirrors
    /// `didcomm_quickstart::setup_default`.
    #[wasm_bindgen(js_name = setupDefault)]
    pub fn setup_default(generated: &GeneratedDid) -> Result<DidcommMessaging, JsValue> {
        let key_agreement_key =
            X25519KeyPair::from_jwk(&generated.key_agreement_secret_jwk).map_err(to_js_error)?;
        let verification_key =
            Ed25519KeyPair::from_jwk(&generated.verification_secret_jwk).map_err(to_js_error)?;
        let core_generated = CoreGeneratedDid {
            did: generated.did.clone(),
            verification_key,
            key_agreement_key,
        };
        let dmp = didcomm_quickstart::setup_default(&core_generated);
        Ok(DidcommMessaging { inner: Rc::new(dmp) })
    }

    /// Pack a message (a plain JS object, not a JSON string) to a recipient DID,
    /// optionally authenticated by a sender DID/kid. Returns a `Promise` resolving to
    /// `{ message: Uint8Array, targetServices: { uri, accept, routingKeys }[] }`.
    pub fn pack(&self, message: JsValue, to: String, frm: Option<String>) -> js_sys::Promise {
        let inner = self.inner.clone();
        future_to_promise(async move {
            let message_value: Value =
                serde_wasm_bindgen::from_value(message).map_err(to_js_error)?;
            let result = inner
                .pack(&message_value, &to, frm.as_deref())
                .await
                .map_err(to_js_error)?;

            let out = js_sys::Object::new();
            js_sys::Reflect::set(
                &out,
                &"message".into(),
                &js_sys::Uint8Array::from(result.message.as_slice()).into(),
            )?;

            let services = js_sys::Array::new();
            for service in &result.target_services {
                let service_obj = js_sys::Object::new();
                js_sys::Reflect::set(&service_obj, &"uri".into(), &service.uri.clone().into())?;
                js_sys::Reflect::set(
                    &service_obj,
                    &"accept".into(),
                    &service
                        .accept
                        .iter()
                        .map(|a| JsValue::from_str(a))
                        .collect::<js_sys::Array>(),
                )?;
                js_sys::Reflect::set(
                    &service_obj,
                    &"routingKeys".into(),
                    &service
                        .routing_keys
                        .iter()
                        .map(|k| JsValue::from_str(k))
                        .collect::<js_sys::Array>(),
                )?;
                services.push(&service_obj);
            }
            js_sys::Reflect::set(&out, &"targetServices".into(), &services)?;

            Ok(out.into())
        })
    }

    /// Unpack a received message. Returns a `Promise` resolving to
    /// `{ message, encrypted, authenticated, recipientKid, senderKid? }`, where
    /// `message` is a plain JS object (not a JSON string).
    pub fn unpack(&self, encoded: Vec<u8>) -> js_sys::Promise {
        let inner = self.inner.clone();
        future_to_promise(async move {
            let result = inner.unpack(&encoded).await.map_err(to_js_error)?;
            let message_value = result.message().map_err(to_js_error)?;

            // `.serialize_maps_as_objects(true)`: serde_wasm_bindgen's default turns a
            // JSON object into a JS `Map` (property access needs `.get("key")`), which
            // contradicts this method's "a plain JS object" doc comment above -- a real
            // consumer's message body is exactly the kind of JSON object a JS caller
            // expects to index with `.foo`, not `.get("foo")`.
            let serializer =
                serde_wasm_bindgen::Serializer::new().serialize_maps_as_objects(true);
            let out = js_sys::Object::new();
            js_sys::Reflect::set(
                &out,
                &"message".into(),
                &message_value.serialize(&serializer).map_err(to_js_error)?,
            )?;
            js_sys::Reflect::set(&out, &"encrypted".into(), &JsValue::from_bool(result.encrypted))?;
            js_sys::Reflect::set(
                &out,
                &"authenticated".into(),
                &JsValue::from_bool(result.authenticated),
            )?;
            js_sys::Reflect::set(
                &out,
                &"recipientKid".into(),
                &JsValue::from_str(&result.recipient_kid),
            )?;
            if let Some(sender_kid) = &result.sender_kid {
                js_sys::Reflect::set(&out, &"senderKid".into(), &JsValue::from_str(sender_kid))?;
            }

            Ok(out.into())
        })
    }
}
