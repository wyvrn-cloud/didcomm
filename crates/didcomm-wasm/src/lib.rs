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
//! // packed.message is a Uint8Array ready to send; packed.targetServices tells you where;
//! // packed.contentType is what it was actually packed as (JSON or, per-recipient, CBOR)
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
//! `did:webvh` isn't available here (unlike the native `didcomm-quickstart` default)
//! -- see `didcomm-quickstart`'s `Cargo.toml` for why (an upstream `didwebvh-rs` wasm
//! bug). `did:web` *is* available -- `didcomm-core::resolver::DIDResolver` is `?Send`
//! on wasm32 specifically so `didcomm-resolver-web`'s real network I/O can implement
//! it there (see that trait's own doc comment). This wasm build covers `did:peer:2`,
//! `did:peer:4`, `did:jwk`, and `did:web`.

use std::rc::Rc;

use askar_crypto::{
    alg::{ed25519::Ed25519KeyPair, x25519::X25519KeyPair},
    jwk::{FromJwk, ToJwk},
    repr::KeyGen,
};
use didcomm_crypto_askar::AskarSigningKey;
use didcomm_core::messaging::HeaderPolicy;
use didcomm_quickstart::{DefaultDIDCommMessaging, GeneratedDid as CoreGeneratedDid};
use serde::Serialize;
use serde_json::Value;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::future_to_promise;

fn to_js_error(e: impl std::fmt::Display) -> JsValue {
    JsValue::from_str(&e.to_string())
}

/// Builds the `{ message, contentType, targetServices }` object both
/// [`DidcommMessaging::pack`] and [`DidcommMessaging::pack_as_json`] return, shared so
/// the two don't drift out of sync on the same output shape.
fn pack_result_to_js(result: &didcomm_core::messaging::PackResult) -> Result<JsValue, JsValue> {
    let content_type = didcomm_core::jwe::peek_typ(&result.message).map_err(to_js_error)?;

    let out = js_sys::Object::new();
    js_sys::Reflect::set(
        &out,
        &"message".into(),
        &js_sys::Uint8Array::from(result.message.as_slice()).into(),
    )?;
    js_sys::Reflect::set(&out, &"contentType".into(), &content_type.into())?;

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
}

/// A freshly generated `did:peer:4` and its raw key material (as JWK JSON strings, so
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

/// Generate a fresh `did:peer:4`, ready to hand to
/// [`DidcommMessaging.setupDefault`](DidcommMessaging::setup_default). Mirrors
/// `didcomm_quickstart::generate_did`.
#[wasm_bindgen(js_name = generateDid)]
pub fn generate_did() -> Result<GeneratedDid, JsValue> {
    generated_did_from_core(didcomm_quickstart::generate_did().map_err(to_js_error)?)
}

/// Generate a fresh `did:peer:4` with a caller-chosen service endpoint (e.g. a
/// mediator's granted `routing_did`) instead of the default `didcomm:transport/queue`
/// placeholder. Mirrors `didcomm_quickstart::generate_did_with_endpoint`.
#[wasm_bindgen(js_name = generateDidWithEndpoint)]
pub fn generate_did_with_endpoint(endpoint_uri: String) -> Result<GeneratedDid, JsValue> {
    generated_did_from_core(
        didcomm_quickstart::generate_did_with_endpoint(&endpoint_uri).map_err(to_js_error)?,
    )
}

/// A freshly generated standalone keypair -- not a full DID on its own, just one
/// device's own independent key, to be listed (by its `publicMultikey`) in a shared
/// multi-device Identity DID document via
/// [`generateMultiDeviceIdentityDid`](generate_multi_device_identity_did). The secret
/// half never leaves the device that generated it.
#[wasm_bindgen]
pub struct GeneratedKeypair {
    secret_jwk: String,
    public_multikey: String,
}

#[wasm_bindgen]
impl GeneratedKeypair {
    #[wasm_bindgen(getter, js_name = secretJwk)]
    pub fn secret_jwk(&self) -> String {
        self.secret_jwk.clone()
    }

    #[wasm_bindgen(getter, js_name = publicMultikey)]
    pub fn public_multikey(&self) -> String {
        self.public_multikey.clone()
    }
}

/// Generate a fresh, independent Ed25519 authentication keypair -- for a device being
/// promoted to trusted (multi-device/1.0), never shared with or received from another
/// device. Its `publicMultikey` is what gets sent to an existing trusted device so it
/// can list it in the next Identity DID document.
#[wasm_bindgen(js_name = generateAuthenticationKeypair)]
pub fn generate_authentication_keypair() -> Result<GeneratedKeypair, JsValue> {
    let key = Ed25519KeyPair::random().map_err(to_js_error)?;
    let secret_jwk = key.to_jwk_secret(None).map_err(to_js_error)?;
    Ok(GeneratedKeypair {
        secret_jwk: String::from_utf8(secret_jwk.to_vec()).map_err(to_js_error)?,
        public_multikey: didcomm_quickstart::authentication_public_multikey(&key),
    })
}

/// Generate a fresh, independent X25519 keyAgreement keypair -- for a device
/// enrolling into a multi-device identity (multi-device/1.0), never shared with or
/// received from another device. Its `publicMultikey` is what gets sent to an
/// enrolling device so it can list it in the next Identity DID document.
#[wasm_bindgen(js_name = generateKeyAgreementKeypair)]
pub fn generate_key_agreement_keypair() -> Result<GeneratedKeypair, JsValue> {
    let key = X25519KeyPair::random().map_err(to_js_error)?;
    let secret_jwk = key.to_jwk_secret(None).map_err(to_js_error)?;
    Ok(GeneratedKeypair {
        secret_jwk: String::from_utf8(secret_jwk.to_vec()).map_err(to_js_error)?,
        public_multikey: didcomm_quickstart::key_agreement_public_multikey(&key),
    })
}

/// Mint (or re-mint, on every device enrollment/revocation/trust change) a
/// multi-device Identity DID document from every currently-known device's own public
/// keys -- see `didcomm_quickstart::generate_multi_device_did`'s own doc comment for
/// why this never generates a key itself. `authenticationPublicMultikeys` may be
/// empty (no trusted device yet); `keyAgreementPublicMultikeys` must not be.
#[wasm_bindgen(js_name = generateMultiDeviceIdentityDid)]
pub fn generate_multi_device_identity_did(
    authentication_public_multikeys: Vec<String>,
    key_agreement_public_multikeys: Vec<String>,
    endpoint_uri: String,
) -> Result<String, JsValue> {
    let auth: Vec<&str> = authentication_public_multikeys.iter().map(String::as_str).collect();
    let key_agreement: Vec<&str> = key_agreement_public_multikeys.iter().map(String::as_str).collect();
    didcomm_quickstart::generate_multi_device_did(&auth, &key_agreement, &endpoint_uri)
        .map_err(to_js_error)
}

/// Derive the multikey-encoded public half of an already-generated `keyAgreement`
/// secret (as stored, e.g., in `AgentIdentity.identityKeyAgreementSecretJwk`) --
/// for a caller that only ever persisted the secret and needs its public half again
/// later (e.g. multi-device/1.0 enrollment, finding this device's own kid in a
/// freshly-minted document via `resolveVerificationMethodKid`), without having to
/// also persist the public multikey separately as its own field.
#[wasm_bindgen(js_name = keyAgreementPublicMultikeyFromSecret)]
pub fn key_agreement_public_multikey_from_secret(secret_jwk: String) -> Result<String, JsValue> {
    let key = X25519KeyPair::from_jwk(&secret_jwk).map_err(to_js_error)?;
    Ok(didcomm_quickstart::key_agreement_public_multikey(&key))
}

/// Like [`key_agreement_public_multikey_from_secret`], for an `authentication` secret.
#[wasm_bindgen(js_name = authenticationPublicMultikeyFromSecret)]
pub fn authentication_public_multikey_from_secret(secret_jwk: String) -> Result<String, JsValue> {
    let key = Ed25519KeyPair::from_jwk(&secret_jwk).map_err(to_js_error)?;
    Ok(didcomm_quickstart::authentication_public_multikey(&key))
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

fn setup_from_parts(
    did: &str,
    verification_secret_jwk: &str,
    key_agreement_secret_jwk: &str,
) -> Result<DidcommMessaging, JsValue> {
    let key_agreement_key =
        X25519KeyPair::from_jwk(key_agreement_secret_jwk).map_err(to_js_error)?;
    let verification_key =
        Ed25519KeyPair::from_jwk(verification_secret_jwk).map_err(to_js_error)?;
    let core_generated = CoreGeneratedDid {
        did: did.to_string(),
        verification_key,
        key_agreement_key,
    };
    let dmp = didcomm_quickstart::setup_default(&core_generated);
    Ok(DidcommMessaging { inner: Rc::new(dmp) })
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
    /// `true` packs messages exactly as given -- the same plaintext
    /// `didcomm-messaging-python` produces. `false` (the default) fills in a missing
    /// `id`, `from` (authcrypt only), `to` and `created_time`, and refuses a `from` or
    /// `to` that contradicts the `pack` call (see `didcomm_core::messaging::HeaderPolicy`).
    #[wasm_bindgen(getter = verbatimHeaders)]
    pub fn verbatim_headers(&self) -> bool {
        self.inner.header_policy() == HeaderPolicy::Verbatim
    }

    #[wasm_bindgen(setter = verbatimHeaders)]
    pub fn set_verbatim_headers(&self, verbatim: bool) {
        self.inner.set_header_policy(if verbatim { HeaderPolicy::Verbatim } else { HeaderPolicy::Complete });
    }

    /// Wire up a default `DidcommMessaging` from a [`GeneratedDid`]. Mirrors
    /// `didcomm_quickstart::setup_default`.
    #[wasm_bindgen(js_name = setupDefault)]
    pub fn setup_default(generated: &GeneratedDid) -> Result<DidcommMessaging, JsValue> {
        setup_from_parts(
            &generated.did,
            &generated.verification_secret_jwk,
            &generated.key_agreement_secret_jwk,
        )
    }

    /// Wire up a `DidcommMessaging` directly from previously-generated key material,
    /// instead of from a freshly-generated [`GeneratedDid`] instance.
    ///
    /// [`GeneratedDid`] has a private constructor -- there's no way to build one from
    /// JS other than calling `generateDid`/`generateDidWithEndpoint`, which always
    /// mints a *new* identity. Any consumer that needs to reload a previously
    /// generated (and persisted) identity across a restart -- not just generate one
    /// and use it for the rest of the current process's lifetime, which is all the
    /// existing `generateDid`+`setupDefault` pair supports -- has no way to get back
    /// to a working `DidcommMessaging` without this. Found by actually building
    /// `wyvrn-chat`, a browser app that (unlike the CLI bots this crate was first
    /// proven against) has to survive being reloaded.
    ///
    /// `verification_secret_jwk` is optional -- `setup_default`'s own doc comment
    /// notes it's never actually used for any real crypto operation here (only
    /// `key_agreement_secret_jwk` is), so a caller with no real authentication secret
    /// for this DID at all (e.g. a multi-device/1.0 device that isn't trusted, setting
    /// up messaging for the shared Identity DID using only its own keyAgreement
    /// secret) doesn't need to invent one just to satisfy this signature.
    #[wasm_bindgen(js_name = fromSecrets)]
    pub fn from_secrets(
        did: String,
        verification_secret_jwk: Option<String>,
        key_agreement_secret_jwk: String,
    ) -> Result<DidcommMessaging, JsValue> {
        let verification_secret_jwk = match verification_secret_jwk {
            Some(jwk) => jwk,
            None => {
                let placeholder = Ed25519KeyPair::random().map_err(to_js_error)?;
                String::from_utf8(
                    placeholder.to_jwk_secret(None).map_err(to_js_error)?.to_vec(),
                )
                .map_err(to_js_error)?
            }
        };
        setup_from_parts(&did, &verification_secret_jwk, &key_agreement_secret_jwk)
    }

    /// Like [`fromSecrets`](Self::from_secrets), but registers `key_agreement_secret_jwk`
    /// under `key_agreement_kid` exactly as given, instead of assuming it's always
    /// `{did}#key-2`. Needed for a multi-device/1.0 Identity DID document: it lists one
    /// `keyAgreement` entry per *enrolled device*, so a joining device's own entry can
    /// land on any kid depending on its position in that list -- `fromSecrets`'s
    /// `#key-2` guess is only ever correct for the very first device (or a lone Device
    /// DID's own single-key document). Resolve the real kid first with
    /// `resolveVerificationMethodKid(identityDid, thisDevicesOwnPublicMultikey)` against
    /// any already-constructed `DidcommMessaging` (resolution doesn't depend on which
    /// instance's secrets you call it on) and pass that here. A real, previously-latent
    /// bug this fixes: any device but the founding one packing to/from the shared
    /// Identity DID would resolve some *other* device's public key against its own
    /// secret and fail deep inside `askar-crypto` with an opaque "Encryption error",
    /// found via a live two-device enrollment run (not caught by unit tests, which mock
    /// this layer entirely).
    #[wasm_bindgen(js_name = fromSecretsWithKid)]
    pub fn from_secrets_with_kid(
        key_agreement_secret_jwk: String,
        key_agreement_kid: String,
    ) -> Result<DidcommMessaging, JsValue> {
        let key_agreement_key =
            X25519KeyPair::from_jwk(&key_agreement_secret_jwk).map_err(to_js_error)?;
        let dmp = didcomm_quickstart::setup_with_key_agreement_kid(key_agreement_key, &key_agreement_kid);
        Ok(DidcommMessaging { inner: Rc::new(dmp) })
    }

    /// Pack a message (a plain JS object, not a JSON string) to a recipient DID,
    /// optionally authenticated by a sender DID/kid. Returns a `Promise` resolving to
    /// `{ message: Uint8Array, contentType: string, targetServices: { uri, accept, routingKeys }[] }`.
    /// `contentType` is the real `typ` this specific `pack()` call actually used
    /// (`application/didcomm-encrypted+json` -- or, for a JSON authcrypt that isn't
    /// forward-wrapped, the reference implementation's `application/didcomm+encrypted`,
    /// see `didcomm-crypto-askar` -- or `application/didcomm-encrypted+cbor`) --
    /// `pack()` negotiates JSON vs. the `didcomm/v2+cbor` profile (COSE_Encrypt) per
    /// recipient on its own, so a caller needs this to know what to actually send it as
    /// (e.g. an HTTP `Content-Type` header) rather than assuming one encoding.
    pub fn pack(&self, message: JsValue, to: String, frm: Option<String>) -> js_sys::Promise {
        let inner = self.inner.clone();
        future_to_promise(async move {
            let message_value: Value =
                serde_wasm_bindgen::from_value(message).map_err(to_js_error)?;
            let result = inner
                .pack(&message_value, &to, frm.as_deref())
                .await
                .map_err(to_js_error)?;
            pack_result_to_js(&result)
        })
    }

    /// Like [`pack`](Self::pack), but always packs as plain JSON, skipping content
    /// negotiation entirely -- for a caller who knows their message must stay JSON
    /// regardless of what the recipient might otherwise support, e.g. a message sent
    /// directly over a raw WebSocket connection rather than HTTP (see
    /// `didcomm_core::messaging::DIDCommMessaging::pack_as`'s own doc comment for why
    /// that specific case needs this).
    #[wasm_bindgen(js_name = packAsJson)]
    pub fn pack_as_json(&self, message: JsValue, to: String, frm: Option<String>) -> js_sys::Promise {
        let inner = self.inner.clone();
        future_to_promise(async move {
            let message_value: Value =
                serde_wasm_bindgen::from_value(message).map_err(to_js_error)?;
            let result = inner
                .pack_as(&message_value, &to, frm.as_deref(), didcomm_core::crypto::Encoding::Json)
                .await
                .map_err(to_js_error)?;
            pack_result_to_js(&result)
        })
    }

    /// Unpack a received message. Returns a `Promise` resolving to
    /// `{ message, encrypted, authenticated, recipientKid, senderKid?, signerKid? }`, where
    /// `message` is a plain JS object (not a JSON string).
    pub fn unpack(&self, encoded: Vec<u8>) -> js_sys::Promise {
        let inner = self.inner.clone();
        future_to_promise(async move {
            // unpack_verified: also accepts (and checks the signature of) a signed
            // message, bare or inside encryption -- plain unpack refuses those.
            let result = inner.unpack_verified(&encoded).await.map_err(to_js_error)?;
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
            if let Some(signer_kid) = &result.signer_kid {
                js_sys::Reflect::set(&out, &"signerKid".into(), &JsValue::from_str(signer_kid))?;
            }

            Ok(out.into())
        })
    }

    /// Resolve `did` and find the absolute kid (`did:...#key-N`) of the verification
    /// method whose public key exactly matches `publicMultikey`, or `null` if it isn't
    /// listed. For multi-device/1.0: a device that just minted a new Identity DID
    /// document from its own already-known public key needs this to find out which kid
    /// that key became, since `did:peer:4`'s numbering is positional and this avoids
    /// the caller duplicating that rule itself. Returns a `Promise<string | null>`.
    #[wasm_bindgen(js_name = resolveVerificationMethodKid)]
    pub fn resolve_verification_method_kid(&self, did: String, public_multikey: String) -> js_sys::Promise {
        let inner = self.inner.clone();
        future_to_promise(async move {
            let doc = inner.resolver.resolve_and_parse(&did).await.map_err(to_js_error)?;
            Ok(match doc.find_verification_method_id_by_public_key(&public_multikey) {
                Some(kid) => JsValue::from_str(&kid),
                None => JsValue::NULL,
            })
        })
    }

    /// Sign a `from_prior` DID rotation JWT (multi-device/1.0 Key Rotation): `sub` is
    /// `newDid`, `iss` is `priorDid`, signed by `signingSecretJwk` under `signingKid` --
    /// an `authentication` key the *prior* DID's own document lists (see
    /// `resolveVerificationMethodKid` to find it). `iatSeconds` is Unix seconds -- see
    /// `didcomm_core::rotation::build_from_prior`'s own doc comment for why this crate
    /// never reads wall-clock time itself. Returns a `Promise<string>` (the JWT).
    #[wasm_bindgen(js_name = buildFromPrior)]
    pub fn build_from_prior(
        &self,
        prior_did: String,
        new_did: String,
        signing_secret_jwk: String,
        signing_kid: String,
        iat_seconds: f64,
    ) -> js_sys::Promise {
        let inner = self.inner.clone();
        future_to_promise(async move {
            let key = Ed25519KeyPair::from_jwk(&signing_secret_jwk).map_err(to_js_error)?;
            let signing_key = AskarSigningKey::new(signing_kid, key);
            let jwt = didcomm_core::rotation::build_from_prior(
                &inner.crypto,
                &prior_did,
                &new_did,
                &signing_key,
                iat_seconds as i64,
            )
            .await
            .map_err(to_js_error)?;
            Ok(JsValue::from_str(&jwt))
        })
    }

    /// Verify a `from_prior` JWT, resolving its signer fresh to confirm the signing key
    /// actually belongs to the claimed prior DID (see
    /// `didcomm_core::rotation::verify_from_prior`'s own doc comment). Returns a
    /// `Promise<{ priorDid: string, newDid: string }>`, rejecting if the JWT is
    /// malformed or its signature doesn't check out.
    #[wasm_bindgen(js_name = verifyFromPrior)]
    pub fn verify_from_prior(&self, jwt: String) -> js_sys::Promise {
        let inner = self.inner.clone();
        future_to_promise(async move {
            let (prior_did, new_did) =
                didcomm_core::rotation::verify_from_prior(&inner.crypto, inner.resolver.as_ref(), &jwt)
                    .await
                    .map_err(to_js_error)?;
            let out = js_sys::Object::new();
            js_sys::Reflect::set(&out, &"priorDid".into(), &JsValue::from_str(&prior_did))?;
            js_sys::Reflect::set(&out, &"newDid".into(), &JsValue::from_str(&new_did))?;
            Ok(out.into())
        })
    }
}
