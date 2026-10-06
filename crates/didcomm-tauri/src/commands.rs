//! The actual `#[tauri::command]` functions and their supporting types -- kept in this
//! submodule, not `lib.rs`'s own root, specifically to avoid a confirmed, currently
//! open `tauri::command` macro bug: a `pub fn` command declared directly in a crate's
//! root module self-collides in codegen (`error[E0255]: the name '__cmd__foo' is
//! defined multiple times`), independent of `pub`/`pub(crate)`, independent of
//! `crate-type`, and independent of whether the crate also builds a
//! `tauri::Builder`/`generate_handler!` itself -- see
//! <https://github.com/tauri-apps/tauri/issues/9362> and
//! <https://github.com/tauri-apps/tauri/issues/15921>, reproduced directly against
//! this exact toolchain/tauri-macros combination before landing on this structure.
//! Moving every command into any non-root submodule avoids the bug entirely; see
//! `lib.rs` for the crate-level overview and the confirmed-working
//! `generate_handler!` usage (`commands::foo`, fully qualified through this module --
//! *not* a flattened re-export, which the linked issues show can reintroduce the same
//! collision at the call site).
//!
//! Every command that needs a live `DidcommMessaging` instance is a thin wrapper over
//! an inherent [`DidcommMessagingStore`] method -- `pack`/`unpack`/etc. all live there,
//! not directly on the `#[tauri::command]` function -- specifically so an integration
//! test can exercise the real logic by constructing a `DidcommMessagingStore` directly
//! (`tauri::State` has no public constructor outside a running `tauri::App`, so a test
//! can't call the command functions themselves without one).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use askar_crypto::{
    alg::{ed25519::Ed25519KeyPair, x25519::X25519KeyPair},
    jwk::{FromJwk, ToJwk},
    repr::KeyGen,
};
use didcomm_crypto_askar::AskarSigningKey;
use didcomm_quickstart::{DefaultDIDCommMessaging, GeneratedDid as CoreGeneratedDid};
use serde::{Deserialize, Serialize};

fn to_command_err(e: impl std::fmt::Display) -> String {
    e.to_string()
}

/// A freshly generated `did:peer:4` and its raw key material (as JWK JSON strings, so
/// they're plain, storable data rather than opaque handles) -- the Tauri-facing mirror
/// of [`didcomm_quickstart::GeneratedDid`]. Unlike the wasm/Node bindings' equivalent,
/// this is plain `Serialize`/`Deserialize` data (no getters) -- there's no object
/// identity to preserve across a JSON IPC boundary.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct GeneratedDid {
    pub did: String,
    pub verification_secret_jwk: String,
    pub key_agreement_secret_jwk: String,
}

fn generated_did_from_core(generated: CoreGeneratedDid) -> Result<GeneratedDid, String> {
    let verification_secret_jwk = generated
        .verification_key
        .to_jwk_secret(None)
        .map_err(to_command_err)?;
    let key_agreement_secret_jwk = generated
        .key_agreement_key
        .to_jwk_secret(None)
        .map_err(to_command_err)?;
    Ok(GeneratedDid {
        did: generated.did,
        verification_secret_jwk: String::from_utf8(verification_secret_jwk.to_vec())
            .map_err(to_command_err)?,
        key_agreement_secret_jwk: String::from_utf8(key_agreement_secret_jwk.to_vec())
            .map_err(to_command_err)?,
    })
}

/// Generate a fresh `did:peer:4`, ready to hand to [`setup_default`]. Mirrors
/// `didcomm_quickstart::generate_did`.
#[tauri::command]
pub fn generate_did() -> Result<GeneratedDid, String> {
    generated_did_from_core(didcomm_quickstart::generate_did().map_err(to_command_err)?)
}

/// Like [`generate_did`], but with a caller-chosen `serviceEndpoint.uri` instead of the
/// unset-transport placeholder -- for a DID meant to be directly reachable, or routed
/// through a specific mediator (that mediator's own DID as the endpoint). Mirrors
/// `didcomm_quickstart::generate_did_with_endpoint`.
#[tauri::command]
pub fn generate_did_with_endpoint(endpoint_uri: String) -> Result<GeneratedDid, String> {
    generated_did_from_core(
        didcomm_quickstart::generate_did_with_endpoint(&endpoint_uri).map_err(to_command_err)?,
    )
}

/// A freshly generated standalone keypair -- not a full DID on its own, just one
/// device's own independent key, to be listed (by its `public_multikey`) in a shared
/// multi-device Identity DID document via [`generate_multi_device_identity_did`]. The
/// secret half never leaves the device that generated it.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct GeneratedKeypair {
    pub secret_jwk: String,
    pub public_multikey: String,
}

/// Generate a fresh, independent Ed25519 authentication keypair -- for a device being
/// promoted to trusted (multi-device/1.0), never shared with or received from another
/// device. Its `public_multikey` is what gets sent to an existing trusted device so it
/// can list it in the next Identity DID document.
#[tauri::command]
pub fn generate_authentication_keypair() -> Result<GeneratedKeypair, String> {
    let key = Ed25519KeyPair::random().map_err(to_command_err)?;
    let secret_jwk = key.to_jwk_secret(None).map_err(to_command_err)?;
    Ok(GeneratedKeypair {
        secret_jwk: String::from_utf8(secret_jwk.to_vec()).map_err(to_command_err)?,
        public_multikey: didcomm_quickstart::authentication_public_multikey(&key),
    })
}

/// Generate a fresh, independent X25519 keyAgreement keypair -- for a device enrolling
/// into a multi-device identity (multi-device/1.0), never shared with or received from
/// another device. Its `public_multikey` is what gets sent to an enrolling device so it
/// can list it in the next Identity DID document.
#[tauri::command]
pub fn generate_key_agreement_keypair() -> Result<GeneratedKeypair, String> {
    let key = X25519KeyPair::random().map_err(to_command_err)?;
    let secret_jwk = key.to_jwk_secret(None).map_err(to_command_err)?;
    Ok(GeneratedKeypair {
        secret_jwk: String::from_utf8(secret_jwk.to_vec()).map_err(to_command_err)?,
        public_multikey: didcomm_quickstart::key_agreement_public_multikey(&key),
    })
}

/// Mint (or re-mint, on every device enrollment/revocation/trust change) a
/// multi-device Identity DID document from every currently-known device's own public
/// keys -- see `didcomm_quickstart::generate_multi_device_did`'s own doc comment for
/// why this never generates a key itself. `authentication_public_multikeys` may be
/// empty (no trusted device yet); `key_agreement_public_multikeys` must not be.
#[tauri::command]
pub fn generate_multi_device_identity_did(
    authentication_public_multikeys: Vec<String>,
    key_agreement_public_multikeys: Vec<String>,
    endpoint_uri: String,
) -> Result<String, String> {
    let auth: Vec<&str> = authentication_public_multikeys.iter().map(String::as_str).collect();
    let key_agreement: Vec<&str> =
        key_agreement_public_multikeys.iter().map(String::as_str).collect();
    didcomm_quickstart::generate_multi_device_did(&auth, &key_agreement, &endpoint_uri)
        .map_err(to_command_err)
}

/// Derive the multikey-encoded public half of an already-generated `keyAgreement`
/// secret (as stored, e.g., in `AgentIdentity.identityKeyAgreementSecretJwk`) -- for a
/// caller that only ever persisted the secret and needs its public half again later
/// (e.g. multi-device/1.0 enrollment, finding this device's own kid in a freshly-minted
/// document via [`resolve_verification_method_kid`]), without having to also persist
/// the public multikey separately as its own field.
#[tauri::command]
pub fn key_agreement_public_multikey_from_secret(secret_jwk: String) -> Result<String, String> {
    let key = X25519KeyPair::from_jwk(&secret_jwk).map_err(to_command_err)?;
    Ok(didcomm_quickstart::key_agreement_public_multikey(&key))
}

/// Like [`key_agreement_public_multikey_from_secret`], for an `authentication` secret.
#[tauri::command]
pub fn authentication_public_multikey_from_secret(secret_jwk: String) -> Result<String, String> {
    let key = Ed25519KeyPair::from_jwk(&secret_jwk).map_err(to_command_err)?;
    Ok(didcomm_quickstart::authentication_public_multikey(&key))
}

fn setup_from_parts(
    did: &str,
    verification_secret_jwk: &str,
    key_agreement_secret_jwk: &str,
) -> Result<DefaultDIDCommMessaging, String> {
    let key_agreement_key =
        X25519KeyPair::from_jwk(key_agreement_secret_jwk).map_err(to_command_err)?;
    let verification_key =
        Ed25519KeyPair::from_jwk(verification_secret_jwk).map_err(to_command_err)?;
    let core_generated = CoreGeneratedDid {
        did: did.to_string(),
        verification_key,
        key_agreement_key,
    };
    Ok(didcomm_quickstart::setup_default(&core_generated))
}

/// One entry of [`PackResult::target_services`]: a resolved DIDComm v2 service
/// endpoint to actually deliver the packed message to.
#[derive(Serialize, Debug)]
#[serde(rename_all = "snake_case")]
pub struct TargetService {
    pub uri: String,
    pub accept: Vec<String>,
    pub routing_keys: Vec<String>,
}

/// Return value of [`DidcommMessagingStore::pack`]/[`DidcommMessagingStore::pack_as_json`].
#[derive(Serialize, Debug)]
#[serde(rename_all = "snake_case")]
pub struct PackResult {
    pub message: Vec<u8>,
    pub content_type: String,
    pub target_services: Vec<TargetService>,
}

fn pack_result_from_core(result: &didcomm_core::messaging::PackResult) -> Result<PackResult, String> {
    let content_type = didcomm_core::jwe::peek_typ(&result.message).map_err(to_command_err)?;
    Ok(PackResult {
        message: result.message.clone(),
        content_type,
        target_services: result
            .target_services
            .iter()
            .map(|service| TargetService {
                uri: service.uri.clone(),
                accept: service.accept.clone(),
                routing_keys: service.routing_keys.clone(),
            })
            .collect(),
    })
}

/// Return value of [`DidcommMessagingStore::unpack`].
#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
pub struct UnpackResult {
    pub message: serde_json::Value,
    pub encrypted: bool,
    pub authenticated: bool,
    pub recipient_kid: String,
    pub sender_kid: Option<String>,
}

/// Return value of [`DidcommMessagingStore::verify_from_prior`].
#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
pub struct FromPriorResult {
    pub prior_did: String,
    pub new_did: String,
}

/// Holds every live [`DefaultDIDCommMessaging`] instance a Tauri app has set up, keyed
/// by an opaque handle returned from [`DidcommMessagingStore::setup_default`]/
/// [`DidcommMessagingStore::from_secrets`]/[`DidcommMessagingStore::from_secrets_with_kid`]
/// -- registered once via `.manage(DidcommMessagingStore::default())` on the consuming
/// app's `tauri::Builder`. Stands in for the object identity `didcomm-wasm`/
/// `didcomm-node` get for free from their own binding macros, which plain JSON IPC has
/// no equivalent of. Every method here is the real logic behind this module's
/// `#[tauri::command]` functions of the same name, callable directly (no `tauri::App`
/// needed) -- see this module's own doc comment for why that split exists.
#[derive(Default)]
pub struct DidcommMessagingStore {
    instances: Mutex<HashMap<String, Arc<DefaultDIDCommMessaging>>>,
}

impl DidcommMessagingStore {
    fn insert(&self, dmp: DefaultDIDCommMessaging) -> String {
        let handle = uuid::Uuid::new_v4().to_string();
        self.instances
            .lock()
            .expect("DidcommMessagingStore mutex poisoned")
            .insert(handle.clone(), Arc::new(dmp));
        handle
    }

    fn get(&self, handle: &str) -> Result<Arc<DefaultDIDCommMessaging>, String> {
        self.instances
            .lock()
            .expect("DidcommMessagingStore mutex poisoned")
            .get(handle)
            .cloned()
            .ok_or_else(|| format!("unknown DidcommMessaging handle: {handle}"))
    }

    /// Wire up a default `DidcommMessaging` from a [`GeneratedDid`], returning an
    /// opaque handle for every later call. Mirrors `didcomm_quickstart::setup_default`.
    pub fn setup_default(&self, generated: GeneratedDid) -> Result<String, String> {
        let dmp = setup_from_parts(
            &generated.did,
            &generated.verification_secret_jwk,
            &generated.key_agreement_secret_jwk,
        )?;
        Ok(self.insert(dmp))
    }

    /// Wire up a `DidcommMessaging` directly from previously-generated key material,
    /// instead of from a freshly-generated [`GeneratedDid`] -- for reloading a
    /// previously generated (and persisted) identity across an app restart.
    /// `verification_secret_jwk` is optional -- `setup_default`'s own doc comment
    /// notes it's never actually used for any real crypto operation here (only
    /// `key_agreement_secret_jwk` is), so a caller with no real authentication secret
    /// for this DID at all (e.g. a multi-device/1.0 device that isn't trusted, setting
    /// up messaging for the shared Identity DID using only its own keyAgreement
    /// secret) doesn't need to invent one just to satisfy this signature.
    pub fn from_secrets(
        &self,
        did: &str,
        verification_secret_jwk: Option<String>,
        key_agreement_secret_jwk: &str,
    ) -> Result<String, String> {
        let verification_secret_jwk = match verification_secret_jwk {
            Some(jwk) => jwk,
            None => {
                let placeholder = Ed25519KeyPair::random().map_err(to_command_err)?;
                String::from_utf8(
                    placeholder.to_jwk_secret(None).map_err(to_command_err)?.to_vec(),
                )
                .map_err(to_command_err)?
            }
        };
        let dmp = setup_from_parts(did, &verification_secret_jwk, key_agreement_secret_jwk)?;
        Ok(self.insert(dmp))
    }

    /// Like [`from_secrets`](Self::from_secrets), but registers `key_agreement_secret_jwk`
    /// under `key_agreement_kid` exactly as given, instead of assuming it's always
    /// `{did}#key-2`. Needed for a multi-device/1.0 Identity DID document: it lists
    /// one `keyAgreement` entry per *enrolled device*, so a joining device's own entry
    /// can land on any kid depending on its position in that list -- `from_secrets`'s
    /// `#key-2` guess is only ever correct for the very first device (or a lone
    /// Device DID's own single-key document). Resolve the real kid first with
    /// `resolve_verification_method_kid(identityDid, thisDevicesOwnPublicMultikey)`
    /// against any already-constructed messaging handle (resolution doesn't depend on
    /// which instance's secrets you call it on) and pass that here.
    pub fn from_secrets_with_kid(
        &self,
        key_agreement_secret_jwk: &str,
        key_agreement_kid: &str,
    ) -> Result<String, String> {
        let key_agreement_key =
            X25519KeyPair::from_jwk(key_agreement_secret_jwk).map_err(to_command_err)?;
        let dmp =
            didcomm_quickstart::setup_with_key_agreement_kid(key_agreement_key, key_agreement_kid);
        Ok(self.insert(dmp))
    }

    /// Pack a message to a recipient DID, optionally authenticated by a sender DID/kid.
    /// `content_type` is the real JOSE `typ` this specific `pack()` call actually
    /// used -- `pack()` negotiates JSON vs. the `didcomm/v2+cbor`
    /// profile per recipient on its own, so a caller needs this to know what to
    /// actually send it as (e.g. an HTTP `Content-Type` header) rather than assuming
    /// one encoding.
    pub async fn pack(
        &self,
        handle: &str,
        message: &serde_json::Value,
        to: &str,
        frm: Option<&str>,
    ) -> Result<PackResult, String> {
        let inner = self.get(handle)?;
        let result = inner.pack(message, to, frm).await.map_err(to_command_err)?;
        pack_result_from_core(&result)
    }

    /// Like [`pack`](Self::pack), but always packs as plain JSON, skipping content
    /// negotiation entirely -- for a caller who knows their message must stay JSON
    /// regardless of what the recipient might otherwise support, e.g. a message sent
    /// directly over a raw WebSocket connection rather than HTTP.
    pub async fn pack_as_json(
        &self,
        handle: &str,
        message: &serde_json::Value,
        to: &str,
        frm: Option<&str>,
    ) -> Result<PackResult, String> {
        let inner = self.get(handle)?;
        let result = inner
            .pack_as(message, to, frm, didcomm_core::crypto::Encoding::Json)
            .await
            .map_err(to_command_err)?;
        pack_result_from_core(&result)
    }

    /// Unpack a received message.
    pub async fn unpack(&self, handle: &str, encoded: &[u8]) -> Result<UnpackResult, String> {
        let inner = self.get(handle)?;
        let result = inner.unpack(encoded).await.map_err(to_command_err)?;
        let message = result.message().map_err(to_command_err)?;
        Ok(UnpackResult {
            message,
            encrypted: result.encrypted,
            authenticated: result.authenticated,
            recipient_kid: result.recipient_kid,
            sender_kid: result.sender_kid,
        })
    }

    /// Resolve `did` and find the absolute kid (`did:...#key-N`) of the verification
    /// method whose public key exactly matches `public_multikey`, or `None` if it
    /// isn't listed. For multi-device/1.0: a device that just minted a new Identity
    /// DID document from its own already-known public key needs this to find out
    /// which kid that key became, since `did:peer:4`'s numbering is positional and
    /// this avoids the caller duplicating that rule itself.
    pub async fn resolve_verification_method_kid(
        &self,
        handle: &str,
        did: &str,
        public_multikey: &str,
    ) -> Result<Option<String>, String> {
        let inner = self.get(handle)?;
        let doc = inner.resolver.resolve_and_parse(did).await.map_err(to_command_err)?;
        Ok(doc.find_verification_method_id_by_public_key(public_multikey))
    }

    /// Sign a `from_prior` DID rotation JWT (multi-device/1.0 Key Rotation): `sub` is
    /// `new_did`, `iss` is `prior_did`, signed by `signing_secret_jwk` under
    /// `signing_kid` -- an `authentication` key the *prior* DID's own document lists
    /// (see [`resolve_verification_method_kid`](Self::resolve_verification_method_kid)
    /// to find it). `iat_seconds` is Unix seconds -- see
    /// `didcomm_core::rotation::build_from_prior`'s own doc comment for why this crate
    /// never reads wall-clock time itself.
    pub async fn build_from_prior(
        &self,
        handle: &str,
        prior_did: &str,
        new_did: &str,
        signing_secret_jwk: &str,
        signing_kid: &str,
        iat_seconds: i64,
    ) -> Result<String, String> {
        let inner = self.get(handle)?;
        let key = Ed25519KeyPair::from_jwk(signing_secret_jwk).map_err(to_command_err)?;
        let signing_key = AskarSigningKey::new(signing_kid.to_string(), key);
        didcomm_core::rotation::build_from_prior(
            &inner.crypto,
            prior_did,
            new_did,
            &signing_key,
            iat_seconds,
        )
        .await
        .map_err(to_command_err)
    }

    /// Verify a `from_prior` JWT, resolving its signer fresh to confirm the signing
    /// key actually belongs to the claimed prior DID (see
    /// `didcomm_core::rotation::verify_from_prior`'s own doc comment). Fails if the
    /// JWT is malformed or its signature doesn't check out.
    pub async fn verify_from_prior(&self, handle: &str, jwt: &str) -> Result<FromPriorResult, String> {
        let inner = self.get(handle)?;
        let (prior_did, new_did) = didcomm_core::rotation::verify_from_prior(
            &inner.crypto,
            inner.resolver.as_ref(),
            jwt,
        )
        .await
        .map_err(to_command_err)?;
        Ok(FromPriorResult { prior_did, new_did })
    }

    /// Drop a no-longer-needed `DidcommMessaging` handle (e.g. a short-lived instance
    /// used only to complete one enrollment exchange). Not required for a handle
    /// meant to live for the app's whole session -- only for hygiene when a caller
    /// knows it won't reuse one again.
    pub fn dispose(&self, handle: &str) {
        self.instances
            .lock()
            .expect("DidcommMessagingStore mutex poisoned")
            .remove(handle);
    }
}

#[tauri::command]
pub fn setup_default(
    state: tauri::State<'_, DidcommMessagingStore>,
    generated: GeneratedDid,
) -> Result<String, String> {
    state.setup_default(generated)
}

#[tauri::command]
pub fn from_secrets(
    state: tauri::State<'_, DidcommMessagingStore>,
    did: String,
    verification_secret_jwk: Option<String>,
    key_agreement_secret_jwk: String,
) -> Result<String, String> {
    state.from_secrets(&did, verification_secret_jwk, &key_agreement_secret_jwk)
}

#[tauri::command]
pub fn from_secrets_with_kid(
    state: tauri::State<'_, DidcommMessagingStore>,
    key_agreement_secret_jwk: String,
    key_agreement_kid: String,
) -> Result<String, String> {
    state.from_secrets_with_kid(&key_agreement_secret_jwk, &key_agreement_kid)
}

#[tauri::command]
pub async fn pack(
    state: tauri::State<'_, DidcommMessagingStore>,
    handle: String,
    message: serde_json::Value,
    to: String,
    frm: Option<String>,
) -> Result<PackResult, String> {
    state.pack(&handle, &message, &to, frm.as_deref()).await
}

#[tauri::command]
pub async fn pack_as_json(
    state: tauri::State<'_, DidcommMessagingStore>,
    handle: String,
    message: serde_json::Value,
    to: String,
    frm: Option<String>,
) -> Result<PackResult, String> {
    state.pack_as_json(&handle, &message, &to, frm.as_deref()).await
}

#[tauri::command]
pub async fn unpack(
    state: tauri::State<'_, DidcommMessagingStore>,
    handle: String,
    encoded: Vec<u8>,
) -> Result<UnpackResult, String> {
    state.unpack(&handle, &encoded).await
}

#[tauri::command]
pub async fn resolve_verification_method_kid(
    state: tauri::State<'_, DidcommMessagingStore>,
    handle: String,
    did: String,
    public_multikey: String,
) -> Result<Option<String>, String> {
    state.resolve_verification_method_kid(&handle, &did, &public_multikey).await
}

#[tauri::command]
pub async fn build_from_prior(
    state: tauri::State<'_, DidcommMessagingStore>,
    handle: String,
    prior_did: String,
    new_did: String,
    signing_secret_jwk: String,
    signing_kid: String,
    iat_seconds: i64,
) -> Result<String, String> {
    state
        .build_from_prior(&handle, &prior_did, &new_did, &signing_secret_jwk, &signing_kid, iat_seconds)
        .await
}

#[tauri::command]
pub async fn verify_from_prior(
    state: tauri::State<'_, DidcommMessagingStore>,
    handle: String,
    jwt: String,
) -> Result<FromPriorResult, String> {
    state.verify_from_prior(&handle, &jwt).await
}

#[tauri::command]
pub fn dispose_messaging(
    state: tauri::State<'_, DidcommMessagingStore>,
    handle: String,
) -> Result<(), String> {
    state.dispose(&handle);
    Ok(())
}
