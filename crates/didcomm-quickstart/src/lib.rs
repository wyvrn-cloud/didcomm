//! Batteries-included DID generation and default setup, mirroring the non-transport
//! parts of `didcomm_messaging.quickstart` (`generate_did`, `setup_default`).
//!
//! What made the Python original worth having wasn't just that it exists -- it's that
//! it's short and heavily commented enough to teach you how to assemble the same pieces
//! yourself. `setup_default` wires together one specific crypto backend, one specific
//! set of DID resolvers, and an in-memory secrets store; as your application grows past
//! what those defaults cover, the intent is that you read this module, copy the parts
//! you need, and swap in your own choices -- your own secrets storage, a different
//! resolver set, maybe eventually a different crypto backend -- rather than being stuck
//! with what's wired up here. Every dependency this crate pulls in is one you can drop
//! once you've outgrown it: nothing else in this workspace depends on
//! `didcomm-quickstart`.
//!
//! `quickstart.py`'s transport-touching functions (`send_http_message`, `setup_relay`)
//! aren't ported here -- they're `aiohttp` calls, and the equivalent for a Rust/wasm/
//! Python binding is each binding's own idiomatic HTTP client, not one shared
//! abstraction (see `PLAN.md` §6's table for where that line is drawn).

use askar_crypto::{
    alg::{ed25519::Ed25519KeyPair, x25519::X25519KeyPair},
    repr::{KeyGen, KeyPublicBytes},
};
use didcomm_core::messaging::DIDCommMessaging;
use didcomm_core::resolver::{DIDResolver, PrefixResolver};
use didcomm_core::secrets::InMemorySecretsManager;
use didcomm_crypto_askar::{AskarCryptoService, AskarSecretKey};
use didcomm_multiformats::{multicodec, multikey};
use didcomm_resolver_jwk::JwkResolver;
use didcomm_resolver_peer::{peer4::Peer4, KeyPurpose, Peer2};
#[cfg(feature = "did-web")]
use didcomm_resolver_web::DidWeb;
#[cfg(feature = "did-webvh")]
use didcomm_resolver_webvh::DidWebVh;
use serde_json::json;

/// Errors generating a DID or setting up a default `DIDCommMessaging`.
#[derive(Debug, thiserror::Error)]
pub enum QuickstartError {
    #[error("key generation failed: {0}")]
    Askar(#[from] askar_crypto::Error),
    #[error("failed to construct did:peer:4: {0}")]
    Peer(#[from] didcomm_resolver_peer::peer4::Peer4Error),
}

/// A freshly generated `did:peer:4`, with its raw key material.
pub struct GeneratedDid {
    pub did: String,
    /// For the DID's "authentication" verification relationship. `AskarCryptoService`'s
    /// own `CryptoService` methods are all keyAgreement-based and don't touch this, but
    /// its separate `SigningService` implementation (`didcomm-core::crypto`) can
    /// sign/verify with a key like this one -- intended for `from_prior` DID rotation.
    pub verification_key: Ed25519KeyPair,
    /// For the DID's "keyAgreement" verification relationship. This is the key
    /// DIDComm v2 pack/unpack actually uses.
    pub key_agreement_key: X25519KeyPair,
}

/// Generate a fresh `did:peer:4` with one authentication key and one key-agreement key,
/// and a service endpoint queued for later pickup (`"didcomm:transport/queue"`) rather
/// than a live transport address -- swap it for a real endpoint, or route through a
/// mediator via [`didcomm_core::routing::RoutingService`], before actually using this
/// DID. Mirrors `quickstart.generate_did`, generating `did:peer:4` rather than the
/// Python original's `did:peer:2` -- the reference mediator this workspace's `did:web`
/// support (`wyvrn-mediator-identity`) is modeled on calls `did:peer:2` deprecated and
/// prefers `did:peer:4` underneath, and this workspace now generates one everywhere for
/// the same reason. `did:peer:2` *resolution* stays fully supported (via
/// [`Peer2`]/[`didcomm_resolver_peer::resolve`]) for interop with peers, and any
/// already-existing identity on disk, that still use it.
pub fn generate_did() -> Result<GeneratedDid, QuickstartError> {
    generate_did_with_endpoint("didcomm:transport/queue")
}

/// Like [`generate_did`], but with a caller-chosen `serviceEndpoint.uri` instead of the
/// unset-transport placeholder -- for a DID meant to be directly reachable (a real HTTP(S)
/// endpoint) or routed through a specific mediator (that mediator's own DID as the
/// endpoint, which [`didcomm_core::routing::RoutingService`]'s own resolution recognizes
/// as "needs forwarding," the same way a bare HTTP(S) URL means "reachable directly").
/// This exact pattern -- generate, then hand-register the extra endpoint -- had been
/// hand-duplicated across this workspace's own test fixtures and interop harnesses often
/// enough (`didcomm-mediator-core`, `wyvrn-mediator-protocols`, `wyvrn-mediator-legacy`,
/// the `didcomm-v2-test-util` interop script, ...) that it belongs here instead.
pub fn generate_did_with_endpoint(endpoint_uri: &str) -> Result<GeneratedDid, QuickstartError> {
    let verification_key = Ed25519KeyPair::random()?;
    let key_agreement_key = X25519KeyPair::random()?;

    let verification_material = multikey::encode(
        multicodec::ED25519_PUB,
        &verification_key.with_public_bytes(<[u8]>::to_vec),
    );
    let key_agreement_material = multikey::encode(
        multicodec::X25519_PUB,
        &key_agreement_key.with_public_bytes(<[u8]>::to_vec),
    );

    let did = didcomm_resolver_peer::peer4::generate(
        &[
            (KeyPurpose::Authentication, verification_material.as_str()),
            (KeyPurpose::KeyAgreement, key_agreement_material.as_str()),
        ],
        &[json!({
            "type": "DIDCommMessaging",
            "serviceEndpoint": {
                "uri": endpoint_uri,
                "accept": didcomm_diddoc::DIDCOMM_V2_ACCEPT,
                "routingKeys": [],
            },
        })],
    )?;

    Ok(GeneratedDid {
        did,
        verification_key,
        key_agreement_key,
    })
}

/// Mint an Identity DID document from *existing* public keys -- one `authentication`
/// entry per trusted device, one `keyAgreement` entry per any enrolled device (see
/// `wyvrn-protocols`' `multi-device/1.0`: one document, several independent
/// per-device keys of each kind, never a shared secret). Unlike
/// [`generate_did`]/[`generate_did_with_endpoint`], this never generates a key itself
/// -- every device generates and keeps its own locally; this only builds the shared
/// document listing everyone's already-generated *public* half. Callers get their own
/// public multikey strings from [`authentication_public_multikey`]/
/// [`key_agreement_public_multikey`], or from a sibling device's own announcement.
///
/// `key_agreement_public_multikeys` must not be empty (a document with no keyAgreement
/// entries can't receive anything); `authentication_public_multikeys` may be, for an
/// identity with no trusted device yet.
pub fn generate_multi_device_did(
    authentication_public_multikeys: &[&str],
    key_agreement_public_multikeys: &[&str],
    endpoint_uri: &str,
) -> Result<String, QuickstartError> {
    let mut keys: Vec<(KeyPurpose, &str)> =
        Vec::with_capacity(authentication_public_multikeys.len() + key_agreement_public_multikeys.len());
    for material in authentication_public_multikeys {
        keys.push((KeyPurpose::Authentication, material));
    }
    for material in key_agreement_public_multikeys {
        keys.push((KeyPurpose::KeyAgreement, material));
    }
    Ok(didcomm_resolver_peer::peer4::generate(
        &keys,
        &[json!({
            "type": "DIDCommMessaging",
            "serviceEndpoint": {
                "uri": endpoint_uri,
                "accept": didcomm_diddoc::DIDCOMM_V2_ACCEPT,
                "routingKeys": [],
            },
        })],
    )?)
}

/// The multikey-encoded public half of a freshly generated Ed25519 authentication
/// keypair -- what a device announces to others so a trusted device can list it in a
/// shared Identity DID document (see [`generate_multi_device_did`]), without ever
/// exposing the secret itself.
pub fn authentication_public_multikey(key: &Ed25519KeyPair) -> String {
    multikey::encode(multicodec::ED25519_PUB, &key.with_public_bytes(<[u8]>::to_vec))
}

/// The multikey-encoded public half of a freshly generated X25519 keyAgreement
/// keypair -- see [`authentication_public_multikey`], same idea for the other key
/// type.
pub fn key_agreement_public_multikey(key: &X25519KeyPair) -> String {
    multikey::encode(multicodec::X25519_PUB, &key.with_public_bytes(<[u8]>::to_vec))
}

/// The concrete `DIDCommMessaging` type [`setup_default`] returns.
pub type DefaultDIDCommMessaging =
    DIDCommMessaging<AskarCryptoService, InMemorySecretsManager<AskarSecretKey>>;

/// Wire up a ready-to-use `DIDCommMessaging`: the `askar-crypto` backend, an in-memory
/// secrets manager pre-loaded with `generated`'s key-agreement key, and a resolver
/// covering `did:peer:2`, `did:peer:4`, `did:jwk`, and (with this crate's default
/// features -- see the `did-web`/`did-webvh` features) `did:web` and `did:webvh`.
/// Mirrors `quickstart.setup_default`.
///
/// Only the key-agreement key gets registered as a secret -- the verification key
/// `generated` also carries isn't usable by `AskarCryptoService` yet (see
/// [`GeneratedDid`]'s docs), so there's nothing useful to register it for today.
pub fn setup_default(generated: &GeneratedDid) -> DefaultDIDCommMessaging {
    let secrets = InMemorySecretsManager::new();
    secrets.add_secret(AskarSecretKey::new(
        format!("{}#key-2", generated.did),
        generated.key_agreement_key.clone(),
    ));

    // `mut` and the pushes below are only exercised when at least one of the
    // did-web/did-webvh features is on -- harmless either way, so just silence the
    // warning rather than duplicating this list per feature combination.
    #[allow(unused_mut)]
    let mut resolvers: Vec<(&str, Box<dyn DIDResolver>)> = vec![
        ("did:peer:2", Box::new(Peer2) as Box<dyn DIDResolver>),
        (
            "did:peer:4",
            Box::new(Peer4) as Box<dyn DIDResolver>,
        ),
        ("did:jwk:", Box::new(JwkResolver) as Box<dyn DIDResolver>),
    ];
    #[cfg(feature = "did-webvh")]
    resolvers.push(("did:webvh:", Box::new(DidWebVh) as Box<dyn DIDResolver>));
    #[cfg(feature = "did-web")]
    resolvers.push(("did:web:", Box::new(DidWeb::new()) as Box<dyn DIDResolver>));

    let resolver: Box<dyn DIDResolver> = Box::new(PrefixResolver::new(resolvers));

    DIDCommMessaging::new(AskarCryptoService, secrets, resolver)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_a_did_peer_4_with_a_key_agreement_key() {
        let generated = generate_did().unwrap();
        assert!(generated.did.starts_with("did:peer:4"));
        let doc = didcomm_resolver_peer::peer4::resolve(&generated.did).unwrap();
        assert!(doc["keyAgreement"].as_array().is_some_and(|a| !a.is_empty()));
    }

    #[test]
    fn generate_did_with_endpoint_uses_the_given_endpoint() {
        let generated = generate_did_with_endpoint("did:example:mediator").unwrap();
        let doc = didcomm_resolver_peer::peer4::resolve(&generated.did).unwrap();
        assert_eq!(
            doc["service"][0]["serviceEndpoint"]["uri"],
            "did:example:mediator"
        );
    }

    #[test]
    fn generate_multi_device_did_lists_every_given_key() {
        let device_a = X25519KeyPair::random().unwrap();
        let device_b = X25519KeyPair::random().unwrap();
        let trusted_device_auth = Ed25519KeyPair::random().unwrap();

        let did = generate_multi_device_did(
            &[&authentication_public_multikey(&trusted_device_auth)],
            &[
                &key_agreement_public_multikey(&device_a),
                &key_agreement_public_multikey(&device_b),
            ],
            "did:example:mediator",
        )
        .unwrap();

        let doc = didcomm_resolver_peer::peer4::resolve(&did).unwrap();
        assert_eq!(doc["authentication"].as_array().unwrap().len(), 1);
        assert_eq!(doc["keyAgreement"].as_array().unwrap().len(), 2);
        assert_eq!(
            doc["service"][0]["serviceEndpoint"]["uri"],
            "did:example:mediator"
        );
    }

    #[test]
    fn generate_multi_device_did_allows_no_trusted_device_yet() {
        let device_a = X25519KeyPair::random().unwrap();
        let did = generate_multi_device_did(
            &[],
            &[&key_agreement_public_multikey(&device_a)],
            "did:example:mediator",
        )
        .unwrap();
        let doc = didcomm_resolver_peer::peer4::resolve(&did).unwrap();
        assert!(doc["authentication"].as_array().map(Vec::is_empty).unwrap_or(true));
        assert_eq!(doc["keyAgreement"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn generate_multi_device_did_reproduces_generate_did_with_endpoints_own_did_for_the_same_single_key_pair() {
        // wyvrn-chat's migration of an existing single-device identity into the
        // multi-device shape depends on this holding: re-minting a document with
        // exactly the same one authentication + one keyAgreement key (and the same
        // endpoint) through the new multi-device path must produce the byte-identical
        // DID generate_did_with_endpoint already produced -- so migrating never needs
        // a from_prior rotation just to keep using the identity's existing address.
        let original = generate_did_with_endpoint("did:example:mediator").unwrap();

        let remade = generate_multi_device_did(
            &[&authentication_public_multikey(&original.verification_key)],
            &[&key_agreement_public_multikey(&original.key_agreement_key)],
            "did:example:mediator",
        )
        .unwrap();

        assert_eq!(remade, original.did);
    }

    #[test]
    fn setup_default_can_pack_and_unpack_to_itself() {
        // Not a realistic scenario (packing a message to your own DID), but it proves
        // setup_default's resolver + secrets wiring is internally consistent: the
        // did:peer:4 it generates resolves to a document whose key-agreement key
        // matches the secret it registered.
        let generated = generate_did().unwrap();
        let dmp = setup_default(&generated);

        pollster::block_on(async {
            let packed = dmp
                .pack(
                    &json!({"type": "https://didcomm.org/basicmessage/2.0/message", "body": {}}),
                    &generated.did,
                    None,
                )
                .await
                .unwrap();
            let unpacked = dmp.unpack(&packed.message).await.unwrap();
            assert_eq!(
                unpacked.message().unwrap()["type"],
                "https://didcomm.org/basicmessage/2.0/message"
            );
        });
    }
}
