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
use didcomm_resolver_peer::{KeyPurpose, Peer2};
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
    #[error("failed to construct did:peer:2: {0}")]
    Peer(#[from] didcomm_resolver_peer::PeerError),
}

/// A freshly generated `did:peer:2`, with its raw key material.
pub struct GeneratedDid {
    pub did: String,
    /// For the DID's "authentication" verification relationship. Not yet usable by
    /// [`AskarCryptoService`] for anything -- this workspace doesn't implement Ed25519
    /// signing yet -- but generated anyway so the DID document is spec-complete rather
    /// than key-agreement-only, and so it's there once signing support exists.
    pub verification_key: Ed25519KeyPair,
    /// For the DID's "keyAgreement" verification relationship. This is the key
    /// DIDComm v2 pack/unpack actually uses.
    pub key_agreement_key: X25519KeyPair,
}

/// Generate a fresh `did:peer:2` with one authentication key and one key-agreement key,
/// and a service endpoint queued for later pickup (`"didcomm:transport/queue"`) rather
/// than a live transport address -- swap it for a real endpoint, or route through a
/// mediator via [`didcomm_core::routing::RoutingService`], before actually using this
/// DID. Mirrors `quickstart.generate_did`.
pub fn generate_did() -> Result<GeneratedDid, QuickstartError> {
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

    let did = didcomm_resolver_peer::generate(
        &[
            (KeyPurpose::Authentication, verification_material.as_str()),
            (KeyPurpose::KeyAgreement, key_agreement_material.as_str()),
        ],
        &[json!({
            "type": "DIDCommMessaging",
            "serviceEndpoint": {
                "uri": "didcomm:transport/queue",
                "accept": ["didcomm/v2"],
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
        ("did:peer:4", Box::new(didcomm_resolver_peer::peer4::Peer4) as Box<dyn DIDResolver>),
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
    fn generates_a_did_peer_2_with_a_key_agreement_key() {
        let generated = generate_did().unwrap();
        assert!(generated.did.starts_with("did:peer:2.Vz"));
        assert!(generated.did.contains(".Ez"));
    }

    #[test]
    fn setup_default_can_pack_and_unpack_to_itself() {
        // Not a realistic scenario (packing a message to your own DID), but it proves
        // setup_default's resolver + secrets wiring is internally consistent: the
        // did:peer:2 it generates resolves to a document whose key-agreement key
        // matches the secret it registered.
        let generated = generate_did().unwrap();
        let dmp = setup_default(&generated);

        pollster::block_on(async {
            let packed = dmp
                .pack(&json!({"type": "https://didcomm.org/basicmessage/2.0/message", "body": {}}), &generated.did, None)
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
