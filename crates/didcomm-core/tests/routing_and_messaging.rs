//! Proves `RoutingService`'s actual reason for existing: a recipient behind a mediator
//! gets a `routing/2.0/forward`-wrapped message instead of a direct one, and
//! `DIDCommMessaging` (pack + prepare_forward together) delivers that transparently.
//!
//! Same `StaticResolver` approach as `packaging_end_to_end.rs`: a trivial in-memory
//! resolver, real `askar-crypto`-backed crypto, real `PackagingService`/`RoutingService`
//! logic underneath.

use std::collections::HashMap;

use askar_crypto::{
    alg::x25519::X25519KeyPair,
    repr::{KeyGen, KeyPublicBytes},
};
use async_trait::async_trait;
use serde_json::{json, Value};

use didcomm_core::messaging::DIDCommMessaging;
use didcomm_core::resolver::{DIDResolver, ResolutionError};
use didcomm_core::secrets::InMemorySecretsManager;
use didcomm_crypto_askar::{AskarCryptoService, AskarSecretKey};
use didcomm_multiformats::{multibase, multicodec};

struct StaticResolver(HashMap<String, Value>);

#[async_trait]
impl DIDResolver for StaticResolver {
    async fn resolve(&self, did: &str) -> Result<Value, ResolutionError> {
        self.0
            .get(did)
            .cloned()
            .ok_or_else(|| ResolutionError::Resolution(format!("not found: {did}")))
    }

    async fn is_resolvable(&self, did: &str) -> bool {
        self.0.contains_key(did)
    }
}

fn multikey(pub_bytes: &[u8]) -> String {
    format!(
        "z{}",
        multibase::encode_base58btc(multicodec::wrap(multicodec::X25519_PUB, pub_bytes))
    )
}

fn doc_with_endpoint(did: &str, pub_bytes: &[u8], endpoint_uri: &str, routing_keys: &[&str]) -> Value {
    json!({
        "id": did,
        "verificationMethod": [{
            "id": "#key-1",
            "type": "Multikey",
            "controller": did,
            "publicKeyMultibase": multikey(pub_bytes),
        }],
        "keyAgreement": ["#key-1"],
        "service": [{
            "id": "#service",
            "type": "DIDCommMessaging",
            "serviceEndpoint": {
                "uri": endpoint_uri,
                "accept": ["didcomm/v2"],
                "routingKeys": routing_keys,
            },
        }],
    })
}

/// A message to a recipient with no mediator (service endpoint is a plain URI) isn't
/// forward-wrapped at all -- prepare_forward should be a no-op.
#[test]
fn packs_directly_when_there_is_no_mediator() {
    let recipient_key = X25519KeyPair::random().unwrap();
    let recipient_pub = recipient_key.with_public_bytes(<[u8]>::to_vec);
    let recipient_did = "did:example:recipient";

    let mut docs = HashMap::new();
    docs.insert(
        recipient_did.to_string(),
        doc_with_endpoint(recipient_did, &recipient_pub, "https://recipient.example/inbox", &[]),
    );
    let resolver: Box<dyn DIDResolver> = Box::new(StaticResolver(docs));

    let secrets = InMemorySecretsManager::<AskarSecretKey>::new();
    secrets.add_secret(AskarSecretKey::new(format!("{recipient_did}#key-1"), recipient_key));

    let dmp = DIDCommMessaging::new(AskarCryptoService, secrets, resolver);

    pollster::block_on(async {
        let packed = dmp
            .pack(&json!({"type": "https://didcomm.org/basicmessage/2.0/message", "body": {"content": "hi"}}), recipient_did, None)
            .await
            .expect("packs");

        assert_eq!(packed.get_endpoint("https"), Some("https://recipient.example/inbox"));

        // Not forward-wrapped: unpacking directly (as the recipient would) yields the
        // original message, not a routing/2.0/forward envelope around it.
        let unpacked = dmp.unpack(&packed.message).await.expect("unpacks");
        let message = unpacked.message().unwrap();
        assert_eq!(message["type"], "https://didcomm.org/basicmessage/2.0/message");
    });
}

/// A message to a recipient *behind* a mediator (service endpoint is another DID) gets
/// wrapped in a routing/2.0/forward envelope addressed to the mediator, which the
/// mediator itself must unpack to learn who to deliver the inner message to.
#[test]
fn wraps_in_a_forward_message_when_there_is_a_mediator() {
    let recipient_key = X25519KeyPair::random().unwrap();
    let recipient_pub = recipient_key.with_public_bytes(<[u8]>::to_vec);
    let recipient_did = "did:example:recipient";

    let mediator_key = X25519KeyPair::random().unwrap();
    let mediator_pub = mediator_key.with_public_bytes(<[u8]>::to_vec);
    let mediator_did = "did:example:mediator";

    let mut docs = HashMap::new();
    // The recipient's own service endpoint points at the mediator DID, not a URI.
    docs.insert(
        recipient_did.to_string(),
        doc_with_endpoint(recipient_did, &recipient_pub, mediator_did, &[]),
    );
    docs.insert(
        mediator_did.to_string(),
        doc_with_endpoint(mediator_did, &mediator_pub, "https://mediator.example/inbox", &[]),
    );
    let resolver_data = docs;

    let secrets = InMemorySecretsManager::<AskarSecretKey>::new();
    secrets.add_secret(AskarSecretKey::new(format!("{recipient_did}#key-1"), recipient_key));
    secrets.add_secret(AskarSecretKey::new(format!("{mediator_did}#key-1"), mediator_key));

    let dmp = DIDCommMessaging::new(
        AskarCryptoService,
        secrets,
        Box::new(StaticResolver(resolver_data)) as Box<dyn DIDResolver>,
    );

    pollster::block_on(async {
        let packed = dmp
            .pack(&json!({"type": "https://didcomm.org/basicmessage/2.0/message", "body": {"content": "hi"}}), recipient_did, None)
            .await
            .expect("packs");

        // Delivered to the mediator's endpoint, not the recipient's (there isn't one).
        assert_eq!(packed.get_endpoint("https"), Some("https://mediator.example/inbox"));

        // The mediator unpacks the outer layer and finds a routing/2.0/forward
        // envelope naming the recipient as "next", with the original encrypted
        // message attached (still encrypted *to the recipient*, unreadable by the
        // mediator).
        let unpacked_by_mediator = dmp.unpack(&packed.message).await.expect("mediator unpacks outer layer");
        let forward = unpacked_by_mediator.message().unwrap();
        assert_eq!(forward["type"], "https://didcomm.org/routing/2.0/forward");
        assert_eq!(forward["body"]["next"], recipient_did);

        let inner_message = &forward["attachments"][0]["data"]["json"];
        let inner_bytes = serde_json::to_vec(inner_message).unwrap();
        let unpacked_by_recipient = dmp.unpack(&inner_bytes).await.expect("recipient unpacks inner layer");
        let message = unpacked_by_recipient.message().unwrap();
        assert_eq!(message["type"], "https://didcomm.org/basicmessage/2.0/message");
        assert_eq!(message["body"]["content"], "hi");
    });
}

/// `pack_direct` never forward-wraps, even for a recipient whose own document looks
/// mediated (service endpoint is another DID) -- the exact shape a self-mediated
/// wyvrn-chat Identity/Device DID has, since its endpoint is the mediator's own DID
/// (see multi-device/1.0). A real regression: a mediator replying directly to one of
/// its own already-connected clients over `pack()` (not `pack_direct`) resolved that
/// client's endpoint, found *the mediator's own DID* there, and concluded it needed to
/// forward its own reply to itself -- handing the client back a message encrypted to
/// the mediator's own key instead of the client's, which the client could never
/// decrypt ("no recognized recipient key"). `pack_direct` exists specifically so a
/// synchronous reply over an already-open channel skips this resolution entirely.
#[test]
fn pack_direct_never_wraps_even_for_a_mediator_shaped_recipient() {
    let recipient_key = X25519KeyPair::random().unwrap();
    let recipient_pub = recipient_key.with_public_bytes(<[u8]>::to_vec);
    let recipient_did = "did:example:recipient";

    let mediator_key = X25519KeyPair::random().unwrap();
    let mediator_pub = mediator_key.with_public_bytes(<[u8]>::to_vec);
    let mediator_did = "did:example:mediator";

    let mut docs = HashMap::new();
    docs.insert(
        recipient_did.to_string(),
        doc_with_endpoint(recipient_did, &recipient_pub, mediator_did, &[]),
    );
    docs.insert(
        mediator_did.to_string(),
        doc_with_endpoint(mediator_did, &mediator_pub, "https://mediator.example/inbox", &[]),
    );

    let secrets = InMemorySecretsManager::<AskarSecretKey>::new();
    secrets.add_secret(AskarSecretKey::new(format!("{recipient_did}#key-1"), recipient_key));
    secrets.add_secret(AskarSecretKey::new(format!("{mediator_did}#key-1"), mediator_key));

    let dmp = DIDCommMessaging::new(
        AskarCryptoService,
        secrets,
        Box::new(StaticResolver(docs)) as Box<dyn DIDResolver>,
    );

    pollster::block_on(async {
        let packed = dmp
            .pack_direct(
                &json!({"type": "https://didcomm.org/basicmessage/2.0/message", "body": {"content": "hi"}}),
                recipient_did,
                Some(mediator_did),
            )
            .await
            .expect("packs");

        assert!(packed.target_services.is_empty());

        // The recipient itself can unpack it directly -- no routing/2.0/forward layer
        // to peel off first, and no dependency on the mediator's own key at all.
        let unpacked = dmp.unpack(&packed.message).await.expect("recipient unpacks directly");
        let message = unpacked.message().unwrap();
        assert_eq!(message["type"], "https://didcomm.org/basicmessage/2.0/message");
        assert_eq!(message["body"]["content"], "hi");
    });
}
