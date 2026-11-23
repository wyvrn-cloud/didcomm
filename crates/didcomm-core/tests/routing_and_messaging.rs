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
        assert_eq!(forward["to"], json!([mediator_did]));
        assert!(forward["created_time"].as_u64().unwrap() > 1_700_000_000);

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

/// A mediator whose service lists a routing key that is a DID URL (`did:...#key-1`):
/// the message is wrapped once per key, and every forward's `to` header names a DID --
/// the spec forbids a fragment there -- while `body.next` keeps naming the exact hop.
#[test]
fn forwards_name_their_recipient_by_did_even_for_key_routing_keys() {
    let recipient_key = X25519KeyPair::random().unwrap();
    let recipient_pub = recipient_key.with_public_bytes(<[u8]>::to_vec);
    let recipient_did = "did:example:recipient";

    let mediator_key = X25519KeyPair::random().unwrap();
    let mediator_pub = mediator_key.with_public_bytes(<[u8]>::to_vec);
    let mediator_did = "did:example:mediator";
    let mediator_key_id = format!("{mediator_did}#key-1");

    let mut docs = HashMap::new();
    docs.insert(
        recipient_did.to_string(),
        doc_with_endpoint(recipient_did, &recipient_pub, mediator_did, &[]),
    );
    docs.insert(
        mediator_did.to_string(),
        doc_with_endpoint(mediator_did, &mediator_pub, "https://mediator.example/inbox", &[&mediator_key_id]),
    );

    let secrets = InMemorySecretsManager::<AskarSecretKey>::new();
    secrets.add_secret(AskarSecretKey::new(format!("{recipient_did}#key-1"), recipient_key));
    secrets.add_secret(AskarSecretKey::new(mediator_key_id.clone(), mediator_key));
    let dmp = DIDCommMessaging::new(
        AskarCryptoService,
        secrets,
        Box::new(StaticResolver(docs)) as Box<dyn DIDResolver>,
    );

    pollster::block_on(async {
        let packed = dmp
            .pack(&json!({"type": "https://didcomm.org/basicmessage/2.0/message", "body": {"content": "hi"}}), recipient_did, None)
            .await
            .expect("packs");

        // Outer forward: to the mediator's DID, onward to the routing key.
        let outer = dmp.unpack(&packed.message).await.expect("outer").message().unwrap();
        assert_eq!(outer["to"], json!([mediator_did]));
        assert_eq!(outer["body"]["next"], mediator_key_id);
        assert!(outer["created_time"].is_u64());

        // Inner forward: addressed to the routing key, whose `to` is still the DID.
        let inner_bytes = serde_json::to_vec(&outer["attachments"][0]["data"]["json"]).unwrap();
        let inner = dmp.unpack(&inner_bytes).await.expect("inner").message().unwrap();
        assert_eq!(inner["type"], "https://didcomm.org/routing/2.0/forward");
        assert_eq!(inner["to"], json!([mediator_did]));
        assert_eq!(inner["body"]["next"], recipient_did);
        assert!(inner["created_time"].is_u64());

        let message_bytes = serde_json::to_vec(&inner["attachments"][0]["data"]["json"]).unwrap();
        let message = dmp.unpack(&message_bytes).await.expect("message").message().unwrap();
        assert_eq!(message["body"]["content"], "hi");
    });
}

/// A DID whose endpoint is itself, two that name each other, or a chain too long:
/// refused, never followed for ever (security review WYV-02).
#[test]
fn a_route_that_loops_or_runs_on_is_refused() {
    let key = X25519KeyPair::random().unwrap();
    let public = key.with_public_bytes(<[u8]>::to_vec);
    let mut docs = HashMap::new();
    docs.insert("did:example:self".to_string(), doc_with_endpoint("did:example:self", &public, "did:example:self", &[]));
    docs.insert("did:example:a".to_string(), doc_with_endpoint("did:example:a", &public, "did:example:b", &[]));
    docs.insert("did:example:b".to_string(), doc_with_endpoint("did:example:b", &public, "did:example:a", &[]));
    for n in 0..8 {
        let next = if n == 7 { "https://far.example/".to_string() } else { format!("did:example:hop{}", n + 1) };
        docs.insert(format!("did:example:hop{n}"), doc_with_endpoint(&format!("did:example:hop{n}"), &public, &next, &[]));
    }
    let secrets = InMemorySecretsManager::<AskarSecretKey>::new();
    let dmp = DIDCommMessaging::new(AskarCryptoService, secrets, Box::new(StaticResolver(docs)) as Box<dyn DIDResolver>);
    pollster::block_on(async {
        let message = json!({"type": "https://didcomm.org/basicmessage/2.0/message", "body": {"content": "hi"}});
        for to in ["did:example:self", "did:example:a", "did:example:hop0"] {
            let refused = dmp.pack(&message, to, None).await.err().unwrap_or_else(|| panic!("{to} should be refused"));
            assert!(refused.to_string().contains("loops"), "{to}: {refused}");
        }
    });
}

/// A recipient behind `mediator_did`, whose service lists `routing_keys` (each a
/// DID URL of a key the test holds), behind a second mediator if `second` is given
/// (with its own routing keys).
fn routed(routing_keys: &[String], second: Option<&[String]>) -> (DIDCommMessaging<AskarCryptoService, InMemorySecretsManager<AskarSecretKey>>, &'static str) {
    let secrets = InMemorySecretsManager::<AskarSecretKey>::new();
    let mut docs = HashMap::new();
    let key_doc = |did: &str, endpoint: &str, routing: &[String], docs: &mut HashMap<String, Value>| {
        let key = X25519KeyPair::random().unwrap();
        let routing: Vec<&str> = routing.iter().map(String::as_str).collect();
        docs.insert(did.to_string(), doc_with_endpoint(did, &key.with_public_bytes(<[u8]>::to_vec), endpoint, &routing));
        secrets.add_secret(AskarSecretKey::new(format!("{did}#key-1"), key));
    };
    // Every routing key is a DID of its own with a key-1 (no endpoint to ask).
    let mut all: Vec<String> = routing_keys.to_vec();
    all.extend(second.unwrap_or_default().iter().cloned());
    for key in &all {
        let did = key.split('#').next().unwrap().to_string();
        if !docs.contains_key(&did) {
            key_doc(&did, "https://unused.example/", &[], &mut docs);
        }
    }
    let first_endpoint = if second.is_some() { "did:example:mediator2" } else { "https://mediator.example/inbox" };
    key_doc("did:example:mediator", first_endpoint, routing_keys, &mut docs);
    if let Some(second) = second {
        key_doc("did:example:mediator2", "https://mediator2.example/inbox", second, &mut docs);
    }
    key_doc("did:example:recipient", "did:example:mediator", &[], &mut docs);
    let dmp = DIDCommMessaging::new(AskarCryptoService, secrets, Box::new(StaticResolver(docs)) as Box<dyn DIDResolver>);
    (dmp, "did:example:recipient")
}

fn routing_key(n: usize) -> String {
    format!("did:example:rk{n}#key-1")
}

/// Security review WYV-66: a service listing 100 routing keys would wrap the
/// message 100 times (each layer ~4/3 the last). Refused, as a local error.
#[test]
fn a_service_with_100_routing_keys_is_refused() {
    let keys: Vec<String> = (0..100).map(routing_key).collect();
    let (dmp, to) = routed(&keys, None);
    pollster::block_on(async {
        let message = json!({"type": "https://didcomm.org/basicmessage/2.0/message", "body": {"content": "hi"}});
        let refused = dmp.pack(&message, to, None).await.err().expect("refused");
        assert!(refused.to_string().contains("100 routing keys"), "{refused}");

        // Four is fine; two mediators of four keys each (10 layers) are not.
        let four: Vec<String> = (0..4).map(routing_key).collect();
        let (dmp, to) = routed(&four, None);
        assert!(dmp.pack(&message, to, None).await.is_ok());
        let others: Vec<String> = (4..8).map(routing_key).collect();
        let (dmp, to) = routed(&four, Some(&others));
        let refused = dmp.pack(&message, to, None).await.err().expect("refused");
        assert!(refused.to_string().contains("wraps the message 10 times"), "{refused}");
    });
}

/// A repeated routing key is wrapped for once, in its first place, rather than the
/// route refused (spec conformance: the route still works).
#[test]
fn duplicate_routing_keys_are_dropped_keeping_the_first() {
    let keys = vec![routing_key(1), routing_key(2), routing_key(1), routing_key(2), routing_key(1), routing_key(1)];
    let (dmp, to) = routed(&keys, None);
    pollster::block_on(async {
        let message = json!({"type": "https://didcomm.org/basicmessage/2.0/message", "body": {"content": "hi"}});
        let packed = dmp.pack(&message, to, None).await.expect("packs");
        // Mediator -> rk1 -> rk2 -> recipient: three forwards, in that order.
        let mut bytes = packed.message;
        let mut nexts = Vec::new();
        loop {
            let unpacked = dmp.unpack(&bytes).await.unwrap().message().unwrap();
            if unpacked["type"] != "https://didcomm.org/routing/2.0/forward" {
                assert_eq!(unpacked["body"]["content"], "hi");
                break;
            }
            nexts.push(unpacked["body"]["next"].as_str().unwrap().to_string());
            bytes = serde_json::to_vec(&unpacked["attachments"][0]["data"]["json"]).unwrap();
        }
        assert_eq!(nexts, vec![routing_key(1), routing_key(2), "did:example:recipient".to_string()]);
    });
}
