//! Proves `V1DIDCommMessaging` end to end: pack a message to a recipient DID, with the
//! recipient behind a mediator (a `routingKeys` entry pointing at a *different* DID's
//! key), and confirms the result is `routing/1.0/forward`-wrapped and addressed to the
//! mediator's own key -- the same shape of proof used for v2's `RoutingService`.

use std::collections::HashMap;

use askar_crypto::{
    alg::ed25519::Ed25519KeyPair,
    repr::{KeyGen, KeyPublicBytes},
};
use async_trait::async_trait;
use didcomm_core::resolver::{DIDResolver, ResolutionError};
use didcomm_core::secrets::InMemorySecretsManager;
use didcomm_multiformats::{multibase, multicodec};
use didcomm_v1::messaging::{PackTo, V1DIDCommMessaging};
use didcomm_v1::packaging::V1SecretKey;
use serde_json::{json, Value};

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
        multibase::encode_base58btc(multicodec::wrap(multicodec::ED25519_PUB, pub_bytes))
    )
}

fn doc_with_v1_service(
    did: &str,
    pub_bytes: &[u8],
    endpoint: &str,
    routing_keys: &[&str],
) -> Value {
    json!({
        "id": did,
        "verificationMethod": [{
            "id": "#key-1",
            "type": "Multikey",
            "controller": did,
            "publicKeyMultibase": multikey(pub_bytes),
        }],
        "service": [{
            "id": "#service",
            "type": "did-communication",
            "serviceEndpoint": endpoint,
            "recipientKeys": ["#key-1"],
            "routingKeys": routing_keys,
        }],
    })
}

#[test]
fn wraps_in_a_routing_1_0_forward_message_when_there_is_a_mediator() {
    let recipient_key = Ed25519KeyPair::random().unwrap();
    let recipient_pub = recipient_key.with_public_bytes(<[u8]>::to_vec);
    let recipient_did = "did:example:recipient";

    let mediator_key = Ed25519KeyPair::random().unwrap();
    let mediator_pub = mediator_key.with_public_bytes(<[u8]>::to_vec);
    let mediator_did = "did:example:mediator";
    let mediator_kid = multibase::encode_base58btc(&mediator_pub);

    let mut docs = HashMap::new();
    docs.insert(
        recipient_did.to_string(),
        doc_with_v1_service(
            recipient_did,
            &recipient_pub,
            "http://mediator.example/inbox",
            &[&format!("{mediator_did}#key-1")],
        ),
    );
    docs.insert(
        mediator_did.to_string(),
        doc_with_v1_service(mediator_did, &mediator_pub, "http://mediator.example/inbox", &[]),
    );

    let secrets = InMemorySecretsManager::<V1SecretKey>::new();
    secrets.add_secret(V1SecretKey::new(recipient_key));
    secrets.add_secret(V1SecretKey::new(mediator_key));

    let dmp = V1DIDCommMessaging::new(secrets, Box::new(StaticResolver(docs)));

    pollster::block_on(async {
        let message = serde_json::to_vec(&json!({
            "@type": "https://didcomm.org/basicmessage/1.0/message",
            "content": "hi",
        }))
        .unwrap();

        let packed = dmp
            .pack(&message, PackTo::Did(recipient_did), None)
            .await
            .expect("packs");
        assert_eq!(packed.target_endpoint, "http://mediator.example/inbox");

        // The mediator unpacks the outer layer and finds a routing/1.0/forward
        // message naming the recipient as "to", with the original (still encrypted
        // to the recipient) message attached.
        let unpacked_by_mediator = dmp.unpack(&packed.message).await.expect("mediator unpacks outer layer");
        assert_eq!(unpacked_by_mediator.recipient_kid, mediator_kid);
        let forward = unpacked_by_mediator.message().unwrap();
        assert_eq!(forward["@type"], "https://didcomm.org/routing/1.0/forward");

        let inner_bytes = serde_json::to_vec(&forward["msg"]).unwrap();
        let unpacked_by_recipient = dmp.unpack(&inner_bytes).await.expect("recipient unpacks inner layer");
        let inner_message = unpacked_by_recipient.message().unwrap();
        assert_eq!(inner_message["content"], "hi");
    });
}
