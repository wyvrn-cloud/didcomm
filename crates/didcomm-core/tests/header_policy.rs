//! `HeaderPolicy`: `pack` completes a message's standard headers by default (and refuses
//! contradictory ones), `HeaderPolicy::Verbatim` opts out, and `unpack` rejects an
//! authcrypted message whose `from` doesn't own the key that encrypted it.
//!
//! Same `StaticResolver` approach as `routing_and_messaging.rs`.

use std::collections::HashMap;

use askar_crypto::{
    alg::x25519::X25519KeyPair,
    repr::{KeyGen, KeyPublicBytes},
};
use async_trait::async_trait;
use serde_json::{json, Value};

use didcomm_core::messaging::{DIDCommMessaging, HeaderPolicy, MessagingError};
use didcomm_core::resolver::{DIDResolver, ResolutionError};
use didcomm_core::secrets::InMemorySecretsManager;
use didcomm_crypto_askar::{AskarCryptoService, AskarSecretKey};
use didcomm_multiformats::{multibase, multicodec};

const ALICE: &str = "did:example:alice";
const BOB: &str = "did:example:bob";
const BASICMESSAGE: &str = "https://didcomm.org/basicmessage/2.0/message";

type Messaging = DIDCommMessaging<AskarCryptoService, InMemorySecretsManager<AskarSecretKey>>;

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

fn doc(did: &str, key: &X25519KeyPair) -> Value {
    let multikey = format!(
        "z{}",
        multibase::encode_base58btc(multicodec::wrap(
            multicodec::X25519_PUB,
            &key.with_public_bytes(<[u8]>::to_vec)
        ))
    );
    json!({
        "id": did,
        "verificationMethod": [{
            "id": "#key-1",
            "type": "Multikey",
            "controller": did,
            "publicKeyMultibase": multikey,
        }],
        "keyAgreement": ["#key-1"],
        "service": [{
            "id": "#service",
            "type": "DIDCommMessaging",
            "serviceEndpoint": {"uri": format!("https://{did}.example/inbox"), "accept": ["didcomm/v2"]},
        }],
    })
}

/// One `DIDCommMessaging` holding both Alice's and Bob's keys, so a test can pack as
/// one and unpack as the other without wiring up two instances.
fn messaging() -> Messaging {
    let alice = X25519KeyPair::random().unwrap();
    let bob = X25519KeyPair::random().unwrap();
    let docs = HashMap::from([(ALICE.to_string(), doc(ALICE, &alice)), (BOB.to_string(), doc(BOB, &bob))]);
    let secrets = InMemorySecretsManager::<AskarSecretKey>::new();
    secrets.add_secret(AskarSecretKey::new(format!("{ALICE}#key-1"), alice));
    secrets.add_secret(AskarSecretKey::new(format!("{BOB}#key-1"), bob));
    DIDCommMessaging::new(AskarCryptoService, secrets, Box::new(StaticResolver(docs)))
}

fn basicmessage() -> Value {
    json!({"type": BASICMESSAGE, "body": {"content": "hi"}})
}

/// Pack `message` to Bob (authcrypted as Alice if `frm` is given) and unpack it again.
fn round_trip(dmp: &Messaging, message: &Value, frm: Option<&str>) -> Result<Value, MessagingError> {
    pollster::block_on(async {
        let packed = dmp.pack(message, BOB, frm).await?;
        Ok(dmp.unpack(&packed.message).await?.message()?)
    })
}

fn header_error(result: Result<Value, MessagingError>) -> &'static str {
    match result {
        Err(MessagingError::Header { header, .. }) => header,
        other => panic!("expected a header error, got {other:?}"),
    }
}

#[test]
fn complete_is_the_default() {
    assert_eq!(messaging().header_policy, HeaderPolicy::Complete);
}

#[test]
fn fills_missing_headers_when_authcrypting() {
    let received = round_trip(&messaging(), &basicmessage(), Some(ALICE)).unwrap();

    assert!(!received["id"].as_str().unwrap().is_empty());
    assert_eq!(received["from"], ALICE);
    assert_eq!(received["to"], json!([BOB]));
    assert!(received["created_time"].as_u64().unwrap() > 1_700_000_000);
    assert_eq!(received["body"]["content"], "hi");
}

#[test]
fn anoncrypt_gets_no_from() {
    let received = round_trip(&messaging(), &basicmessage(), None).unwrap();

    assert!(received.get("from").is_none());
    assert_eq!(received["to"], json!([BOB]));
    assert!(received["id"].is_string());
    assert!(received["created_time"].is_u64());
}

#[test]
fn sender_and_recipient_given_as_did_urls_become_plain_dids() {
    // pack_direct, since routing (unrelated to headers) can't resolve a service
    // endpoint for a bare key-agreement DID URL.
    let received = pollster::block_on(async {
        let dmp = messaging();
        let packed = dmp
            .pack_direct(&basicmessage(), &format!("{BOB}#key-1"), Some(&format!("{ALICE}#key-1")))
            .await
            .unwrap();
        dmp.unpack(&packed.message).await.unwrap().message().unwrap()
    });

    assert_eq!(received["from"], ALICE);
    assert_eq!(received["to"], json!([BOB]));
}

#[test]
fn keeps_headers_the_caller_set() {
    let mut message = basicmessage();
    message["id"] = json!("my-id");
    message["from"] = json!(ALICE);
    message["to"] = json!(["did:example:carol", BOB]);
    message["created_time"] = json!(1_547_577_721);

    let received = round_trip(&messaging(), &message, Some(ALICE)).unwrap();

    assert_eq!(received["id"], "my-id");
    assert_eq!(received["to"], json!(["did:example:carol", BOB]));
    assert_eq!(received["created_time"], 1_547_577_721);
}

#[test]
fn null_headers_count_as_missing() {
    let mut message = basicmessage();
    for header in ["id", "from", "to", "created_time"] {
        message[header] = Value::Null;
    }

    let received = round_trip(&messaging(), &message, Some(ALICE)).unwrap();

    assert!(received["id"].is_string());
    assert_eq!(received["from"], ALICE);
    assert_eq!(received["to"], json!([BOB]));
    assert!(received["created_time"].is_u64());
}

#[test]
fn rejects_a_from_that_is_not_the_sender() {
    let mut message = basicmessage();
    message["from"] = json!("did:example:mallory");

    assert_eq!(header_error(round_trip(&messaging(), &message, Some(ALICE))), "from");
}

#[test]
fn rejects_a_to_that_does_not_list_the_recipient() {
    let mut message = basicmessage();
    message["to"] = json!(["did:example:carol"]);

    assert_eq!(header_error(round_trip(&messaging(), &message, Some(ALICE))), "to");
}

#[test]
fn rejects_a_to_that_is_not_an_array() {
    let mut message = basicmessage();
    message["to"] = json!(BOB);

    assert_eq!(header_error(round_trip(&messaging(), &message, Some(ALICE))), "to");
}

#[test]
fn verbatim_packs_the_message_exactly_as_given() {
    let dmp = messaging().with_header_policy(HeaderPolicy::Verbatim);
    let message = basicmessage();

    let received = pollster::block_on(async {
        let packed = dmp.pack(&message, BOB, Some(ALICE)).await.unwrap();
        dmp.unpack(&packed.message).await.unwrap().unpacked
    });

    assert_eq!(received, serde_json::to_vec(&message).unwrap());
}

#[test]
fn verbatim_does_not_check_headers_either() {
    let dmp = messaging().with_header_policy(HeaderPolicy::Verbatim);
    let mut message = basicmessage();
    message["to"] = json!(["did:example:carol"]);

    let received = round_trip(&dmp, &message, Some(ALICE)).unwrap();

    assert_eq!(received["to"], json!(["did:example:carol"]));
}

#[test]
fn pack_direct_completes_headers_too() {
    let dmp = messaging();
    let received = pollster::block_on(async {
        let packed = dmp.pack_direct(&basicmessage(), BOB, Some(ALICE)).await.unwrap();
        dmp.unpack(&packed.message).await.unwrap().message().unwrap()
    });

    assert_eq!(received["from"], ALICE);
    assert_eq!(received["to"], json!([BOB]));
}

#[test]
fn unpack_accepts_an_authcrypted_message_without_from() {
    // Peers built on didcomm-messaging-python routinely omit `from`.
    let dmp = messaging().with_header_policy(HeaderPolicy::Verbatim);

    let received = round_trip(&dmp, &basicmessage(), Some(ALICE)).unwrap();

    assert!(received.get("from").is_none());
}

#[test]
fn unpack_rejects_a_from_that_does_not_own_the_sender_key() {
    // Alice's key encrypts it, but the plaintext claims to be from Carol. Verbatim is
    // the only way to produce this; the receiving side's check applies regardless.
    let sender = messaging().with_header_policy(HeaderPolicy::Verbatim);
    let mut message = basicmessage();
    message["from"] = json!("did:example:carol");

    assert_eq!(header_error(round_trip(&sender, &message, Some(ALICE))), "from");
}
