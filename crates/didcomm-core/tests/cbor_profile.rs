//! The `didcomm/v2+cbor` profile end to end: COSE_Encrypt envelopes, CBOR plaintexts,
//! `data.binary` forward attachments, per-hop negotiation, and signed messages
//! (JWS / COSE_Sign1) -- with real askar-backed crypto and an in-memory resolver.

use std::collections::HashMap;

use askar_crypto::{
    alg::{ed25519::Ed25519KeyPair, x25519::X25519KeyPair},
    repr::{KeyGen, KeyPublicBytes},
};
use async_trait::async_trait;
use ciborium::Value as CborValue;
use serde_json::{json, Value};

use didcomm_core::cose::{self, CoseKind};
use didcomm_core::crypto::Encoding;
use didcomm_core::messaging::{DIDCommMessaging, MessagingError};
use didcomm_core::plaintext;
use didcomm_core::resolver::{DIDResolver, ResolutionError};
use didcomm_core::secrets::InMemorySecretsManager;
use didcomm_crypto_askar::{AskarCryptoService, AskarSecretKey, AskarSigningKey};
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

fn multikey(codec: multicodec::Multicodec, pub_bytes: &[u8]) -> String {
    format!("z{}", multibase::encode_base58btc(multicodec::wrap(codec, pub_bytes)))
}

struct Party {
    did: &'static str,
    agreement: X25519KeyPair,
    auth: Ed25519KeyPair,
}

impl Party {
    fn new(did: &'static str) -> Self {
        Self { did, agreement: X25519KeyPair::random().unwrap(), auth: Ed25519KeyPair::random().unwrap() }
    }

    fn doc(&self, endpoint: &str, accept: &[&str]) -> Value {
        json!({
            "id": self.did,
            "verificationMethod": [
                {
                    "id": "#key-1",
                    "type": "Multikey",
                    "controller": self.did,
                    "publicKeyMultibase": multikey(multicodec::X25519_PUB, &self.agreement.with_public_bytes(<[u8]>::to_vec)),
                },
                {
                    "id": "#key-2",
                    "type": "Multikey",
                    "controller": self.did,
                    "publicKeyMultibase": multikey(multicodec::ED25519_PUB, &self.auth.with_public_bytes(<[u8]>::to_vec)),
                },
            ],
            "keyAgreement": ["#key-1"],
            "authentication": ["#key-2"],
            "service": [{
                "id": "#service",
                "type": "DIDCommMessaging",
                "serviceEndpoint": {"uri": endpoint, "accept": accept, "routingKeys": []},
            }],
        })
    }

    fn secret(&self) -> AskarSecretKey {
        AskarSecretKey::new(format!("{}#key-1", self.did), self.agreement.clone())
    }

    fn signing_key(&self) -> AskarSigningKey {
        AskarSigningKey::new(format!("{}#key-2", self.did), self.auth.clone())
    }
}

type Dmp = DIDCommMessaging<AskarCryptoService, InMemorySecretsManager<AskarSecretKey>>;

fn dmp_for(docs: &HashMap<String, Value>, own: &[&Party]) -> Dmp {
    let secrets = InMemorySecretsManager::<AskarSecretKey>::new();
    for party in own {
        secrets.add_secret(party.secret());
    }
    DIDCommMessaging::new(AskarCryptoService, secrets, Box::new(StaticResolver(docs.clone())))
}

const CBOR: &[&str] = &["didcomm/v2+cbor", "didcomm/v2"];
const JSON_ONLY: &[&str] = &["didcomm/v2"];

/// Alice -> mediator -> Bob, with Bob's mediator chain set up as given.
fn mediated(mediator_accept: &[&str], bob_accept: &[&str]) -> (Party, Party, Party, HashMap<String, Value>) {
    let alice = Party::new("did:example:alice");
    let mediator = Party::new("did:example:mediator");
    let bob = Party::new("did:example:bob");
    let mut docs = HashMap::new();
    docs.insert(alice.did.into(), alice.doc("https://alice.example", CBOR));
    docs.insert(mediator.did.into(), mediator.doc("https://mediator.example", mediator_accept));
    docs.insert(bob.did.into(), bob.doc(mediator.did, bob_accept));
    (alice, mediator, bob, docs)
}

fn hello() -> Value {
    json!({"type": "https://didcomm.org/basicmessage/2.0/message", "body": {"content": "Hello world!"}})
}

fn cbor_map_get<'a>(value: &'a CborValue, key: &str) -> &'a CborValue {
    let CborValue::Map(entries) = value else { panic!("not a CBOR map: {value:?}") };
    &entries.iter().find(|(k, _)| k == &CborValue::Text(key.into())).unwrap_or_else(|| panic!("no {key}")).1
}

/// The case asked about directly: a CBOR-capable recipient behind a CBOR-capable
/// mediator. Every layer -- the forward's envelope and plaintext, and the inner
/// message's envelope and plaintext -- is CBOR, and the inner message rides in the
/// forward as a raw byte string under `data.binary`, not base64 text.
#[test]
fn mediated_message_is_cbor_at_every_layer() {
    let (alice, mediator, bob, docs) = mediated(CBOR, CBOR);
    let alice_dmp = dmp_for(&docs, &[&alice]);
    let mediator_dmp = dmp_for(&docs, &[&mediator]);
    let bob_dmp = dmp_for(&docs, &[&bob]);

    pollster::block_on(async {
        let packed = alice_dmp.pack(&hello(), bob.did, Some(alice.did)).await.unwrap();

        // Outer: a tagged COSE_Encrypt to the mediator.
        assert_eq!(&packed.message[..2], &[0xd8, 0x60]);
        assert_eq!(didcomm_core::jwe::peek_typ(&packed.message).unwrap(), "application/didcomm-encrypted+cbor");

        // Forward plaintext on the wire: a CBOR map whose attachment data.binary is a
        // byte string holding the inner COSE_Encrypt.
        let (forward_plaintext, _) = mediator_dmp
            .packaging
            .unpack(&mediator_dmp.crypto, mediator_dmp.resolver.as_ref(), &mediator_dmp.secrets, &packed.message)
            .await
            .unwrap();
        assert_eq!(cose::classify(&forward_plaintext).unwrap(), CoseKind::Plaintext);
        let raw: CborValue = ciborium::from_reader(forward_plaintext.as_slice()).unwrap();
        assert_eq!(cbor_map_get(&raw, "typ"), &CborValue::Text(plaintext::PLAIN_CBOR_TYP.into()));
        let CborValue::Array(attachments) = cbor_map_get(&raw, "attachments") else { panic!() };
        let CborValue::Bytes(inner) = cbor_map_get(cbor_map_get(&attachments[0], "data"), "binary") else {
            panic!("data.binary must be a raw byte string");
        };
        assert_eq!(&inner[..2], &[0xd8, 0x60]);

        // The same, through the mediator's normal API (the JSON view).
        let forward = mediator_dmp.unpack(&packed.message).await.unwrap();
        assert_eq!(forward.plaintext_encoding, Encoding::Cbor);
        let forward_msg = forward.message().unwrap();
        assert_eq!(forward_msg["type"], "https://didcomm.org/routing/2.0/forward");
        assert_eq!(forward_msg["body"]["next"], bob.did);
        assert_eq!(forward_msg["attachments"][0]["media_type"], "application/didcomm-encrypted+cbor");
        assert!(forward_msg["attachments"][0]["data"].get("binary").is_none(), "the JSON view says base64");
        let inner_view = plaintext::attachment_bytes(&forward_msg["attachments"][0]).unwrap();
        assert_eq!(&inner_view, inner);

        // Inner: authcrypt COSE_Encrypt with the spec's media type, CBOR plaintext.
        assert_eq!(didcomm_core::jwe::peek_typ(inner).unwrap(), "application/didcomm-encrypted+cbor");
        let delivered = bob_dmp.unpack(inner).await.unwrap();
        assert_eq!(delivered.plaintext_encoding, Encoding::Cbor);
        assert!(delivered.authenticated);
        assert_eq!(delivered.sender_kid.as_deref(), Some("did:example:alice#key-1"));
        assert_eq!(delivered.message().unwrap()["body"]["content"], "Hello world!");
    });
}

/// Per-hop negotiation: a JSON-only mediator still gets a JSON forward even though Bob
/// gets CBOR, and the CBOR inner message travels as the spec's standard `data.base64`.
#[test]
fn json_only_mediator_gets_json_forward_around_cbor_inner_message() {
    let (alice, mediator, bob, docs) = mediated(JSON_ONLY, CBOR);
    let alice_dmp = dmp_for(&docs, &[&alice]);
    let mediator_dmp = dmp_for(&docs, &[&mediator]);
    let bob_dmp = dmp_for(&docs, &[&bob]);

    pollster::block_on(async {
        let packed = alice_dmp.pack(&hello(), bob.did, Some(alice.did)).await.unwrap();
        assert_eq!(packed.message[0], b'{');

        let forward = mediator_dmp.unpack(&packed.message).await.unwrap();
        assert_eq!(forward.plaintext_encoding, Encoding::Json);
        let data = &forward.message().unwrap()["attachments"][0]["data"];
        assert!(data.get("binary").is_none(), "data.binary never appears in a JSON plaintext");
        let inner = multibase::decode(data["base64"].as_str().unwrap()).unwrap();
        assert_eq!(&inner[..2], &[0xd8, 0x60]);

        let delivered = bob_dmp.unpack(&inner).await.unwrap();
        assert_eq!(delivered.plaintext_encoding, Encoding::Cbor);
        assert_eq!(delivered.message().unwrap()["body"]["content"], "Hello world!");
    });
}

/// A routing key with no endpoint of its own (here a key-only DID, like a `did:key`)
/// can't be asked what it accepts, so its forward follows the recipient's `accept`,
/// which the spec makes a promise about the whole inbound route -- not JSON.
#[test]
fn routing_key_without_an_endpoint_inherits_the_recipients_encoding() {
    let (alice, mediator, bob, mut docs) = mediated(CBOR, CBOR);
    let relay = Party::new("did:example:relay");
    let mut relay_doc = relay.doc("unused", CBOR);
    relay_doc.as_object_mut().unwrap().remove("service");
    docs.insert(relay.did.into(), relay_doc);
    docs.get_mut(mediator.did).unwrap()["service"][0]["serviceEndpoint"]["routingKeys"] =
        json!([format!("{}#key-1", relay.did)]);
    let alice_dmp = dmp_for(&docs, &[&alice]);
    let mediator_dmp = dmp_for(&docs, &[&mediator]);
    let relay_dmp = dmp_for(&docs, &[&relay]);
    let bob_dmp = dmp_for(&docs, &[&bob]);

    pollster::block_on(async {
        let packed = alice_dmp.pack(&hello(), bob.did, Some(alice.did)).await.unwrap();
        let outer = mediator_dmp.unpack(&packed.message).await.unwrap();
        assert_eq!(outer.plaintext_encoding, Encoding::Cbor);
        let to_relay = plaintext::attachment_bytes(&outer.message().unwrap()["attachments"][0]).unwrap();
        assert_eq!(Encoding::detect(&to_relay).unwrap(), Encoding::Cbor);

        let hop = relay_dmp.unpack(&to_relay).await.unwrap();
        assert_eq!(hop.plaintext_encoding, Encoding::Cbor);
        assert_eq!(hop.message().unwrap()["body"]["next"], bob.did);
        let to_bob = plaintext::attachment_bytes(&hop.message().unwrap()["attachments"][0]).unwrap();
        let message = bob_dmp.unpack(&to_bob).await.unwrap();
        assert_eq!(message.message().unwrap()["body"]["content"], "Hello world!");
    });
}

/// `anoncrypt(sign(plaintext))` in both encodings: a JWS in a JWE for a JSON-only
/// recipient, a COSE_Sign1 in a COSE_Encrypt for a CBOR one.
#[test]
fn signed_messages_round_trip_in_both_encodings() {
    for (accept, encoding) in [(JSON_ONLY, Encoding::Json), (CBOR, Encoding::Cbor)] {
        let alice = Party::new("did:example:alice");
        let bob = Party::new("did:example:bob");
        let mut docs = HashMap::new();
        docs.insert(alice.did.to_string(), alice.doc("https://alice.example", CBOR));
        docs.insert(bob.did.to_string(), bob.doc("https://bob.example", accept));
        let alice_dmp = dmp_for(&docs, &[&alice]);
        let bob_dmp = dmp_for(&docs, &[&bob]);

        pollster::block_on(async {
            let packed = alice_dmp.pack_signed(&hello(), bob.did, &alice.signing_key()).await.unwrap();
            assert_eq!(Encoding::detect(&packed.message).unwrap(), encoding);

            // The envelope is anoncrypt (no sender key); the signed layer is inside it.
            let (inner, metadata) = bob_dmp
                .packaging
                .unpack(&bob_dmp.crypto, bob_dmp.resolver.as_ref(), &bob_dmp.secrets, &packed.message)
                .await
                .unwrap();
            assert!(metadata.sender_kid.is_none());
            assert!(didcomm_core::signed::is_signed(&inner));
            let expected_typ = match encoding {
                Encoding::Json => "application/didcomm-signed+json",
                Encoding::Cbor => "application/didcomm-signed+cbor",
            };
            assert_eq!(didcomm_core::jwe::peek_typ(&inner).unwrap(), expected_typ);

            // Plain unpack refuses to hand back an unverified signed message.
            assert!(matches!(bob_dmp.unpack(&packed.message).await, Err(MessagingError::SignedNeedsVerification)));

            let unpacked = bob_dmp.unpack_verified(&packed.message).await.unwrap();
            assert!(unpacked.encrypted);
            assert!(unpacked.authenticated);
            assert_eq!(unpacked.signer_kid.as_deref(), Some("did:example:alice#key-2"));
            assert_eq!(unpacked.plaintext_encoding, encoding);
            let message = unpacked.message().unwrap();
            assert_eq!(message["from"], alice.did);
            assert_eq!(message["to"], json!([bob.did]));
            assert_eq!(message["body"]["content"], "Hello world!");
        });
    }
}

/// A signature by a key the claimed signer's document doesn't list fails verification.
#[test]
fn signed_message_with_a_forged_signer_key_is_rejected() {
    let alice = Party::new("did:example:alice");
    let bob = Party::new("did:example:bob");
    let mut docs = HashMap::new();
    docs.insert(alice.did.to_string(), alice.doc("https://alice.example", CBOR));
    docs.insert(bob.did.to_string(), bob.doc("https://bob.example", CBOR));
    let alice_dmp = dmp_for(&docs, &[&alice]);
    let bob_dmp = dmp_for(&docs, &[&bob]);

    // Claims Alice's kid, but signs with an unrelated key.
    let forged = AskarSigningKey::new("did:example:alice#key-2", Ed25519KeyPair::random().unwrap());
    pollster::block_on(async {
        let packed = alice_dmp.pack_signed(&hello(), bob.did, &forged).await.unwrap();
        assert!(matches!(
            bob_dmp.unpack_verified(&packed.message).await,
            Err(MessagingError::Signed(didcomm_core::signed::SignedError::InvalidSignature))
        ));
    });
}

/// authcrypt(sign(plaintext)) whose signer isn't the authcrypt sender must be an error
/// (spec, "DIDComm Messaging - Message Formats"), even with no `from` header to compare.
#[test]
fn authcrypt_around_a_signature_by_someone_else_is_rejected() {
    for (accept, encoding) in [(JSON_ONLY, Encoding::Json), (CBOR, Encoding::Cbor)] {
        let alice = Party::new("did:example:alice");
        let mallory = Party::new("did:example:mallory");
        let bob = Party::new("did:example:bob");
        let mut docs = HashMap::new();
        for p in [&alice, &mallory, &bob] {
            docs.insert(p.did.to_string(), p.doc(&format!("https://{}.example", p.did), accept));
        }
        let alice_dmp = dmp_for(&docs, &[&alice]);
        let bob_dmp = dmp_for(&docs, &[&bob]);

        pollster::block_on(async {
            // Mallory's signature over a message with no `from`, authcrypted by Alice.
            let plaintext = didcomm_core::plaintext::encode(
                &json!({"id": "1", "type": "https://didcomm.org/basicmessage/2.0/message", "to": [bob.did], "body": {"content": "hi"}}),
                encoding,
            )
            .unwrap();
            let signed = didcomm_core::signed::sign(&AskarCryptoService, &mallory.signing_key(), &plaintext, encoding).await.unwrap();
            let packed = alice_dmp
                .packaging
                .pack(&alice_dmp.crypto, alice_dmp.resolver.as_ref(), &alice_dmp.secrets, &signed, &[bob.did], Some(alice.did), encoding)
                .await
                .unwrap();
            let result = bob_dmp.unpack_verified(&packed).await;
            assert!(
                matches!(result, Err(MessagingError::Header { header: "from", .. })),
                "{encoding:?}: {result:?}"
            );
        });
    }
}

/// A signature must come from a key in the signer's `authentication` relationship.
#[test]
fn signature_by_a_key_outside_authentication_is_rejected() {
    let alice = Party::new("did:example:alice");
    let bob = Party::new("did:example:bob");
    let mut alice_doc = alice.doc("https://alice.example", CBOR);
    // The same Ed25519 key, listed only as an assertion method.
    let auth = alice_doc.as_object_mut().unwrap().remove("authentication").unwrap();
    alice_doc["assertionMethod"] = auth;
    let mut docs = HashMap::new();
    docs.insert(alice.did.to_string(), alice_doc);
    docs.insert(bob.did.to_string(), bob.doc("https://bob.example", CBOR));
    let alice_dmp = dmp_for(&docs, &[&alice]);
    let bob_dmp = dmp_for(&docs, &[&bob]);

    pollster::block_on(async {
        let packed = alice_dmp.pack_signed(&hello(), bob.did, &alice.signing_key()).await.unwrap();
        assert!(matches!(
            bob_dmp.unpack_verified(&packed.message).await,
            Err(MessagingError::Signed(didcomm_core::signed::SignedError::NotAuthentication(_)))
        ));
    });
}

/// Surreptitious forwarding: Carol re-encrypts Alice's signed message (addressed to
/// Carol) to Bob. Bob must reject it, since its `to` doesn't name him.
#[test]
fn a_signed_message_forwarded_to_someone_else_is_rejected() {
    for (accept, encoding) in [(JSON_ONLY, Encoding::Json), (CBOR, Encoding::Cbor)] {
        let (alice, bob, carol) = (Party::new("did:example:alice"), Party::new("did:example:bob"), Party::new("did:example:carol"));
        let mut docs = HashMap::new();
        for p in [&alice, &bob, &carol] {
            docs.insert(p.did.to_string(), p.doc(&format!("https://{}.example", p.did), accept));
        }
        let (alice_dmp, bob_dmp, carol_dmp) = (dmp_for(&docs, &[&alice]), dmp_for(&docs, &[&bob]), dmp_for(&docs, &[&carol]));

        pollster::block_on(async {
            let to_carol = alice_dmp.pack_signed(&hello(), carol.did, &alice.signing_key()).await.unwrap();
            let (signed, _) = carol_dmp
                .packaging
                .unpack(&carol_dmp.crypto, carol_dmp.resolver.as_ref(), &carol_dmp.secrets, &to_carol.message)
                .await
                .unwrap();
            let to_bob = carol_dmp
                .packaging
                .pack(&carol_dmp.crypto, carol_dmp.resolver.as_ref(), &carol_dmp.secrets, &signed, &[bob.did], None, encoding)
                .await
                .unwrap();
            let result = bob_dmp.unpack_verified(&to_bob).await;
            assert!(matches!(result, Err(MessagingError::Header { header: "to", .. })), "{encoding:?}: {result:?}");
        });
    }
}

/// The JWE-as-a-CBOR-map layout earlier versions of this crate sent as
/// `didcomm/v2+cbor` (before it meant COSE): `envelope`'s general-form fields, with the
/// binary ones as byte strings. (Those versions also put `+cbor` in the protected
/// header's `typ`; that header is bound into the ciphertext, so here it stays as packed.)
fn legacy_cbor(envelope: &didcomm_core::jwe::JweEnvelope) -> Vec<u8> {
    let text = |s: &str| CborValue::Text(s.into());
    let recipients = envelope
        .recipients
        .iter()
        .map(|r| {
            CborValue::Map(vec![
                (text("encrypted_key"), CborValue::Bytes(r.encrypted_key.clone())),
                (text("header"), CborValue::serialized(&r.header).unwrap()),
            ])
        })
        .collect();
    let map = CborValue::Map(vec![
        (text("protected"), text(&envelope.protected_b64)),
        (text("recipients"), CborValue::Array(recipients)),
        (text("iv"), CborValue::Bytes(envelope.iv.clone())),
        (text("ciphertext"), CborValue::Bytes(envelope.ciphertext.clone())),
        (text("tag"), CborValue::Bytes(envelope.tag.clone())),
    ]);
    let mut bytes = Vec::new();
    ciborium::into_writer(&map, &mut bytes).unwrap();
    bytes
}

/// A peer on an earlier version, answering someone whose DID document accepts
/// `didcomm/v2+cbor`, sends that legacy layout. It's still read: decrypted as the JWE
/// it is, its JSON plaintext reported as JSON.
#[test]
fn the_legacy_cbor_jwe_layout_is_still_read() {
    let alice = Party::new("did:example:alice");
    let bob = Party::new("did:example:bob");
    let mut docs = HashMap::new();
    docs.insert(alice.did.into(), alice.doc("https://alice.example", CBOR));
    docs.insert(bob.did.into(), bob.doc("https://bob.example", CBOR));
    let alice_dmp = dmp_for(&docs, &[&alice]);
    let bob_dmp = dmp_for(&docs, &[&bob]);

    pollster::block_on(async {
        let packed = alice_dmp.pack_as(&hello(), bob.did, Some(alice.did), Encoding::Json).await.unwrap();
        let envelope = didcomm_core::jwe::JweEnvelope::from_json(&packed.message).unwrap();
        let legacy = legacy_cbor(&envelope);
        assert_eq!(Encoding::detect(&legacy).unwrap(), Encoding::Cbor);
        assert!(didcomm_core::jwe::JweEnvelope::is_legacy_cbor(&legacy));
        assert!(didcomm_core::jwe::peek_typ(&legacy).is_ok());

        let unpacked = bob_dmp.unpack(&legacy).await.unwrap();
        assert!(unpacked.authenticated);
        assert_eq!(unpacked.plaintext_encoding, Encoding::Json);
        assert_eq!(unpacked.message().unwrap()["body"]["content"], "Hello world!");
        let verified = bob_dmp.unpack_verified(&legacy).await.unwrap();
        assert_eq!(verified.message().unwrap()["body"]["content"], "Hello world!");

        // Neither a COSE_Encrypt nor a CBOR plaintext is taken for one.
        let cose = alice_dmp.pack_as(&hello(), bob.did, Some(alice.did), Encoding::Cbor).await.unwrap();
        assert!(!didcomm_core::jwe::JweEnvelope::is_legacy_cbor(&cose.message));
        let plain = plaintext::encode(&json!({"id": "1", "type": "x", "body": {}}), Encoding::Cbor).unwrap();
        assert!(!didcomm_core::jwe::JweEnvelope::is_legacy_cbor(&plain));
    });
}
