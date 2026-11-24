//! Every envelope combination DIDComm v2.1 allows inside one hop ("IANA Media
//! Types"), packed and unpacked in both profiles (JWE/JWS and COSE), every other
//! nesting refused, and anoncrypt(authcrypt(plaintext)) ([`SenderPrivacy::Protected`])
//! keeping the sender out of what the recipient's mediator stores.
//!
//! | combination | packed by | unpacked by |
//! |---|---|---|
//! | plaintext | `pack_plaintext` | `unpack`, `unpack_verified` |
//! | sign(plaintext) | `pack_signed_unencrypted` | `unpack_verified` |
//! | anoncrypt(plaintext) | `pack_as` without a sender | both |
//! | authcrypt(plaintext) | `pack_as` with a sender | both |
//! | anoncrypt(sign(plaintext)) | `pack_signed` | `unpack_verified` |
//! | authcrypt(sign(plaintext)) | never emitted (SHOULD NOT); built by hand | `unpack_verified` |
//! | anoncrypt(authcrypt(plaintext)) | `pack_as_with_privacy(.., Protected)` | both |

use std::collections::HashMap;

use askar_crypto::{
    alg::{ed25519::Ed25519KeyPair, x25519::X25519KeyPair},
    repr::{KeyGen, KeyPublicBytes},
};
use async_trait::async_trait;
use serde_json::{json, Value};

use didcomm_core::crypto::Encoding;
use didcomm_core::envelope::EncryptedEnvelope;
use didcomm_core::messaging::{DIDCommMessaging, MessagingError, SenderPrivacy, UnpackResult};
use didcomm_core::packaging::PackagingError;
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
    format!(
        "z{}",
        multibase::encode_base58btc(multicodec::wrap(codec, pub_bytes))
    )
}

struct Party {
    did: &'static str,
    agreement: X25519KeyPair,
    auth: Ed25519KeyPair,
}

impl Party {
    fn new(did: &'static str) -> Self {
        Self {
            did,
            agreement: X25519KeyPair::random().unwrap(),
            auth: Ed25519KeyPair::random().unwrap(),
        }
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

    fn kid(&self) -> String {
        format!("{}#key-1", self.did)
    }

    fn signer_kid(&self) -> String {
        format!("{}#key-2", self.did)
    }

    fn secret(&self) -> AskarSecretKey {
        AskarSecretKey::new(self.kid(), self.agreement.clone())
    }

    fn signing_key(&self) -> AskarSigningKey {
        AskarSigningKey::new(self.signer_kid(), self.auth.clone())
    }
}

type Dmp = DIDCommMessaging<AskarCryptoService, InMemorySecretsManager<AskarSecretKey>>;

fn dmp_for(docs: &HashMap<String, Value>, own: &[&Party]) -> Dmp {
    let secrets = InMemorySecretsManager::<AskarSecretKey>::new();
    for party in own {
        secrets.add_secret(party.secret());
    }
    DIDCommMessaging::new(
        AskarCryptoService,
        secrets,
        Box::new(StaticResolver(docs.clone())),
    )
}

const CBOR: &[&str] = &["didcomm/v2+cbor", "didcomm/v2"];
const JSON_ONLY: &[&str] = &["didcomm/v2"];
const PROFILES: [(&[&str], Encoding); 2] = [(JSON_ONLY, Encoding::Json), (CBOR, Encoding::Cbor)];

/// Alice and Bob (and Carol), each reachable directly at a URL of their own.
struct World {
    alice: Party,
    bob: Party,
    carol: Party,
    docs: HashMap<String, Value>,
    encoding: Encoding,
}

impl World {
    fn new(accept: &[&str], encoding: Encoding) -> Self {
        let alice = Party::new("did:example:alice");
        let bob = Party::new("did:example:bob");
        let carol = Party::new("did:example:carol");
        let mut docs = HashMap::new();
        for p in [&alice, &bob, &carol] {
            docs.insert(
                p.did.to_string(),
                p.doc(&format!("https://{}.example", &p.did[12..]), accept),
            );
        }
        Self {
            alice,
            bob,
            carol,
            docs,
            encoding,
        }
    }

    fn alice_dmp(&self) -> Dmp {
        dmp_for(&self.docs, &[&self.alice])
    }

    fn bob_dmp(&self) -> Dmp {
        dmp_for(&self.docs, &[&self.bob])
    }

    fn plaintext(&self, from: Option<&str>) -> Vec<u8> {
        let mut message = json!({"id": "1", "type": "https://didcomm.org/basicmessage/2.0/message", "to": [self.bob.did], "body": {"content": "Hello world!"}});
        if let Some(from) = from {
            message["from"] = json!(from);
        }
        didcomm_core::plaintext::encode(&message, self.encoding).unwrap()
    }

    /// One encryption layer, to `to`, by `frm` (authcrypt) or none (anoncrypt), built
    /// straight on `PackagingService` as a peer that nests by hand would.
    async fn encrypt(&self, bytes: &[u8], to: &str, frm: Option<&str>) -> Vec<u8> {
        let dmp = self.alice_dmp();
        dmp.packaging
            .pack(
                &dmp.crypto,
                dmp.resolver.as_ref(),
                &dmp.secrets,
                bytes,
                &[to],
                frm,
                self.encoding,
            )
            .await
            .unwrap()
    }

    async fn sign(&self, bytes: &[u8]) -> Vec<u8> {
        didcomm_core::signed::sign(
            &AskarCryptoService,
            &self.alice.signing_key(),
            bytes,
            self.encoding,
        )
        .await
        .unwrap()
    }
}

fn hello() -> Value {
    json!({"type": "https://didcomm.org/basicmessage/2.0/message", "body": {"content": "Hello world!"}})
}

fn says_hello(result: &UnpackResult) {
    let message = result.message().unwrap();
    assert_eq!(message["body"]["content"], "Hello world!", "{message}");
}

fn alg_of(packed: &[u8]) -> String {
    EncryptedEnvelope::from_encoded(packed)
        .unwrap()
        .key_agreement_alg()
        .unwrap()
}

#[test]
fn plaintext_round_trips() {
    for (accept, encoding) in PROFILES {
        let w = World::new(accept, encoding);
        let (alice, bob) = (w.alice_dmp(), w.bob_dmp());
        pollster::block_on(async {
            let packed = alice.pack_plaintext(&hello(), w.bob.did, encoding).unwrap();
            assert!(!didcomm_core::envelope::is_encrypted(&packed));
            for result in [
                bob.unpack(&packed).await.unwrap(),
                bob.unpack_verified(&packed).await.unwrap(),
            ] {
                says_hello(&result);
                assert!(!result.encrypted && !result.authenticated && !result.sender_protected);
                assert_eq!(result.sender_kid, None);
                assert_eq!(result.plaintext_encoding, encoding);
            }
        });
    }
}

#[test]
fn signed_plaintext_round_trips() {
    for (accept, encoding) in PROFILES {
        let w = World::new(accept, encoding);
        let (alice, bob) = (w.alice_dmp(), w.bob_dmp());
        pollster::block_on(async {
            let packed = alice
                .pack_signed_unencrypted(&hello(), w.bob.did, &w.alice.signing_key(), encoding)
                .await
                .unwrap();
            assert!(didcomm_core::signed::is_signed(&packed));
            assert!(matches!(
                bob.unpack(&packed).await,
                Err(MessagingError::SignedNeedsVerification)
            ));
            let result = bob.unpack_verified(&packed).await.unwrap();
            says_hello(&result);
            assert!(!result.encrypted && result.authenticated && !result.sender_protected);
            assert_eq!(
                result.signer_kid.as_deref(),
                Some(w.alice.signer_kid().as_str())
            );
            assert_eq!(result.message().unwrap()["from"], w.alice.did);
        });
    }
}

#[test]
fn anoncrypt_round_trips() {
    for (accept, encoding) in PROFILES {
        let w = World::new(accept, encoding);
        let (alice, bob) = (w.alice_dmp(), w.bob_dmp());
        pollster::block_on(async {
            let packed = alice
                .pack_as(&hello(), w.bob.did, None, encoding)
                .await
                .unwrap();
            assert!(alg_of(&packed.message).starts_with("ECDH-ES"));
            for result in [
                bob.unpack(&packed.message).await.unwrap(),
                bob.unpack_verified(&packed.message).await.unwrap(),
            ] {
                says_hello(&result);
                assert!(result.encrypted && !result.authenticated && !result.sender_protected);
                assert_eq!(result.recipient_kid, w.bob.kid());
            }
            // Protected changes nothing without a sender: there is none to hide.
            let protected = alice
                .pack_as_with_privacy(
                    &hello(),
                    w.bob.did,
                    None,
                    encoding,
                    SenderPrivacy::Protected,
                )
                .await
                .unwrap();
            let result = bob.unpack(&protected.message).await.unwrap();
            assert!(!result.authenticated && !result.sender_protected);
        });
    }
}

#[test]
fn authcrypt_round_trips() {
    for (accept, encoding) in PROFILES {
        let w = World::new(accept, encoding);
        let (alice, bob) = (w.alice_dmp(), w.bob_dmp());
        pollster::block_on(async {
            let packed = alice
                .pack_as(&hello(), w.bob.did, Some(w.alice.did), encoding)
                .await
                .unwrap();
            assert!(alg_of(&packed.message).starts_with("ECDH-1PU"));
            for result in [
                bob.unpack(&packed.message).await.unwrap(),
                bob.unpack_verified(&packed.message).await.unwrap(),
            ] {
                says_hello(&result);
                assert!(result.encrypted && result.authenticated && !result.sender_protected);
                assert_eq!(result.sender_kid.as_deref(), Some(w.alice.kid().as_str()));
            }
        });
    }
}

#[test]
fn anoncrypt_around_a_signature_round_trips() {
    for (accept, encoding) in PROFILES {
        let w = World::new(accept, encoding);
        let (alice, bob) = (w.alice_dmp(), w.bob_dmp());
        pollster::block_on(async {
            let packed = alice
                .pack_signed(&hello(), w.bob.did, &w.alice.signing_key())
                .await
                .unwrap();
            // pack_signed emits anoncrypt(sign), never authcrypt(sign).
            assert!(alg_of(&packed.message).starts_with("ECDH-ES"));
            assert!(matches!(
                bob.unpack(&packed.message).await,
                Err(MessagingError::SignedNeedsVerification)
            ));
            let result = bob.unpack_verified(&packed.message).await.unwrap();
            says_hello(&result);
            assert!(result.encrypted && result.authenticated && !result.sender_protected);
            assert_eq!(result.sender_kid, None);
            assert_eq!(
                result.signer_kid.as_deref(),
                Some(w.alice.signer_kid().as_str())
            );
            assert_eq!(result.plaintext_encoding, encoding);
        });
    }
}

/// authcrypt(sign(plaintext)) SHOULD NOT be emitted, and nothing here does; it MAY be
/// accepted, and is, with the signer the authcrypt sender.
#[test]
fn authcrypt_around_a_signature_is_accepted_from_others() {
    for (accept, encoding) in PROFILES {
        let w = World::new(accept, encoding);
        let bob = w.bob_dmp();
        pollster::block_on(async {
            let signed = w.sign(&w.plaintext(Some(w.alice.did))).await;
            let packed = w.encrypt(&signed, w.bob.did, Some(w.alice.did)).await;
            let result = bob.unpack_verified(&packed).await.unwrap();
            says_hello(&result);
            assert!(result.encrypted && result.authenticated && !result.sender_protected);
            assert_eq!(result.sender_kid.as_deref(), Some(w.alice.kid().as_str()));
            assert_eq!(
                result.signer_kid.as_deref(),
                Some(w.alice.signer_kid().as_str())
            );
        });
    }
}

#[test]
fn anoncrypt_around_authcrypt_round_trips() {
    for (accept, encoding) in PROFILES {
        let w = World::new(accept, encoding);
        let (alice, bob) = (w.alice_dmp(), w.bob_dmp());
        pollster::block_on(async {
            let packed = alice
                .pack_as_with_privacy(
                    &hello(),
                    w.bob.did,
                    Some(w.alice.did),
                    encoding,
                    SenderPrivacy::Protected,
                )
                .await
                .unwrap();
            // Outside, anoncrypt to Bob: no sender.
            let outer = EncryptedEnvelope::from_encoded(&packed.message).unwrap();
            assert!(outer.key_agreement_alg().unwrap().starts_with("ECDH-ES"));
            assert_eq!(outer.skid(), None);
            assert!(outer.apu_bytes().is_err());
            assert_eq!(outer.recipient_key_ids(), vec![w.bob.kid()]);
            for result in [
                bob.unpack(&packed.message).await.unwrap(),
                bob.unpack_verified(&packed.message).await.unwrap(),
            ] {
                says_hello(&result);
                assert!(result.encrypted && result.authenticated && result.sender_protected);
                assert_eq!(result.sender_kid.as_deref(), Some(w.alice.kid().as_str()));
                assert_eq!(result.recipient_kid, w.bob.kid());
                assert_eq!(result.message().unwrap()["from"], w.alice.did);
            }
            // The same envelope built by hand (as another implementation would) reads
            // the same.
            let by_hand = w
                .encrypt(
                    &w.encrypt(
                        &w.plaintext(Some(w.alice.did)),
                        w.bob.did,
                        Some(w.alice.did),
                    )
                    .await,
                    w.bob.did,
                    None,
                )
                .await;
            let result = bob.unpack(&by_hand).await.unwrap();
            assert!(result.sender_protected);
            assert_eq!(result.sender_kid.as_deref(), Some(w.alice.kid().as_str()));
        });
    }
}

/// The inner layer's checks still hold: a `from` that isn't the authcrypt sender is
/// refused, protected or not.
#[test]
fn anoncrypt_around_authcrypt_still_checks_from() {
    for (accept, encoding) in PROFILES {
        let w = World::new(accept, encoding);
        let bob = w.bob_dmp();
        pollster::block_on(async {
            let inner = w
                .encrypt(
                    &w.plaintext(Some(w.carol.did)),
                    w.bob.did,
                    Some(w.alice.did),
                )
                .await;
            let packed = w.encrypt(&inner, w.bob.did, None).await;
            for result in [
                bob.unpack(&packed).await,
                bob.unpack_verified(&packed).await,
            ] {
                assert!(
                    matches!(result, Err(MessagingError::Header { header: "from", .. })),
                    "{encoding:?}: {result:?}"
                );
            }
        });
    }
}

fn is_disallowed(result: &Result<UnpackResult, MessagingError>) -> bool {
    matches!(
        result,
        Err(MessagingError::Packaging(
            PackagingError::DisallowedNesting(_)
        ))
    )
}

/// Every nesting of encryption the spec doesn't list is refused by both unpacks --
/// never handed on with the inner envelope taken for the message.
#[test]
fn every_other_nesting_of_encryption_is_refused() {
    for (accept, encoding) in PROFILES {
        let w = World::new(accept, encoding);
        let bob = w.bob_dmp();
        let (alice, bob_did) = (Some(w.alice.did), w.bob.did);
        pollster::block_on(async {
            let plain = w.plaintext(Some(w.alice.did));
            let anon = w.encrypt(&plain, bob_did, None).await;
            let auth = w.encrypt(&plain, bob_did, alice).await;
            let signed = w.sign(&plain).await;
            let cases: Vec<(&str, Vec<u8>)> = vec![
                (
                    "anoncrypt(anoncrypt)",
                    w.encrypt(&anon, bob_did, None).await,
                ),
                (
                    "authcrypt(authcrypt)",
                    w.encrypt(&auth, bob_did, alice).await,
                ),
                (
                    "authcrypt(anoncrypt)",
                    w.encrypt(&anon, bob_did, alice).await,
                ),
                (
                    "anoncrypt(authcrypt(sign))",
                    w.encrypt(&w.encrypt(&signed, bob_did, alice).await, bob_did, None)
                        .await,
                ),
                (
                    "anoncrypt(anoncrypt(authcrypt))",
                    w.encrypt(&w.encrypt(&auth, bob_did, None).await, bob_did, None)
                        .await,
                ),
                (
                    "anoncrypt(authcrypt(anoncrypt))",
                    w.encrypt(&w.encrypt(&anon, bob_did, alice).await, bob_did, None)
                        .await,
                ),
                (
                    "anoncrypt(authcrypt(authcrypt))",
                    w.encrypt(&w.encrypt(&auth, bob_did, alice).await, bob_did, None)
                        .await,
                ),
            ];
            for (name, packed) in cases {
                let plain_unpack = bob.unpack(&packed).await;
                let verified = bob.unpack_verified(&packed).await;
                assert!(
                    is_disallowed(&plain_unpack),
                    "{encoding:?} {name}: unpack {plain_unpack:?}"
                );
                assert!(
                    is_disallowed(&verified),
                    "{encoding:?} {name}: unpack_verified {verified:?}"
                );
            }
        });
    }
}

/// A signature is over a plaintext only: sign(sign), sign(encrypted), and one inside
/// anoncrypt around an encrypted payload, are refused.
#[test]
fn a_signature_over_anything_but_a_plaintext_is_refused() {
    for (accept, encoding) in PROFILES {
        let w = World::new(accept, encoding);
        let bob = w.bob_dmp();
        pollster::block_on(async {
            let plain = w.plaintext(Some(w.alice.did));
            let anon = w.encrypt(&plain, w.bob.did, None).await;
            let signed = w.sign(&plain).await;
            let cases: Vec<(&str, Vec<u8>)> = vec![
                ("sign(sign)", w.sign(&signed).await),
                ("sign(anoncrypt)", w.sign(&anon).await),
                (
                    "anoncrypt(sign(anoncrypt))",
                    w.encrypt(&w.sign(&anon).await, w.bob.did, None).await,
                ),
            ];
            for (name, packed) in cases {
                let verified = bob.unpack_verified(&packed).await;
                assert!(
                    is_disallowed(&verified),
                    "{encoding:?} {name}: {verified:?}"
                );
                assert!(bob.unpack(&packed).await.is_err(), "{encoding:?} {name}");
            }
        });
    }
}

/// Both layers of anoncrypt(authcrypt) are the recipient's: one whose inner layer is
/// for another DID (even one the same agent holds) is refused.
#[test]
fn anoncrypt_around_authcrypt_for_someone_else_is_refused() {
    for (accept, encoding) in PROFILES {
        let w = World::new(accept, encoding);
        let bob_and_carol = dmp_for(&w.docs, &[&w.bob, &w.carol]);
        pollster::block_on(async {
            let inner = w
                .encrypt(
                    &w.plaintext(Some(w.alice.did)),
                    w.carol.did,
                    Some(w.alice.did),
                )
                .await;
            let packed = w.encrypt(&inner, w.bob.did, None).await;
            let result = bob_and_carol.unpack(&packed).await;
            assert!(
                matches!(
                    result,
                    Err(MessagingError::Packaging(
                        PackagingError::NestedRecipientMismatch { .. }
                    ))
                ),
                "{encoding:?}: {result:?}"
            );
        });
    }
}

/// Alice -> Bob's mediator -> Bob. What the mediator keeps for Bob, once it has taken
/// off its forward, names nobody but Bob in Protected mode; in Standard mode it names
/// Alice (so the check below can see a sender when there is one).
#[test]
fn what_the_mediator_stores_in_protected_mode_names_no_sender() {
    for (accept, encoding) in PROFILES {
        let alice = Party::new("did:example:alice");
        let mediator = Party::new("did:example:mediator");
        let bob = Party::new("did:example:bob");
        let mut docs = HashMap::new();
        docs.insert(alice.did.into(), alice.doc("https://alice.example", accept));
        docs.insert(
            mediator.did.into(),
            mediator.doc("https://mediator.example", accept),
        );
        docs.insert(bob.did.into(), bob.doc(mediator.did, accept));
        let alice_dmp = dmp_for(&docs, &[&alice]);
        let mediator_dmp = dmp_for(&docs, &[&mediator]);
        let bob_dmp = dmp_for(&docs, &[&bob]);

        pollster::block_on(async {
            for privacy in [SenderPrivacy::Standard, SenderPrivacy::Protected] {
                let packed = alice_dmp
                    .pack_with_privacy(&hello(), bob.did, Some(alice.did), privacy)
                    .await
                    .unwrap();
                assert_eq!(
                    packed.get_endpoint("https"),
                    Some("https://mediator.example")
                );
                // The mediator takes off its layer: a forward to Bob.
                let forward = mediator_dmp.unpack(&packed.message).await.unwrap();
                let forward = forward.message().unwrap();
                assert_eq!(forward["type"], "https://didcomm.org/routing/2.0/forward");
                assert_eq!(forward["body"]["next"], bob.did);
                let stored = didcomm_core::plaintext::attachment_bytes(&forward["attachments"][0])
                    .expect("the attached message");

                let names_alice = names(&stored, &alice);
                match privacy {
                    SenderPrivacy::Standard => assert!(
                        names_alice.is_some(),
                        "{encoding:?}: the check finds a sender in plain authcrypt"
                    ),
                    SenderPrivacy::Protected => assert_eq!(
                        names_alice, None,
                        "{encoding:?}: the mediator's copy names the sender"
                    ),
                }

                let result = bob_dmp.unpack(&stored).await.unwrap();
                says_hello(&result);
                assert_eq!(
                    result.sender_kid.as_deref(),
                    Some(format!("{}#key-1", alice.did).as_str())
                );
                assert_eq!(result.sender_protected, privacy == SenderPrivacy::Protected);
            }
        });
    }
}

/// Where `stored` (an encrypted envelope, as read without any key) names `sender`, if
/// it does: a `skid` or `apu` header, or the sender's DID anywhere in the bytes, in the
/// decoded protected header, or base64url-encoded (as `apu` carries it).
fn names(stored: &[u8], sender: &Party) -> Option<&'static str> {
    let envelope = EncryptedEnvelope::from_encoded(stored).unwrap();
    if envelope.skid().is_some() {
        return Some("skid");
    }
    if envelope.apu_bytes().is_ok() {
        return Some("apu");
    }
    let kid = format!("{}#key-1", sender.did);
    let needles: Vec<Vec<u8>> = vec![
        sender.did.as_bytes().to_vec(),
        multibase::encode(kid.as_bytes()).into_bytes(),
        multibase::encode(sender.did.as_bytes()).into_bytes(),
    ];
    let mut haystacks = vec![stored.to_vec()];
    if let EncryptedEnvelope::Jwe(jwe) = &envelope {
        haystacks.push(serde_json::to_vec(&jwe.protected).unwrap());
    }
    let found = haystacks.iter().any(|hay| {
        needles
            .iter()
            .any(|needle| hay.windows(needle.len()).any(|w| w == needle.as_slice()))
    });
    found.then_some("the sender's DID")
}
