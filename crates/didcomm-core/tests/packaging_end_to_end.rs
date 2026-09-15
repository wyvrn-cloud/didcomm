//! End-to-end proof that the layers built so far actually compose: pack a message "to"
//! a DID (not a raw key), resolving through a `DIDResolver`, for both DIDComm v2
//! encryption modes, then unpack it back out the other side.
//!
//! Uses a trivial in-memory `StaticResolver` rather than `didcomm-resolver-peer` -- this
//! test is about `PackagingService`'s own logic (resolve -> extract key -> crypto),
//! which should work with *any* conforming `DIDResolver`, not about did:peer:2
//! specifically (that's already covered in didcomm-resolver-peer's own tests).

use std::collections::HashMap;

use askar_crypto::{alg::x25519::X25519KeyPair, repr::{KeyGen, KeyPublicBytes}};
use async_trait::async_trait;
use serde_json::{json, Value};

use didcomm_core::packaging::{Method, PackagingService};
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

fn make_doc(did: &str, pub_bytes: &[u8]) -> Value {
    json!({
        "id": did,
        "verificationMethod": [{
            "id": "#key-1",
            "type": "Multikey",
            "controller": did,
            "publicKeyMultibase": multikey(pub_bytes),
        }],
        "keyAgreement": ["#key-1"],
    })
}

#[test]
fn packs_and_unpacks_anonymous_and_authenticated_messages_by_did() {
    let recipient_key = X25519KeyPair::random().unwrap();
    let recipient_pub = recipient_key.with_public_bytes(<[u8]>::to_vec);
    let recipient_did = "did:example:recipient";

    let sender_key = X25519KeyPair::random().unwrap();
    let sender_pub = sender_key.with_public_bytes(<[u8]>::to_vec);
    let sender_did = "did:example:sender";

    let mut docs = HashMap::new();
    docs.insert(recipient_did.to_string(), make_doc(recipient_did, &recipient_pub));
    docs.insert(sender_did.to_string(), make_doc(sender_did, &sender_pub));
    let resolver = StaticResolver(docs);

    let secrets = InMemorySecretsManager::<AskarSecretKey>::new();
    secrets.add_secret(AskarSecretKey::new(format!("{recipient_did}#key-1"), recipient_key));
    secrets.add_secret(AskarSecretKey::new(format!("{sender_did}#key-1"), sender_key));

    let crypto = AskarCryptoService;
    let packaging = PackagingService;

    pollster::block_on(async {
        // Anonymous encryption (ECDH-ES): no `frm`.
        let packed = packaging
            .pack(&crypto, &resolver, &secrets, b"Hello world!", &[recipient_did], None)
            .await
            .expect("packs anonymously");
        let (plaintext, metadata) = packaging
            .unpack(&crypto, &resolver, &secrets, &packed)
            .await
            .expect("unpacks anonymously");
        assert_eq!(plaintext, b"Hello world!");
        assert_eq!(metadata.method, Method::EcdhEs);
        assert!(metadata.sender_kid.is_none());

        // Authenticated encryption (ECDH-1PU): with `frm`.
        let packed = packaging
            .pack(
                &crypto,
                &resolver,
                &secrets,
                b"Hello world!",
                &[recipient_did],
                Some(sender_did),
            )
            .await
            .expect("packs authenticated");
        let (plaintext, metadata) = packaging
            .unpack(&crypto, &resolver, &secrets, &packed)
            .await
            .expect("unpacks authenticated");
        assert_eq!(plaintext, b"Hello world!");
        assert_eq!(metadata.method, Method::Ecdh1Pu);
        assert_eq!(metadata.sender_kid.as_deref(), Some(format!("{sender_did}#key-1").as_str()));
    });
}
