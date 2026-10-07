//! Packing to a bare DID encrypts to every `keyAgreement` key (one per device), and
//! `apv` must be the hash of the *sorted* recipient kids (DIDComm v2 "ECDH-ES key
//! wrapping and common protected headers") -- regardless of the order the document
//! lists them in, and in either encoding.

use std::collections::HashMap;

use askar_crypto::{
    alg::x25519::X25519KeyPair,
    repr::{KeyGen, KeyPublicBytes},
};
use async_trait::async_trait;
use serde_json::{json, Value};

use didcomm_core::crypto::Encoding;
use didcomm_core::messaging::DIDCommMessaging;
use didcomm_core::resolver::{DIDResolver, ResolutionError};
use didcomm_core::secrets::InMemorySecretsManager;
use didcomm_crypto_askar::{AskarCryptoService, AskarSecretKey};
use didcomm_multiformats::{multibase, multicodec};

struct StaticResolver(HashMap<String, Value>);

#[async_trait]
impl DIDResolver for StaticResolver {
    async fn resolve(&self, did: &str) -> Result<Value, ResolutionError> {
        self.0.get(did).cloned().ok_or_else(|| ResolutionError::Resolution(format!("not found: {did}")))
    }

    async fn is_resolvable(&self, did: &str) -> bool {
        self.0.contains_key(did)
    }
}

fn vm(did: &str, id: &str, key: &X25519KeyPair) -> Value {
    json!({
        "id": id,
        "type": "Multikey",
        "controller": did,
        "publicKeyMultibase": format!("z{}", multibase::encode_base58btc(multicodec::wrap(
            multicodec::X25519_PUB,
            &key.with_public_bytes(<[u8]>::to_vec),
        ))),
    })
}

#[test]
fn every_device_unpacks_whatever_order_the_document_lists_keys_in() {
    for (accept, encoding) in [(vec!["didcomm/v2"], Encoding::Json), (vec!["didcomm/v2+cbor", "didcomm/v2"], Encoding::Cbor)] {
        let did = "did:example:bob";
        let (phone, laptop) = (X25519KeyPair::random().unwrap(), X25519KeyPair::random().unwrap());
        // Listed in reverse-sorted order: "#z-phone" before "#a-laptop".
        let doc = json!({
            "id": did,
            "verificationMethod": [vm(did, "#z-phone", &phone), vm(did, "#a-laptop", &laptop)],
            "keyAgreement": ["#z-phone", "#a-laptop"],
            "service": [{
                "id": "#service",
                "type": "DIDCommMessaging",
                "serviceEndpoint": {"uri": "https://bob.example", "accept": accept, "routingKeys": []},
            }],
        });
        let docs = HashMap::from([(did.to_string(), doc)]);

        let sender = DIDCommMessaging::new(
            AskarCryptoService,
            InMemorySecretsManager::<AskarSecretKey>::new(),
            Box::new(StaticResolver(docs.clone())),
        );
        let device = |kid: &str, key: &X25519KeyPair| {
            let secrets = InMemorySecretsManager::<AskarSecretKey>::new();
            secrets.add_secret(AskarSecretKey::new(format!("{did}{kid}"), key.clone()));
            DIDCommMessaging::new(AskarCryptoService, secrets, Box::new(StaticResolver(docs.clone())))
        };

        pollster::block_on(async {
            let packed = sender
                .pack(&json!({"type": "https://didcomm.org/basicmessage/2.0/message", "body": {"content": "hi"}}), did, None)
                .await
                .unwrap();
            assert_eq!(Encoding::detect(&packed.message).unwrap(), encoding);
            // Recipients go out in sorted-kid order, so a verifier that hashes them in
            // wire order (didcomm-messaging-python) gets the same apv.
            let envelope = didcomm_core::envelope::EncryptedEnvelope::from_encoded(&packed.message).unwrap();
            assert_eq!(envelope.recipient_key_ids(), vec![format!("{did}#a-laptop"), format!("{did}#z-phone")]);
            for (kid, key) in [("#z-phone", &phone), ("#a-laptop", &laptop)] {
                let unpacked = device(kid, key).unpack(&packed.message).await.unwrap_or_else(|e| panic!("{encoding:?} {kid}: {e}"));
                assert_eq!(unpacked.recipient_kid, format!("{did}{kid}"));
                assert_eq!(unpacked.message().unwrap()["body"]["content"], "hi");
            }
        });
    }
}
