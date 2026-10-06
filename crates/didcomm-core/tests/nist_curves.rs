//! P-384 (required by DIDComm v2) and P-256 (deprecated, still allowed) key agreement
//! end to end: Multikey and JsonWebKey2020 verification methods, anoncrypt and
//! authcrypt, JSON and CBOR.

use std::collections::HashMap;

use async_trait::async_trait;
use serde_json::{json, Value};

use didcomm_core::crypto::Encoding;
use didcomm_core::messaging::DIDCommMessaging;
use didcomm_core::resolver::{DIDResolver, ResolutionError};
use didcomm_core::secrets::InMemorySecretsManager;
use didcomm_crypto_askar::{AgreementKey, AskarCryptoService, AskarSecretKey, Curve};
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

fn doc(did: &str, key: &AgreementKey, as_jwk: bool, accept: &[&str]) -> Value {
    let vm = if as_jwk {
        json!({"id": "#key-1", "type": "JsonWebKey2020", "controller": did, "publicKeyJwk": key.to_jwk_public().unwrap()})
    } else {
        let codec = match key.curve() {
            Curve::P256 => multicodec::P256_PUB,
            Curve::P384 => multicodec::P384_PUB,
            Curve::X25519 => multicodec::X25519_PUB,
        };
        json!({
            "id": "#key-1",
            "type": "Multikey",
            "controller": did,
            "publicKeyMultibase": format!("z{}", multibase::encode_base58btc(multicodec::wrap(codec, &key.public_bytes()))),
        })
    };
    json!({
        "id": did,
        "verificationMethod": [vm],
        "keyAgreement": ["#key-1"],
        "service": [{
            "id": "#service",
            "type": "DIDCommMessaging",
            "serviceEndpoint": {"uri": format!("https://{did}.example"), "accept": accept, "routingKeys": []},
        }],
    })
}

#[test]
fn nist_curve_dids_round_trip_in_every_mode() {
    for curve in [Curve::P384, Curve::P256] {
        for as_jwk in [false, true] {
            for accept in [&["didcomm/v2"][..], &["didcomm/v2", "didcomm/v2+cbor"][..]] {
                let (alice, bob) = ("did:example:alice", "did:example:bob");
                let (alice_key, bob_key) = (AgreementKey::generate(curve).unwrap(), AgreementKey::generate(curve).unwrap());
                let docs = HashMap::from([
                    (alice.to_string(), doc(alice, &alice_key, as_jwk, accept)),
                    (bob.to_string(), doc(bob, &bob_key, as_jwk, accept)),
                ]);
                let dmp = |did: &str, key: &AgreementKey| {
                    let secrets = InMemorySecretsManager::<AskarSecretKey>::new();
                    secrets.add_secret(AskarSecretKey::new(format!("{did}#key-1"), key.clone()));
                    DIDCommMessaging::new(AskarCryptoService, secrets, Box::new(StaticResolver(docs.clone())))
                };
                let (alice_dmp, bob_dmp) = (dmp(alice, &alice_key), dmp(bob, &bob_key));
                let label = format!("{curve:?} jwk={as_jwk} accept={accept:?}");

                pollster::block_on(async {
                    for frm in [None, Some(alice)] {
                        let packed = alice_dmp
                            .pack(&json!({"type": "https://didcomm.org/basicmessage/2.0/message", "body": {"content": "hi"}}), bob, frm)
                            .await
                            .unwrap_or_else(|e| panic!("{label} pack: {e}"));
                        let expected = if accept.len() == 2 { Encoding::Cbor } else { Encoding::Json };
                        assert_eq!(Encoding::detect(&packed.message).unwrap(), expected, "{label}");
                        let unpacked = bob_dmp.unpack(&packed.message).await.unwrap_or_else(|e| panic!("{label} unpack: {e}"));
                        assert_eq!(unpacked.authenticated, frm.is_some(), "{label}");
                        assert_eq!(unpacked.message().unwrap()["body"]["content"], "hi", "{label}");
                    }
                });
            }
        }
    }
}
