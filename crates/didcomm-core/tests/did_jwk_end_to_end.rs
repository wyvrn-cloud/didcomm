//! Proves `did:jwk` support end to end with the *real* resolver (not a mock): build a
//! did:jwk from a freshly generated key, resolve it through the actual `JwkResolver`,
//! and pack/unpack a message to it.

use askar_crypto::{alg::x25519::X25519KeyPair, jwk::ToJwk, repr::KeyGen};
use didcomm_core::crypto::Encoding;
use didcomm_core::packaging::PackagingService;
use didcomm_core::resolver::{DIDResolver, PrefixResolver};
use didcomm_core::secrets::InMemorySecretsManager;
use didcomm_crypto_askar::{AskarCryptoService, AskarSecretKey};
use didcomm_multiformats::multibase;
use didcomm_resolver_jwk::JwkResolver;
use serde_json::Value;

fn setup() -> (String, InMemorySecretsManager<AskarSecretKey>, Box<dyn DIDResolver>) {
    let key = X25519KeyPair::random().unwrap();
    let mut public_jwk: Value = serde_json::from_str(&key.to_jwk_public(None).unwrap()).unwrap();
    public_jwk["use"] = Value::String("enc".into());
    let encoded = multibase::encode(serde_json::to_vec(&public_jwk).unwrap());
    let did = format!("did:jwk:{encoded}");
    let kid = format!("{did}#0");

    let resolver: Box<dyn DIDResolver> = Box::new(PrefixResolver::new(vec![(
        "did:jwk:",
        Box::new(JwkResolver) as Box<dyn DIDResolver>,
    )]));

    let secrets = InMemorySecretsManager::<AskarSecretKey>::new();
    secrets.add_secret(AskarSecretKey::new(kid, key));

    (did, secrets, resolver)
}

#[test]
fn packs_and_unpacks_to_a_real_did_jwk() {
    let (did, secrets, resolver) = setup();
    let crypto = AskarCryptoService;
    let packaging = PackagingService;

    pollster::block_on(async {
        let packed = packaging
            .pack(
                &crypto,
                resolver.as_ref(),
                &secrets,
                b"Hello world!",
                &[did.as_str()],
                None,
                Encoding::Json,
            )
            .await
            .expect("packs to a real did:jwk");
        let (plaintext, _metadata) = packaging
            .unpack(&crypto, resolver.as_ref(), &secrets, &packed)
            .await
            .expect("unpacks");
        assert_eq!(plaintext, b"Hello world!");
    });
}

#[test]
fn packs_and_unpacks_to_a_real_did_jwk_cbor_encoded() {
    let (did, secrets, resolver) = setup();
    let crypto = AskarCryptoService;
    let packaging = PackagingService;

    pollster::block_on(async {
        let packed = packaging
            .pack(
                &crypto,
                resolver.as_ref(),
                &secrets,
                b"Hello world!",
                &[did.as_str()],
                None,
                Encoding::Cbor,
            )
            .await
            .expect("packs to a real did:jwk");
        assert_ne!(packed[0], b'{');
        let (plaintext, _metadata) = packaging
            .unpack(&crypto, resolver.as_ref(), &secrets, &packed)
            .await
            .expect("unpacks");
        assert_eq!(plaintext, b"Hello world!");
    });
}
