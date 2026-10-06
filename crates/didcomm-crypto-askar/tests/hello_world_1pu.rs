//! Same milestone as hello_world_es.rs, for the authenticated (ECDH-1PU) path: a
//! "Hello world!" DIDComm v2 message, packed by the actual `didcomm-messaging-python`
//! library's `AskarCryptoService.ecdh_1pu_encrypt`, decrypts correctly here.

use didcomm_core::jwe::JweEnvelope;
use didcomm_crypto_askar::{ecdh_1pu_decrypt, AgreementKey, Curve};
use serde_json::Value;

const FIXTURE: &str = include_str!("../../../fixtures/wire-compat/hello_world_1pu.json");

#[test]
fn decrypts_a_python_produced_hello_world() {
    let fixture: Value = serde_json::from_str(FIXTURE).expect("fixture is valid JSON");

    let recipient_kid = fixture["recipient_kid"].as_str().unwrap();
    let secret_jwk_d = fixture["recipient_x25519_secret_jwk"]["d"].as_str().unwrap();
    let recipient_secret_bytes =
        didcomm_multiformats::multibase::decode(secret_jwk_d).expect("valid base64url");

    let sender_public_x = fixture["sender_x25519_public_jwk"]["x"].as_str().unwrap();
    let sender_public_bytes =
        didcomm_multiformats::multibase::decode(sender_public_x).expect("valid base64url");

    let jwe_json = serde_json::to_string(&fixture["packed_jwe"]).unwrap();
    let jwe = JweEnvelope::from_json(jwe_json).expect("fixture JWE parses");

    let plaintext = ecdh_1pu_decrypt(
        &jwe,
        recipient_kid,
        &AgreementKey::from_secret_bytes(Curve::X25519, &recipient_secret_bytes).unwrap(),
        &AgreementKey::from_public_bytes(Curve::X25519, &sender_public_bytes).unwrap(),
    )
    .expect("decrypts with the Rust askar-crypto backend");

    assert_eq!(
        String::from_utf8(plaintext).unwrap(),
        fixture["plaintext"].as_str().unwrap(),
    );
}
