//! The milestone this whole crate exists to prove: a "Hello world!" DIDComm v2 ECDH-ES
//! message, packed by the actual `didcomm-messaging-python` reference library's
//! `AskarCryptoService`, decrypts correctly here -- with no shared process or state
//! between the two implementations, only the wire format and a copy of the recipient's
//! raw key material. See `/fixtures/wire-compat/README.md` for how the fixture was
//! produced.

use didcomm_core::jwe::JweEnvelope;
use didcomm_crypto_askar::{ecdh_es_decrypt, AgreementKey, Curve};
use serde_json::Value;

const FIXTURE: &str = include_str!("../../../fixtures/wire-compat/hello_world_es.json");

#[test]
fn decrypts_a_python_produced_hello_world() {
    let fixture: Value = serde_json::from_str(FIXTURE).expect("fixture is valid JSON");

    let recipient_kid = fixture["recipient_kid"].as_str().unwrap();
    let secret_jwk_d = fixture["recipient_x25519_secret_jwk"]["d"].as_str().unwrap();
    let recipient_secret_bytes =
        didcomm_multiformats::multibase::decode(secret_jwk_d).expect("valid base64url");

    let jwe_json = serde_json::to_string(&fixture["packed_jwe"]).unwrap();
    let jwe = JweEnvelope::from_json(jwe_json).expect("fixture JWE parses");

    let recipient_key = AgreementKey::from_secret_bytes(Curve::X25519, &recipient_secret_bytes).unwrap();
    let plaintext = ecdh_es_decrypt(&jwe, recipient_kid, &recipient_key)
        .expect("decrypts with the Rust askar-crypto backend");

    assert_eq!(
        String::from_utf8(plaintext).unwrap(),
        fixture["plaintext"].as_str().unwrap(),
    );
}
