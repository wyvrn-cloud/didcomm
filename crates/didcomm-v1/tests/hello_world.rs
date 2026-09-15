//! DIDComm v1's equivalent of the v2 "Hello world!" wire-compat milestone: real
//! Anoncrypt and Authcrypt envelopes, packed by the actual `didcomm-messaging-python`
//! library's `NaclV1CryptoService`, decrypt correctly here.

use askar_crypto::{alg::ed25519::Ed25519KeyPair, repr::KeySecretBytes};
use didcomm_core::jwe::JweEnvelope;
use didcomm_v1::unpack_message;
use serde_json::Value;

const FIXTURE: &str = include_str!("../../../fixtures/v1/fixture.json");

fn key_from_seed_hex(seed_hex: &str) -> Ed25519KeyPair {
    let seed = hex_decode(seed_hex);
    Ed25519KeyPair::from_secret_bytes(&seed).unwrap()
}

fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn decrypts_a_python_produced_anoncrypt_hello_world() {
    let fixture: Value = serde_json::from_str(FIXTURE).unwrap();
    let recipient = key_from_seed_hex(fixture["recipient_seed_hex"].as_str().unwrap());
    let recipient_kid = fixture["recipient_kid"].as_str().unwrap();

    let jwe_json = serde_json::to_string(&fixture["anoncrypt"]).unwrap();
    let jwe = JweEnvelope::from_json_v1(jwe_json).expect("fixture JWE parses");

    let (plaintext, sender_vk) =
        unpack_message(&jwe, recipient_kid, &recipient).expect("decrypts with our own crypto_box");

    assert_eq!(
        String::from_utf8(plaintext).unwrap(),
        fixture["plaintext"].as_str().unwrap()
    );
    assert_eq!(sender_vk, None);
}

#[test]
fn decrypts_a_python_produced_authcrypt_hello_world() {
    let fixture: Value = serde_json::from_str(FIXTURE).unwrap();
    let recipient = key_from_seed_hex(fixture["recipient_seed_hex"].as_str().unwrap());
    let recipient_kid = fixture["recipient_kid"].as_str().unwrap();
    let sender_kid = fixture["sender_kid"].as_str().unwrap();

    let jwe_json = serde_json::to_string(&fixture["authcrypt"]).unwrap();
    let jwe = JweEnvelope::from_json_v1(jwe_json).expect("fixture JWE parses");

    let (plaintext, sender_vk) =
        unpack_message(&jwe, recipient_kid, &recipient).expect("decrypts with our own crypto_box");

    assert_eq!(
        String::from_utf8(plaintext).unwrap(),
        fixture["plaintext"].as_str().unwrap()
    );
    assert_eq!(sender_vk.as_deref(), Some(sender_kid));
}
