//! Generates the reverse-direction wire-compat fixture for ECDH-1PU: a "Hello world!"
//! envelope packed by *this* crate, to be decrypted by the actual
//! `didcomm-messaging-python` library -- see
//! `/fixtures/wire-compat/verify_hello_world_1pu_from_rust.py`.
//!
//! Fixed sender/recipient secrets, as in generate_hello_world_es_from_rust.rs, so the
//! fixture is reproducible.

use askar_crypto::{alg::x25519::X25519KeyPair, jwk::ToJwk, repr::KeySecretBytes};
use didcomm_crypto_askar::ecdh_1pu_encrypt;
use serde_json::{json, Value};

const SENDER_SECRET_HEX: &str =
    "2a4c6e8f0b1d3f5a7c9e0b2d4f6a8c0e2a4c6e8f0b1d3f5a7c9e0b2d4f6a8c0e";
const RECIPIENT_SECRET_HEX: &str =
    "1f6a3e0c8b9d2a4f5e7c1b0d3a9f8e6c4b2d0a1f3e5c7b9d1a3f5e7c9b0d2a4f";

fn main() {
    let sender_key = X25519KeyPair::from_secret_bytes(&hex_decode(SENDER_SECRET_HEX))
        .expect("valid X25519 secret");
    let sender_kid = "did:example:rust-sender#key-1";

    let recipient_key = X25519KeyPair::from_secret_bytes(&hex_decode(RECIPIENT_SECRET_HEX))
        .expect("valid X25519 secret");
    let recipient_kid = "did:example:rust-recipient#key-1";

    let jwe_json = ecdh_1pu_encrypt(
        &[(recipient_kid, recipient_key.clone())],
        sender_kid,
        &sender_key,
        b"Hello world!",
    )
    .expect("encryption succeeds");
    let packed_jwe: Value = serde_json::from_str(&jwe_json).unwrap();

    let sender_public_jwk: Value =
        serde_json::from_str(&sender_key.to_jwk_public(None).unwrap()).unwrap();
    let recipient_secret_jwk: Value =
        serde_json::from_slice(recipient_key.to_jwk_secret(None).unwrap().as_ref()).unwrap();

    let fixture = json!({
        "plaintext": "Hello world!",
        "sender_kid": sender_kid,
        "sender_x25519_public_jwk": sender_public_jwk,
        "recipient_kid": recipient_kid,
        "recipient_x25519_secret_jwk": recipient_secret_jwk,
        "packed_jwe": packed_jwe,
    });

    println!("{}", serde_json::to_string_pretty(&fixture).unwrap());
}

fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}
