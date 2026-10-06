//! Generates the reverse-direction wire-compat fixture: a "Hello world!" ECDH-ES
//! envelope packed by *this* crate, to be decrypted by the actual
//! `didcomm-messaging-python` library -- see
//! `/fixtures/wire-compat/verify_hello_world_es_from_rust.py`.
//!
//! Uses a fixed recipient secret (not a fresh random one) so the fixture is
//! reproducible: re-running this only changes the ephemeral key and nonce, which
//! doesn't matter for Python's ability to decrypt.

use askar_crypto::{jwk::ToJwk, repr::KeySecretBytes};
use didcomm_core::crypto::Encoding;
use didcomm_crypto_askar::ecdh_es_encrypt;
use serde_json::{json, Value};

const RECIPIENT_SECRET_HEX: &str =
    "1f6a3e0c8b9d2a4f5e7c1b0d3a9f8e6c4b2d0a1f3e5c7b9d1a3f5e7c9b0d2a4f";

fn main() {
    let secret_bytes = hex_decode(RECIPIENT_SECRET_HEX);
    let recipient_key = askar_crypto::alg::x25519::X25519KeyPair::from_secret_bytes(
        &secret_bytes,
    )
    .expect("valid X25519 secret");
    let kid = "did:example:rust-recipient#key-1";

    let jwe_json = ecdh_es_encrypt(&[(kid, recipient_key.clone().into())], b"Hello world!", Encoding::Json)
        .expect("encryption succeeds");
    let packed_jwe: Value = serde_json::from_slice(&jwe_json).unwrap();

    let secret_jwk: Value =
        serde_json::from_slice(recipient_key.to_jwk_secret(None).unwrap().as_ref()).unwrap();

    let fixture = json!({
        "plaintext": "Hello world!",
        "recipient_kid": kid,
        "recipient_x25519_secret_jwk": secret_jwk,
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
