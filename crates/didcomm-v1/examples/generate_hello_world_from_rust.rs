//! Generates the reverse-direction wire-compat fixture for DIDComm v1: real Anoncrypt
//! and Authcrypt "Hello world!" envelopes packed by *this* crate, to be decrypted by
//! the actual `didcomm-messaging-python` library -- see
//! `/fixtures/v1/verify_hello_world_from_rust.py`.
//!
//! Fixed seeds, as in the v2 examples, so the fixture is reproducible.

use askar_crypto::repr::KeySecretBytes;
use askar_crypto::alg::ed25519::Ed25519KeyPair;
use didcomm_v1::{kid_for_verkey, pack_message};
use serde_json::{json, Value};

const RECIPIENT_SEED_HEX: &str =
    "1f6a3e0c8b9d2a4f5e7c1b0d3a9f8e6c4b2d0a1f3e5c7b9d1a3f5e7c9b0d2a4f";
const SENDER_SEED_HEX: &str = "2a4c6e8f0b1d3f5a7c9e0b2d4f6a8c0e2a4c6e8f0b1d3f5a7c9e0b2d4f6a8c0e";

fn main() {
    let recipient = Ed25519KeyPair::from_secret_bytes(&hex_decode(RECIPIENT_SEED_HEX)).unwrap();
    let sender = Ed25519KeyPair::from_secret_bytes(&hex_decode(SENDER_SEED_HEX)).unwrap();

    let anoncrypt = pack_message(&[recipient.clone()], None, b"Hello world!").unwrap();
    let authcrypt = pack_message(&[recipient.clone()], Some(&sender), b"Hello world!").unwrap();

    let fixture = json!({
        "plaintext": "Hello world!",
        "recipient_kid": kid_for_verkey(&recipient),
        "recipient_seed_hex": RECIPIENT_SEED_HEX,
        "sender_kid": kid_for_verkey(&sender),
        "sender_seed_hex": SENDER_SEED_HEX,
        "anoncrypt": serde_json::from_str::<Value>(&anoncrypt).unwrap(),
        "authcrypt": serde_json::from_str::<Value>(&authcrypt).unwrap(),
    });

    println!("{}", serde_json::to_string_pretty(&fixture).unwrap());
}

fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}
