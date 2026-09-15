//! DIDComm v2 crypto backend built on `askar-crypto`, mirroring
//! `didcomm_messaging.crypto.backend.askar.AskarCryptoService`.
//!
//! `askar-crypto`'s public API only exposes the low-level ECDH-ES/ECDH-1PU key
//! derivation (`kdf::ecdh_es`/`kdf::ecdh_1pu`) plus per-algorithm key wrap and AEAD
//! primitives -- the JOSE-level composition (derive a wrap key, unwrap the CEK, then
//! AEAD-decrypt the payload) that Python's `aries_askar.ecdh.EcdhEs` does in its own
//! Python code has no equivalent single call in the Rust crate. That composition is
//! reimplemented here, directly against `askar-crypto`'s primitives, following exactly
//! what `aries-askar`'s own `src/kms/envelope.rs::derive_key_ecdh_es` does internally.
//!
//! Only ECDH-ES decryption exists so far -- this crate exists right now to prove one
//! thing end-to-end: a `"Hello world!"` message packed by `didcomm-messaging-python`'s
//! `AskarCryptoService` decrypts correctly here, with no shared process or state between
//! the two implementations (see `tests/hello_world_es.rs` and `/fixtures/wire-compat`).
//! Encryption, ECDH-1PU, and the full `CryptoService` trait from the plan follow in
//! later milestones.

use askar_crypto::{
    alg::{
        aes::{A256Kw, AesKey},
        chacha20::{Chacha20Key, XC20P},
        x25519::X25519KeyPair,
    },
    encrypt::{KeyAeadInPlace, KeyAeadMeta},
    jwk::{FromJwk, ToJwk},
    kdf::{ecdh_es::EcdhEs, KeyDerivation},
    repr::{KeyGen, KeySecretBytes},
};
use didcomm_core::jwe::{encode_protected, JweEnvelope, JweError, JweRecipient};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

/// Errors from the Askar-backed crypto operations.
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error(transparent)]
    Jwe(#[from] JweError),
    #[error("unsupported ECDH-ES algorithm: {0}")]
    UnsupportedAlg(String),
    #[error("askar-crypto error: {0}")]
    Askar(#[from] askar_crypto::Error),
    #[error("recipient is missing its ephemeral key (epk) header")]
    MissingEpk,
    #[error("could not (de)serialize a JWK header: {0}")]
    HeaderJson(#[from] serde_json::Error),
    #[error("no message recipients")]
    NoRecipients,
}

/// Decrypt a DIDComm v2 ECDH-ES ("anonymous encryption") envelope, i.e. the output of
/// `AskarCryptoService.ecdh_es_encrypt` on the Python side.
///
/// `recipient_kid` selects which entry of the JWE's `recipients` array to unwrap.
/// `recipient_secret_bytes` is that recipient's raw X25519 secret scalar (32 bytes,
/// e.g. the base64url-decoded `d` value of its JWK).
pub fn ecdh_es_decrypt(
    jwe: &JweEnvelope,
    recipient_kid: &str,
    recipient_secret_bytes: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    // 1. Only ECDH-ES+A256KW/XC20P is supported today -- this is the only combination
    //    AskarCryptoService.ecdh_es_encrypt ever produces (see crypto/backend/askar.py).
    let alg = jwe
        .protected
        .get("alg")
        .and_then(|v| v.as_str())
        .unwrap_or("<missing>");
    if alg != "ECDH-ES+A256KW" {
        return Err(CryptoError::UnsupportedAlg(alg.to_string()));
    }

    let recipient = jwe.get_recipient(recipient_kid)?;
    let epk_value = recipient.header.get("epk").ok_or(CryptoError::MissingEpk)?;
    let epk_json = serde_json::to_string(epk_value)?;
    let ephemeral_key = X25519KeyPair::from_jwk(&epk_json)?;
    let recipient_key = X25519KeyPair::from_secret_bytes(recipient_secret_bytes)?;

    // 2. Derive the key-wrapping key via ECDH-ES + ConcatKDF. The KDF's AlgorithmID is
    //    the full "alg" header value (not just the "A256KW" suffix) per RFC 7518 §4.6.2's
    //    "Key Agreement with Key Wrapping" case.
    let apv = jwe.apv_bytes()?;
    let mut wrap_key_bytes = [0u8; 32];
    EcdhEs::new(&ephemeral_key, &recipient_key, alg.as_bytes(), b"", &apv, true)
        .derive_key_bytes(&mut wrap_key_bytes)?;
    let wrap_key = AesKey::<A256Kw>::from_secret_bytes(&wrap_key_bytes)?;

    // 3. Unwrap the content-encryption key (AES Key Wrap, RFC 3394 -- modeled as a
    //    nonce-less, AAD-less "AEAD" in askar-crypto).
    let mut cek_bytes = recipient.encrypted_key.clone();
    wrap_key.decrypt_in_place(&mut cek_bytes, &[], &[])?;
    let cek = Chacha20Key::<XC20P>::from_secret_bytes(&cek_bytes)?;

    // 4. AEAD-decrypt the payload. The AAD is the ASCII bytes of the base64url-encoded
    //    protected header (JweEnvelope::combined_aad), and askar-crypto expects the tag
    //    appended to the ciphertext rather than passed separately.
    let mut payload = jwe.ciphertext.clone();
    payload.extend_from_slice(&jwe.tag);
    let aad = jwe.combined_aad();
    cek.decrypt_in_place(&mut payload, &jwe.iv, &aad)?;

    Ok(payload)
}

/// Encrypt a message into a DIDComm v2 ECDH-ES ("anonymous encryption") envelope,
/// mirroring `AskarCryptoService.ecdh_es_encrypt` on the Python side.
///
/// `to_keys` is the recipient list as `(kid, public key)` pairs. Returns the envelope's
/// JSON serialization, ready to send.
pub fn ecdh_es_encrypt(
    to_keys: &[(&str, X25519KeyPair)],
    message: &[u8],
) -> Result<String, CryptoError> {
    if to_keys.is_empty() {
        return Err(CryptoError::NoRecipients);
    }

    // apv (Agreement PartyVInfo) identifies the recipient set: sha256 of their sorted
    // kids, joined with ".". Every recipient shares this value, so it's computed once.
    let mut kids: Vec<&str> = to_keys.iter().map(|(kid, _)| *kid).collect();
    kids.sort_unstable();
    let apv = Sha256::digest(kids.join(".").as_bytes()).to_vec();

    let cek = Chacha20Key::<XC20P>::random()?;
    let cek_bytes = cek
        .with_secret_bytes(|b| b.map(<[u8]>::to_vec))
        .expect("a freshly generated key always has secret bytes");

    // One ephemeral X25519 key and one AES-256-KW-wrapped copy of the CEK per recipient,
    // per the spec's "sender process to enable multiple recipients".
    let mut recipients = Vec::with_capacity(to_keys.len());
    for (kid, recip_key) in to_keys {
        let epk = X25519KeyPair::random()?;

        let mut wrap_key_bytes = [0u8; 32];
        EcdhEs::new(&epk, recip_key, b"ECDH-ES+A256KW", b"", &apv, false)
            .derive_key_bytes(&mut wrap_key_bytes)?;
        let wrap_key = AesKey::<A256Kw>::from_secret_bytes(&wrap_key_bytes)?;

        let mut encrypted_key = cek_bytes.clone();
        wrap_key.encrypt_in_place(&mut encrypted_key, &[], &[])?;

        let epk_jwk: Value = serde_json::from_str(&epk.to_jwk_public(None)?)?;
        let mut header = Map::new();
        header.insert("kid".into(), Value::String((*kid).to_string()));
        header.insert("epk".into(), epk_jwk);

        recipients.push(JweRecipient {
            encrypted_key,
            header,
        });
    }

    let mut protected = Map::new();
    protected.insert(
        "typ".into(),
        Value::String("application/didcomm-encrypted+json".into()),
    );
    protected.insert("alg".into(), Value::String("ECDH-ES+A256KW".into()));
    protected.insert("enc".into(), Value::String("XC20P".into()));
    protected.insert(
        "apv".into(),
        Value::String(didcomm_multiformats::multibase::encode(&apv)),
    );
    let protected_b64 = encode_protected(&protected)?;

    // The AAD is exactly the ASCII bytes of the (not-yet-embedded) protected_b64 string
    // -- computed before the envelope exists, since the envelope needs the ciphertext
    // this produces.
    let nonce = Chacha20Key::<XC20P>::random_nonce();
    let mut payload = message.to_vec();
    cek.encrypt_in_place(&mut payload, &nonce, protected_b64.as_bytes())?;
    // askar-crypto appends the AEAD tag to the buffer; DIDComm's JWE keeps them separate.
    let tag = payload.split_off(payload.len() - 16);

    let envelope = JweEnvelope {
        protected_b64,
        protected,
        recipients,
        iv: nonce.to_vec(),
        ciphertext: payload,
        tag,
        aad: None,
    };

    Ok(envelope.to_json()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_through_our_own_decrypt() {
        let recipient_key = X25519KeyPair::random().unwrap();
        let recipient_secret_bytes = recipient_key
            .with_secret_bytes(|b| b.map(<[u8]>::to_vec))
            .unwrap();
        let kid = "did:example:recipient#key-1";

        let jwe_json = ecdh_es_encrypt(&[(kid, recipient_key)], b"Hello world!").unwrap();
        let jwe = JweEnvelope::from_json(jwe_json).unwrap();
        let plaintext = ecdh_es_decrypt(&jwe, kid, &recipient_secret_bytes).unwrap();

        assert_eq!(plaintext, b"Hello world!");
    }
}
