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
    encrypt::KeyAeadInPlace,
    jwk::FromJwk,
    kdf::{ecdh_es::EcdhEs, KeyDerivation},
    repr::KeySecretBytes,
};
use didcomm_core::jwe::{JweEnvelope, JweError};

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
    #[error("could not serialize epk header: {0}")]
    EpkJson(#[from] serde_json::Error),
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
