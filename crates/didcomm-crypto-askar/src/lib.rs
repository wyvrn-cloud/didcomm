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
        aes::{A256CbcHs512, A256Kw, AesKey},
        chacha20::{Chacha20Key, XC20P},
        x25519::X25519KeyPair,
    },
    encrypt::{KeyAeadInPlace, KeyAeadMeta},
    jwk::{FromJwk, ToJwk},
    kdf::{ecdh_1pu::Ecdh1PU, ecdh_es::EcdhEs, KeyDerivation},
    repr::{KeyGen, KeyPublicBytes, KeySecretBytes},
};
use didcomm_core::crypto::SecretKey as _;
use didcomm_core::jwe::{encode_protected, JweEnvelope, JweError, JweRecipient};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

/// Errors from the Askar-backed crypto operations.
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error(transparent)]
    Jwe(#[from] JweError),
    #[error("unsupported ECDH-ES/ECDH-1PU algorithm: {0}")]
    UnsupportedAlg(String),
    #[error("unsupported content encryption: {0}")]
    UnsupportedEnc(String),
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

/// Decrypt a DIDComm v2 ECDH-1PU ("authenticated encryption") envelope, i.e. the output
/// of `AskarCryptoService.ecdh_1pu_encrypt` on the Python side.
///
/// `sender_public_bytes` is the sender's raw X25519 public key (32 bytes), which a real
/// caller resolves from the sender's DID document (`skid`/`apu` in the header identifies
/// which key) -- this crate doesn't do DID resolution yet, so it's a direct parameter.
pub fn ecdh_1pu_decrypt(
    jwe: &JweEnvelope,
    recipient_kid: &str,
    recipient_secret_bytes: &[u8],
    sender_public_bytes: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let alg = jwe
        .protected
        .get("alg")
        .and_then(|v| v.as_str())
        .unwrap_or("<missing>");
    if alg != "ECDH-1PU+A256KW" {
        return Err(CryptoError::UnsupportedAlg(alg.to_string()));
    }
    let enc = jwe
        .protected
        .get("enc")
        .and_then(|v| v.as_str())
        .unwrap_or("<missing>");
    if enc != "A256CBC-HS512" {
        return Err(CryptoError::UnsupportedEnc(enc.to_string()));
    }

    let recipient = jwe.get_recipient(recipient_kid)?;
    let epk_value = recipient.header.get("epk").ok_or(CryptoError::MissingEpk)?;
    let epk_json = serde_json::to_string(epk_value)?;
    let ephemeral_key = X25519KeyPair::from_jwk(&epk_json)?;
    let recipient_key = X25519KeyPair::from_secret_bytes(recipient_secret_bytes)?;
    let sender_key = X25519KeyPair::from_public_bytes(sender_public_bytes)?;

    // Unlike ECDH-ES, the wrap key here is bound to the payload's own AEAD tag
    // (cc_tag) -- part of what makes ECDH-1PU's key agreement authenticated rather
    // than just anonymous: only someone who could reproduce that tag (i.e. who has
    // the sender's or a recipient's key material) could have derived a matching wrap
    // key. The tag is already known at this point (it's a field of the envelope), so
    // there's no ordering concern on the decrypt side the way there is on encrypt.
    let apu = jwe.apu_bytes()?;
    let apv = jwe.apv_bytes()?;
    let mut wrap_key_bytes = [0u8; 32];
    Ecdh1PU::new(
        &ephemeral_key,
        &sender_key,
        &recipient_key,
        alg.as_bytes(),
        &apu,
        &apv,
        &jwe.tag,
        true,
    )
    .derive_key_bytes(&mut wrap_key_bytes)?;
    let wrap_key = AesKey::<A256Kw>::from_secret_bytes(&wrap_key_bytes)?;

    let mut cek_bytes = recipient.encrypted_key.clone();
    wrap_key.decrypt_in_place(&mut cek_bytes, &[], &[])?;
    let cek = AesKey::<A256CbcHs512>::from_secret_bytes(&cek_bytes)?;

    let mut payload = jwe.ciphertext.clone();
    payload.extend_from_slice(&jwe.tag);
    let aad = jwe.combined_aad();
    cek.decrypt_in_place(&mut payload, &jwe.iv, &aad)?;

    Ok(payload)
}

/// Encrypt a message into a DIDComm v2 ECDH-1PU ("authenticated encryption") envelope,
/// mirroring `AskarCryptoService.ecdh_1pu_encrypt` on the Python side.
///
/// `sender_kid` is the sender's own kid (goes into `apu`/`skid`, and is what a receiver
/// resolves to get `sender_public_bytes` for `ecdh_1pu_decrypt`); `sender_key` is the
/// sender's full X25519 keypair (must have its secret half, unlike the recipients).
pub fn ecdh_1pu_encrypt(
    to_keys: &[(&str, X25519KeyPair)],
    sender_kid: &str,
    sender_key: &X25519KeyPair,
    message: &[u8],
) -> Result<String, CryptoError> {
    if to_keys.is_empty() {
        return Err(CryptoError::NoRecipients);
    }

    let mut kids: Vec<&str> = to_keys.iter().map(|(kid, _)| *kid).collect();
    kids.sort_unstable();
    let apv = Sha256::digest(kids.join(".").as_bytes()).to_vec();
    let apu = sender_kid.as_bytes();

    let cek = AesKey::<A256CbcHs512>::random()?;
    let cek_bytes = cek
        .with_secret_bytes(|b| b.map(<[u8]>::to_vec))
        .expect("a freshly generated key always has secret bytes");

    // Unlike ECDH-ES, there's one ephemeral key shared by every recipient (it lives in
    // the protected header, not per-recipient) -- ECDH-1PU also authenticates via the
    // sender's static key, so a per-recipient ephemeral buys nothing extra here.
    let epk = X25519KeyPair::random()?;
    let epk_jwk: Value = serde_json::from_str(&epk.to_jwk_public(None)?)?;

    let mut protected = Map::new();
    // Matches AskarCryptoService.ecdh_1pu_encrypt's protected["typ"] exactly -- yes,
    // "application/didcomm+encrypted" rather than ECDH-ES's
    // "application/didcomm-encrypted+json". Not a typo on this side: byte-for-byte
    // wire compatibility means reproducing what the reference implementation actually
    // sends, inconsistency and all.
    protected.insert(
        "typ".into(),
        Value::String("application/didcomm+encrypted".into()),
    );
    protected.insert("alg".into(), Value::String("ECDH-1PU+A256KW".into()));
    protected.insert("enc".into(), Value::String("A256CBC-HS512".into()));
    protected.insert(
        "apu".into(),
        Value::String(didcomm_multiformats::multibase::encode(apu)),
    );
    protected.insert(
        "apv".into(),
        Value::String(didcomm_multiformats::multibase::encode(&apv)),
    );
    protected.insert("epk".into(), epk_jwk);
    protected.insert("skid".into(), Value::String(sender_kid.to_string()));
    let protected_b64 = encode_protected(&protected)?;

    let nonce = AesKey::<A256CbcHs512>::random_nonce();
    let mut payload = message.to_vec();
    cek.encrypt_in_place(&mut payload, &nonce, protected_b64.as_bytes())?;
    // AesCbcHmac<Aes256, Sha512>::TagSize is the AES-256 key size (32 bytes) -- the
    // JWE spec truncates the HMAC-SHA-512 output to match, per RFC 7518 §5.2.3.
    let tag = payload.split_off(payload.len() - 32);

    // The wrap key derivation binds in `tag` (the payload's own AEAD tag) as cc_tag,
    // so it has to happen after payload encryption -- unlike ECDH-ES, where recipient
    // wrapping and payload encryption are independent of each other.
    let mut recipients = Vec::with_capacity(to_keys.len());
    for (kid, recip_key) in to_keys {
        let mut wrap_key_bytes = [0u8; 32];
        Ecdh1PU::new(
            &epk,
            sender_key,
            recip_key,
            b"ECDH-1PU+A256KW",
            apu,
            &apv,
            &tag,
            false,
        )
        .derive_key_bytes(&mut wrap_key_bytes)?;
        let wrap_key = AesKey::<A256Kw>::from_secret_bytes(&wrap_key_bytes)?;

        let mut encrypted_key = cek_bytes.clone();
        wrap_key.encrypt_in_place(&mut encrypted_key, &[], &[])?;

        let mut header = Map::new();
        header.insert("kid".into(), Value::String((*kid).to_string()));
        recipients.push(JweRecipient {
            encrypted_key,
            header,
        });
    }

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

/// A public key usable with [`AskarCryptoService`] -- an X25519 key (public-only or
/// full) plus the DID URL kid it's known by.
#[derive(Debug, Clone)]
pub struct AskarPublicKey {
    pub key: X25519KeyPair,
    kid: String,
}

impl AskarPublicKey {
    pub fn new(kid: impl Into<String>, key: X25519KeyPair) -> Self {
        Self { kid: kid.into(), key }
    }
}

impl didcomm_core::crypto::PublicKey for AskarPublicKey {
    fn kid(&self) -> &str {
        &self.kid
    }
}

/// A secret key usable with [`AskarCryptoService`] -- an X25519 keypair (with its
/// secret half) plus the DID URL kid it's known by.
#[derive(Debug, Clone)]
pub struct AskarSecretKey {
    pub key: X25519KeyPair,
    kid: String,
}

impl AskarSecretKey {
    pub fn new(kid: impl Into<String>, key: X25519KeyPair) -> Self {
        Self { kid: kid.into(), key }
    }

    fn secret_bytes(&self) -> Vec<u8> {
        self.key
            .with_secret_bytes(|b| b.map(<[u8]>::to_vec))
            .expect("AskarSecretKey always wraps a keypair with its secret half")
    }
}

impl didcomm_core::crypto::SecretKey for AskarSecretKey {
    fn kid(&self) -> &str {
        &self.kid
    }
}

/// [`CryptoService`](didcomm_core::crypto::CryptoService) backed by `askar-crypto`,
/// mirroring `AskarCryptoService` on the Python side. Only X25519 (the curve DIDComm v2
/// key agreement actually uses) is supported.
#[derive(Debug, Default, Clone, Copy)]
pub struct AskarCryptoService;

#[async_trait::async_trait]
impl didcomm_core::crypto::CryptoService for AskarCryptoService {
    type PublicKey = AskarPublicKey;
    type SecretKey = AskarSecretKey;

    async fn ecdh_es_encrypt(
        &self,
        to_keys: &[AskarPublicKey],
        message: &[u8],
    ) -> Result<Vec<u8>, didcomm_core::crypto::CryptoServiceError> {
        let keys: Vec<(&str, X25519KeyPair)> = to_keys
            .iter()
            .map(|k| (k.kid.as_str(), k.key.clone()))
            .collect();
        let json = ecdh_es_encrypt(&keys, message)
            .map_err(|e| didcomm_core::crypto::CryptoServiceError::msg(e.to_string()))?;
        Ok(json.into_bytes())
    }

    async fn ecdh_es_decrypt(
        &self,
        enc_message: &[u8],
        recip_key: &AskarSecretKey,
    ) -> Result<Vec<u8>, didcomm_core::crypto::CryptoServiceError> {
        let jwe = JweEnvelope::from_json(enc_message)
            .map_err(|e| didcomm_core::crypto::CryptoServiceError::msg(e.to_string()))?;
        ecdh_es_decrypt(&jwe, recip_key.kid(), &recip_key.secret_bytes())
            .map_err(|e| didcomm_core::crypto::CryptoServiceError::msg(e.to_string()))
    }

    async fn ecdh_1pu_encrypt(
        &self,
        to_keys: &[AskarPublicKey],
        sender_key: &AskarSecretKey,
        message: &[u8],
    ) -> Result<Vec<u8>, didcomm_core::crypto::CryptoServiceError> {
        let keys: Vec<(&str, X25519KeyPair)> = to_keys
            .iter()
            .map(|k| (k.kid.as_str(), k.key.clone()))
            .collect();
        let json = ecdh_1pu_encrypt(&keys, sender_key.kid(), &sender_key.key, message)
            .map_err(|e| didcomm_core::crypto::CryptoServiceError::msg(e.to_string()))?;
        Ok(json.into_bytes())
    }

    async fn ecdh_1pu_decrypt(
        &self,
        enc_message: &[u8],
        recip_key: &AskarSecretKey,
        sender_key: &AskarPublicKey,
    ) -> Result<Vec<u8>, didcomm_core::crypto::CryptoServiceError> {
        let jwe = JweEnvelope::from_json(enc_message)
            .map_err(|e| didcomm_core::crypto::CryptoServiceError::msg(e.to_string()))?;
        let sender_public_bytes = sender_key.key.with_public_bytes(<[u8]>::to_vec);
        ecdh_1pu_decrypt(
            &jwe,
            recip_key.kid(),
            &recip_key.secret_bytes(),
            &sender_public_bytes,
        )
        .map_err(|e| didcomm_core::crypto::CryptoServiceError::msg(e.to_string()))
    }

    fn verification_method_to_public_key(
        &self,
        vm: &didcomm_diddoc::VerificationMethod,
    ) -> Result<AskarPublicKey, didcomm_core::crypto::CryptoServiceError> {
        let kid = if vm.id.starts_with('#') {
            format!("{}{}", vm.controller, vm.id)
        } else {
            vm.id.clone()
        };

        // did:jwk (and any other JsonWebKey2020-typed method, e.g. did:web with an
        // embedded JWK) carries the key as a JWK rather than multibase-encoded raw
        // bytes -- askar-crypto's own FromJwk handles that encoding directly.
        if vm.type_ == "JsonWebKey2020" {
            let jwk = vm.public_key_jwk.as_ref().ok_or_else(|| {
                didcomm_core::crypto::CryptoServiceError::InvalidVerificationMethod(
                    "JsonWebKey2020 verification method missing publicKeyJwk".into(),
                )
            })?;
            let jwk_str = serde_json::to_string(jwk).map_err(|e| {
                didcomm_core::crypto::CryptoServiceError::InvalidVerificationMethod(e.to_string())
            })?;
            let key = X25519KeyPair::from_jwk(&jwk_str).map_err(|e| {
                didcomm_core::crypto::CryptoServiceError::InvalidVerificationMethod(e.to_string())
            })?;
            return Ok(AskarPublicKey::new(kid, key));
        }

        let key_bytes = didcomm_core::crypto::multikey_bytes_from_verification_method(vm)?;
        let key = X25519KeyPair::from_public_bytes(&key_bytes).map_err(|e| {
            didcomm_core::crypto::CryptoServiceError::InvalidVerificationMethod(e.to_string())
        })?;
        Ok(AskarPublicKey::new(kid, key))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use didcomm_core::crypto::CryptoService;

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

    #[test]
    fn round_trips_1pu_through_our_own_decrypt() {
        let sender_key = X25519KeyPair::random().unwrap();
        let sender_public_bytes = sender_key.with_public_bytes(<[u8]>::to_vec);
        let sender_kid = "did:example:sender#key-1";

        let recipient_key = X25519KeyPair::random().unwrap();
        let recipient_secret_bytes = recipient_key
            .with_secret_bytes(|b| b.map(<[u8]>::to_vec))
            .unwrap();
        let recipient_kid = "did:example:recipient#key-1";

        let jwe_json = ecdh_1pu_encrypt(
            &[(recipient_kid, recipient_key)],
            sender_kid,
            &sender_key,
            b"Hello world!",
        )
        .unwrap();
        let jwe = JweEnvelope::from_json(jwe_json).unwrap();
        let plaintext = ecdh_1pu_decrypt(
            &jwe,
            recipient_kid,
            &recipient_secret_bytes,
            &sender_public_bytes,
        )
        .unwrap();

        assert_eq!(plaintext, b"Hello world!");
    }

    #[test]
    fn round_trips_through_the_crypto_service_trait() {
        let recipient_key = X25519KeyPair::random().unwrap();
        let recipient_kid = "did:example:recipient#key-1";
        let secret = AskarSecretKey::new(recipient_kid, recipient_key.clone());
        let public = AskarPublicKey::new(recipient_kid, recipient_key);

        let service = AskarCryptoService;
        pollster::block_on(async {
            let packed = service
                .ecdh_es_encrypt(&[public], b"Hello world!")
                .await
                .unwrap();
            let plaintext = service.ecdh_es_decrypt(&packed, &secret).await.unwrap();
            assert_eq!(plaintext, b"Hello world!");
        });
    }
}
