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
        aes::{A256CbcHs512, A256Gcm, A256Kw, AesKey},
        chacha20::{Chacha20Key, XC20P},
        ed25519::Ed25519KeyPair,
        x25519::X25519KeyPair,
    },
    encrypt::{KeyAeadInPlace, KeyAeadMeta},
    jwk::{FromJwk, ToJwk},
    kdf::{ecdh_1pu::Ecdh1PU, ecdh_es::EcdhEs, KeyDerivation, KeyExchange},
    repr::{KeyGen, KeyPublicBytes, KeySecretBytes},
};
use ciborium::Value as CborValue;
use didcomm_core::cose::{self, label, Alg, CoseEncrypt, CoseError, CoseRecipient, HeaderMap};
use didcomm_core::crypto::{Encoding, SecretKey as _};
use didcomm_core::jwe::{encode_protected, JweEnvelope, JweError, JweRecipient};
use hkdf::Hkdf;
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
    #[error(transparent)]
    Cose(#[from] CoseError),
    #[error("COSE recipient is missing its {0} header")]
    MissingCoseHeader(&'static str),
}

/// The `typ` of every COSE_Encrypt this crate produces, authcrypt or anoncrypt alike
/// (the spec gives both the same media type, so only the recipient learns which).
pub const COSE_ENCRYPTED_TYP: &str = "application/didcomm-encrypted+cbor";

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
/// serialization in the requested `encoding`, ready to send.
pub fn ecdh_es_encrypt(
    to_keys: &[(&str, X25519KeyPair)],
    message: &[u8],
    encoding: Encoding,
) -> Result<Vec<u8>, CryptoError> {
    if encoding == Encoding::Cbor {
        return cose_ecdh_es_encrypt(to_keys, message);
    }
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

    Ok(envelope.to_json()?.into_bytes())
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
    encoding: Encoding,
) -> Result<Vec<u8>, CryptoError> {
    if encoding == Encoding::Cbor {
        return cose_ecdh_1pu_encrypt(to_keys, sender_kid, sender_key, message);
    }
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
    // sends, inconsistency and all. (The COSE path, which has no such legacy to match,
    // uses the spec's "application/didcomm-encrypted+cbor".)
    protected.insert("typ".into(), Value::String("application/didcomm+encrypted".into()));
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

    Ok(envelope.to_json()?.into_bytes())
}

/// Sorted recipient kids, `.`-joined and SHA-256 hashed: the `apv` value JWE and COSE
/// envelopes both carry (DIDComm's definition, unchanged by encoding).
fn apv_for(to_keys: &[(&str, X25519KeyPair)]) -> Vec<u8> {
    let mut kids: Vec<&str> = to_keys.iter().map(|(kid, _)| *kid).collect();
    kids.sort_unstable();
    Sha256::digest(kids.join(".").as_bytes()).to_vec()
}

/// HKDF-SHA-256 over the ECDH shared secret `z`, with the recipient's
/// `COSE_KDF_Context` as `info` and no salt (RFC 9053 §6.3), producing the A256KW
/// key-wrapping key.
fn cose_wrap_key(z: &[u8], kdf_context: &[u8]) -> Result<AesKey<A256Kw>, CryptoError> {
    let mut okm = [0u8; 32];
    Hkdf::<Sha256>::new(None, z)
        .expand(kdf_context, &mut okm)
        .expect("32 bytes is a valid HKDF-SHA-256 output length");
    Ok(AesKey::<A256Kw>::from_secret_bytes(&okm)?)
}

/// The body headers and AEAD of a COSE_Encrypt: encrypt `message` under `cek`'s
/// algorithm, returning the protected header bytes, unprotected header and
/// ciphertext (with the AEAD tag appended, per COSE).
fn cose_encrypt_body<K: KeyAeadInPlace + KeyAeadMeta + KeyGen>(
    cek: &K,
    alg: Alg,
    message: &[u8],
) -> Result<(HeaderMap, Vec<u8>, HeaderMap, Vec<u8>), CryptoError> {
    let mut protected = HeaderMap::default();
    protected.insert(label::ALG, alg.to_cbor());
    protected.insert(label::TYP, CborValue::Text(COSE_ENCRYPTED_TYP.into()));
    let protected_bytes = protected.to_protected_bytes()?;
    let nonce = K::random_nonce();
    let mut ciphertext = message.to_vec();
    cek.encrypt_in_place(&mut ciphertext, &nonce, &cose::enc_structure(&protected_bytes))?;
    let mut unprotected = HeaderMap::default();
    unprotected.insert(label::IV, CborValue::Bytes(nonce.to_vec()));
    Ok((protected, protected_bytes, unprotected, ciphertext))
}

/// Decrypt a COSE_Encrypt body with an unwrapped CEK, for whichever content algorithm
/// it declares.
fn cose_decrypt_body(cose: &CoseEncrypt, cek_bytes: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let iv = cose.iv().ok_or(CryptoError::MissingCoseHeader("IV"))?;
    let aad = cose.enc_structure();
    let mut payload = cose.ciphertext.clone();
    match cose.content_alg() {
        Some(Alg::Xc20p) => Chacha20Key::<XC20P>::from_secret_bytes(cek_bytes)?.decrypt_in_place(&mut payload, iv, &aad)?,
        Some(Alg::A256Gcm) => AesKey::<A256Gcm>::from_secret_bytes(cek_bytes)?.decrypt_in_place(&mut payload, iv, &aad)?,
        Some(Alg::A256CbcHs512) => {
            AesKey::<A256CbcHs512>::from_secret_bytes(cek_bytes)?.decrypt_in_place(&mut payload, iv, &aad)?
        }
        other => return Err(CryptoError::UnsupportedEnc(format!("{other:?}"))),
    }
    Ok(payload)
}

fn kid_header(kid: &str) -> HeaderMap {
    let mut unprotected = HeaderMap::default();
    unprotected.insert(label::KID, CborValue::Bytes(kid.as_bytes().to_vec()));
    unprotected
}

fn cose_epk(recipient: &CoseRecipient) -> Result<X25519KeyPair, CryptoError> {
    let epk = recipient.header(label::EPHEMERAL_KEY).ok_or(CryptoError::MissingEpk)?;
    Ok(X25519KeyPair::from_public_bytes(&cose::x25519_from_cose_key(epk)?)?)
}

/// Encrypt a message as a `didcomm/v2+cbor` anoncrypt COSE_Encrypt: `ECDH-ES + A256KW`
/// (-31) key agreement per recipient, each with its own ephemeral key, and `XC20P`
/// content encryption -- the same algorithms as [`ecdh_es_encrypt`]'s JWE.
pub fn cose_ecdh_es_encrypt(to_keys: &[(&str, X25519KeyPair)], message: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if to_keys.is_empty() {
        return Err(CryptoError::NoRecipients);
    }
    let apv = apv_for(to_keys);
    let cek = Chacha20Key::<XC20P>::random()?;
    let cek_bytes = cek
        .with_secret_bytes(|b| b.map(<[u8]>::to_vec))
        .expect("a freshly generated key always has secret bytes");
    let (protected, protected_bytes, unprotected, ciphertext) = cose_encrypt_body(&cek, Alg::Xc20p, message)?;

    let mut recipients = Vec::with_capacity(to_keys.len());
    for (kid, recip_key) in to_keys {
        let epk = X25519KeyPair::random()?;
        let mut r_protected = HeaderMap::default();
        r_protected.insert(label::ALG, Alg::EcdhEsA256Kw.to_cbor());
        r_protected.insert(label::EPHEMERAL_KEY, cose::x25519_cose_key(&epk.with_public_bytes(<[u8]>::to_vec)));
        r_protected.insert(label::PARTY_V_IDENTITY, CborValue::Bytes(apv.clone()));
        let r_protected_bytes = r_protected.to_protected_bytes()?;

        let z = epk.key_exchange_bytes(recip_key)?;
        let wrap_key = cose_wrap_key(&z, &cose::kdf_context(None, Some(&apv), &r_protected_bytes, None))?;
        let mut encrypted_key = cek_bytes.clone();
        wrap_key.encrypt_in_place(&mut encrypted_key, &[], &[])?;
        recipients.push(CoseRecipient {
            protected_bytes: r_protected_bytes,
            protected: r_protected,
            unprotected: kid_header(kid),
            encrypted_key,
        });
    }

    Ok(CoseEncrypt { protected_bytes, protected, unprotected, ciphertext, recipients }.to_cbor()?)
}

/// Decrypt a `didcomm/v2+cbor` anoncrypt COSE_Encrypt -- the inverse of
/// [`cose_ecdh_es_encrypt`].
pub fn cose_ecdh_es_decrypt(
    cose: &CoseEncrypt,
    recipient_kid: &str,
    recipient_secret_bytes: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let recipient = cose.get_recipient(recipient_kid)?;
    match recipient.protected.alg() {
        Some(Alg::EcdhEsA256Kw) => {}
        other => return Err(CryptoError::UnsupportedAlg(format!("{other:?}"))),
    }
    let epk = cose_epk(recipient)?;
    let recipient_key = X25519KeyPair::from_secret_bytes(recipient_secret_bytes)?;
    let apv = recipient.protected.bytes(label::PARTY_V_IDENTITY);

    let z = recipient_key.key_exchange_bytes(&epk)?;
    let wrap_key = cose_wrap_key(&z, &cose::kdf_context(None, apv, &recipient.protected_bytes, None))?;
    let mut cek_bytes = recipient.encrypted_key.clone();
    wrap_key.decrypt_in_place(&mut cek_bytes, &[], &[])?;
    cose_decrypt_body(cose, &cek_bytes)
}

/// Encrypt a message as a `didcomm/v2+cbor` authcrypt COSE_Encrypt:
/// `"ECDH-1PU+A256KW"` key agreement with `A256CBC-HS512` content encryption, as
/// ECDH-1PU requires. Every recipient shares one ephemeral key and identical
/// `apu`/`apv`/`skid`, and -- as in the JWE form -- the content's AEAD tag is bound into
/// each wrap key's derivation (`COSE_KDF_Context`'s `SuppPubInfo.other`), so payload
/// encryption happens first. The shared secret is `Ze || Zs`, per draft-madden-ecdh-1pu.
pub fn cose_ecdh_1pu_encrypt(
    to_keys: &[(&str, X25519KeyPair)],
    sender_kid: &str,
    sender_key: &X25519KeyPair,
    message: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if to_keys.is_empty() {
        return Err(CryptoError::NoRecipients);
    }
    let apv = apv_for(to_keys);
    let apu = sender_kid.as_bytes();
    let cek = AesKey::<A256CbcHs512>::random()?;
    let cek_bytes = cek
        .with_secret_bytes(|b| b.map(<[u8]>::to_vec))
        .expect("a freshly generated key always has secret bytes");
    let (protected, protected_bytes, unprotected, ciphertext) =
        cose_encrypt_body(&cek, Alg::A256CbcHs512, message)?;
    // A256CBC-HS512's tag is the HMAC-SHA-512 output truncated to 32 bytes.
    let tag = &ciphertext[ciphertext.len() - 32..];

    let epk = X25519KeyPair::random()?;
    let mut r_protected = HeaderMap::default();
    r_protected.insert(label::ALG, Alg::Ecdh1PuA256Kw.to_cbor());
    r_protected.insert(label::EPHEMERAL_KEY, cose::x25519_cose_key(&epk.with_public_bytes(<[u8]>::to_vec)));
    r_protected.insert(label::PARTY_U_IDENTITY, CborValue::Bytes(apu.to_vec()));
    r_protected.insert(label::PARTY_V_IDENTITY, CborValue::Bytes(apv.clone()));
    r_protected.insert(label::STATIC_KEY_ID, CborValue::Bytes(apu.to_vec()));
    let r_protected_bytes = r_protected.to_protected_bytes()?;
    let kdf_context = cose::kdf_context(Some(apu), Some(&apv), &r_protected_bytes, Some(tag));

    let mut recipients = Vec::with_capacity(to_keys.len());
    for (kid, recip_key) in to_keys {
        let mut z = epk.key_exchange_bytes(recip_key)?.as_ref().to_vec();
        z.extend_from_slice(sender_key.key_exchange_bytes(recip_key)?.as_ref());
        let wrap_key = cose_wrap_key(&z, &kdf_context)?;
        let mut encrypted_key = cek_bytes.clone();
        wrap_key.encrypt_in_place(&mut encrypted_key, &[], &[])?;
        recipients.push(CoseRecipient {
            protected_bytes: r_protected_bytes.clone(),
            protected: r_protected.clone(),
            unprotected: kid_header(kid),
            encrypted_key,
        });
    }

    Ok(CoseEncrypt { protected_bytes, protected, unprotected, ciphertext, recipients }.to_cbor()?)
}

/// Decrypt a `didcomm/v2+cbor` authcrypt COSE_Encrypt -- the inverse of
/// [`cose_ecdh_1pu_encrypt`]. `sender_public_bytes` is the sender's X25519 key,
/// resolved by the caller from the envelope's `skid`/`apu`.
pub fn cose_ecdh_1pu_decrypt(
    cose: &CoseEncrypt,
    recipient_kid: &str,
    recipient_secret_bytes: &[u8],
    sender_public_bytes: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let recipient = cose.get_recipient(recipient_kid)?;
    match recipient.protected.alg() {
        Some(Alg::Ecdh1PuA256Kw) => {}
        other => return Err(CryptoError::UnsupportedAlg(format!("{other:?}"))),
    }
    if cose.content_alg() != Some(Alg::A256CbcHs512) {
        return Err(CryptoError::UnsupportedEnc(format!("{:?}", cose.content_alg())));
    }
    if cose.ciphertext.len() < 32 {
        return Err(CryptoError::UnsupportedEnc("ciphertext shorter than its tag".into()));
    }
    let tag = &cose.ciphertext[cose.ciphertext.len() - 32..];
    let epk = cose_epk(recipient)?;
    let recipient_key = X25519KeyPair::from_secret_bytes(recipient_secret_bytes)?;
    let sender_key = X25519KeyPair::from_public_bytes(sender_public_bytes)?;
    let apu = recipient.protected.bytes(label::PARTY_U_IDENTITY);
    let apv = recipient.protected.bytes(label::PARTY_V_IDENTITY);

    let mut z = recipient_key.key_exchange_bytes(&epk)?.as_ref().to_vec();
    z.extend_from_slice(recipient_key.key_exchange_bytes(&sender_key)?.as_ref());
    let wrap_key = cose_wrap_key(&z, &cose::kdf_context(apu, apv, &recipient.protected_bytes, Some(tag)))?;
    let mut cek_bytes = recipient.encrypted_key.clone();
    wrap_key.decrypt_in_place(&mut cek_bytes, &[], &[])?;
    cose_decrypt_body(cose, &cek_bytes)
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
        encoding: didcomm_core::crypto::Encoding,
    ) -> Result<Vec<u8>, didcomm_core::crypto::CryptoServiceError> {
        let keys: Vec<(&str, X25519KeyPair)> = to_keys
            .iter()
            .map(|k| (k.kid.as_str(), k.key.clone()))
            .collect();
        ecdh_es_encrypt(&keys, message, encoding)
            .map_err(|e| didcomm_core::crypto::CryptoServiceError::msg(e.to_string()))
    }

    async fn ecdh_es_decrypt(
        &self,
        enc_message: &[u8],
        recip_key: &AskarSecretKey,
    ) -> Result<Vec<u8>, didcomm_core::crypto::CryptoServiceError> {
        let result = match Encoding::detect(enc_message) {
            Ok(Encoding::Json) => JweEnvelope::from_json(enc_message)
                .map_err(CryptoError::from)
                .and_then(|jwe| ecdh_es_decrypt(&jwe, recip_key.kid(), &recip_key.secret_bytes())),
            Ok(Encoding::Cbor) => CoseEncrypt::from_cbor(enc_message)
                .map_err(CryptoError::from)
                .and_then(|cose| cose_ecdh_es_decrypt(&cose, recip_key.kid(), &recip_key.secret_bytes())),
            Err(e) => Err(CryptoError::Jwe(e.into())),
        };
        result.map_err(|e| didcomm_core::crypto::CryptoServiceError::msg(e.to_string()))
    }

    async fn ecdh_1pu_encrypt(
        &self,
        to_keys: &[AskarPublicKey],
        sender_key: &AskarSecretKey,
        message: &[u8],
        encoding: didcomm_core::crypto::Encoding,
    ) -> Result<Vec<u8>, didcomm_core::crypto::CryptoServiceError> {
        let keys: Vec<(&str, X25519KeyPair)> = to_keys
            .iter()
            .map(|k| (k.kid.as_str(), k.key.clone()))
            .collect();
        ecdh_1pu_encrypt(&keys, sender_key.kid(), &sender_key.key, message, encoding)
            .map_err(|e| didcomm_core::crypto::CryptoServiceError::msg(e.to_string()))
    }

    async fn ecdh_1pu_decrypt(
        &self,
        enc_message: &[u8],
        recip_key: &AskarSecretKey,
        sender_key: &AskarPublicKey,
    ) -> Result<Vec<u8>, didcomm_core::crypto::CryptoServiceError> {
        let sender_public_bytes = sender_key.key.with_public_bytes(<[u8]>::to_vec);
        let result = match Encoding::detect(enc_message) {
            Ok(Encoding::Json) => JweEnvelope::from_json(enc_message).map_err(CryptoError::from).and_then(|jwe| {
                ecdh_1pu_decrypt(&jwe, recip_key.kid(), &recip_key.secret_bytes(), &sender_public_bytes)
            }),
            Ok(Encoding::Cbor) => CoseEncrypt::from_cbor(enc_message).map_err(CryptoError::from).and_then(|cose| {
                cose_ecdh_1pu_decrypt(&cose, recip_key.kid(), &recip_key.secret_bytes(), &sender_public_bytes)
            }),
            Err(e) => Err(CryptoError::Jwe(e.into())),
        };
        result.map_err(|e| didcomm_core::crypto::CryptoServiceError::msg(e.to_string()))
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

/// A public key usable for Ed25519 signature verification (a DID's `authentication`
/// verification method) plus the DID URL kid it's known by.
#[derive(Debug, Clone)]
pub struct AskarVerifyingKey {
    pub key: Ed25519KeyPair,
    kid: String,
}

impl AskarVerifyingKey {
    pub fn new(kid: impl Into<String>, key: Ed25519KeyPair) -> Self {
        Self { kid: kid.into(), key }
    }
}

impl didcomm_core::crypto::VerifyingKey for AskarVerifyingKey {
    fn kid(&self) -> &str {
        &self.kid
    }
}

/// A secret key usable for Ed25519 signing -- an `authentication` keypair (with its
/// secret half) plus the DID URL kid it's known by.
#[derive(Debug, Clone)]
pub struct AskarSigningKey {
    pub key: Ed25519KeyPair,
    kid: String,
}

impl AskarSigningKey {
    pub fn new(kid: impl Into<String>, key: Ed25519KeyPair) -> Self {
        Self { kid: kid.into(), key }
    }
}

impl didcomm_core::crypto::SigningKey for AskarSigningKey {
    fn kid(&self) -> &str {
        &self.kid
    }
}

#[async_trait::async_trait]
impl didcomm_core::crypto::SigningService for AskarCryptoService {
    type SigningKey = AskarSigningKey;
    type VerifyingKey = AskarVerifyingKey;

    async fn sign(
        &self,
        key: &AskarSigningKey,
        message: &[u8],
    ) -> Result<Vec<u8>, didcomm_core::crypto::CryptoServiceError> {
        key.key.sign(message).map(|sig| sig.to_vec()).ok_or_else(|| {
            didcomm_core::crypto::CryptoServiceError::msg(
                "Ed25519 signing failed -- key is missing its secret half",
            )
        })
    }

    async fn verify(
        &self,
        key: &AskarVerifyingKey,
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool, didcomm_core::crypto::CryptoServiceError> {
        Ok(key.key.verify_signature(message, signature))
    }

    fn verification_method_to_verifying_key(
        &self,
        vm: &didcomm_diddoc::VerificationMethod,
    ) -> Result<AskarVerifyingKey, didcomm_core::crypto::CryptoServiceError> {
        let kid = if vm.id.starts_with('#') {
            format!("{}{}", vm.controller, vm.id)
        } else {
            vm.id.clone()
        };

        if vm.type_ == "JsonWebKey2020" {
            let jwk = vm.public_key_jwk.as_ref().ok_or_else(|| {
                didcomm_core::crypto::CryptoServiceError::InvalidVerificationMethod(
                    "JsonWebKey2020 verification method missing publicKeyJwk".into(),
                )
            })?;
            let jwk_str = serde_json::to_string(jwk).map_err(|e| {
                didcomm_core::crypto::CryptoServiceError::InvalidVerificationMethod(e.to_string())
            })?;
            let key = Ed25519KeyPair::from_jwk(&jwk_str).map_err(|e| {
                didcomm_core::crypto::CryptoServiceError::InvalidVerificationMethod(e.to_string())
            })?;
            return Ok(AskarVerifyingKey::new(kid, key));
        }

        let key_bytes = didcomm_core::crypto::multikey_bytes_from_verification_method(vm)?;
        let key = Ed25519KeyPair::from_public_bytes(&key_bytes).map_err(|e| {
            didcomm_core::crypto::CryptoServiceError::InvalidVerificationMethod(e.to_string())
        })?;
        Ok(AskarVerifyingKey::new(kid, key))
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

        let jwe_json = ecdh_es_encrypt(&[(kid, recipient_key)], b"Hello world!", Encoding::Json).unwrap();
        let jwe = JweEnvelope::from_json(jwe_json).unwrap();
        let plaintext = ecdh_es_decrypt(&jwe, kid, &recipient_secret_bytes).unwrap();

        assert_eq!(plaintext, b"Hello world!");
    }

    #[test]
    fn round_trips_through_our_own_decrypt_cbor_encoded() {
        let recipient_key = X25519KeyPair::random().unwrap();
        let recipient_secret_bytes = recipient_key
            .with_secret_bytes(|b| b.map(<[u8]>::to_vec))
            .unwrap();
        let kid = "did:example:recipient#key-1";

        let packed = ecdh_es_encrypt(&[(kid, recipient_key)], b"Hello world!", Encoding::Cbor).unwrap();
        // A tagged COSE_Encrypt (tag 96 = 0xd8 0x60), not a CBOR rendering of a JWE.
        assert_eq!(&packed[..2], &[0xd8, 0x60]);
        let cose = CoseEncrypt::from_cbor(&packed).unwrap();
        assert_eq!(cose.typ(), Some("application/didcomm-encrypted+cbor"));
        assert_eq!(cose.content_alg(), Some(Alg::Xc20p));
        assert_eq!(cose.recipients[0].protected.alg(), Some(Alg::EcdhEsA256Kw));
        let plaintext = cose_ecdh_es_decrypt(&cose, kid, &recipient_secret_bytes).unwrap();

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
            Encoding::Json,
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
    fn round_trips_1pu_through_our_own_decrypt_cbor_encoded() {
        let sender_key = X25519KeyPair::random().unwrap();
        let sender_public_bytes = sender_key.with_public_bytes(<[u8]>::to_vec);
        let sender_kid = "did:example:sender#key-1";

        let recipient_key = X25519KeyPair::random().unwrap();
        let recipient_secret_bytes = recipient_key
            .with_secret_bytes(|b| b.map(<[u8]>::to_vec))
            .unwrap();
        let recipient_kid = "did:example:recipient#key-1";

        let packed = ecdh_1pu_encrypt(
            &[(recipient_kid, recipient_key)],
            sender_kid,
            &sender_key,
            b"Hello world!",
            Encoding::Cbor,
        )
        .unwrap();
        assert_eq!(&packed[..2], &[0xd8, 0x60]);
        let cose = CoseEncrypt::from_cbor(&packed).unwrap();
        // The spec's media type -- unlike the JSON form's legacy "application/didcomm+encrypted".
        assert_eq!(cose.typ(), Some("application/didcomm-encrypted+cbor"));
        assert_eq!(cose.content_alg(), Some(Alg::A256CbcHs512));
        let recipient = &cose.recipients[0];
        assert_eq!(recipient.protected.alg(), Some(Alg::Ecdh1PuA256Kw));
        assert_eq!(recipient.protected.kid_str(label::STATIC_KEY_ID).as_deref(), Some(sender_kid));
        let plaintext = cose_ecdh_1pu_decrypt(
            &cose,
            recipient_kid,
            &recipient_secret_bytes,
            &sender_public_bytes,
        )
        .unwrap();
        assert_eq!(plaintext, b"Hello world!");

        // The tag is bound into the wrap key: tampering with the ciphertext must fail
        // key unwrapping or content decryption, never yield a plaintext.
        let mut tampered = cose.clone();
        let last = tampered.ciphertext.len() - 1;
        tampered.ciphertext[last] ^= 1;
        assert!(cose_ecdh_1pu_decrypt(&tampered, recipient_kid, &recipient_secret_bytes, &sender_public_bytes).is_err());

        // ...and a different (claimed) sender key must not decrypt it either.
        let impostor = X25519KeyPair::random().unwrap().with_public_bytes(<[u8]>::to_vec);
        assert!(cose_ecdh_1pu_decrypt(&cose, recipient_kid, &recipient_secret_bytes, &impostor).is_err());
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
                .ecdh_es_encrypt(&[public], b"Hello world!", Encoding::Json)
                .await
                .unwrap();
            let plaintext = service.ecdh_es_decrypt(&packed, &secret).await.unwrap();
            assert_eq!(plaintext, b"Hello world!");
        });
    }

    #[test]
    fn round_trips_through_the_crypto_service_trait_cbor_encoded() {
        let recipient_key = X25519KeyPair::random().unwrap();
        let recipient_kid = "did:example:recipient#key-1";
        let secret = AskarSecretKey::new(recipient_kid, recipient_key.clone());
        let public = AskarPublicKey::new(recipient_kid, recipient_key);

        let service = AskarCryptoService;
        pollster::block_on(async {
            let packed = service
                .ecdh_es_encrypt(&[public], b"Hello world!", Encoding::Cbor)
                .await
                .unwrap();
            assert_ne!(packed[0], b'{');
            // The trait's decrypt methods take no encoding parameter -- they sniff it
            // from the message itself (JweEnvelope::from_encoded), so this proves that
            // dispatch actually works through the full trait, not just JweEnvelope's
            // own unit tests.
            let plaintext = service.ecdh_es_decrypt(&packed, &secret).await.unwrap();
            assert_eq!(plaintext, b"Hello world!");
        });
    }

    #[test]
    fn sign_and_verify_round_trip() {
        use didcomm_core::crypto::SigningService;

        let keypair = Ed25519KeyPair::random().unwrap();
        let kid = "did:example:alice#key-1";
        let signing = AskarSigningKey::new(kid, keypair.clone());
        let verifying = AskarVerifyingKey::new(kid, keypair);

        let service = AskarCryptoService;
        pollster::block_on(async {
            let signature = service.sign(&signing, b"hello from_prior").await.unwrap();
            assert!(service
                .verify(&verifying, b"hello from_prior", &signature)
                .await
                .unwrap());
        });
    }

    #[test]
    fn verify_rejects_a_tampered_message() {
        use didcomm_core::crypto::SigningService;

        let keypair = Ed25519KeyPair::random().unwrap();
        let kid = "did:example:alice#key-1";
        let signing = AskarSigningKey::new(kid, keypair.clone());
        let verifying = AskarVerifyingKey::new(kid, keypair);

        let service = AskarCryptoService;
        pollster::block_on(async {
            let signature = service.sign(&signing, b"original message").await.unwrap();
            assert!(!service
                .verify(&verifying, b"a different message", &signature)
                .await
                .unwrap());
        });
    }

    #[test]
    fn verify_rejects_a_signature_from_the_wrong_key() {
        use didcomm_core::crypto::SigningService;

        let real_key = Ed25519KeyPair::random().unwrap();
        let attacker_key = Ed25519KeyPair::random().unwrap();
        let kid = "did:example:alice#key-1";
        let attacker_signing = AskarSigningKey::new(kid, attacker_key);
        let real_verifying = AskarVerifyingKey::new(kid, real_key);

        let service = AskarCryptoService;
        pollster::block_on(async {
            let signature = service
                .sign(&attacker_signing, b"a rotation claim")
                .await
                .unwrap();
            assert!(!service
                .verify(&real_verifying, b"a rotation claim", &signature)
                .await
                .unwrap());
        });
    }
}
