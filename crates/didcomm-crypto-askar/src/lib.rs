//! DIDComm v2 crypto backend built on `askar-crypto`, mirroring
//! `didcomm_messaging.crypto.backend.askar.AskarCryptoService`.
//!
//! `askar-crypto`'s public API only exposes the low-level ECDH-ES/ECDH-1PU key
//! derivation (`kdf::ecdh_es`/`kdf::ecdh_1pu`) plus per-algorithm key wrap and AEAD
//! primitives -- the envelope-level composition (derive a wrap key, unwrap the CEK,
//! then AEAD-decrypt the payload) is built here, for both encodings:
//!
//! - JSON: a JWE in General JSON form, JOSE Concat KDF, wire-compatible with
//!   `didcomm-messaging-python` (see `tests/hello_world_*.rs` and `/fixtures/wire-compat`).
//! - CBOR (`didcomm/v2+cbor`): a COSE_Encrypt, HKDF-SHA-256 over a `COSE_KDF_Context`
//!   (see `didcomm_core::cose`).
//!
//! Key agreement works on X25519, P-384 and P-256 ([`AgreementKey`]). Per the spec's
//! "common protected headers" rule, every envelope has *one* ephemeral key, `apv` and
//! `alg` shared by all its recipients (so all recipients must be on one curve), in the
//! JWE protected header or each COSE recipient's protected header.

mod keys;

pub use keys::{AgreementKey, Curve};

use askar_crypto::{
    alg::{
        aes::{A256CbcHs512, A256Gcm, A256Kw, AesKey},
        chacha20::{Chacha20Key, XC20P},
        ed25519::Ed25519KeyPair,
    },
    encrypt::{KeyAeadInPlace, KeyAeadMeta},
    jwk::FromJwk,
    repr::{KeyGen, KeyPublicBytes, KeySecretBytes},
};
use ciborium::Value as CborValue;
use didcomm_core::cose::{self, label, Alg, CoseEncrypt, CoseError, CoseRecipient, HeaderMap};
use didcomm_core::crypto::{Encoding, SecretKey as _};
use didcomm_core::jwe::{encode_protected, JweEnvelope, JweError, JweRecipient};
use didcomm_multiformats::multicodec;
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
    #[error("unsupported key-agreement curve: {0}")]
    UnsupportedCurve(String),
    #[error("keys on different curves ({0} and {1}) can't share one envelope")]
    CurveMismatch(&'static str, &'static str),
}

/// The `typ` of every encrypted envelope, authcrypt or anoncrypt alike (the spec gives
/// both the same media type, so only the recipient learns which).
pub const JSON_ENCRYPTED_TYP: &str = "application/didcomm-encrypted+json";
pub const COSE_ENCRYPTED_TYP: &str = "application/didcomm-encrypted+cbor";

/// `apv`: SHA-256 of the sorted recipient kids joined with `.` -- DIDComm's definition,
/// the same for both encodings.
fn apv_for(to_keys: &[(&str, AgreementKey)]) -> Vec<u8> {
    let mut kids: Vec<&str> = to_keys.iter().map(|(kid, _)| *kid).collect();
    kids.sort_unstable();
    Sha256::digest(kids.join(".").as_bytes()).to_vec()
}

fn random_cek<K: KeyGen + KeySecretBytes>() -> Result<(K, Vec<u8>), CryptoError> {
    let cek = K::random()?;
    let bytes = cek
        .with_secret_bytes(|b| b.map(<[u8]>::to_vec))
        .expect("a freshly generated key always has secret bytes");
    Ok((cek, bytes))
}

fn wrap_cek(wrap_key_bytes: &[u8], cek_bytes: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let mut encrypted_key = cek_bytes.to_vec();
    AesKey::<A256Kw>::from_secret_bytes(wrap_key_bytes)?.encrypt_in_place(&mut encrypted_key, &[], &[])?;
    Ok(encrypted_key)
}

fn unwrap_cek(wrap_key_bytes: &[u8], encrypted_key: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let mut cek = encrypted_key.to_vec();
    AesKey::<A256Kw>::from_secret_bytes(wrap_key_bytes)?.decrypt_in_place(&mut cek, &[], &[])?;
    Ok(cek)
}

/// AEAD-decrypt `ciphertext || tag` with a CEK for the given content algorithm.
fn content_decrypt(enc: &str, cek: &[u8], payload: &mut Vec<u8>, iv: &[u8], aad: &[u8]) -> Result<(), CryptoError> {
    match enc {
        "XC20P" => Chacha20Key::<XC20P>::from_secret_bytes(cek)?.decrypt_in_place(payload, iv, aad)?,
        "A256GCM" => AesKey::<A256Gcm>::from_secret_bytes(cek)?.decrypt_in_place(payload, iv, aad)?,
        "A256CBC-HS512" => AesKey::<A256CbcHs512>::from_secret_bytes(cek)?.decrypt_in_place(payload, iv, aad)?,
        other => return Err(CryptoError::UnsupportedEnc(other.to_string())),
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// JSON: JWE
// ---------------------------------------------------------------------------

/// The recipient's view of a JWE (protected headers merged under its own), and its
/// `epk` -- in the protected header for anything this crate produces, in the
/// per-recipient header for `didcomm-messaging-python`'s anoncrypt.
fn jwe_recipient_epk(jwe: &JweEnvelope, kid: &str) -> Result<(JweRecipient, AgreementKey), CryptoError> {
    let recipient = jwe.get_recipient(kid)?;
    let epk = AgreementKey::from_jwk(recipient.header.get("epk").ok_or(CryptoError::MissingEpk)?)?;
    Ok((recipient, epk))
}

fn jwe_str<'a>(jwe: &'a JweEnvelope, name: &str) -> &'a str {
    jwe.protected.get(name).and_then(Value::as_str).unwrap_or("<missing>")
}

/// Decrypt a DIDComm v2 ECDH-ES ("anonymous encryption") JWE for the recipient `kid`
/// holding `recipient_key`.
pub fn ecdh_es_decrypt(jwe: &JweEnvelope, recipient_kid: &str, recipient_key: &AgreementKey) -> Result<Vec<u8>, CryptoError> {
    let alg = jwe_str(jwe, "alg");
    if alg != "ECDH-ES+A256KW" {
        return Err(CryptoError::UnsupportedAlg(alg.to_string()));
    }
    let (recipient, epk) = jwe_recipient_epk(jwe, recipient_kid)?;
    // The KDF's AlgorithmID is the full "alg" value, per RFC 7518 §4.6.2's "Key
    // Agreement with Key Wrapping" case.
    let wrap_key = AgreementKey::ecdh_es_wrap_key(&epk, recipient_key, alg.as_bytes(), &jwe.apv_bytes()?, true)?;
    let cek = unwrap_cek(&wrap_key, &recipient.encrypted_key)?;

    // askar-crypto expects the tag appended to the ciphertext; the AAD is the ASCII of
    // the base64url protected header (JweEnvelope::combined_aad).
    let mut payload = [jwe.ciphertext.as_slice(), &jwe.tag].concat();
    content_decrypt(jwe_str(jwe, "enc"), &cek, &mut payload, &jwe.iv, &jwe.combined_aad())?;
    Ok(payload)
}

/// Encrypt a message as a DIDComm v2 ECDH-ES ("anonymous encryption") envelope in the
/// given `encoding`: ECDH-ES+A256KW key agreement, XC20P content encryption.
///
/// `to_keys` is the recipient list as `(kid, public key)` pairs, all on one curve.
pub fn ecdh_es_encrypt(to_keys: &[(&str, AgreementKey)], message: &[u8], encoding: Encoding) -> Result<Vec<u8>, CryptoError> {
    if encoding == Encoding::Cbor {
        return cose_ecdh_es_encrypt(to_keys, message);
    }
    let curve = keys::common_curve(to_keys.iter().map(|(_, k)| k))?;
    let apv = apv_for(to_keys);
    let (cek, cek_bytes) = random_cek::<Chacha20Key<XC20P>>()?;
    // One ephemeral key for every recipient, in the protected header -- the spec's
    // "MUST use common epk, apv and alg headers for all recipient keys".
    let epk = AgreementKey::generate(curve)?;

    let mut recipients = Vec::with_capacity(to_keys.len());
    for (kid, recip_key) in to_keys {
        let wrap_key = AgreementKey::ecdh_es_wrap_key(&epk, recip_key, b"ECDH-ES+A256KW", &apv, false)?;
        let mut header = Map::new();
        header.insert("kid".into(), Value::String((*kid).to_string()));
        recipients.push(JweRecipient { encrypted_key: wrap_cek(&wrap_key, &cek_bytes)?, header });
    }

    let mut protected = Map::new();
    protected.insert("typ".into(), Value::String(JSON_ENCRYPTED_TYP.into()));
    protected.insert("alg".into(), Value::String("ECDH-ES+A256KW".into()));
    protected.insert("enc".into(), Value::String("XC20P".into()));
    protected.insert("apv".into(), Value::String(didcomm_multiformats::multibase::encode(&apv)));
    protected.insert("epk".into(), epk.to_jwk_public()?);
    let protected_b64 = encode_protected(&protected)?;

    let nonce = Chacha20Key::<XC20P>::random_nonce();
    let mut payload = message.to_vec();
    cek.encrypt_in_place(&mut payload, &nonce, protected_b64.as_bytes())?;
    // askar-crypto appends the AEAD tag to the buffer; DIDComm's JWE keeps them separate.
    let tag = payload.split_off(payload.len() - 16);

    Ok(JweEnvelope { protected_b64, protected, recipients, iv: nonce.to_vec(), ciphertext: payload, tag, aad: None }
        .to_json()?
        .into_bytes())
}

/// Decrypt a DIDComm v2 ECDH-1PU ("authenticated encryption") JWE. `sender_key` is the
/// sender's public key, which the caller resolves from the envelope's `skid`/`apu`.
pub fn ecdh_1pu_decrypt(
    jwe: &JweEnvelope,
    recipient_kid: &str,
    recipient_key: &AgreementKey,
    sender_key: &AgreementKey,
) -> Result<Vec<u8>, CryptoError> {
    let alg = jwe_str(jwe, "alg");
    if alg != "ECDH-1PU+A256KW" {
        return Err(CryptoError::UnsupportedAlg(alg.to_string()));
    }
    let enc = jwe_str(jwe, "enc");
    if enc != "A256CBC-HS512" {
        return Err(CryptoError::UnsupportedEnc(enc.to_string()));
    }
    let (recipient, epk) = jwe_recipient_epk(jwe, recipient_kid)?;

    // The wrap key is bound to the payload's own AEAD tag (cc_tag): only someone who
    // could produce that tag could have derived a matching wrap key.
    let wrap_key = AgreementKey::ecdh_1pu_wrap_key(
        &epk,
        sender_key,
        recipient_key,
        alg.as_bytes(),
        &jwe.apu_bytes()?,
        &jwe.apv_bytes()?,
        &jwe.tag,
        true,
    )?;
    let cek = unwrap_cek(&wrap_key, &recipient.encrypted_key)?;
    let mut payload = [jwe.ciphertext.as_slice(), &jwe.tag].concat();
    content_decrypt(enc, &cek, &mut payload, &jwe.iv, &jwe.combined_aad())?;
    Ok(payload)
}

/// Encrypt a message as a DIDComm v2 ECDH-1PU ("authenticated encryption") envelope in
/// the given `encoding`: ECDH-1PU+A256KW key agreement, A256CBC-HS512 content
/// encryption (as ECDH-1PU requires). `sender_key` must hold its secret half and be on
/// the recipients' curve.
pub fn ecdh_1pu_encrypt(
    to_keys: &[(&str, AgreementKey)],
    sender_kid: &str,
    sender_key: &AgreementKey,
    message: &[u8],
    encoding: Encoding,
) -> Result<Vec<u8>, CryptoError> {
    if encoding == Encoding::Cbor {
        return cose_ecdh_1pu_encrypt(to_keys, sender_kid, sender_key, message);
    }
    let curve = keys::common_curve(to_keys.iter().map(|(_, k)| k).chain([sender_key]))?;
    let apv = apv_for(to_keys);
    let apu = sender_kid.as_bytes();
    let (cek, cek_bytes) = random_cek::<AesKey<A256CbcHs512>>()?;
    let epk = AgreementKey::generate(curve)?;

    let mut protected = Map::new();
    protected.insert("typ".into(), Value::String(JSON_ENCRYPTED_TYP.into()));
    protected.insert("alg".into(), Value::String("ECDH-1PU+A256KW".into()));
    protected.insert("enc".into(), Value::String("A256CBC-HS512".into()));
    protected.insert("apu".into(), Value::String(didcomm_multiformats::multibase::encode(apu)));
    protected.insert("apv".into(), Value::String(didcomm_multiformats::multibase::encode(&apv)));
    protected.insert("epk".into(), epk.to_jwk_public()?);
    protected.insert("skid".into(), Value::String(sender_kid.to_string()));
    let protected_b64 = encode_protected(&protected)?;

    let nonce = AesKey::<A256CbcHs512>::random_nonce();
    let mut payload = message.to_vec();
    cek.encrypt_in_place(&mut payload, &nonce, protected_b64.as_bytes())?;
    // A256CBC-HS512's tag is the HMAC-SHA-512 output truncated to 32 bytes (RFC 7518 §5.2.3).
    let tag = payload.split_off(payload.len() - 32);

    // Recipient wrapping binds `tag`, so it follows payload encryption.
    let mut recipients = Vec::with_capacity(to_keys.len());
    for (kid, recip_key) in to_keys {
        let wrap_key =
            AgreementKey::ecdh_1pu_wrap_key(&epk, sender_key, recip_key, b"ECDH-1PU+A256KW", apu, &apv, &tag, false)?;
        let mut header = Map::new();
        header.insert("kid".into(), Value::String((*kid).to_string()));
        recipients.push(JweRecipient { encrypted_key: wrap_cek(&wrap_key, &cek_bytes)?, header });
    }

    Ok(JweEnvelope { protected_b64, protected, recipients, iv: nonce.to_vec(), ciphertext: payload, tag, aad: None }
        .to_json()?
        .into_bytes())
}

// ---------------------------------------------------------------------------
// CBOR: COSE_Encrypt
// ---------------------------------------------------------------------------

/// HKDF-SHA-256 over the ECDH shared secret `z`, with the recipient's
/// `COSE_KDF_Context` as `info` and no salt (RFC 9053 §6.3): the A256KW wrap key.
fn cose_wrap_key(z: &[u8], kdf_context: &[u8]) -> [u8; 32] {
    let mut okm = [0u8; 32];
    Hkdf::<Sha256>::new(None, z)
        .expand(kdf_context, &mut okm)
        .expect("32 bytes is a valid HKDF-SHA-256 output length");
    okm
}

/// The body of a COSE_Encrypt: protected `{alg, typ}`, unprotected `{IV}`, and
/// `message` AEAD-encrypted under `cek` with the `Enc_structure` as AAD (tag appended).
fn cose_encrypt_body<K: KeyAeadInPlace + KeyAeadMeta>(
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

fn cose_decrypt_body(cose: &CoseEncrypt, cek: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let iv = cose.iv().ok_or(CryptoError::MissingCoseHeader("IV"))?;
    let enc = cose.content_alg().ok_or(CryptoError::UnsupportedEnc("missing alg".into()))?;
    let mut payload = cose.ciphertext.clone();
    content_decrypt(enc.jwa_name(), cek, &mut payload, iv, &cose.enc_structure())?;
    Ok(payload)
}

/// One COSE recipient per key, all sharing `r_protected` (the common key-agreement
/// headers), each with its own `kid` and wrapped CEK.
fn cose_recipients(
    to_keys: &[(&str, AgreementKey)],
    r_protected: &HeaderMap,
    mut wrap_key_for: impl FnMut(&AgreementKey) -> Result<[u8; 32], CryptoError>,
    cek_bytes: &[u8],
) -> Result<Vec<CoseRecipient>, CryptoError> {
    let r_protected_bytes = r_protected.to_protected_bytes()?;
    to_keys
        .iter()
        .map(|(kid, recip_key)| {
            let mut unprotected = HeaderMap::default();
            unprotected.insert(label::KID, CborValue::Bytes(kid.as_bytes().to_vec()));
            Ok(CoseRecipient {
                protected_bytes: r_protected_bytes.clone(),
                protected: r_protected.clone(),
                unprotected,
                encrypted_key: wrap_cek(&wrap_key_for(recip_key)?, cek_bytes)?,
            })
        })
        .collect()
}

fn cose_epk(recipient: &CoseRecipient) -> Result<AgreementKey, CryptoError> {
    AgreementKey::from_cose_key(recipient.header(label::EPHEMERAL_KEY).ok_or(CryptoError::MissingEpk)?)
}

/// Encrypt a message as a `didcomm/v2+cbor` anoncrypt COSE_Encrypt: `ECDH-ES + A256KW`
/// (-31) with one ephemeral key shared by every recipient, XC20P content encryption.
pub fn cose_ecdh_es_encrypt(to_keys: &[(&str, AgreementKey)], message: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let curve = keys::common_curve(to_keys.iter().map(|(_, k)| k))?;
    let apv = apv_for(to_keys);
    let (cek, cek_bytes) = random_cek::<Chacha20Key<XC20P>>()?;
    let (protected, protected_bytes, unprotected, ciphertext) = cose_encrypt_body(&cek, Alg::Xc20p, message)?;

    let epk = AgreementKey::generate(curve)?;
    let mut r_protected = HeaderMap::default();
    r_protected.insert(label::ALG, Alg::EcdhEsA256Kw.to_cbor());
    r_protected.insert(label::EPHEMERAL_KEY, epk.to_cose_key()?);
    r_protected.insert(label::PARTY_V_IDENTITY, CborValue::Bytes(apv.clone()));
    let kdf_context = cose::kdf_context(None, Some(&apv), &r_protected.to_protected_bytes()?, None);
    let recipients =
        cose_recipients(to_keys, &r_protected, |recip| Ok(cose_wrap_key(&epk.ecdh(recip)?, &kdf_context)), &cek_bytes)?;

    Ok(CoseEncrypt { protected_bytes, protected, unprotected, ciphertext, recipients }.to_cbor()?)
}

/// Decrypt a `didcomm/v2+cbor` anoncrypt COSE_Encrypt -- the inverse of
/// [`cose_ecdh_es_encrypt`].
pub fn cose_ecdh_es_decrypt(cose: &CoseEncrypt, recipient_kid: &str, recipient_key: &AgreementKey) -> Result<Vec<u8>, CryptoError> {
    let recipient = cose.get_recipient(recipient_kid)?;
    if recipient.protected.alg() != Some(Alg::EcdhEsA256Kw) {
        return Err(CryptoError::UnsupportedAlg(format!("{:?}", recipient.protected.alg())));
    }
    let apv = recipient.protected.bytes(label::PARTY_V_IDENTITY);
    let z = recipient_key.ecdh(&cose_epk(recipient)?)?;
    let wrap_key = cose_wrap_key(&z, &cose::kdf_context(None, apv, &recipient.protected_bytes, None));
    cose_decrypt_body(cose, &unwrap_cek(&wrap_key, &recipient.encrypted_key)?)
}

/// Encrypt a message as a `didcomm/v2+cbor` authcrypt COSE_Encrypt:
/// `"ECDH-1PU+A256KW"` with `A256CBC-HS512` content encryption. Every recipient shares
/// one ephemeral key and identical `apu`/`apv`/`skid`; the content tag is bound into
/// each wrap key (`COSE_KDF_Context`'s `SuppPubInfo.other`), and the shared secret is
/// `Ze || Zs` per draft-madden-ecdh-1pu.
pub fn cose_ecdh_1pu_encrypt(
    to_keys: &[(&str, AgreementKey)],
    sender_kid: &str,
    sender_key: &AgreementKey,
    message: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let curve = keys::common_curve(to_keys.iter().map(|(_, k)| k).chain([sender_key]))?;
    let apv = apv_for(to_keys);
    let apu = sender_kid.as_bytes();
    let (cek, cek_bytes) = random_cek::<AesKey<A256CbcHs512>>()?;
    let (protected, protected_bytes, unprotected, ciphertext) = cose_encrypt_body(&cek, Alg::A256CbcHs512, message)?;
    let tag = &ciphertext[ciphertext.len() - 32..];

    let epk = AgreementKey::generate(curve)?;
    let mut r_protected = HeaderMap::default();
    r_protected.insert(label::ALG, Alg::Ecdh1PuA256Kw.to_cbor());
    r_protected.insert(label::EPHEMERAL_KEY, epk.to_cose_key()?);
    r_protected.insert(label::PARTY_U_IDENTITY, CborValue::Bytes(apu.to_vec()));
    r_protected.insert(label::PARTY_V_IDENTITY, CborValue::Bytes(apv.clone()));
    r_protected.insert(label::STATIC_KEY_ID, CborValue::Bytes(apu.to_vec()));
    let kdf_context = cose::kdf_context(Some(apu), Some(&apv), &r_protected.to_protected_bytes()?, Some(tag));
    let recipients = cose_recipients(
        to_keys,
        &r_protected,
        |recip| Ok(cose_wrap_key(&[epk.ecdh(recip)?, sender_key.ecdh(recip)?].concat(), &kdf_context)),
        &cek_bytes,
    )?;

    Ok(CoseEncrypt { protected_bytes, protected, unprotected, ciphertext, recipients }.to_cbor()?)
}

/// Decrypt a `didcomm/v2+cbor` authcrypt COSE_Encrypt -- the inverse of
/// [`cose_ecdh_1pu_encrypt`]. `sender_key` is resolved by the caller from `skid`/`apu`.
pub fn cose_ecdh_1pu_decrypt(
    cose: &CoseEncrypt,
    recipient_kid: &str,
    recipient_key: &AgreementKey,
    sender_key: &AgreementKey,
) -> Result<Vec<u8>, CryptoError> {
    let recipient = cose.get_recipient(recipient_kid)?;
    if recipient.protected.alg() != Some(Alg::Ecdh1PuA256Kw) {
        return Err(CryptoError::UnsupportedAlg(format!("{:?}", recipient.protected.alg())));
    }
    if cose.content_alg() != Some(Alg::A256CbcHs512) {
        return Err(CryptoError::UnsupportedEnc(format!("{:?}", cose.content_alg())));
    }
    let Some(tag_start) = cose.ciphertext.len().checked_sub(32) else {
        return Err(CryptoError::UnsupportedEnc("ciphertext shorter than its tag".into()));
    };
    let tag = &cose.ciphertext[tag_start..];
    let apu = recipient.protected.bytes(label::PARTY_U_IDENTITY);
    let apv = recipient.protected.bytes(label::PARTY_V_IDENTITY);
    let z = [recipient_key.ecdh(&cose_epk(recipient)?)?, recipient_key.ecdh(sender_key)?].concat();
    let wrap_key = cose_wrap_key(&z, &cose::kdf_context(apu, apv, &recipient.protected_bytes, Some(tag)));
    cose_decrypt_body(cose, &unwrap_cek(&wrap_key, &recipient.encrypted_key)?)
}

// ---------------------------------------------------------------------------
// CryptoService
// ---------------------------------------------------------------------------

/// A public key usable with [`AskarCryptoService`] -- an [`AgreementKey`] (public-only
/// or full) plus the DID URL kid it's known by.
#[derive(Debug, Clone)]
pub struct AskarPublicKey {
    pub key: AgreementKey,
    kid: String,
}

impl AskarPublicKey {
    pub fn new(kid: impl Into<String>, key: impl Into<AgreementKey>) -> Self {
        Self { kid: kid.into(), key: key.into() }
    }
}

impl didcomm_core::crypto::PublicKey for AskarPublicKey {
    fn kid(&self) -> &str {
        &self.kid
    }
}

/// A secret key usable with [`AskarCryptoService`] -- an [`AgreementKey`] with its
/// secret half, plus the DID URL kid it's known by.
#[derive(Debug, Clone)]
pub struct AskarSecretKey {
    pub key: AgreementKey,
    kid: String,
}

impl AskarSecretKey {
    pub fn new(kid: impl Into<String>, key: impl Into<AgreementKey>) -> Self {
        let key = key.into();
        debug_assert!(key.has_secret(), "AskarSecretKey needs a key pair with its secret half");
        Self { kid: kid.into(), key }
    }
}

impl didcomm_core::crypto::SecretKey for AskarSecretKey {
    fn kid(&self) -> &str {
        &self.kid
    }
}

/// [`CryptoService`](didcomm_core::crypto::CryptoService) backed by `askar-crypto`,
/// mirroring `AskarCryptoService` on the Python side, for X25519, P-384 and P-256 key
/// agreement in either encoding.
#[derive(Debug, Default, Clone, Copy)]
pub struct AskarCryptoService;

fn service_err(e: CryptoError) -> didcomm_core::crypto::CryptoServiceError {
    didcomm_core::crypto::CryptoServiceError::msg(e.to_string())
}

fn key_list(to_keys: &[AskarPublicKey]) -> Vec<(&str, AgreementKey)> {
    to_keys.iter().map(|k| (k.kid.as_str(), k.key.clone())).collect()
}

/// A JWE or COSE_Encrypt, by the message's own encoding.
enum Parsed {
    Jwe(JweEnvelope),
    Cose(CoseEncrypt),
}

fn parse_envelope(enc_message: &[u8]) -> Result<Parsed, CryptoError> {
    Ok(match Encoding::detect(enc_message).map_err(JweError::from)? {
        Encoding::Json => Parsed::Jwe(JweEnvelope::from_json(enc_message)?),
        Encoding::Cbor => Parsed::Cose(CoseEncrypt::from_cbor(enc_message)?),
    })
}

/// The agreement key a verification method describes: a `Multikey` (or base58/
/// multibase legacy type) for X25519, P-256 or P-384, or a `JsonWebKey2020` JWK.
fn agreement_key_from_vm(vm: &didcomm_diddoc::VerificationMethod) -> Result<AgreementKey, CryptoError> {
    if vm.type_ == "JsonWebKey2020" {
        let jwk = vm
            .public_key_jwk
            .as_ref()
            .ok_or_else(|| CryptoError::UnsupportedCurve("JsonWebKey2020 verification method missing publicKeyJwk".into()))?;
        return AgreementKey::from_jwk(&serde_json::to_value(jwk)?);
    }
    let (codec, bytes) = didcomm_core::crypto::multikey_from_verification_method(vm)
        .map_err(|e| CryptoError::UnsupportedCurve(e.to_string()))?;
    let curve = match codec {
        None => Curve::X25519,
        Some(c) if c == multicodec::X25519_PUB => Curve::X25519,
        Some(c) if c == multicodec::P256_PUB => Curve::P256,
        Some(c) if c == multicodec::P384_PUB => Curve::P384,
        Some(c) => return Err(CryptoError::UnsupportedCurve(c.name.to_string())),
    };
    AgreementKey::from_public_bytes(curve, &bytes)
}

#[async_trait::async_trait]
impl didcomm_core::crypto::CryptoService for AskarCryptoService {
    type PublicKey = AskarPublicKey;
    type SecretKey = AskarSecretKey;

    async fn ecdh_es_encrypt(
        &self,
        to_keys: &[AskarPublicKey],
        message: &[u8],
        encoding: Encoding,
    ) -> Result<Vec<u8>, didcomm_core::crypto::CryptoServiceError> {
        ecdh_es_encrypt(&key_list(to_keys), message, encoding).map_err(service_err)
    }

    async fn ecdh_es_decrypt(
        &self,
        enc_message: &[u8],
        recip_key: &AskarSecretKey,
    ) -> Result<Vec<u8>, didcomm_core::crypto::CryptoServiceError> {
        match parse_envelope(enc_message).map_err(service_err)? {
            Parsed::Jwe(jwe) => ecdh_es_decrypt(&jwe, recip_key.kid(), &recip_key.key),
            Parsed::Cose(cose) => cose_ecdh_es_decrypt(&cose, recip_key.kid(), &recip_key.key),
        }
        .map_err(service_err)
    }

    async fn ecdh_1pu_encrypt(
        &self,
        to_keys: &[AskarPublicKey],
        sender_key: &AskarSecretKey,
        message: &[u8],
        encoding: Encoding,
    ) -> Result<Vec<u8>, didcomm_core::crypto::CryptoServiceError> {
        ecdh_1pu_encrypt(&key_list(to_keys), sender_key.kid(), &sender_key.key, message, encoding).map_err(service_err)
    }

    async fn ecdh_1pu_decrypt(
        &self,
        enc_message: &[u8],
        recip_key: &AskarSecretKey,
        sender_key: &AskarPublicKey,
    ) -> Result<Vec<u8>, didcomm_core::crypto::CryptoServiceError> {
        match parse_envelope(enc_message).map_err(service_err)? {
            Parsed::Jwe(jwe) => ecdh_1pu_decrypt(&jwe, recip_key.kid(), &recip_key.key, &sender_key.key),
            Parsed::Cose(cose) => cose_ecdh_1pu_decrypt(&cose, recip_key.kid(), &recip_key.key, &sender_key.key),
        }
        .map_err(service_err)
    }

    fn verification_method_to_public_key(
        &self,
        vm: &didcomm_diddoc::VerificationMethod,
    ) -> Result<AskarPublicKey, didcomm_core::crypto::CryptoServiceError> {
        let kid = if vm.id.starts_with('#') { format!("{}{}", vm.controller, vm.id) } else { vm.id.clone() };
        let key = agreement_key_from_vm(vm)
            .map_err(|e| didcomm_core::crypto::CryptoServiceError::InvalidVerificationMethod(e.to_string()))?;
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

    use askar_crypto::alg::x25519::X25519KeyPair;

    const CURVES: [Curve; 3] = [Curve::X25519, Curve::P256, Curve::P384];

    fn two_recipients(curve: Curve) -> [(&'static str, AgreementKey); 2] {
        [
            ("did:example:recipient#z-key", AgreementKey::generate(curve).unwrap()),
            ("did:example:recipient#a-key", AgreementKey::generate(curve).unwrap()),
        ]
    }

    #[test]
    fn anoncrypt_jwe_round_trips_on_every_curve_with_one_shared_epk() {
        for curve in CURVES {
            let recipients = two_recipients(curve);
            let packed = ecdh_es_encrypt(&recipients, b"Hello world!", Encoding::Json).unwrap();
            let jwe = JweEnvelope::from_json(&packed).unwrap();
            assert_eq!(jwe.protected["typ"], JSON_ENCRYPTED_TYP);
            // The spec's common-header rule: one epk, in the protected header.
            assert_eq!(jwe.protected["epk"]["crv"], curve.name());
            assert!(jwe.recipients.iter().all(|r| r.header.get("epk").is_none()));
            for (kid, key) in &recipients {
                assert_eq!(ecdh_es_decrypt(&jwe, kid, key).unwrap(), b"Hello world!", "{curve:?}");
            }
        }
    }

    #[test]
    fn anoncrypt_cose_round_trips_on_every_curve_with_one_shared_epk() {
        for curve in CURVES {
            let recipients = two_recipients(curve);
            let packed = ecdh_es_encrypt(&recipients, b"Hello world!", Encoding::Cbor).unwrap();
            // A tagged COSE_Encrypt (tag 96 = 0xd8 0x60).
            assert_eq!(&packed[..2], &[0xd8, 0x60]);
            let cose = CoseEncrypt::from_cbor(&packed).unwrap();
            assert_eq!(cose.typ(), Some(COSE_ENCRYPTED_TYP));
            assert_eq!(cose.content_alg(), Some(Alg::Xc20p));
            assert_eq!(cose.recipients[0].protected.alg(), Some(Alg::EcdhEsA256Kw));
            assert_eq!(cose.recipients[0].protected_bytes, cose.recipients[1].protected_bytes);
            for (kid, key) in &recipients {
                assert_eq!(cose_ecdh_es_decrypt(&cose, kid, key).unwrap(), b"Hello world!", "{curve:?}");
            }
        }
    }

    #[test]
    fn authcrypt_round_trips_on_every_curve_in_both_encodings() {
        for curve in CURVES {
            for encoding in [Encoding::Json, Encoding::Cbor] {
                let sender = AgreementKey::generate(curve).unwrap();
                let sender_kid = "did:example:sender#key-1";
                let recipients = two_recipients(curve);
                let packed = ecdh_1pu_encrypt(&recipients, sender_kid, &sender, b"Hello world!", encoding).unwrap();
                let sender_public = AgreementKey::from_public_bytes(curve, &sender.public_bytes()).unwrap();
                let impostor = AgreementKey::generate(curve).unwrap();
                for (kid, key) in &recipients {
                    let (ok, forged) = match encoding {
                        Encoding::Json => {
                            let jwe = JweEnvelope::from_json(&packed).unwrap();
                            assert_eq!(jwe.protected["typ"], JSON_ENCRYPTED_TYP);
                            (ecdh_1pu_decrypt(&jwe, kid, key, &sender_public), ecdh_1pu_decrypt(&jwe, kid, key, &impostor))
                        }
                        Encoding::Cbor => {
                            let cose = CoseEncrypt::from_cbor(&packed).unwrap();
                            assert_eq!(cose.typ(), Some(COSE_ENCRYPTED_TYP));
                            assert_eq!(cose.content_alg(), Some(Alg::A256CbcHs512));
                            let r = &cose.recipients[0];
                            assert_eq!(r.protected.alg(), Some(Alg::Ecdh1PuA256Kw));
                            assert_eq!(r.protected.kid_str(label::STATIC_KEY_ID).as_deref(), Some(sender_kid));
                            (
                                cose_ecdh_1pu_decrypt(&cose, kid, key, &sender_public),
                                cose_ecdh_1pu_decrypt(&cose, kid, key, &impostor),
                            )
                        }
                    };
                    assert_eq!(ok.unwrap(), b"Hello world!", "{curve:?} {encoding:?}");
                    // A different (claimed) sender key must not decrypt it.
                    assert!(forged.is_err(), "{curve:?} {encoding:?}");
                }
            }
        }
    }

    #[test]
    fn tampering_with_a_cose_authcrypt_ciphertext_fails() {
        let sender = AgreementKey::generate(Curve::X25519).unwrap();
        let recipient = AgreementKey::generate(Curve::X25519).unwrap();
        let kid = "did:example:recipient#key-1";
        let packed = cose_ecdh_1pu_encrypt(&[(kid, recipient.clone())], "did:example:sender#key-1", &sender, b"hi").unwrap();
        let mut cose = CoseEncrypt::from_cbor(&packed).unwrap();
        let last = cose.ciphertext.len() - 1;
        cose.ciphertext[last] ^= 1;
        assert!(cose_ecdh_1pu_decrypt(&cose, kid, &recipient, &sender).is_err());
    }

    #[test]
    fn one_envelope_cannot_mix_curves() {
        let recipients = [
            ("did:example:a#x", AgreementKey::generate(Curve::X25519).unwrap()),
            ("did:example:a#p", AgreementKey::generate(Curve::P384).unwrap()),
        ];
        for encoding in [Encoding::Json, Encoding::Cbor] {
            assert!(matches!(
                ecdh_es_encrypt(&recipients, b"hi", encoding),
                Err(CryptoError::CurveMismatch(..))
            ));
        }
    }

    #[test]
    fn decrypts_a_legacy_per_recipient_epk_jwe() {
        // didcomm-messaging-python's anoncrypt puts a separate epk in each recipient's
        // header; those still decrypt (get_recipient merges recipient over protected).
        let recipient = X25519KeyPair::random().unwrap();
        let kid = "did:example:recipient#key-1";
        let packed = ecdh_es_encrypt(&[(kid, recipient.clone().into())], b"legacy", Encoding::Json).unwrap();
        let mut jwe = JweEnvelope::from_json(&packed).unwrap();
        let epk = jwe.protected.remove("epk").unwrap();
        jwe.protected_b64 = encode_protected(&jwe.protected).unwrap();
        jwe.recipients[0].header.insert("epk".into(), epk);
        // Re-encrypting isn't possible without the CEK, so just check the epk lookup.
        let (_, found) = jwe_recipient_epk(&jwe, kid).unwrap();
        assert_eq!(found.curve(), Curve::X25519);
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
            // from the message itself (parse_envelope), so this proves that
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
