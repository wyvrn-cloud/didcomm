//! DIDComm v1 ("legacy" Aries pack format, RFC 0019), mirroring
//! `didcomm_messaging.legacy.crypto` and the v1 crypto backends built on it
//! (`v1/crypto/nacl.py` in particular, which is what this crate's algorithm follows --
//! see its `pack_message`/`unpack_message` for the exact reference).
//!
//! DIDComm v1 identifies keys by their own kid scheme -- a bare base58-encoded Ed25519
//! public key ("verkey"), not a DID URL like v2 uses -- and always works in terms of
//! Ed25519 signing keys, converted to X25519 internally for the actual key agreement
//! (`Ed25519KeyPair::to_x25519_keypair`, matching NaCl's
//! `crypto_sign_ed25519_{pk,sk}_to_curve25519`). Encryption is NaCl's `crypto_box`
//! (X25519 + XSalsa20-Poly1305) for wrapping a per-message content-encryption key, and
//! (despite the "xchacha20poly1305_ietf" label the protected header actually uses --
//! reproduced here for wire compatibility, not "corrected") plain
//! ChaCha20-Poly1305-IETF (12-byte nonce, not XChaCha's 24-byte one) for the payload.
//!
//! `askar-crypto` already implements every primitive this needs -- the Ed25519/X25519
//! conversion, `crypto_box`/`crypto_box_seal` (byte-compatible with libsodium, which is
//! what PyNaCl itself wraps), and `C20P` (plain ChaCha20-Poly1305) -- so, like v2, this
//! crate needs no additional crypto dependency beyond it.

use askar_crypto::{
    alg::{
        chacha20::{Chacha20Key, C20P},
        ed25519::Ed25519KeyPair,
    },
    encrypt::{crypto_box, KeyAeadInPlace},
    random::fill_random,
    repr::{KeyGen, KeyPublicBytes, KeySecretBytes},
};
use didcomm_core::jwe::{encode_protected_v1, JweEnvelope, JweError, JweRecipient};
use didcomm_multiformats::multibase;
use serde_json::{Map, Value};

pub mod packaging;

/// The nonce length NaCl's `crypto_box` (as opposed to the sealed-box variant) uses --
/// `askar_crypto::encrypt::crypto_box::CBOX_NONCE_LENGTH` isn't exported, so this
/// mirrors it directly (it's a stable constant of the XSalsa20-Poly1305 construction,
/// not something that varies).
const CBOX_NONCE_LENGTH: usize = 24;
/// The nonce length for the payload's ChaCha20-Poly1305-IETF AEAD (12 bytes) -- half of
/// `CBOX_NONCE_LENGTH`, and easy to confuse with it, hence naming both explicitly.
const PAYLOAD_NONCE_LENGTH: usize = 12;

/// Errors from DIDComm v1 pack/unpack.
#[derive(Debug, thiserror::Error)]
pub enum V1Error {
    #[error(transparent)]
    Jwe(#[from] JweError),
    #[error(transparent)]
    Askar(#[from] askar_crypto::Error),
    #[error(transparent)]
    Multibase(#[from] multibase::DecodeError),
    #[error("unsupported DIDComm v1 pack algorithm: {0}")]
    UnsupportedAlg(String),
    #[error("recipient is missing its encrypted_key")]
    MissingEncryptedKey,
    #[error("sender public key not provided for Authcrypt message")]
    MissingSenderKey,
    #[error("no message recipients")]
    NoRecipients,
    #[error("invalid sender verkey: {0}")]
    InvalidSenderVerkey(String),
    #[error("no recognized recipient key")]
    NoRecognizedRecipient,
}

/// The DIDComm v1 kid for a verkey: a bare base58-encoded Ed25519 public key, no
/// multicodec prefix (unlike v2's multikey-encoded verification methods).
pub fn kid_for_verkey(verkey: &Ed25519KeyPair) -> String {
    multibase::encode_base58btc(verkey.with_public_bytes(<[u8]>::to_vec))
}

/// Pack a message for one or more recipients, optionally authenticated by a sender.
/// Mirrors `NaclV1CryptoService.pack_message` (via `legacy.crypto.pack_message`'s
/// algorithm).
pub fn pack_message(
    to_verkeys: &[Ed25519KeyPair],
    from_key: Option<&Ed25519KeyPair>,
    message: &[u8],
) -> Result<String, V1Error> {
    if to_verkeys.is_empty() {
        return Err(V1Error::NoRecipients);
    }

    let cek = Chacha20Key::<C20P>::random()?;
    let cek_bytes = cek
        .with_secret_bytes(|b| b.map(<[u8]>::to_vec))
        .expect("a freshly generated key always has secret bytes");

    let sender_xkey = from_key.map(Ed25519KeyPair::to_x25519_keypair);
    let sender_vk_b58 = from_key.map(kid_for_verkey);

    let mut recipients = Vec::with_capacity(to_verkeys.len());
    for target_vk in to_verkeys {
        let target_xk = target_vk.to_x25519_keypair();
        let mut header = Map::new();
        header.insert("kid".into(), Value::String(kid_for_verkey(target_vk)));

        let encrypted_key = if let (Some(sender_xkey), Some(sender_vk_b58)) =
            (&sender_xkey, &sender_vk_b58)
        {
            let enc_sender = crypto_box::crypto_box_seal(&target_xk, sender_vk_b58.as_bytes())?;
            let mut nonce = [0u8; CBOX_NONCE_LENGTH];
            fill_random(&mut nonce);
            let mut enc_cek = cek_bytes.clone();
            crypto_box::crypto_box(&target_xk, sender_xkey, &mut enc_cek, &nonce)?;

            header.insert("sender".into(), Value::String(multibase::encode(enc_sender.as_ref())));
            header.insert("iv".into(), Value::String(multibase::encode(nonce)));
            enc_cek
        } else {
            crypto_box::crypto_box_seal(&target_xk, &cek_bytes)?.to_vec()
        };

        recipients.push(JweRecipient {
            encrypted_key,
            header,
        });
    }

    let mut protected = Map::new();
    // "xchacha20poly1305_ietf" here, despite the payload actually using plain
    // ChaCha20-Poly1305-IETF below -- see this module's doc comment.
    protected.insert("enc".into(), Value::String("xchacha20poly1305_ietf".into()));
    protected.insert("typ".into(), Value::String("JWM/1.0".into()));
    protected.insert(
        "alg".into(),
        Value::String(if from_key.is_some() { "Authcrypt" } else { "Anoncrypt" }.into()),
    );
    let protected_b64 = encode_protected_v1(&protected, &recipients)?;

    let mut nonce = [0u8; PAYLOAD_NONCE_LENGTH];
    fill_random(&mut nonce);
    let mut payload = message.to_vec();
    cek.encrypt_in_place(&mut payload, &nonce, protected_b64.as_bytes())?;
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
    Ok(envelope.to_json_v1()?)
}

/// Unpack a message, returning the plaintext and the sender's verkey (as a base58
/// string), if the message was authenticated. Mirrors
/// `NaclV1CryptoService.unpack_message` (via `_extract_payload_key`).
pub fn unpack_message(
    jwe: &JweEnvelope,
    recipient_kid: &str,
    recipient_key: &Ed25519KeyPair,
) -> Result<(Vec<u8>, Option<String>), V1Error> {
    let alg = jwe
        .protected
        .get("alg")
        .and_then(|v| v.as_str())
        .unwrap_or("<missing>");
    let is_authcrypt = alg == "Authcrypt";
    if !is_authcrypt && alg != "Anoncrypt" {
        return Err(V1Error::UnsupportedAlg(alg.to_string()));
    }

    let recipient = jwe.get_recipient(recipient_kid)?;
    let recip_xkey = recipient_key.to_x25519_keypair();

    let sender_header = recipient
        .header
        .get("sender")
        .and_then(Value::as_str)
        .zip(recipient.header.get("iv").and_then(Value::as_str));

    let (cek_bytes, sender_vk) = if let Some((enc_sender_b64, nonce_b64)) = sender_header {
        let enc_sender = multibase::decode(enc_sender_b64)?;
        let nonce = multibase::decode(nonce_b64)?;

        let sender_vk_bytes = crypto_box::crypto_box_seal_open(&recip_xkey, &enc_sender)?;
        let sender_vk_b58 = String::from_utf8(sender_vk_bytes.to_vec())
            .map_err(|e| V1Error::InvalidSenderVerkey(e.to_string()))?;
        let sender_verkey_bytes = multibase::decode_base58btc(&sender_vk_b58)
            .map_err(|e| V1Error::InvalidSenderVerkey(e.to_string()))?;
        let sender_ed_pub = Ed25519KeyPair::from_public_bytes(&sender_verkey_bytes)?;
        let sender_xk_pub = sender_ed_pub.to_x25519_keypair();

        let encrypted_key = recipient.encrypted_key.clone();
        if encrypted_key.is_empty() {
            return Err(V1Error::MissingEncryptedKey);
        }
        let mut cek_buf = encrypted_key;
        crypto_box::crypto_box_open(&recip_xkey, &sender_xk_pub, &mut cek_buf, &nonce)?;
        (cek_buf, Some(sender_vk_b58))
    } else {
        let cek = crypto_box::crypto_box_seal_open(&recip_xkey, &recipient.encrypted_key)?;
        (cek.to_vec(), None)
    };

    if sender_vk.is_none() && is_authcrypt {
        return Err(V1Error::MissingSenderKey);
    }

    let cek = Chacha20Key::<C20P>::from_secret_bytes(&cek_bytes)?;
    let mut payload = jwe.ciphertext.clone();
    payload.extend_from_slice(&jwe.tag);
    let aad = jwe.combined_aad();
    cek.decrypt_in_place(&mut payload, &jwe.iv, &aad)?;

    Ok((payload, sender_vk))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_anoncrypt_through_our_own_unpack() {
        let recipient = Ed25519KeyPair::random().unwrap();
        let kid = kid_for_verkey(&recipient);

        let packed = pack_message(&[recipient.clone()], None, b"Hello world!").unwrap();
        let jwe = JweEnvelope::from_json_v1(packed).unwrap();
        let (plaintext, sender_vk) = unpack_message(&jwe, &kid, &recipient).unwrap();

        assert_eq!(plaintext, b"Hello world!");
        assert_eq!(sender_vk, None);
    }

    #[test]
    fn round_trips_authcrypt_through_our_own_unpack() {
        let sender = Ed25519KeyPair::random().unwrap();
        let sender_kid = kid_for_verkey(&sender);
        let recipient = Ed25519KeyPair::random().unwrap();
        let recipient_kid = kid_for_verkey(&recipient);

        let packed =
            pack_message(&[recipient.clone()], Some(&sender), b"Hello world!").unwrap();
        let jwe = JweEnvelope::from_json_v1(packed).unwrap();
        let (plaintext, sender_vk) = unpack_message(&jwe, &recipient_kid, &recipient).unwrap();

        assert_eq!(plaintext, b"Hello world!");
        assert_eq!(sender_vk.as_deref(), Some(sender_kid.as_str()));
    }
}
