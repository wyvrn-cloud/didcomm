//! DIDComm signed messages: `application/didcomm-signed+json` (a general-form JWS) or,
//! for the `didcomm/v2+cbor` profile, `application/didcomm-signed+cbor` (a tagged
//! `COSE_Sign1`, per #463). Both sign an already-encoded plaintext (see
//! [`crate::plaintext`]) with an `EdDSA` key from the signer's `authentication`
//! relationship, through the same [`SigningService`] `from_prior` rotation uses.
//!
//! The spec's recommended combination is `anoncrypt(sign(plaintext))` -- see
//! `DIDCommMessaging::pack_signed`/`unpack_verified`.

use didcomm_diddoc::VerificationRelationshipEntry;
use didcomm_multiformats::multibase;
use serde_json::{json, Value};

use crate::cose::{self, label, Alg, CoseError, CoseKind, CoseSign1, HeaderMap};
use crate::crypto::{CryptoServiceError, Encoding, SigningKey, SigningService};
use crate::resolver::{DIDResolver, ResolutionError};

pub const SIGNED_JSON_TYP: &str = "application/didcomm-signed+json";
pub const SIGNED_CBOR_TYP: &str = "application/didcomm-signed+cbor";

/// Errors signing or verifying a signed message.
#[derive(Debug, thiserror::Error)]
pub enum SignedError {
    #[error(transparent)]
    Crypto(#[from] CryptoServiceError),
    #[error(transparent)]
    Resolution(#[from] ResolutionError),
    #[error(transparent)]
    Cose(#[from] CoseError),
    #[error("invalid JWS: {0}")]
    Json(#[from] serde_json::Error),
    #[error("malformed signed message: {0}")]
    Malformed(&'static str),
    #[error("unsupported signature algorithm: {0}")]
    UnsupportedAlg(String),
    #[error("signature verification failed")]
    InvalidSignature,
    #[error("{0} is not an authentication key of its DID")]
    NotAuthentication(String),
}

/// Whether `message` is a signed message (a JWS or a COSE_Sign1), as opposed to a
/// plaintext or an encrypted envelope.
pub fn is_signed(message: &[u8]) -> bool {
    match Encoding::detect(message) {
        Ok(Encoding::Json) => serde_json::from_slice::<Value>(message)
            // General form (`signatures`) or flattened (`protected` + `signature`).
            .map(|v| v.get("payload").is_some() && (v.get("signatures").is_some() || v.get("signature").is_some()))
            .unwrap_or(false),
        Ok(Encoding::Cbor) => matches!(cose::classify(message), Ok(CoseKind::Sign1)),
        Err(_) => false,
    }
}

/// Sign an encoded `plaintext`, producing a signed message in `encoding` (which
/// should match the plaintext's own).
pub async fn sign<S: SigningService>(
    crypto: &S,
    key: &S::SigningKey,
    plaintext: &[u8],
    encoding: Encoding,
) -> Result<Vec<u8>, SignedError> {
    let kid = key.kid();
    match encoding {
        Encoding::Json => {
            let protected = multibase::encode(serde_json::to_vec(&json!({
                "typ": SIGNED_JSON_TYP,
                "alg": "EdDSA",
                "kid": kid,
            }))?);
            let payload = multibase::encode(plaintext);
            let signature = crypto.sign(key, format!("{protected}.{payload}").as_bytes()).await?;
            Ok(serde_json::to_vec(&json!({
                "payload": payload,
                "signatures": [{
                    "protected": protected,
                    "signature": multibase::encode(signature),
                    "header": {"kid": kid},
                }],
            }))?)
        }
        Encoding::Cbor => {
            let mut protected = HeaderMap::default();
            protected.insert(label::ALG, Alg::EdDsa.to_cbor());
            protected.insert(label::TYP, ciborium::Value::Text(SIGNED_CBOR_TYP.into()));
            protected.insert(label::KID, ciborium::Value::Bytes(kid.as_bytes().to_vec()));
            let protected_bytes = protected.to_protected_bytes()?;
            let signature = crypto.sign(key, &cose::sig_structure1(&protected_bytes, plaintext)).await?;
            Ok(CoseSign1 {
                protected_bytes,
                protected,
                unprotected: HeaderMap::default(),
                payload: plaintext.to_vec(),
                signature,
            }
            .to_cbor()?)
        }
    }
}

/// A verified signed message: its (still-encoded) plaintext payload and the kid of
/// the key that signed it.
#[derive(Debug, Clone)]
pub struct Verified {
    pub payload: Vec<u8>,
    pub signer_kid: String,
}

/// Verify a signed message of either encoding, resolving the signer's key from its
/// `kid` through `resolver`.
pub async fn verify<S: SigningService>(
    crypto: &S,
    resolver: &dyn DIDResolver,
    message: &[u8],
) -> Result<Verified, SignedError> {
    let detected = Encoding::detect(message).map_err(|_| SignedError::Malformed("unrecognized encoding"))?;
    let (kid, signing_input, signature, payload) = match detected {
        Encoding::Json => {
            let jws: Value = serde_json::from_slice(message)?;
            let payload_b64 = jws["payload"].as_str().ok_or(SignedError::Malformed("missing payload"))?;
            // General form; a flattened JWS has its one signature at the top level.
            let sig = match jws["signatures"].as_array() {
                Some(sigs) if sigs.len() == 1 => &sigs[0],
                Some(_) => return Err(SignedError::Malformed("exactly one signature is supported")),
                None => &jws,
            };
            let protected_b64 = sig["protected"].as_str().ok_or(SignedError::Malformed("missing protected"))?;
            let protected: Value = serde_json::from_slice(
                &multibase::decode(protected_b64).map_err(|_| SignedError::Malformed("protected is not base64url"))?,
            )?;
            if protected["alg"] != "EdDSA" {
                return Err(SignedError::UnsupportedAlg(protected["alg"].to_string()));
            }
            let kid = protected["kid"]
                .as_str()
                .or_else(|| sig["header"]["kid"].as_str())
                .ok_or(SignedError::Malformed("missing kid"))?
                .to_string();
            let signature = multibase::decode(sig["signature"].as_str().ok_or(SignedError::Malformed("missing signature"))?)
                .map_err(|_| SignedError::Malformed("signature is not base64url"))?;
            let payload = multibase::decode(payload_b64).map_err(|_| SignedError::Malformed("payload is not base64url"))?;
            (kid, format!("{protected_b64}.{payload_b64}").into_bytes(), signature, payload)
        }
        Encoding::Cbor => {
            let sign1 = CoseSign1::from_cbor(message)?;
            match sign1.protected.alg() {
                Some(Alg::EdDsa) => {}
                other => return Err(SignedError::UnsupportedAlg(format!("{other:?}"))),
            }
            let kid = sign1
                .protected
                .kid_str(label::KID)
                .or_else(|| sign1.unprotected.kid_str(label::KID))
                .ok_or(SignedError::Malformed("missing kid"))?;
            let input = cose::sig_structure1(&sign1.protected_bytes, &sign1.payload);
            (kid, input, sign1.signature, sign1.payload)
        }
    };

    // A DIDComm signature must come from the signer's `authentication` relationship,
    // not just any key its document lists.
    let doc = resolver.resolve_and_parse(kid.split('#').next().unwrap_or(&kid)).await?;
    let absolute = |id: &str| if id.starts_with('#') { format!("{}{id}", doc.id) } else { id.to_string() };
    let authorized = doc.authentication.iter().any(|entry| match entry {
        VerificationRelationshipEntry::Reference(id) => absolute(id) == kid,
        VerificationRelationshipEntry::Embedded(vm) => absolute(&vm.id) == kid,
    });
    if !authorized {
        return Err(SignedError::NotAuthentication(kid));
    }
    let vm = doc
        .dereference_verification_method(&kid)
        .ok_or_else(|| SignedError::NotAuthentication(kid.clone()))?;
    let key = crypto.verification_method_to_verifying_key(&vm)?;
    if !crypto.verify(&key, &signing_input, &signature).await? {
        return Err(SignedError::InvalidSignature);
    }
    Ok(Verified { payload, signer_kid: kid })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_general_and_flattened_jws_but_not_plaintext_or_jwe() {
        assert!(is_signed(br#"{"payload":"e30","signatures":[{"protected":"e30","signature":"AA"}]}"#));
        assert!(is_signed(br#"{"payload":"e30","protected":"e30","signature":"AA"}"#));
        assert!(!is_signed(br#"{"id":"1","type":"x","body":{}}"#));
        assert!(!is_signed(br#"{"protected":"e30","ciphertext":"AA","recipients":[]}"#));
    }
}
