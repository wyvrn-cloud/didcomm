//! The settling proof of a Wyvrn account's second rotation (multi-device/1.0,
//! "Recovery keys, and settling a fork"): what lets a contact or a server that has
//! followed a rotation `P -> T` follow a second rotation of the same `P`, to `S`.
//!
//! DIDComm v2.1's DID Rotation has a party that followed `P -> T` ignore anything
//! later from `P`. A Wyvrn account whose `P -> T` was a thief's (a stolen trusted
//! device that removed the others) takes the account back with a recovery key or a
//! passkey, which no device keeps, and moves `P -> S`. That second rotation is taken
//! only with its proof: the `identity-settled` message's body, or the same four
//! fields as an `identity_settled` header beside the `from_prior` (for a request
//! whose body belongs to another protocol, such as a mediator's
//! `recipient-update`). This is an extra condition on top of the rotation's own
//! rules, never in place of them: the `from_prior` `P -> S` is verified as any other
//! ([`crate::rotation`]), and this checks that a recovery key of `P` approved it.
//!
//! [`verify_identity_settle`] checks, as the Wyvrn app does (its `settleNoticeHolds`):
//!
//! - `recovery_proof.purpose` is [`SETTLE_PURPOSE`];
//! - the key `recovery_proof.key` names is one of `recovery_keys`;
//! - `P`'s document lists the method `P#<recovery_proof.key>` in its
//!   `verificationMethod`, named by no verification relationship, with that key's
//!   `public_key` as its `publicKeyMultibase` ([`recovery_keys_listed_in`]);
//! - the signature is over [`settle_bytes`], the RFC 8785 (JCS) form of `{ purpose,
//!   rotation_seq, prior_did: P, identity_did: S, roster_digest, recovery_keys }`:
//!   Ed25519 for `kind: "recovery"`, and for `kind: "passkey"` a WebAuthn ES256
//!   assertion (`type` `webauthn.get`, challenge the SHA-256 of those bytes, RP ID
//!   hash the SHA-256 of `rp_id`, user present and user verified), its origin not
//!   checked, since it differs from one of the account's apps to another.

use didcomm_diddoc::VerificationMethod;
use didcomm_multiformats::{multibase, multicodec, multikey};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::crypto::{signature_key_type, SignatureKeyType, SigningService};

/// The `purpose` of a settling proof a contact or server can check: over the
/// roster's digest, not the roster, which only the account's devices are shown.
pub const SETTLE_PURPOSE: &str = "wyvrn-roster-settle/2";

/// The message that tells a contact of a settling change (its body is the settle).
pub const IDENTITY_SETTLED_TYPE: &str = "https://wyvrn.app/multi-device/1.0/identity-settled";

/// The header that carries the same fields beside a `from_prior`, on a message whose
/// body belongs to another protocol.
pub const IDENTITY_SETTLED_HEADER: &str = "identity_settled";

/// As many recovery keys as a list may hold (the Wyvrn app's `MAX_RECOVERY_KEYS`).
pub const MAX_RECOVERY_KEYS: usize = 10;

/// The verification relationships of DID Core 1.0, none of which may name a
/// recovery key's method.
const RELATIONSHIPS: [&str; 5] = [
    "authentication",
    "assertionMethod",
    "keyAgreement",
    "capabilityInvocation",
    "capabilityDelegation",
];

/// Why a settle was refused.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SettleError {
    /// A field is missing or not of the shape multi-device/1.0 gives it.
    #[error("malformed settle: {0}")]
    Malformed(&'static str),
    /// `recovery_proof.purpose` isn't [`SETTLE_PURPOSE`].
    #[error("the recovery proof is not a settling proof ({SETTLE_PURPOSE})")]
    WrongPurpose,
    /// `recovery_proof.key` names none of `recovery_keys`.
    #[error("the recovery proof's key is not among the recovery keys")]
    UnknownKey,
    /// The prior DID's document doesn't list `P#<key>`, under no relationship, with
    /// that public key.
    #[error("the prior DID's document doesn't list that recovery key")]
    NotListed,
    /// The signature (or the passkey's assertion) doesn't verify.
    #[error("the recovery proof doesn't verify")]
    InvalidProof,
}

/// A recovery key or passkey, as a roster change lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryKey {
    pub id: String,
    /// `"recovery"` (Ed25519) or `"passkey"` (WebAuthn, P-256).
    pub kind: String,
    /// Multikey: `z6Mk…` for a recovery key, `zDn…` for a passkey.
    pub public_key: String,
    /// A passkey's only.
    pub credential_id: Option<String>,
    /// A passkey's only.
    pub rp_id: Option<String>,
}

impl RecoveryKey {
    /// As the proof covers it: only the fields its kind has.
    fn to_value(&self) -> Value {
        let mut object = Map::new();
        object.insert("id".into(), json!(self.id));
        object.insert("kind".into(), json!(self.kind));
        object.insert("public_key".into(), json!(self.public_key));
        if let (Some(credential_id), Some(rp_id)) = (&self.credential_id, &self.rp_id) {
            object.insert("credential_id".into(), json!(credential_id));
            object.insert("rp_id".into(), json!(rp_id));
        }
        Value::Object(object)
    }
}

/// A roster change's `recovery_proof`. The byte strings are base64url.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryProof {
    pub key: String,
    pub purpose: String,
    pub signature: String,
    pub authenticator_data: Option<String>,
    pub client_data_json: Option<String>,
}

/// An `identity-settled` body, or an `identity_settled` header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentitySettle {
    pub rotation_seq: i64,
    pub roster_digest: String,
    pub recovery_keys: Vec<RecoveryKey>,
    pub recovery_proof: RecoveryProof,
}

/// A string of 1 to `max` UTF-16 code units (JavaScript's `length`, which is what
/// the app that makes these counts).
fn text(value: &Value, max: usize) -> Option<&str> {
    let s = value.as_str()?;
    let length = s.encode_utf16().count();
    (length > 0 && length <= max).then_some(s)
}

/// The largest integer JavaScript holds exactly (`Number.MAX_SAFE_INTEGER`).
const MAX_SAFE_INTEGER: i64 = (1 << 53) - 1;

impl IdentitySettle {
    /// Reads a settle, by shape only, as the Wyvrn app reads one
    /// (`recoveryKeysFrom`, `recoveryProofFrom`): a list of keys with anything wrong
    /// in it (too many, a duplicate id, an id that isn't a plain fragment, a passkey
    /// without its `credential_id` or `rp_id`) is no list.
    pub fn from_value(value: &Value) -> Result<Self, SettleError> {
        let rotation_seq = value["rotation_seq"]
            .as_i64()
            .filter(|seq| seq.abs() <= MAX_SAFE_INTEGER)
            .ok_or(SettleError::Malformed("rotation_seq"))?;
        let roster_digest = value["roster_digest"]
            .as_str()
            .filter(|digest| {
                digest.len() == 43
                    && digest
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            })
            .ok_or(SettleError::Malformed("roster_digest"))?
            .to_string();
        let recovery_keys = recovery_keys_from(&value["recovery_keys"])
            .ok_or(SettleError::Malformed("recovery_keys"))?;
        let proof = &value["recovery_proof"];
        let (Some(key), Some(purpose), Some(signature)) = (
            text(&proof["key"], 128),
            proof["purpose"].as_str(),
            text(&proof["signature"], 1024),
        ) else {
            return Err(SettleError::Malformed("recovery_proof"));
        };
        let recovery_proof = RecoveryProof {
            key: key.to_string(),
            purpose: purpose.to_string(),
            signature: signature.to_string(),
            authenticator_data: text(&proof["authenticator_data"], 2048).map(str::to_string),
            client_data_json: text(&proof["client_data_json"], 4096).map(str::to_string),
        };
        Ok(Self {
            rotation_seq,
            roster_digest,
            recovery_keys,
            recovery_proof,
        })
    }
}

/// Whether `id` is 1 to 128 of RFC 3986's unreserved characters: a DID URL fragment
/// as it stands.
fn is_plain_fragment(id: &str) -> bool {
    (1..=128).contains(&id.len())
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~'))
}

fn recovery_keys_from(value: &Value) -> Option<Vec<RecoveryKey>> {
    let entries = value.as_array()?;
    if entries.len() > MAX_RECOVERY_KEYS {
        return None;
    }
    let mut keys: Vec<RecoveryKey> = Vec::with_capacity(entries.len());
    for entry in entries {
        let id = text(&entry["id"], 128).filter(|id| is_plain_fragment(id))?;
        let kind = entry["kind"]
            .as_str()
            .filter(|kind| *kind == "recovery" || *kind == "passkey")?;
        let public_key = text(&entry["public_key"], 128)?;
        if keys.iter().any(|held| held.id == id) {
            return None;
        }
        let (credential_id, rp_id) = if kind == "passkey" {
            (
                Some(text(&entry["credential_id"], 1024)?.to_string()),
                Some(text(&entry["rp_id"], 253)?.to_string()),
            )
        } else {
            (None, None)
        };
        keys.push(RecoveryKey {
            id: id.to_string(),
            kind: kind.to_string(),
            public_key: public_key.to_string(),
            credential_id,
            rp_id,
        });
    }
    Some(keys)
}

/// RFC 8785 (JCS) for the values a settle is made of: strings, integers, arrays and
/// objects, keys sorted by their UTF-16 code units, strings escaped as ECMAScript's
/// `JSON.stringify` escapes them (which `serde_json` matches).
fn canonical(value: &Value, out: &mut String) {
    match value {
        Value::Object(object) => {
            let mut keys: Vec<&String> = object.keys().collect();
            keys.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
            out.push('{');
            for (index, key) in keys.into_iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                out.push_str(&Value::String(key.clone()).to_string());
                out.push(':');
                canonical(&object[key], out);
            }
            out.push('}');
        }
        Value::Array(items) => {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                canonical(item, out);
            }
            out.push(']');
        }
        other => out.push_str(&other.to_string()),
    }
}

/// What a settling proof is over: the JCS form of `{ purpose, rotation_seq,
/// prior_did, identity_did, roster_digest, recovery_keys }`, exactly as the Wyvrn
/// app's `settleBytes` makes it.
pub fn settle_bytes(
    rotation_seq: i64,
    prior_did: &str,
    identity_did: &str,
    roster_digest: &str,
    recovery_keys: &[RecoveryKey],
) -> Vec<u8> {
    let value = json!({
        "purpose": SETTLE_PURPOSE,
        "rotation_seq": rotation_seq,
        "prior_did": prior_did,
        "identity_did": identity_did,
        "roster_digest": roster_digest,
        "recovery_keys": recovery_keys.iter().map(RecoveryKey::to_value).collect::<Vec<_>>(),
    });
    let mut out = String::new();
    canonical(&value, &mut out);
    out.into_bytes()
}

/// The recovery keys a DID document lists (multi-device/1.0, "Recovery keys in the
/// document"): `(fragment, publicKeyMultibase)` of each `verificationMethod` entry
/// that no verification relationship names. The first method of a fragment counts.
pub fn recovery_keys_listed_in(document: &Value) -> Vec<(String, String)> {
    fn fragment(id: Option<&str>) -> &str {
        id.and_then(|id| id.split_once('#'))
            .map_or("", |(_, fragment)| fragment)
    }
    let mut named = std::collections::BTreeSet::new();
    for relationship in RELATIONSHIPS {
        for entry in document[relationship].as_array().into_iter().flatten() {
            named.insert(fragment(entry.as_str().or_else(|| entry["id"].as_str())).to_string());
        }
    }
    let mut listed: Vec<(String, String)> = Vec::new();
    for method in document["verificationMethod"]
        .as_array()
        .into_iter()
        .flatten()
    {
        let id = fragment(method["id"].as_str());
        let Some(public_key) = method["publicKeyMultibase"].as_str() else {
            continue;
        };
        if id.is_empty() || named.contains(id) || listed.iter().any(|(held, _)| held == id) {
            continue;
        }
        listed.push((id.to_string(), public_key.to_string()));
    }
    listed
}

/// Checks a settle of the move `prior_did` -> `identity_did`, given `prior_did`'s
/// resolved document (see the module's notes). `settle` is an `identity-settled`
/// body or an `identity_settled` header. The `from_prior` the move came with is the
/// caller's to verify, as any rotation.
pub async fn verify_identity_settle<S: SigningService>(
    crypto: &S,
    prior_did: &str,
    prior_document: &Value,
    identity_did: &str,
    settle: &Value,
) -> Result<IdentitySettle, SettleError> {
    let settle = IdentitySettle::from_value(settle)?;
    let proof = &settle.recovery_proof;
    if proof.purpose != SETTLE_PURPOSE {
        return Err(SettleError::WrongPurpose);
    }
    let key = settle
        .recovery_keys
        .iter()
        .find(|key| key.id == proof.key)
        .ok_or(SettleError::UnknownKey)?;
    let listed = recovery_keys_listed_in(prior_document);
    if !listed
        .iter()
        .any(|(id, public_key)| *id == key.id && *public_key == key.public_key)
    {
        return Err(SettleError::NotListed);
    }
    let bytes = settle_bytes(
        settle.rotation_seq,
        prior_did,
        identity_did,
        &settle.roster_digest,
        &settle.recovery_keys,
    );
    let verified = if key.kind == "recovery" {
        verifies_recovery_key(crypto, prior_did, key, proof, &bytes).await
    } else {
        verifies_passkey(crypto, prior_did, key, proof, &bytes).await
    };
    if verified {
        Ok(settle)
    } else {
        Err(SettleError::InvalidProof)
    }
}

/// The key as a verification method of `prior_did`, if it is a key of the type
/// `expected`.
fn method_of(
    prior_did: &str,
    key: &RecoveryKey,
    expected: SignatureKeyType,
) -> Option<VerificationMethod> {
    let codec = multikey::decode(&key.public_key).ok()?.0;
    let codec_expected = match expected {
        SignatureKeyType::Ed25519 => multicodec::ED25519_PUB,
        SignatureKeyType::P256 => multicodec::P256_PUB,
        SignatureKeyType::Secp256k1 => return None,
    };
    if codec != codec_expected {
        return None;
    }
    let method = VerificationMethod {
        id: format!("{prior_did}#{}", key.id),
        type_: "Multikey".to_string(),
        controller: prior_did.to_string(),
        public_key_multibase: Some(key.public_key.clone()),
        public_key_base58: None,
        public_key_jwk: None,
    };
    (signature_key_type(&method).ok()? == expected).then_some(method)
}

async fn verify_with<S: SigningService>(
    crypto: &S,
    method: &VerificationMethod,
    message: &[u8],
    signature: &[u8],
) -> bool {
    let Ok(key) = crypto.verification_method_to_verifying_key(method) else {
        return false;
    };
    crypto
        .verify(&key, message, signature)
        .await
        .unwrap_or(false)
}

async fn verifies_recovery_key<S: SigningService>(
    crypto: &S,
    prior_did: &str,
    key: &RecoveryKey,
    proof: &RecoveryProof,
    bytes: &[u8],
) -> bool {
    let (Some(method), Ok(signature)) = (
        method_of(prior_did, key, SignatureKeyType::Ed25519),
        multibase::decode(&proof.signature),
    ) else {
        return false;
    };
    signature.len() == 64 && verify_with(crypto, &method, bytes, &signature).await
}

/// WebAuthn's verification of an assertion (§7.2), but not its origin: `type`
/// `webauthn.get`, the challenge, the RP ID's hash, user present and verified, and
/// the ES256 signature over the authenticator data and the client data's hash.
async fn verifies_passkey<S: SigningService>(
    crypto: &S,
    prior_did: &str,
    key: &RecoveryKey,
    proof: &RecoveryProof,
    bytes: &[u8],
) -> bool {
    let (Some(rp_id), Some(authenticator_data), Some(client_data_json)) = (
        &key.rp_id,
        &proof.authenticator_data,
        &proof.client_data_json,
    ) else {
        return false;
    };
    let (Ok(authenticator_data), Ok(client_data_json), Ok(signature)) = (
        multibase::decode(authenticator_data),
        multibase::decode(client_data_json),
        multibase::decode(&proof.signature),
    ) else {
        return false;
    };
    if authenticator_data.len() < 37 {
        return false;
    }
    let Ok(client_data) = serde_json::from_slice::<Value>(&client_data_json) else {
        return false;
    };
    let challenge = multibase::encode(Sha256::digest(bytes));
    if client_data["type"] != "webauthn.get" || client_data["challenge"] != challenge.as_str() {
        return false;
    }
    if authenticator_data[..32] != Sha256::digest(rp_id.as_bytes())[..] {
        return false;
    }
    let flags = authenticator_data[32];
    if flags & 0x01 == 0 || flags & 0x04 == 0 {
        return false;
    }
    let (Some(method), Some(raw)) = (
        method_of(prior_did, key, SignatureKeyType::P256),
        der_to_raw(&signature),
    ) else {
        return false;
    };
    let mut signed = authenticator_data;
    signed.extend_from_slice(&Sha256::digest(&client_data_json));
    verify_with(crypto, &method, &signed, &low_s(raw)).await
}

/// An ECDSA signature in DER, as WebAuthn gives it, as the `r || s` ES256 checks.
fn der_to_raw(der: &[u8]) -> Option<[u8; 64]> {
    if der.len() < 2 || der[0] != 0x30 || usize::from(der[1]) != der.len() - 2 {
        return None;
    }
    let mut raw = [0u8; 64];
    let mut at = 2;
    for half in raw.chunks_mut(32) {
        if der.get(at) != Some(&0x02) {
            return None;
        }
        let length = usize::from(*der.get(at + 1)?);
        let value = der.get(at + 2..at + 2 + length)?;
        at += 2 + length;
        let start = value.iter().position(|&b| b != 0).unwrap_or(value.len());
        let trimmed = &value[start..];
        if length == 0 || trimmed.len() > 32 {
            return None;
        }
        half[32 - trimmed.len()..].copy_from_slice(trimmed);
    }
    (at == der.len()).then_some(raw)
}

/// P-256's group order.
const P256_N: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
];

/// `(r, s)` with `s` in the lower half of the order, as some verifiers insist on: an
/// authenticator may give either, and `(r, n - s)` is as valid as `(r, s)`. WebAuthn
/// (and WebCrypto, which the app checks with) takes both.
fn low_s(mut raw: [u8; 64]) -> [u8; 64] {
    let s: [u8; 32] = raw[32..].try_into().expect("32 bytes");
    // n / 2, rounded down.
    let mut half = [0u8; 32];
    let mut carry = 0u8;
    for (i, byte) in P256_N.iter().enumerate() {
        half[i] = (carry << 7) | (byte >> 1);
        carry = byte & 1;
    }
    if s > half && s < P256_N {
        let mut borrow = 0i16;
        for i in (0..32).rev() {
            let mut digit = i16::from(P256_N[i]) - i16::from(s[i]) - borrow;
            borrow = i16::from(digit < 0);
            if digit < 0 {
                digit += 256;
            }
            raw[32 + i] = digit as u8;
        }
    }
    raw
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_json_sorts_keys_by_utf16_and_escapes_as_json_stringify() {
        let mut out = String::new();
        canonical(
            &json!({"b": [1, {"z": "\u{1f}\"\\é", "a": -3}], "a": "x", "\u{e9}": 1, "\u{1f600}": 2}),
            &mut out,
        );
        // By UTF-16 code units: U+00E9 (00E9) before U+1F600 (D83D DE00).
        assert_eq!(
            out,
            "{\"a\":\"x\",\"b\":[1,{\"a\":-3,\"z\":\"\\u001f\\\"\\\\é\"}],\"é\":1,\"😀\":2}"
        );
    }

    #[test]
    fn der_signatures_are_read_strictly() {
        let mut der = vec![0x30, 0x44, 0x02, 0x20];
        der.extend([0x11; 32]);
        der.extend([0x02, 0x20]);
        der.extend([0x22; 32]);
        let raw = der_to_raw(&der).unwrap();
        assert_eq!(&raw[..32], &[0x11; 32]);
        assert_eq!(&raw[32..], &[0x22; 32]);
        let mut trailing = der.clone();
        trailing.push(0);
        assert!(der_to_raw(&trailing).is_none());
        assert!(der_to_raw(&der[..der.len() - 1]).is_none());
    }

    #[test]
    fn a_high_s_is_brought_low_and_a_low_one_left() {
        let mut raw = [0u8; 64];
        raw[63] = 5;
        assert_eq!(low_s(raw), raw);
        let mut high = [0u8; 64];
        high[32..].copy_from_slice(&P256_N);
        high[63] -= 5;
        let low = low_s(high);
        assert_eq!(&low[32..63], &[0u8; 31]);
        assert_eq!(low[63], 5);
    }

    #[test]
    fn a_list_with_anything_wrong_in_it_is_no_list() {
        let good = json!({"id": "recovery-1", "kind": "recovery", "public_key": "z6Mk"});
        assert!(recovery_keys_from(&json!([good])).is_some());
        assert!(
            recovery_keys_from(&json!([good, good])).is_none(),
            "a duplicate id"
        );
        assert!(recovery_keys_from(
            &json!([{"id": "a b", "kind": "recovery", "public_key": "z6Mk"}])
        )
        .is_none());
        assert!(
            recovery_keys_from(&json!([{"id": "p", "kind": "passkey", "public_key": "zDn"}]))
                .is_none()
        );
        assert!(
            recovery_keys_from(&json!([{"id": "x", "kind": "other", "public_key": "z6Mk"}]))
                .is_none()
        );
        assert!(recovery_keys_from(&Value::Array(vec![good.clone(); 11])).is_none());
        // A recovery key's passkey fields are no part of it.
        let extra = json!([{"id": "r", "kind": "recovery", "public_key": "z6Mk", "rp_id": "x", "credential_id": "y", "more": 1}]);
        let keys = recovery_keys_from(&extra).unwrap();
        assert_eq!(
            keys[0].to_value(),
            json!({"id": "r", "kind": "recovery", "public_key": "z6Mk"})
        );
    }

    #[test]
    fn only_methods_no_relationship_names_are_recovery_keys() {
        let document = json!({
            "id": "did:example:p",
            "verificationMethod": [
                {"id": "#key-1", "publicKeyMultibase": "z6MkAuth"},
                {"id": "did:example:p#key-2", "publicKeyMultibase": "z6LSka"},
                {"id": "#recovery-1", "publicKeyMultibase": "z6MkRec"},
                {"id": "#recovery-1", "publicKeyMultibase": "z6MkSecond"},
                {"id": "#cred-1", "publicKeyMultibase": "z6MkCred"},
            ],
            "authentication": ["#key-1"],
            "keyAgreement": ["did:example:p#key-2"],
            "assertionMethod": [{"id": "#cred-1"}],
        });
        assert_eq!(
            recovery_keys_listed_in(&document),
            vec![("recovery-1".to_string(), "z6MkRec".to_string())]
        );
    }
}
