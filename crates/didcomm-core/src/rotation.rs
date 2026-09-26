//! `from_prior` DID rotation, per
//! [DIDComm Messaging v2.1](https://identity.foundation/didcomm-messaging/spec/v2.1/)'s
//! "DID Rotation" section: a JWT (`sub`: new DID, `iss`: prior DID, `iat`), signed by
//! a key the prior DID's own document authorizes (its `EdDSA`/`authentication` key --
//! see `didcomm-core::crypto::SigningService`), carried as a plaintext message header
//! named `from_prior`. Not an envelope-level concern -- `messaging.rs` just threads
//! the resulting string through as one more plaintext header, same as `thid`.
//!
//! Deliberately platform-agnostic about wall-clock time: `build_from_prior` takes
//! `iat` as a parameter rather than reading it itself, since `std::time::SystemTime`
//! has no working implementation on `wasm32-unknown-unknown` (the target
//! `didcomm-wasm` actually ships) -- the caller (a browser via `Date.now()`, or a
//! native caller via `SystemTime`) is always in a better position to supply it than
//! this crate would be.

use didcomm_multiformats::multibase;
use serde::{Deserialize, Serialize};

use crate::crypto::{CryptoServiceError, SigningKey, SigningService};
use crate::resolver::{DIDResolver, ResolutionError};

/// Errors building or verifying a `from_prior` rotation.
#[derive(Debug, thiserror::Error)]
pub enum RotationError {
    #[error(transparent)]
    Crypto(#[from] CryptoServiceError),
    #[error(transparent)]
    Resolution(#[from] ResolutionError),
    #[error("malformed from_prior JWT: {0}")]
    Malformed(String),
    #[error("from_prior signature verification failed")]
    InvalidSignature,
}

#[derive(Serialize, Deserialize)]
struct FromPriorHeader {
    typ: String,
    alg: String,
    crv: String,
    kid: String,
}

#[derive(Serialize, Deserialize)]
struct FromPriorPayload {
    sub: String,
    iss: String,
    iat: i64,
}

/// Build a `from_prior` JWT: `sub` the new DID, `iss` the prior one, signed by
/// `signing_key` (a key the prior DID's own document lists as `authentication` --
/// see [`crate::crypto::SigningService::verification_method_to_verifying_key`] for
/// the corresponding lookup on the verifying side). `iat` is Unix seconds -- per
/// spec, the datetime of the rotation itself, not of whatever message this header
/// ends up attached to.
pub async fn build_from_prior<S: SigningService>(
    crypto: &S,
    prior_did: &str,
    new_did: &str,
    signing_key: &S::SigningKey,
    iat: i64,
) -> Result<String, RotationError> {
    let header = FromPriorHeader {
        typ: "JWT".to_string(),
        alg: "EdDSA".to_string(),
        crv: "ED25519".to_string(),
        kid: signing_key.kid().to_string(),
    };
    let payload = FromPriorPayload {
        sub: new_did.to_string(),
        iss: prior_did.to_string(),
        iat,
    };
    let header_b64 = multibase::encode(serde_json::to_vec(&header).map_err(|e| {
        RotationError::Malformed(format!("failed to serialize from_prior header: {e}"))
    })?);
    let payload_b64 = multibase::encode(serde_json::to_vec(&payload).map_err(|e| {
        RotationError::Malformed(format!("failed to serialize from_prior payload: {e}"))
    })?);
    let signing_input = format!("{header_b64}.{payload_b64}");
    let signature = crypto.sign(signing_key, signing_input.as_bytes()).await?;
    let signature_b64 = multibase::encode(signature);
    Ok(format!("{signing_input}.{signature_b64}"))
}

/// Verify a `from_prior` JWT, resolving its `kid` via `resolver` to find the
/// verification method the signature must check out against -- the spec's own
/// requirement that the signing key be "authorized in the DID Document of the prior
/// DID (`iss`)", enforced here by resolving `iss` fresh rather than trusting `kid`
/// alone (a `kid` for a different, unrelated DID would be a forged rotation, not a
/// legitimate one). Returns `(prior_did, new_did)` from the payload's `(iss, sub)` on
/// success; `Ok`, never a signature-related `Err`, is reserved for "this JWT is
/// exactly what it claims to be" -- a genuinely malformed JWT (wrong shape, unparsable
/// segments) is still an `Err`, since that's not a trust decision, just invalid input.
pub async fn verify_from_prior<S: SigningService>(
    crypto: &S,
    resolver: &dyn DIDResolver,
    jwt: &str,
) -> Result<(String, String), RotationError> {
    let mut parts = jwt.splitn(3, '.');
    let (header_b64, payload_b64, signature_b64) =
        match (parts.next(), parts.next(), parts.next()) {
            (Some(h), Some(p), Some(s)) if parts.next().is_none() => (h, p, s),
            _ => {
                return Err(RotationError::Malformed(
                    "expected exactly 3 dot-separated segments".to_string(),
                ))
            }
        };

    let header: FromPriorHeader = serde_json::from_slice(
        &multibase::decode(header_b64).map_err(|e| RotationError::Malformed(e.to_string()))?,
    )
    .map_err(|e| RotationError::Malformed(format!("invalid from_prior header: {e}")))?;
    if header.alg != "EdDSA" {
        return Err(RotationError::Malformed(format!(
            "unsupported from_prior alg: {}",
            header.alg
        )));
    }

    let payload: FromPriorPayload = serde_json::from_slice(
        &multibase::decode(payload_b64).map_err(|e| RotationError::Malformed(e.to_string()))?,
    )
    .map_err(|e| RotationError::Malformed(format!("invalid from_prior payload: {e}")))?;

    // The kid a forged JWT names has to actually belong to the DID it claims (`iss`)
    // -- resolving iss and dereferencing kid *within that document* is what enforces
    // that, rather than resolving kid's own bare DID (which, for a forged JWT, could
    // be an entirely different, attacker-controlled one).
    let kid_did = header
        .kid
        .split_once('#')
        .map(|(did, _)| did)
        .unwrap_or(&header.kid);
    if kid_did != payload.iss {
        return Err(RotationError::Malformed(
            "from_prior kid does not belong to the claimed iss".to_string(),
        ));
    }

    let signature = multibase::decode(signature_b64)
        .map_err(|e| RotationError::Malformed(e.to_string()))?;

    let vm = resolver
        .resolve_and_dereference_verification_method(&header.kid)
        .await?;
    let verifying_key = crypto.verification_method_to_verifying_key(&vm)?;

    let signing_input = format!("{header_b64}.{payload_b64}");
    let valid = crypto
        .verify(&verifying_key, signing_input.as_bytes(), &signature)
        .await?;
    if !valid {
        return Err(RotationError::InvalidSignature);
    }

    Ok((payload.iss, payload.sub))
}

// Tested in tests/rotation.rs, not here: exercising this against a real
// SigningService/DIDResolver (AskarCryptoService, Peer4) needs those crates as a
// dependency, and they in turn depend on didcomm-core -- fine for a true integration
// test (a separate binary linking this crate normally), but a #[cfg(test)] unit test
// module *inside* this crate would instead hit Cargo's classic "multiple different
// versions of crate didcomm_core" duplicate when the very same trait needs to unify
// across that self-referential dev-dependency edge.
