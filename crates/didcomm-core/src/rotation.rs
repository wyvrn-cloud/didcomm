//! `from_prior` DID rotation, per
//! [DIDComm Messaging v2.1](https://identity.foundation/didcomm-messaging/spec/v2.1/)'s
//! "DID Rotation" section: a JWT (`sub`: new DID, or none to end the relationship;
//! `iss`: prior DID; `iat`), signed by a key the prior DID's own document authorizes
//! (an `authentication` key: EdDSA, ES256 or ES256K by its type -- see
//! `didcomm-core::crypto::SigningService`), carried as a plaintext message header
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
    /// From [`verify_from_prior`] only: a valid `from_prior` with no `sub`, which
    /// ends the relationship with `prior_did` rather than moving it (DIDComm v2.1,
    /// DID Rotation, "Ending a Relationship"). [`verify_rotation`] returns it as
    /// [`FromPrior::new_did`] `None` instead.
    #[error("from_prior ends the relationship with {prior_did}: it names no new DID")]
    EndsRelationship { prior_did: String },
}

/// The JOSE header. `typ` and `crv` are optional, and checked only when present:
/// DIDComm's header is an example "with appropriate values changed", RFC 7519 makes
/// `typ` optional, and JWS (RFC 7515) has no `crv` at all -- a standard JWT library
/// writes `{alg, kid}`. What is always checked is that `alg` is the algorithm of the
/// key `kid` names.
#[derive(Serialize, Deserialize)]
struct FromPriorHeader {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    typ: Option<String>,
    alg: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    crv: Option<String>,
    kid: String,
}

#[derive(Serialize, Deserialize)]
struct FromPriorPayload {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    sub: Option<String>,
    iss: String,
    iat: i64,
}

/// A verified `from_prior`: [`verify_rotation`]'s answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FromPrior {
    /// `iss`: the DID being rotated away from.
    pub prior_did: String,
    /// `sub`: the DID rotated to, or `None` when the JWT omits it -- the sender
    /// ends the relationship with `prior_did` (DIDComm v2.1, DID Rotation, "Ending a
    /// Relationship"), and the recipient should end or forget it.
    pub new_did: Option<String>,
    /// `iat`: when the rotation was made, Unix seconds.
    pub iat: i64,
}

/// The algorithms a `from_prior` may be signed with: those of the key types this
/// library reads (see [`crate::crypto::SignatureKeyType`]).
const ALGS: [&str; 3] = ["EdDSA", "ES256", "ES256K"];

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
    sign_from_prior(crypto, prior_did, Some(new_did), signing_key, iat).await
}

/// Build a `from_prior` with no `sub`, which ends the relationship with `prior_did`
/// (DIDComm v2.1, DID Rotation, "Ending a Relationship"). The message carrying it is
/// to be sent without a `from`.
pub async fn build_ending_from_prior<S: SigningService>(
    crypto: &S,
    prior_did: &str,
    signing_key: &S::SigningKey,
    iat: i64,
) -> Result<String, RotationError> {
    sign_from_prior(crypto, prior_did, None, signing_key, iat).await
}

/// The header is the spec's example (`typ` JWT, `alg` EdDSA, `crv` ED25519): every
/// signing key this library holds is Ed25519.
async fn sign_from_prior<S: SigningService>(
    crypto: &S,
    prior_did: &str,
    new_did: Option<&str>,
    signing_key: &S::SigningKey,
    iat: i64,
) -> Result<String, RotationError> {
    let header = FromPriorHeader {
        typ: Some("JWT".to_string()),
        alg: "EdDSA".to_string(),
        crv: Some("ED25519".to_string()),
        kid: signing_key.kid().to_string(),
    };
    let payload = FromPriorPayload {
        sub: new_did.map(str::to_string),
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
///
/// A valid JWT without `sub` (ending the relationship) is
/// [`RotationError::EndsRelationship`] here, since there is no new DID to return:
/// [`verify_rotation`] is the same check, and returns it.
pub async fn verify_from_prior<S: SigningService>(
    crypto: &S,
    resolver: &dyn DIDResolver,
    jwt: &str,
) -> Result<(String, String), RotationError> {
    let verified = verify_rotation(crypto, resolver, jwt).await?;
    match verified.new_did {
        Some(new_did) => Ok((verified.prior_did, new_did)),
        None => Err(RotationError::EndsRelationship {
            prior_did: verified.prior_did,
        }),
    }
}

/// Verify a `from_prior` JWT (DIDComm v2.1, DID Rotation): what
/// [`verify_from_prior`] checks, returning a [`FromPrior`] whose `new_did` is `None`
/// when the JWT ends the relationship.
///
/// - `alg` is EdDSA, ES256 or ES256K, and must be the algorithm of the key `kid`
///   names (Ed25519, P-256, secp256k1): never another, so a signature can't be
///   checked under an algorithm it wasn't made with.
/// - `typ`, if present, is `JWT` (any case); `crv`, if present, names that key's
///   curve (any case: the spec's example says `ED25519`).
/// - `kid` is a key of `iss`, listed in `iss`'s `authentication` (matched by
///   fragment).
/// - `iat` is no more than 300 s in the future.
pub async fn verify_rotation<S: SigningService>(
    crypto: &S,
    resolver: &dyn DIDResolver,
    jwt: &str,
) -> Result<FromPrior, RotationError> {
    let mut parts = jwt.splitn(3, '.');
    let (header_b64, payload_b64, signature_b64) = match (parts.next(), parts.next(), parts.next())
    {
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
    if !ALGS.contains(&header.alg.as_str()) {
        return Err(RotationError::Malformed(format!(
            "unsupported from_prior alg: {}",
            header.alg
        )));
    }
    if header
        .typ
        .as_deref()
        .is_some_and(|typ| !typ.eq_ignore_ascii_case("JWT"))
    {
        return Err(RotationError::Malformed(
            "from_prior's typ, when given, must be JWT".to_string(),
        ));
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

    let signature =
        multibase::decode(signature_b64).map_err(|e| RotationError::Malformed(e.to_string()))?;

    // Not from the future (a few minutes' clocks apart allowed).
    // (SystemTime panics in the browser's wasm: the library's own clock.)
    let now = crate::messaging::now_epoch_secs() as i64;
    if payload.iat > now + 300 {
        return Err(RotationError::Malformed(
            "from_prior is dated in the future".to_string(),
        ));
    }

    // Only a key the prior DID lists for authentication speaks for it: not one it
    // lists for credentials alone (an untrusted device's), which would otherwise
    // hand the account's mail and push to another DID (WYV-27).
    let prior = resolver.resolve(&payload.iss).await?;
    // By fragment: the prior DID's own document, and one DID can be named short or
    // long (a did:peer:4).
    let fragment = |id: &str| {
        id.rsplit_once('#')
            .map(|(_, f)| f.to_string())
            .unwrap_or_else(|| id.to_string())
    };
    let names_it = |entry: &serde_json::Value| {
        let id = entry
            .as_str()
            .or_else(|| entry["id"].as_str())
            .unwrap_or_default();
        fragment(id) == fragment(&header.kid)
    };
    if !prior["authentication"]
        .as_array()
        .is_some_and(|list| list.iter().any(names_it))
    {
        return Err(RotationError::Malformed(
            "from_prior is signed by a key the prior DID doesn't authenticate with".to_string(),
        ));
    }

    let vm = resolver
        .resolve_and_dereference_verification_method(&header.kid)
        .await?;
    // The algorithm is the key's, whatever the header says (WYV-27's protection
    // against algorithm confusion, kept for the three algorithms now allowed).
    let key_type = crate::crypto::signature_key_type(&vm)?;
    if header.alg != key_type.alg() {
        return Err(RotationError::Malformed(format!(
            "from_prior says {} but its key is for {}",
            header.alg,
            key_type.alg()
        )));
    }
    if header
        .crv
        .as_deref()
        .is_some_and(|crv| !key_type.is_crv(crv))
    {
        return Err(RotationError::Malformed(
            "from_prior's crv is not its key's curve".to_string(),
        ));
    }
    let verifying_key = crypto.verification_method_to_verifying_key(&vm)?;

    let signing_input = format!("{header_b64}.{payload_b64}");
    let valid = crypto
        .verify(&verifying_key, signing_input.as_bytes(), &signature)
        .await?;
    if !valid {
        return Err(RotationError::InvalidSignature);
    }

    Ok(FromPrior {
        prior_did: payload.iss,
        new_did: payload.sub,
        iat: payload.iat,
    })
}

// Tested in tests/rotation.rs, not here: exercising this against a real
// SigningService/DIDResolver (AskarCryptoService, Peer4) needs those crates as a
// dependency, and they in turn depend on didcomm-core -- fine for a true integration
// test (a separate binary linking this crate normally), but a #[cfg(test)] unit test
// module *inside* this crate would instead hit Cargo's classic "multiple different
// versions of crate didcomm_core" duplicate when the very same trait needs to unify
// across that self-referential dev-dependency edge.
