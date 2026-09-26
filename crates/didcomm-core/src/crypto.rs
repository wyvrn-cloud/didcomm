//! `CryptoService`/`SecretsManager` traits, mirroring `didcomm_messaging.crypto.base`.
//!
//! Concrete backends (`didcomm-crypto-askar`, and any future ones) implement these
//! against their own key types via `CryptoService::PublicKey`/`SecretKey` associated
//! types -- `PackagingService` (see `packaging.rs`) is written generically against the
//! traits, not against any one backend, matching the Python library's swappable-backend
//! design. Unlike `DIDResolver`, these aren't used as `dyn` trait objects anywhere: an
//! application picks one crypto backend, it doesn't mix several the way it might mix
//! several DID method resolvers via `PrefixResolver`.

use async_trait::async_trait;
use didcomm_diddoc::VerificationMethod;
use didcomm_multiformats::{multibase, multicodec};

/// Errors from a `CryptoService` or `SecretsManager` operation.
#[derive(Debug, thiserror::Error)]
pub enum CryptoServiceError {
    #[error("{0}")]
    Message(String),
    #[error("invalid verification method: {0}")]
    InvalidVerificationMethod(String),
}

impl CryptoServiceError {
    pub fn msg(s: impl Into<String>) -> Self {
        Self::Message(s.into())
    }
}

/// Which outer envelope encoding a `CryptoService::ecdh_es_encrypt`/`ecdh_1pu_encrypt`
/// call should produce -- see `didcomm-core::jwe`'s own module docs for the shape
/// difference between plain DIDComm v2 (JSON) and the wyvrn-original `didcomm/v2+cbor`
/// profile. `Json` is always safe (every DIDComm v2 peer understands it); `Cbor` should
/// only ever be chosen once a specific recipient's own resolved `accept` list confirms
/// support for it (see `didcomm-core::messaging`'s content negotiation) -- nothing in
/// this trait itself enforces that, it's the caller's responsibility.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Encoding {
    #[default]
    Json,
    Cbor,
}

impl Encoding {
    /// The negotiation rule `DIDCommMessaging::pack` and
    /// `RoutingService::prepare_forward` both apply to a resolved peer's advertised
    /// `accept` list: `Cbor` iff it contains `"didcomm/v2+cbor"`, `Json` otherwise
    /// (including an empty or unresolvable list -- `Json` is always the safe default).
    pub fn for_accept(accept: &[String]) -> Self {
        if accept.iter().any(|a| a == "didcomm/v2+cbor") {
            Self::Cbor
        } else {
            Self::Json
        }
    }
}

/// A public key usable for encryption or signature verification.
pub trait PublicKey: Send + Sync {
    /// The key ID (typically a DID URL, e.g. `did:example:abc#key-1`).
    fn kid(&self) -> &str;
}

/// A secret (private) key.
pub trait SecretKey: Send + Sync {
    /// The key ID (typically a DID URL, e.g. `did:example:abc#key-1`).
    fn kid(&self) -> &str;
}

/// Cryptographic operations needed to pack/unpack DIDComm v2 messages. Mirrors
/// `didcomm_messaging.crypto.base.CryptoService`.
#[async_trait]
pub trait CryptoService: Send + Sync {
    type PublicKey: PublicKey;
    type SecretKey: SecretKey;

    /// Encode a message into DIDComm v2 anonymous encryption (ECDH-ES).
    async fn ecdh_es_encrypt(
        &self,
        to_keys: &[Self::PublicKey],
        message: &[u8],
        encoding: Encoding,
    ) -> Result<Vec<u8>, CryptoServiceError>;

    /// Decode a message from DIDComm v2 anonymous encryption (ECDH-ES). Accepts either
    /// outer envelope encoding -- the caller doesn't (and can't, before decrypting)
    /// know which one a given message used, so this always sniffs it from the message
    /// itself rather than taking it as a parameter.
    async fn ecdh_es_decrypt(
        &self,
        enc_message: &[u8],
        recip_key: &Self::SecretKey,
    ) -> Result<Vec<u8>, CryptoServiceError>;

    /// Encode a message into DIDComm v2 authenticated encryption (ECDH-1PU).
    async fn ecdh_1pu_encrypt(
        &self,
        to_keys: &[Self::PublicKey],
        sender_key: &Self::SecretKey,
        message: &[u8],
        encoding: Encoding,
    ) -> Result<Vec<u8>, CryptoServiceError>;

    /// Decode a message from DIDComm v2 authenticated encryption (ECDH-1PU).
    async fn ecdh_1pu_decrypt(
        &self,
        enc_message: &[u8],
        recip_key: &Self::SecretKey,
        sender_key: &Self::PublicKey,
    ) -> Result<Vec<u8>, CryptoServiceError>;

    /// Convert a DID Document verification method into this backend's public key type.
    fn verification_method_to_public_key(
        &self,
        vm: &VerificationMethod,
    ) -> Result<Self::PublicKey, CryptoServiceError>;
}

/// A public key usable for signature verification (e.g. a DID's `authentication`
/// verification method).
pub trait VerifyingKey: Send + Sync {
    /// The key ID (typically a DID URL, e.g. `did:example:abc#key-1`).
    fn kid(&self) -> &str;
}

/// A secret key usable for signing.
pub trait SigningKey: Send + Sync {
    /// The key ID (typically a DID URL, e.g. `did:example:abc#key-1`).
    fn kid(&self) -> &str;
}

/// Ed25519 sign/verify, used for `from_prior` DID rotation
/// ([DIDComm Messaging v2.1](https://identity.foundation/didcomm-messaging/spec/v2.1/)
/// -- see `didcomm-core::rotation`). Kept as its own trait rather than folded into
/// [`CryptoService`]: it operates on a DID's `authentication` key (Ed25519), a
/// different key type than pack/unpack's `keyAgreement`/X25519 operations, and a
/// backend may reasonably support one without the other.
#[async_trait]
pub trait SigningService: Send + Sync {
    type SigningKey: SigningKey;
    type VerifyingKey: VerifyingKey;

    /// Sign `message`, returning the raw signature bytes (64 bytes for EdDSA).
    async fn sign(
        &self,
        key: &Self::SigningKey,
        message: &[u8],
    ) -> Result<Vec<u8>, CryptoServiceError>;

    /// Verify `signature` over `message` was produced by `key`. `Ok(false)`, not an
    /// error, for a cryptographically invalid signature -- an `Err` is reserved for a
    /// genuine backend failure (e.g. a malformed key), not an untrusted signature.
    async fn verify(
        &self,
        key: &Self::VerifyingKey,
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool, CryptoServiceError>;

    /// Convert a DID Document verification method into this backend's verifying key
    /// type. Mirrors [`CryptoService::verification_method_to_public_key`], but for the
    /// `authentication` relationship's key type rather than `keyAgreement`'s.
    fn verification_method_to_verifying_key(
        &self,
        vm: &VerificationMethod,
    ) -> Result<Self::VerifyingKey, CryptoServiceError>;
}

/// Retrieves secret keys by key ID, to supplement a `CryptoService` backend. Mirrors
/// `didcomm_messaging.crypto.base.SecretsManager`.
#[async_trait]
pub trait SecretsManager: Send + Sync {
    type SecretKey: SecretKey;

    async fn get_secret_by_kid(&self, kid: &str) -> Option<Self::SecretKey>;
}

/// Decode the raw key bytes out of a verification method's multikey material, mirroring
/// `didcomm_messaging.crypto.base.PublicKey.key_bytes_from_verification_method`. Shared
/// across backends since it's about the DID Document encoding, not any one crypto
/// library's key representation.
pub fn multikey_bytes_from_verification_method(
    vm: &VerificationMethod,
) -> Result<Vec<u8>, CryptoServiceError> {
    let multibase_value = match (&vm.public_key_multibase, &vm.public_key_base58) {
        (Some(_), Some(_)) => {
            return Err(CryptoServiceError::InvalidVerificationMethod(
                "only one of publicKeyMultibase or publicKeyBase58 must be given".into(),
            ))
        }
        (Some(mb), None) => mb.clone(),
        (None, Some(b58)) => format!("z{b58}"),
        (None, None) => {
            return Err(CryptoServiceError::InvalidVerificationMethod(
                "one of publicKeyMultibase or publicKeyBase58 must be given".into(),
            ))
        }
    };

    let decoded = multibase::decode_self_describing(&multibase_value)
        .map_err(|e| CryptoServiceError::InvalidVerificationMethod(e.to_string()))?;

    // A bare 32-byte value (no multicodec prefix) is accepted directly, matching the
    // Python original -- some early did:key-adjacent material was published this way.
    if decoded.len() == 32 {
        return Ok(decoded);
    }

    let (_codec, key_bytes) = multicodec::unwrap(&decoded)
        .map_err(|e| CryptoServiceError::InvalidVerificationMethod(e.to_string()))?;
    Ok(key_bytes.to_vec())
}
