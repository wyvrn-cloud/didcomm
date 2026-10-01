//! An agent's long-lived key material, and saving/loading it.
//!
//! An [`Identity`] is just keys: one Ed25519 authentication key and one X25519
//! key-agreement key. Its DIDs are *derived* from those keys plus a service endpoint
//! ([`Identity::did`]), so the same identity file always yields the same DIDs: the
//! agent's own DID, and (after mediation) the DID it gives out to peers, whose
//! endpoint is the mediator's routing DID. Nothing but the keys needs persisting.

use std::fmt;
use std::path::Path;

use askar_crypto::alg::{ed25519::Ed25519KeyPair, x25519::X25519KeyPair};
use askar_crypto::jwk::{FromJwk, ToJwk};
use askar_crypto::repr::KeyGen;
use didcomm_quickstart::{authentication_public_multikey, did_for_keys, key_agreement_public_multikey};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Errors creating, saving, or loading an [`Identity`].
#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    #[error("key error: {0}")]
    Key(#[from] askar_crypto::Error),
    #[error("identity file I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid identity file: {0}")]
    Json(#[from] serde_json::Error),
    #[error("unsupported identity file version {0} (expected {FILE_VERSION})")]
    Version(u32),
    #[error(transparent)]
    Did(#[from] didcomm_quickstart::QuickstartError),
}

const FILE_VERSION: u32 = 1;

/// On-disk form: both keys as private JWKs.
#[derive(Serialize, Deserialize)]
struct IdentityFile {
    version: u32,
    verification_key: Value,
    key_agreement_key: Value,
}

/// An agent's key material. See the [module docs](self).
pub struct Identity {
    verification_key: Ed25519KeyPair,
    key_agreement_key: X25519KeyPair,
}

impl Identity {
    /// Fresh random keys.
    pub fn generate() -> Result<Self, IdentityError> {
        Ok(Self::from_keys(Ed25519KeyPair::random()?, X25519KeyPair::random()?))
    }

    pub fn from_keys(verification_key: Ed25519KeyPair, key_agreement_key: X25519KeyPair) -> Self {
        Self { verification_key, key_agreement_key }
    }

    pub fn verification_key(&self) -> &Ed25519KeyPair {
        &self.verification_key
    }

    pub fn key_agreement_key(&self) -> &X25519KeyPair {
        &self.key_agreement_key
    }

    /// This identity's `did:peer:4` with `endpoint_uri` as its `DIDCommMessaging`
    /// service endpoint (a transport URI, or a mediator's routing DID). Its
    /// key-agreement key is always `<did>#key-2`.
    pub fn did(&self, endpoint_uri: &str) -> Result<String, IdentityError> {
        Ok(did_for_keys(&self.verification_key, &self.key_agreement_key, endpoint_uri)?)
    }

    /// A DID document for this identity under a DID it doesn't derive itself, e.g. a
    /// `did:web` whose document the agent publishes: the same layout as
    /// [`did`](Self::did)'s (authentication key `#key-1`, key-agreement key `#key-2`,
    /// one `DIDCommMessaging` service at `endpoint_uri`), with absolute ids.
    pub fn did_document(&self, did: &str, endpoint_uri: &str) -> Value {
        serde_json::json!({
            "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/multikey/v1"],
            "id": did,
            "verificationMethod": [
                {
                    "id": format!("{did}#key-1"),
                    "type": "Multikey",
                    "controller": did,
                    "publicKeyMultibase": authentication_public_multikey(&self.verification_key),
                },
                {
                    "id": format!("{did}#key-2"),
                    "type": "Multikey",
                    "controller": did,
                    "publicKeyMultibase": key_agreement_public_multikey(&self.key_agreement_key),
                },
            ],
            "authentication": [format!("{did}#key-1")],
            "keyAgreement": [format!("{did}#key-2")],
            "service": [{
                "id": format!("{did}#didcomm"),
                "type": "DIDCommMessaging",
                "serviceEndpoint": {
                    "uri": endpoint_uri,
                    "accept": ["didcomm/v2"],
                    "routingKeys": [],
                },
            }],
        })
    }

    /// Serialize both keys, *including their secrets*, as JSON.
    pub fn to_json(&self) -> Result<String, IdentityError> {
        let file = IdentityFile {
            version: FILE_VERSION,
            verification_key: serde_json::from_slice(self.verification_key.to_jwk_secret(None)?.as_ref())?,
            key_agreement_key: serde_json::from_slice(self.key_agreement_key.to_jwk_secret(None)?.as_ref())?,
        };
        Ok(serde_json::to_string_pretty(&file)?)
    }

    pub fn from_json(json: &str) -> Result<Self, IdentityError> {
        let file: IdentityFile = serde_json::from_str(json)?;
        if file.version != FILE_VERSION {
            return Err(IdentityError::Version(file.version));
        }
        Ok(Self::from_keys(
            Ed25519KeyPair::from_jwk(&file.verification_key.to_string())?,
            X25519KeyPair::from_jwk(&file.key_agreement_key.to_string())?,
        ))
    }

    /// Write this identity to `path`, readable only by the current user on Unix. Writes
    /// a sibling temporary file first and renames it over `path`, so a crash never
    /// leaves a half-written identity behind.
    pub fn save(&self, path: impl AsRef<Path>) -> Result<(), IdentityError> {
        let path = path.as_ref();
        if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
            std::fs::create_dir_all(dir)?;
        }
        let tmp = path.with_extension("tmp");
        write_private(&tmp, self.to_json()?.as_bytes())?;
        std::fs::rename(&tmp, path)?;
        Ok(())
    }

    pub fn load(path: impl AsRef<Path>) -> Result<Self, IdentityError> {
        Self::from_json(&std::fs::read_to_string(path)?)
    }

    /// [`load`](Self::load) `path` if it exists, otherwise [`generate`](Self::generate)
    /// a new identity and [`save`](Self::save) it there.
    pub fn load_or_generate(path: impl AsRef<Path>) -> Result<Self, IdentityError> {
        let path = path.as_ref();
        if path.exists() {
            return Self::load(path);
        }
        let identity = Self::generate()?;
        identity.save(path)?;
        Ok(identity)
    }
}

impl Clone for Identity {
    fn clone(&self) -> Self {
        Self::from_keys(self.verification_key.clone(), self.key_agreement_key.clone())
    }
}

/// Public keys only -- never prints secrets.
impl fmt::Debug for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Identity")
            .field("verification_key", &authentication_public_multikey(&self.verification_key))
            .field("key_agreement_key", &key_agreement_public_multikey(&self.key_agreement_key))
            .finish()
    }
}

#[cfg(unix)]
fn write_private(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(contents)?;
    file.sync_all()
}

#[cfg(not(unix))]
fn write_private(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    std::fs::write(path, contents)
}
