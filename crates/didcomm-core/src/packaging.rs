//! `PackagingService`, mirroring `didcomm_messaging.packaging`.
//!
//! This is the layer that turns "pack this message to this DID" into the right crypto
//! calls: resolving recipients' (and, for authenticated encryption, the sender's) keys
//! via a `DIDResolver`, choosing ECDH-1PU vs ECDH-ES based on whether a sender was
//! given, and validating a received envelope's metadata (`apv`/`apu`/`skid`
//! consistency) before decrypting.

use didcomm_diddoc::VerificationMethod;
use sha2::{Digest, Sha256};

use crate::crypto::{CryptoService, CryptoServiceError, SecretsManager};
use crate::envelope::EncryptedEnvelope;
use crate::jwe::JweError;
use crate::resolver::{DIDResolver, ResolutionError};

/// Errors from `PackagingService::pack`/`unpack`.
#[derive(Debug, thiserror::Error)]
pub enum PackagingError {
    #[error(transparent)]
    Jwe(#[from] JweError),
    #[error(transparent)]
    Resolution(#[from] ResolutionError),
    #[error(transparent)]
    Crypto(#[from] CryptoServiceError),
    #[error("missing alg header")]
    MissingAlg,
    #[error("unsupported DIDComm encryption algorithm: {0}")]
    UnsupportedAlg(String),
    #[error("no recognized recipient key")]
    NoRecognizedRecipient,
    #[error("missing apv header")]
    MissingApv,
    #[error("invalid apv value")]
    InvalidApv,
    #[error("invalid apu value")]
    InvalidApu,
    #[error("mismatch between skid and apu")]
    ApuSkidMismatch,
    #[error("sender key ID not provided")]
    MissingSenderKid,
    #[error("no key agreement methods found; cannot determine recipient")]
    NoKeyAgreement,
    #[error("no sender key found")]
    NoSenderKey,
}

/// Which DIDComm v2 encryption mode a message used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    EcdhEs,
    Ecdh1Pu,
}

/// Metadata extracted from a packed message, before (and as a prerequisite to)
/// decrypting it. Mirrors `PackedMessageMetadata` in Python.
#[derive(Debug)]
pub struct PackedMessageMetadata<K> {
    pub wrapper: EncryptedEnvelope,
    pub method: Method,
    pub recip_key: K,
    pub sender_kid: Option<String>,
}

/// Packs and unpacks DIDComm v2 messages, generic over a [`CryptoService`] backend and
/// a matching [`SecretsManager`].
#[derive(Debug, Default, Clone, Copy)]
pub struct PackagingService;

impl PackagingService {
    /// Extract and validate a packed message's metadata (which key it's for, which
    /// encryption mode, and -- for ECDH-1PU -- who claims to have sent it) without
    /// decrypting the payload.
    pub async fn extract_packed_message_metadata<C, S>(
        &self,
        enc_message: &[u8],
        secrets: &S,
    ) -> Result<PackedMessageMetadata<C::SecretKey>, PackagingError>
    where
        C: CryptoService,
        S: SecretsManager<SecretKey = C::SecretKey>,
    {
        let wrapper = EncryptedEnvelope::from_encoded(enc_message)?;

        let alg = wrapper.key_agreement_alg().ok_or(PackagingError::MissingAlg)?;
        let method = if alg.contains("ECDH-1PU") {
            Method::Ecdh1Pu
        } else if alg.contains("ECDH-ES") {
            Method::EcdhEs
        } else {
            return Err(PackagingError::UnsupportedAlg(alg));
        };

        let kids = wrapper.recipient_key_ids();
        let mut recip_key = None;
        for kid in &kids {
            if let Some(key) = secrets.get_secret_by_kid(kid).await {
                recip_key = Some(key);
                break;
            }
        }
        let recip_key = recip_key.ok_or(PackagingError::NoRecognizedRecipient)?;

        // apv is the SHA-256 of the *sorted* recipient kids joined with "." (DIDComm v2,
        // "ECDH-ES key wrapping and common protected headers") -- what every encrypter,
        // this crate's and Python's alike, computes. didcomm-messaging-python's own
        // check hashes them in wire order instead, so it rejects its own
        // multi-recipient messages whenever the recipients aren't already sorted.
        let mut sorted_kids: Vec<&str> = kids.iter().map(String::as_str).collect();
        sorted_kids.sort_unstable();
        let expected_apv = Sha256::digest(sorted_kids.join(".").as_bytes()).to_vec();
        let apvs = wrapper.apv_values().map_err(|_| PackagingError::MissingApv)?;
        if apvs != [expected_apv] {
            return Err(PackagingError::InvalidApv);
        }

        let sender_kid = if method == Method::Ecdh1Pu {
            let apu_bytes = wrapper.apu_bytes()?;
            let sender_kid_apu =
                String::from_utf8(apu_bytes).map_err(|_| PackagingError::InvalidApu)?;
            let sender_kid = wrapper.skid().unwrap_or_else(|| sender_kid_apu.clone());
            if sender_kid != sender_kid_apu {
                return Err(PackagingError::ApuSkidMismatch);
            }
            Some(sender_kid)
        } else {
            None
        };

        Ok(PackedMessageMetadata {
            wrapper,
            method,
            recip_key,
            sender_kid,
        })
    }

    /// Unpack (validate metadata, then decrypt) a DIDComm v2 message.
    pub async fn unpack<C, S>(
        &self,
        crypto: &C,
        resolver: &dyn DIDResolver,
        secrets: &S,
        enc_message: &[u8],
    ) -> Result<(Vec<u8>, PackedMessageMetadata<C::SecretKey>), PackagingError>
    where
        C: CryptoService,
        S: SecretsManager<SecretKey = C::SecretKey>,
    {
        let metadata = self
            .extract_packed_message_metadata::<C, S>(enc_message, secrets)
            .await?;

        if metadata.method == Method::EcdhEs {
            let plaintext = crypto.ecdh_es_decrypt(enc_message, &metadata.recip_key).await?;
            return Ok((plaintext, metadata));
        }

        let sender_kid = metadata
            .sender_kid
            .clone()
            .ok_or(PackagingError::MissingSenderKid)?;
        let sender_vm = resolver
            .resolve_and_dereference_verification_method(&sender_kid)
            .await?;
        let sender_key = crypto.verification_method_to_public_key(&sender_vm)?;
        let plaintext = crypto
            .ecdh_1pu_decrypt(enc_message, &metadata.recip_key, &sender_key)
            .await?;
        Ok((plaintext, metadata))
    }

    /// Resolve the recipient key(s) for a `kid` (a DID URL with a fragment -- exactly
    /// one, that specific key) or a bare DID (every `keyAgreement` entry in its
    /// document). See [`didcomm_diddoc::DidDocument::all_key_agreements`] for why a
    /// bare DID resolves to *all* of them, not just the first -- this is what makes a
    /// multi-device identity (one DID document, one independent key per device)
    /// actually reachable on every device from a single `pack()` call, per DIDComm
    /// Messaging v2.1's own recommended default.
    pub async fn recip_keys_for_kid_or_all_for_did<C: CryptoService>(
        &self,
        crypto: &C,
        resolver: &dyn DIDResolver,
        kid_or_did: &str,
    ) -> Result<Vec<C::PublicKey>, PackagingError> {
        if kid_or_did.contains('#') {
            let vm = resolver
                .resolve_and_dereference_verification_method(kid_or_did)
                .await?;
            return Ok(vec![crypto.verification_method_to_public_key(&vm)?]);
        }
        let doc = resolver.resolve_and_parse(kid_or_did).await?;
        let vms = doc.all_key_agreements();
        if vms.is_empty() {
            return Err(PackagingError::NoKeyAgreement);
        }
        vms.iter()
            .map(|vm| crypto.verification_method_to_public_key(vm).map_err(PackagingError::from))
            .collect()
    }


    /// Pack an already-encoded plaintext for one or more recipients, optionally
    /// authenticated by a sender, in the given envelope `encoding` (a JWE, or a
    /// COSE_Encrypt for the `didcomm/v2+cbor` profile). Choosing `encoding` based on
    /// what the recipient(s) actually support is the caller's responsibility -- see
    /// `DIDCommMessaging::pack`'s own content negotiation -- as is encoding `message`
    /// to match it (see [`crate::plaintext::encode`]).
    pub async fn pack<C, S>(
        &self,
        crypto: &C,
        resolver: &dyn DIDResolver,
        secrets: &S,
        message: &[u8],
        to: &[&str],
        frm: Option<&str>,
        encoding: crate::crypto::Encoding,
    ) -> Result<Vec<u8>, PackagingError>
    where
        C: CryptoService,
        S: SecretsManager<SecretKey = C::SecretKey>,
    {
        let mut recip_keys = Vec::with_capacity(to.len());
        for kid in to {
            recip_keys.extend(
                self.recip_keys_for_kid_or_all_for_did(crypto, resolver, kid)
                    .await?,
            );
        }

        let sender_key = match frm {
            Some(frm) if frm.contains('#') => Some(
                secrets
                    .get_secret_by_kid(frm)
                    .await
                    .ok_or(PackagingError::NoSenderKey)?,
            ),
            // A bare DID (no `#kid`) can have more than one `keyAgreement` entry -- a
            // multi-device Identity DID lists one per enrolled device (see
            // `all_key_agreements`'s own doc comment). `default_sender_kid_for_did`
            // would just take the first-listed entry regardless of whether *this*
            // caller actually holds its secret, which only happens to work for
            // whichever device's key was listed first. Instead, try every entry and
            // use whichever one this `SecretsManager` actually has a secret for -- the
            // sender-side mirror of this same function's recipient-side resolution
            // (`recip_keys_for_kid_or_all_for_did` encrypts to *every* keyAgreement
            // entry; this picks *my own* entry among them to encrypt *as*). A
            // resolver-visible detail like document order was never meant to decide
            // which of a caller's own keys it authenticates with -- found via a real
            // two-device enrollment run, where the second device's every outgoing
            // message failed with "no sender key found" despite holding a perfectly
            // valid secret for its own (non-first) entry in the shared document.
            Some(frm) => {
                let doc = resolver.resolve_and_parse(frm).await?;
                let vms = doc.all_key_agreements();
                if vms.is_empty() {
                    return Err(PackagingError::NoKeyAgreement);
                }
                let mut found = None;
                for vm in &vms {
                    let kid = absolute_vm_id(vm);
                    if let Some(secret) = secrets.get_secret_by_kid(&kid).await {
                        found = Some(secret);
                        break;
                    }
                }
                Some(found.ok_or(PackagingError::NoSenderKey)?)
            }
            None => None,
        };

        let packed = match sender_key {
            Some(sender_key) => {
                crypto
                    .ecdh_1pu_encrypt(&recip_keys, &sender_key, message, encoding)
                    .await?
            }
            None => crypto.ecdh_es_encrypt(&recip_keys, message, encoding).await?,
        };
        Ok(packed)
    }
}

fn absolute_vm_id(vm: &VerificationMethod) -> String {
    if vm.id.starts_with('#') {
        format!("{}{}", vm.controller, vm.id)
    } else {
        vm.id.clone()
    }
}
