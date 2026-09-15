//! `V1PackagingService`, mirroring `didcomm_messaging.v1.packaging`: pack/unpack by
//! kid (a bare base58 verkey, DIDComm v1's own identifier scheme) through a
//! [`SecretsManager`]. The DID-based layer on top -- resolving a recipient DID to its
//! `recipientKeys`/`routingKeys` and wrapping in `routing/1.0/forward` envelopes,
//! mirroring `v1/messaging.py` -- is follow-up work; this covers what
//! `didcomm_messaging.v1.packaging.V1PackagingService` itself does.

use askar_crypto::alg::ed25519::Ed25519KeyPair;
use didcomm_core::crypto::{SecretKey, SecretsManager};

use crate::{kid_for_verkey, pack_message, unpack_message, V1Error};
use didcomm_core::jwe::JweEnvelope;

/// A DIDComm v1 secret: an Ed25519 keypair plus the kid (bare base58 verkey) it's
/// stored under -- usable directly with
/// [`InMemorySecretsManager`](didcomm_core::secrets::InMemorySecretsManager).
#[derive(Debug, Clone)]
pub struct V1SecretKey {
    pub key: Ed25519KeyPair,
    kid: String,
}

impl V1SecretKey {
    /// Wrap an Ed25519 keypair, deriving its kid from the public key.
    pub fn new(key: Ed25519KeyPair) -> Self {
        let kid = kid_for_verkey(&key);
        Self { key, kid }
    }
}

impl SecretKey for V1SecretKey {
    fn kid(&self) -> &str {
        &self.kid
    }
}

/// The result of unpacking a DIDComm v1 message, mirroring `V1UnpackResult`.
#[derive(Debug, Clone)]
pub struct V1UnpackResult {
    pub unpacked: Vec<u8>,
    pub encrypted: bool,
    pub authenticated: bool,
    pub recipient_kid: String,
    pub sender_kid: Option<String>,
}

impl V1UnpackResult {
    /// The unpacked message, parsed as JSON.
    pub fn message(&self) -> Result<serde_json::Value, serde_json::Error> {
        serde_json::from_slice(&self.unpacked)
    }
}

/// Packs and unpacks DIDComm v1 messages by kid. Mirrors
/// `didcomm_messaging.v1.packaging.V1PackagingService`.
#[derive(Debug, Default, Clone, Copy)]
pub struct V1PackagingService;

impl V1PackagingService {
    /// Unpack a message, trying each of the envelope's recipients against `secrets`
    /// until one matches -- mirroring `extract_packed_message_metadata`'s search loop.
    pub async fn unpack<S: SecretsManager<SecretKey = V1SecretKey>>(
        &self,
        secrets: &S,
        enc_message: &[u8],
    ) -> Result<V1UnpackResult, V1Error> {
        let jwe = JweEnvelope::from_json_v1(enc_message)?;

        // Collected up front (owned) since `secrets.get_secret_by_kid` is async and
        // `jwe.recipient_key_ids()` borrows `jwe`, which would otherwise need to stay
        // borrowed across every `.await` in the loop below.
        let kids: Vec<String> = jwe.recipient_key_ids().map(str::to_string).collect();

        for kid in &kids {
            if let Some(secret) = secrets.get_secret_by_kid(kid).await {
                let (unpacked, sender_kid) = unpack_message(&jwe, kid, &secret.key)?;
                return Ok(V1UnpackResult {
                    unpacked,
                    encrypted: true,
                    authenticated: sender_kid.is_some(),
                    recipient_kid: kid.clone(),
                    sender_kid,
                });
            }
        }
        Err(V1Error::NoRecognizedRecipient)
    }

    /// Pack a message for one or more recipient verkeys, optionally authenticated by a
    /// sender's secret.
    pub fn pack(
        &self,
        to_verkeys: &[Ed25519KeyPair],
        from_key: Option<&V1SecretKey>,
        message: &[u8],
    ) -> Result<Vec<u8>, V1Error> {
        let packed = pack_message(to_verkeys, from_key.map(|k| &k.key), message)?;
        Ok(packed.into_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use askar_crypto::repr::KeyGen;
    use didcomm_core::secrets::InMemorySecretsManager;

    #[test]
    fn packs_and_unpacks_anonymous_and_authenticated_messages_by_kid() {
        let recipient_public = Ed25519KeyPair::random().unwrap();
        let recipient_secret = V1SecretKey::new(recipient_public.clone());
        let recipient_kid = recipient_secret.kid().to_string();

        let sender_public = Ed25519KeyPair::random().unwrap();
        let sender_kid = kid_for_verkey(&sender_public);
        let sender_secret = V1SecretKey::new(sender_public.clone());

        let secrets = InMemorySecretsManager::new();
        secrets.add_secret(recipient_secret);
        secrets.add_secret(sender_secret);

        let packaging = V1PackagingService;

        pollster::block_on(async {
            // Anonymous (Anoncrypt): no sender.
            let packed = packaging
                .pack(&[recipient_public.clone()], None, b"Hello world!")
                .unwrap();
            let unpacked = packaging.unpack(&secrets, &packed).await.unwrap();
            assert_eq!(unpacked.unpacked, b"Hello world!");
            assert_eq!(unpacked.recipient_kid, recipient_kid);
            assert!(!unpacked.authenticated);
            assert!(unpacked.sender_kid.is_none());

            // Authenticated (Authcrypt): with a sender secret looked up by kid, the
            // same way a real caller would (not by holding onto the V1SecretKey it
            // just constructed).
            let sender_secret = secrets.get_secret_by_kid(&sender_kid).await.unwrap();
            let packed = packaging
                .pack(&[recipient_public], Some(&sender_secret), b"Hello world!")
                .unwrap();
            let unpacked = packaging.unpack(&secrets, &packed).await.unwrap();
            assert_eq!(unpacked.unpacked, b"Hello world!");
            assert!(unpacked.authenticated);
            assert_eq!(unpacked.sender_kid.as_deref(), Some(sender_kid.as_str()));
        });
    }
}
