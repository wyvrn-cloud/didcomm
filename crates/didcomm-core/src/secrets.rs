//! `InMemorySecretsManager`, mirroring `didcomm_messaging.crypto.backend.basic`.
//!
//! `FileBasedSecretsManager` (the other implementation in the Python module) is
//! follow-up work -- not needed to prove pack/unpack works.

use std::collections::HashMap;
use std::sync::RwLock;

use async_trait::async_trait;

use crate::crypto::{SecretKey, SecretsManager};

/// A `SecretsManager` that just holds secrets in memory, for testing and simple use
/// cases -- exactly what the Python original is for too.
pub struct InMemorySecretsManager<K> {
    secrets: RwLock<HashMap<String, K>>,
}

impl<K: SecretKey> InMemorySecretsManager<K> {
    pub fn new() -> Self {
        Self {
            secrets: RwLock::new(HashMap::new()),
        }
    }

    pub fn add_secret(&self, secret: K) {
        self.secrets
            .write()
            .expect("lock poisoned")
            .insert(secret.kid().to_string(), secret);
    }
}

impl<K: SecretKey> Default for InMemorySecretsManager<K> {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl<K: SecretKey + Clone> SecretsManager for InMemorySecretsManager<K> {
    type SecretKey = K;

    async fn get_secret_by_kid(&self, kid: &str) -> Option<K> {
        self.secrets.read().expect("lock poisoned").get(kid).cloned()
    }
}
