//! `DIDResolver` trait and `PrefixResolver`, mirroring `didcomm_messaging.resolver`.
//!
//! Resolving a DID is inherently an `async` operation for most real DID methods
//! (`did:web`, `did:webvh`, ... all need a network fetch) even though the ones
//! implemented so far (`did:peer:2`) don't -- so the trait is `async` from the start
//! rather than becoming a breaking change later. `async-trait` is used for the trait
//! object support `PrefixResolver` needs (dynamic dispatch over a mix of resolvers);
//! revisit if/when native `async fn` in dyn-safe traits covers this without it.
//!
//! The trait (and `PrefixResolver`'s impl of it) is defined twice, gated by
//! `target_arch`, rather than once: on native targets it's `Send + Sync` (needed for
//! e.g. `wyvrn-mediator-service` to hold one across `tokio::spawn`ed tasks), but
//! `wasm32-unknown-unknown` can't offer that for a resolver that does real network
//! I/O -- `reqwest`'s wasm implementation goes through JS `Promise`/`JsFuture`, which
//! aren't (and can't be) `Send`, since wasm is single-threaded and JS values can't
//! cross real threads. `didcomm-resolver-web`'s `DidWeb` is the one resolver this
//! actually affects (found by tracing every real `impl DIDResolver` in the
//! workspace -- `Peer2`/`Peer4`/`JwkResolver` do no I/O, so their futures are
//! trivially `Send` regardless of target and need no such split themselves).
//! `PrefixResolver` aggregates whichever resolvers are registered, so it needs the
//! same relaxation transitively once `DidWeb` might be one of them. Two full trait
//! definitions is more repetition than a clever `cfg_attr` trick would need, but this
//! trait is small (~40 lines) and the duplication is easy to keep in sync by eye --
//! not worth extra macro machinery for.

use async_trait::async_trait;
use didcomm_diddoc::{DidDocError, DidDocument, Resource, VerificationMethod};
use serde_json::Value;

/// Errors resolving or dereferencing a DID.
#[derive(Debug, thiserror::Error)]
pub enum ResolutionError {
    #[error("no resolver registered for DID: {0}")]
    MethodNotSupported(String),
    #[error("error resolving DID: {0}")]
    Resolution(String),
    #[error("error parsing resolved DID document: {0}")]
    DidDoc(#[from] DidDocError),
    #[error("DID URL must be absolute (include a DID), got: {0}")]
    RelativeDidUrl(String),
    #[error("resource not found for DID URL: {0}")]
    NotFound(String),
    #[error("resource is not a verification method: {0}")]
    NotAVerificationMethod(String),
}

#[cfg(not(target_arch = "wasm32"))]
mod imp {
    use super::*;

    /// Resolves a DID to a DID Document. Implementations exist per DID method
    /// (`didcomm-resolver-peer`, `didcomm-resolver-web`, ...); `PrefixResolver`
    /// combines several of them by matching on the DID's method prefix.
    #[async_trait]
    pub trait DIDResolver: Send + Sync {
        /// Resolve a DID to its DID Document, as raw JSON.
        async fn resolve(&self, did: &str) -> Result<Value, ResolutionError>;

        /// Check whether this resolver can handle the given DID, without fully
        /// resolving it.
        async fn is_resolvable(&self, did: &str) -> bool;

        /// Resolve a DID and parse the result into a [`DidDocument`].
        async fn resolve_and_parse(&self, did: &str) -> Result<DidDocument, ResolutionError> {
            let doc = self.resolve(did).await?;
            Ok(DidDocument::deserialize(doc)?)
        }

        /// Resolve a DID URL's DID and dereference the identifier within it.
        async fn resolve_and_dereference(&self, did_url: &str) -> Result<Resource, ResolutionError> {
            let did = did_url
                .split_once('#')
                .map(|(did, _)| did)
                .filter(|did| !did.is_empty())
                .ok_or_else(|| ResolutionError::RelativeDidUrl(did_url.to_string()))?;
            let doc = self.resolve_and_parse(did).await?;
            doc.dereference(did_url)
                .ok_or_else(|| ResolutionError::NotFound(did_url.to_string()))
        }

        /// Resolve a DID URL and require it to dereference to a verification method.
        async fn resolve_and_dereference_verification_method(
            &self,
            did_url: &str,
        ) -> Result<VerificationMethod, ResolutionError> {
            match self.resolve_and_dereference(did_url).await? {
                Resource::VerificationMethod(vm) => Ok(vm),
                Resource::Service(_) => {
                    Err(ResolutionError::NotAVerificationMethod(did_url.to_string()))
                }
            }
        }
    }

    #[async_trait]
    impl DIDResolver for PrefixResolver {
        async fn is_resolvable(&self, did: &str) -> bool {
            match self.resolver_for(did) {
                Some(resolver) => resolver.is_resolvable(did).await,
                None => false,
            }
        }

        async fn resolve(&self, did: &str) -> Result<Value, ResolutionError> {
            match self.resolver_for(did) {
                Some(resolver) => resolver.resolve(did).await,
                None => Err(ResolutionError::MethodNotSupported(did.to_string())),
            }
        }
    }
}

#[cfg(target_arch = "wasm32")]
mod imp {
    use super::*;

    /// See this module's own doc comment for why this is `?Send` and has no
    /// `Send + Sync` bound here specifically (identical otherwise to the native
    /// version in the `not(target_arch = "wasm32")` build of this same module).
    #[async_trait(?Send)]
    pub trait DIDResolver {
        async fn resolve(&self, did: &str) -> Result<Value, ResolutionError>;

        async fn is_resolvable(&self, did: &str) -> bool;

        async fn resolve_and_parse(&self, did: &str) -> Result<DidDocument, ResolutionError> {
            let doc = self.resolve(did).await?;
            Ok(DidDocument::deserialize(doc)?)
        }

        async fn resolve_and_dereference(&self, did_url: &str) -> Result<Resource, ResolutionError> {
            let did = did_url
                .split_once('#')
                .map(|(did, _)| did)
                .filter(|did| !did.is_empty())
                .ok_or_else(|| ResolutionError::RelativeDidUrl(did_url.to_string()))?;
            let doc = self.resolve_and_parse(did).await?;
            doc.dereference(did_url)
                .ok_or_else(|| ResolutionError::NotFound(did_url.to_string()))
        }

        async fn resolve_and_dereference_verification_method(
            &self,
            did_url: &str,
        ) -> Result<VerificationMethod, ResolutionError> {
            match self.resolve_and_dereference(did_url).await? {
                Resource::VerificationMethod(vm) => Ok(vm),
                Resource::Service(_) => {
                    Err(ResolutionError::NotAVerificationMethod(did_url.to_string()))
                }
            }
        }
    }

    #[async_trait(?Send)]
    impl DIDResolver for PrefixResolver {
        async fn is_resolvable(&self, did: &str) -> bool {
            match self.resolver_for(did) {
                Some(resolver) => resolver.is_resolvable(did).await,
                None => false,
            }
        }

        async fn resolve(&self, did: &str) -> Result<Value, ResolutionError> {
            match self.resolver_for(did) {
                Some(resolver) => resolver.resolve(did).await,
                None => Err(ResolutionError::MethodNotSupported(did.to_string())),
            }
        }
    }
}

pub use imp::DIDResolver;

/// Delegates to sub-resolvers by DID method prefix, mirroring
/// `didcomm_messaging.resolver.PrefixResolver`. Prefixes are checked in the order
/// they were registered, first match wins (matching Python dict iteration order).
pub struct PrefixResolver {
    resolvers: Vec<(String, Box<dyn DIDResolver>)>,
}

impl PrefixResolver {
    pub fn new(resolvers: Vec<(impl Into<String>, Box<dyn DIDResolver>)>) -> Self {
        Self {
            resolvers: resolvers
                .into_iter()
                .map(|(prefix, resolver)| (prefix.into(), resolver))
                .collect(),
        }
    }

    fn resolver_for<'a>(&'a self, did: &str) -> Option<&'a dyn DIDResolver> {
        self.resolvers
            .iter()
            .find(|(prefix, _)| did.starts_with(prefix.as_str()))
            .map(|(_, resolver)| resolver.as_ref())
    }
}
