//! `did:web` resolution, mirroring `didcomm_messaging.resolver.web`.
//!
//! The one resolver so far that needs real network I/O: `did:web:<hostname>[:path...]`
//! maps to `https://<hostname>/<path or .well-known>/did.json`, fetched over HTTP. Also
//! the one resolver so far with any internal state -- a 30-minute TTL cache, as the
//! Python original's, but bounded (security review WYV-73): at most
//! [`MOST_CACHED`] DIDs, the least recently used let go first, expired entries
//! dropped, and a failed lookup remembered for [`FAILED_TTL_SECS`] so it isn't
//! fetched again for every message naming it. Each fetch is put to the
//! process-wide [fetch gate](didcomm_core::resolver::set_fetch_gate) first.

use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;
use didcomm_core::resolver::{DIDResolver, ResolutionError};
use serde_json::Value;

const CACHE_TTL_SECS: f64 = 1800.0;

/// How long a lookup that failed (no document, an error status, not JSON, too
/// large, unreachable) is answered from the cache with the same failure.
pub const FAILED_TTL_SECS: f64 = 60.0;

/// The most DIDs kept. Past it the least recently used is let go -- never the
/// whole cache, so a flood of new DIDs can't push out the ones in use for more
/// than its own share.
pub const MOST_CACHED: usize = 1000;

/// Milliseconds since an arbitrary but consistent epoch -- `std::time::Instant`
/// panics on `wasm32-unknown-unknown` (no monotonic clock without going through JS,
/// unlike `wasm32-wasi`), so this crate's TTL cache uses this instead of
/// `Instant`/`Duration` directly, on every target, rather than maintaining two
/// separate cache-entry types.
#[cfg(not(target_arch = "wasm32"))]
fn now_ms() -> f64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before 1970")
        .as_secs_f64()
        * 1000.0
}

#[cfg(target_arch = "wasm32")]
fn now_ms() -> f64 {
    js_sys::Date::now()
}

/// Errors specific to did:web resolution (also surfaced through the `DIDResolver` trait
/// as [`ResolutionError::Resolution`]).
#[derive(Debug, thiserror::Error)]
pub enum DidWebError {
    #[error("invalid did:web: {0}")]
    InvalidDid(String),
    #[error("the did:web {0} returned a 404 not found while resolving")]
    NotFound(String),
    #[error("unknown server error ({status}) while resolving did:web: {did}")]
    ServerError { did: String, status: u16 },
    #[error("the did:web {did} returned invalid JSON: {source}")]
    InvalidJson { did: String, source: serde_json::Error },
    #[error("failed to fetch did:web document: {0}")]
    Request(#[from] reqwest::Error),
    #[error("the did:web {0} document is larger than a DID document is")]
    TooLarge(String),
}

/// The most a DID document may be: anything bigger isn't one, and isn't read
/// further (security review WYV-15).
pub const MAX_DOCUMENT_BYTES: usize = 1024 * 1024;

/// Convert a `did:web` DID into the URI its DID Document is expected to live at,
/// mirroring `DIDWeb._did_to_uri`.
pub fn did_to_uri(did: &str) -> Result<String, DidWebError> {
    let segments: Vec<&str> = did.split(':').collect();
    if segments.len() < 3 || segments[0] != "did" || segments[1] != "web" || segments[2].is_empty()
    {
        return Err(DidWebError::InvalidDid(did.to_string()));
    }
    let hostname = segments[2].to_lowercase().replace("%3a", ":");
    let path = if segments.len() > 3 {
        segments[3..].join("/")
    } else {
        ".well-known".to_string()
    };
    Ok(format!("https://{hostname}/{path}/did.json"))
}

/// Check whether a string has the shape of a resolvable `did:web` DID.
///
/// This is a hand-written approximation of `didcomm_messaging.resolver.web`'s
/// `did_web_pattern` regex, not a character-for-character port of it -- that regex has
/// some odd corners (e.g. its trailing path-segment group only accepts ASCII letters,
/// no digits, hyphens, or percent-encoding, which would reject perfectly normal
/// did:web paths). Rejecting or accepting a handful of unusual edge-case identifiers
/// differently from Python has no wire-protocol consequence here -- unlike a crypto or
/// JWE mismatch, a resolvability false-negative/positive just changes whether this
/// resolver attempts an HTTP fetch, which then succeeds or fails on its own merits.
pub fn is_did_web(did: &str) -> bool {
    let Some(rest) = did.strip_prefix("did:web:") else {
        return false;
    };
    if rest.is_empty() {
        return false;
    }
    let mut segments = rest.split(':');
    let Some(hostname) = segments.next() else {
        return false;
    };
    if !looks_like_hostname(hostname) {
        return false;
    }
    segments.all(|seg| {
        !seg.is_empty()
            && seg
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
    })
}

fn looks_like_hostname(segment: &str) -> bool {
    let lower = segment.to_ascii_lowercase();
    let host = match lower.split_once("%3a") {
        Some((host, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => host,
        Some(_) => return false,
        None => lower.as_str(),
    };
    let labels: Vec<&str> = host.split('.').collect();
    labels.len() >= 2 && labels.iter().all(|label| is_valid_label(label))
}

fn is_valid_label(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= 63
        && !label.starts_with('-')
        && !label.ends_with('-')
        && label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

/// Fetch and JSON-decode a DID document from a URI, mapping HTTP/JSON errors the same
/// way `DIDWeb.resolve` does. Split out from `DidWeb::resolve` (which additionally
/// applies caching and the `did:web` -> URI mapping) so it's testable against a plain
/// `http://` URI without needing a TLS-terminating test server.
/// How long a single did:web fetch is allowed to take before giving up. Without
/// this, a request that never gets a response (a stalled TCP/TLS handshake, a
/// network path that silently drops packets rather than refusing/timing out at
/// the OS level) hangs `fetch`'s caller forever -- `reqwest::Client::default()`
/// sets no timeout of its own. Found live: a native (Tauri/Android) build's
/// onboarding got stuck indefinitely on its own "Setting up…" button with no
/// error ever surfacing, because this exact call -- resolving the mediator's
/// did:web document as part of packing the first `mediate-request` -- never
/// resolved or rejected. Set per-request (`RequestBuilder::timeout`, not
/// `ClientBuilder::timeout`) since only the former exists on every target this
/// crate builds for -- reqwest's wasm32 `ClientBuilder` has no `timeout` method
/// at all (the browser's own `fetch()` has its own unrelated timeout/abort
/// semantics there), but `RequestBuilder::timeout` works identically on both.
const FETCH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

/// The body, read no further than [`MAX_DOCUMENT_BYTES`].
#[cfg(not(target_arch = "wasm32"))]
async fn read_capped(mut response: reqwest::Response, did: &str) -> Result<Vec<u8>, DidWebError> {
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if bytes.len() + chunk.len() > MAX_DOCUMENT_BYTES {
            return Err(DidWebError::TooLarge(did.to_string()));
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

/// (In a browser the body comes whole; the browser bounds what it fetches.)
#[cfg(target_arch = "wasm32")]
async fn read_capped(response: reqwest::Response, did: &str) -> Result<Vec<u8>, DidWebError> {
    let bytes = response.bytes().await?;
    if bytes.len() > MAX_DOCUMENT_BYTES {
        return Err(DidWebError::TooLarge(did.to_string()));
    }
    Ok(bytes.to_vec())
}

async fn fetch(client: &reqwest::Client, did: &str, uri: &str) -> Result<Value, DidWebError> {
    let response = client
        .get(uri)
        .header("User-Agent", "DIDCommRelay/1.0")
        .timeout(FETCH_TIMEOUT)
        .send()
        .await?;

    if response.status() == reqwest::StatusCode::NOT_FOUND {
        return Err(DidWebError::NotFound(did.to_string()));
    }
    if !response.status().is_success() {
        return Err(DidWebError::ServerError {
            did: did.to_string(),
            status: response.status().as_u16(),
        });
    }

    if response.content_length().is_some_and(|len| len as usize > MAX_DOCUMENT_BYTES) {
        return Err(DidWebError::TooLarge(did.to_string()));
    }
    let bytes = read_capped(response, did).await?;
    serde_json::from_slice(&bytes).map_err(|source| DidWebError::InvalidJson {
        did: did.to_string(),
        source,
    })
}

/// One cached lookup.
struct Cached {
    /// When it was fetched, in `now_ms()` milliseconds (`f64`, not
    /// `std::time::Instant`: see `now_ms`).
    at: f64,
    /// When it was last used, by a counter rather than the clock (two uses in one
    /// millisecond still have an order).
    used: u64,
    /// The document, or why there is none.
    outcome: Result<Value, String>,
}

impl Cached {
    fn fresh(&self, now: f64) -> bool {
        let ttl = if self.outcome.is_ok() { CACHE_TTL_SECS } else { FAILED_TTL_SECS };
        now - self.at < ttl * 1000.0
    }
}

#[derive(Default)]
struct Cache {
    entries: HashMap<String, Cached>,
    uses: u64,
}

/// `did:web` as a [`DIDResolver`](didcomm_core::resolver::DIDResolver).
pub struct DidWeb {
    client: reqwest::Client,
    cache: Mutex<Cache>,
    capacity: usize,
}

impl DidWeb {
    pub fn new() -> Self {
        Self::with_capacity(MOST_CACHED)
    }

    /// One that keeps at most `capacity` DIDs (at least one).
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            client: reqwest::Client::new(),
            cache: Mutex::new(Cache::default()),
            capacity: capacity.max(1),
        }
    }

    /// What is cached for `did`, if it is still fresh; an expired entry is dropped.
    fn cached(&self, did: &str) -> Option<Result<Value, String>> {
        let now = now_ms();
        let mut cache = self.cache.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        cache.uses += 1;
        let uses = cache.uses;
        match cache.entries.get_mut(did) {
            Some(entry) if entry.fresh(now) => {
                entry.used = uses;
                Some(entry.outcome.clone())
            }
            Some(_) => {
                cache.entries.remove(did);
                None
            }
            None => None,
        }
    }

    /// Keeps `outcome` for `did`, making room first: expired entries go, then the
    /// least recently used.
    fn remember(&self, did: &str, outcome: Result<Value, String>) {
        let now = now_ms();
        let mut cache = self.cache.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if !cache.entries.contains_key(did) && cache.entries.len() >= self.capacity {
            cache.entries.retain(|_, entry| entry.fresh(now));
            if cache.entries.len() >= self.capacity {
                let oldest = cache.entries.iter().min_by_key(|(_, entry)| entry.used).map(|(did, _)| did.clone());
                if let Some(oldest) = oldest {
                    cache.entries.remove(&oldest);
                }
            }
        }
        cache.uses += 1;
        let used = cache.uses;
        cache.entries.insert(did.to_string(), Cached { at: now, used, outcome });
    }

    /// How many DIDs are cached (successes and failures).
    pub fn cached_count(&self) -> usize {
        self.cache.lock().unwrap_or_else(std::sync::PoisonError::into_inner).entries.len()
    }
}

impl Default for DidWeb {
    fn default() -> Self {
        Self::new()
    }
}

impl DidWeb {
    async fn resolve_impl(&self, did: &str) -> Result<Value, ResolutionError> {
        let uri = did_to_uri(did).map_err(|e| ResolutionError::Resolution(e.to_string()))?;
        self.resolve_at(did, &uri).await
    }

    /// `did`'s document, from the cache or fetched from `uri`.
    async fn resolve_at(&self, did: &str, uri: &str) -> Result<Value, ResolutionError> {
        if let Some(outcome) = self.cached(did) {
            return outcome.map_err(ResolutionError::Resolution);
        }
        // Refused by the gate: not cached, since it says nothing about the DID.
        didcomm_core::resolver::check_fetch(did)?;
        let outcome = fetch(&self.client, did, uri).await.map_err(|e| e.to_string());
        self.remember(did, outcome.clone());
        outcome.map_err(ResolutionError::Resolution)
    }
}

// Split by target for the same reason didcomm-core's DIDResolver trait itself is --
// see that trait's own doc comment. reqwest's wasm implementation goes through JS
// Promise/JsFuture, which aren't (and can't be) Send.
#[cfg(not(target_arch = "wasm32"))]
#[async_trait]
impl DIDResolver for DidWeb {
    async fn resolve(&self, did: &str) -> Result<Value, ResolutionError> {
        self.resolve_impl(did).await
    }

    async fn is_resolvable(&self, did: &str) -> bool {
        is_did_web(did)
    }
}

#[cfg(target_arch = "wasm32")]
#[async_trait(?Send)]
impl DIDResolver for DidWeb {
    async fn resolve(&self, did: &str) -> Result<Value, ResolutionError> {
        self.resolve_impl(did).await
    }

    async fn is_resolvable(&self, did: &str) -> bool {
        is_did_web(did)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    #[test]
    fn maps_dids_to_uris() {
        assert_eq!(
            did_to_uri("did:web:example.com").unwrap(),
            "https://example.com/.well-known/did.json"
        );
        assert_eq!(
            did_to_uri("did:web:example.com:user:alice").unwrap(),
            "https://example.com/user/alice/did.json"
        );
        assert_eq!(
            did_to_uri("did:web:example.com%3A8443").unwrap(),
            "https://example.com:8443/.well-known/did.json"
        );
    }

    #[test]
    fn recognizes_resolvable_dids() {
        assert!(is_did_web("did:web:example.com"));
        assert!(is_did_web("did:web:example.com:user:alice"));
        assert!(is_did_web("did:web:example.com%3A8443"));
        assert!(!is_did_web("did:web:"));
        assert!(!is_did_web("did:web:not-a-domain"));
        assert!(!is_did_web("did:peer:2.Vz6Mk"));
    }

    /// Spawns a background thread serving exactly one plain-HTTP response, and returns
    /// the URI it's listening on. Deliberately not using a real async server/tokio
    /// here -- this only needs to prove `fetch`'s HTTP-status/JSON-decode handling,
    /// not stand in for a production did:web host.
    fn serve_once(status_line: &'static str, body: &'static str) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0u8; 1024];
                let _ = stream.read(&mut buf);
                let response = format!(
                    "{status_line}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes());
            }
        });
        format!("http://{addr}/did.json")
    }

    #[tokio::test]
    async fn fetches_and_decodes_a_document() {
        let uri = serve_once("HTTP/1.1 200 OK", r#"{"id":"did:web:example.com"}"#);
        let doc = fetch(&reqwest::Client::new(), "did:web:example.com", &uri)
            .await
            .unwrap();
        assert_eq!(doc["id"], "did:web:example.com");
    }

    #[tokio::test]
    async fn maps_404_to_a_not_found_error() {
        let uri = serve_once("HTTP/1.1 404 Not Found", "");
        let err = fetch(&reqwest::Client::new(), "did:web:example.com", &uri)
            .await
            .unwrap_err();
        assert!(matches!(err, DidWebError::NotFound(_)));
    }

    /// Security review WYV-73: bounded, the least recently used let go first, a
    /// failure remembered briefly, expired entries dropped.
    #[test]
    fn the_cache_is_bounded_and_lets_the_least_recently_used_go() {
        let resolver = DidWeb::with_capacity(3);
        for n in 0..3 {
            resolver.remember(&format!("did:web:{n}.example"), Ok(serde_json::json!({ "n": n })));
        }
        // 0 is used, so 1 is now the least recently used.
        assert!(resolver.cached("did:web:0.example").is_some());
        resolver.remember("did:web:3.example", Err("not found".into()));
        assert_eq!(resolver.cached_count(), 3);
        assert!(resolver.cached("did:web:1.example").is_none());
        assert!(resolver.cached("did:web:0.example").is_some());
        assert_eq!(resolver.cached("did:web:3.example"), Some(Err("not found".into())));

        // A failure is kept for a minute, a document for 30; past that, dropped.
        let age = |did: &str, secs: f64| resolver.cache.lock().unwrap().entries.get_mut(did).unwrap().at -= secs * 1000.0;
        age("did:web:3.example", FAILED_TTL_SECS + 1.0);
        age("did:web:0.example", FAILED_TTL_SECS + 1.0);
        assert!(resolver.cached("did:web:3.example").is_none());
        assert!(resolver.cached("did:web:0.example").is_some());
        assert_eq!(resolver.cached_count(), 2);
        // Full again: expired entries are dropped before anything in use.
        age("did:web:2.example", CACHE_TTL_SECS + 1.0);
        resolver.remember("did:web:4.example", Ok(serde_json::json!({})));
        resolver.remember("did:web:5.example", Ok(serde_json::json!({})));
        assert!(resolver.cached("did:web:0.example").is_some(), "the expired one went, not this");
        assert_eq!(resolver.cached_count(), 3);
    }

    /// A failed lookup is answered from the cache for a minute: the second message
    /// naming it costs no fetch (this server answers only once).
    #[tokio::test]
    async fn a_failed_lookup_is_not_fetched_again_at_once() {
        let uri = serve_once("HTTP/1.1 404 Not Found", "");
        let resolver = DidWeb::new();
        let first = resolver.resolve_at("did:web:gone.example", &uri).await.unwrap_err();
        let second = resolver.resolve_at("did:web:gone.example", &uri).await.unwrap_err();
        assert_eq!(first.to_string(), second.to_string());
    }

    /// The fetch gate is asked before a fetch, never for what is cached, and a
    /// refusal is its own error, not cached. (Process-wide: the one test that sets it.)
    #[tokio::test]
    async fn the_fetch_gate_is_asked_before_fetching() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        let asked = Arc::new(AtomicUsize::new(0));
        let counted = asked.clone();
        didcomm_core::resolver::set_fetch_gate(Some(Arc::new(move |did: &str| {
            if !did.contains("gated-test") {
                return Ok(());
            }
            counted.fetch_add(1, Ordering::SeqCst);
            Err("over budget".to_string())
        })));
        let resolver = DidWeb::new();
        let refused = resolver.resolve_at("did:web:gated-test.example", "http://127.0.0.1:9/").await.unwrap_err();
        assert!(refused.is_fetch_refused(), "{refused}");
        assert!(resolver.cached("did:web:gated-test.example").is_none());
        resolver.remember("did:web:gated-test.example", Ok(serde_json::json!({})));
        assert!(resolver.resolve_at("did:web:gated-test.example", "http://127.0.0.1:9/").await.is_ok());
        assert_eq!(asked.load(Ordering::SeqCst), 1);
        didcomm_core::resolver::set_fetch_gate(None);
    }

    #[tokio::test]
    async fn maps_invalid_json_to_an_error() {
        let uri = serve_once("HTTP/1.1 200 OK", "not json");
        let err = fetch(&reqwest::Client::new(), "did:web:example.com", &uri)
            .await
            .unwrap_err();
        assert!(matches!(err, DidWebError::InvalidJson { .. }));
    }
}
