//! `did:web` resolution, mirroring `didcomm_messaging.resolver.web`.
//!
//! The one resolver so far that needs real network I/O: `did:web:<hostname>[:path...]`
//! maps to `https://<hostname>/<path or .well-known>/did.json`, fetched over HTTP. Also
//! the one resolver so far with any internal state -- a simple 30-minute TTL cache,
//! matching the Python original's (process-global, in that version) cache.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use didcomm_core::resolver::{DIDResolver, ResolutionError};
use serde_json::Value;

const CACHE_TTL: Duration = Duration::from_secs(1800);

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
}

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
async fn fetch(client: &reqwest::Client, did: &str, uri: &str) -> Result<Value, DidWebError> {
    let response = client
        .get(uri)
        .header("User-Agent", "DIDCommRelay/1.0")
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

    let bytes = response.bytes().await?;
    serde_json::from_slice(&bytes).map_err(|source| DidWebError::InvalidJson {
        did: did.to_string(),
        source,
    })
}

/// `did:web` as a [`DIDResolver`](didcomm_core::resolver::DIDResolver).
pub struct DidWeb {
    client: reqwest::Client,
    cache: Mutex<HashMap<String, (Instant, Value)>>,
}

impl DidWeb {
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::new(),
            cache: Mutex::new(HashMap::new()),
        }
    }
}

impl Default for DidWeb {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl DIDResolver for DidWeb {
    async fn resolve(&self, did: &str) -> Result<Value, ResolutionError> {
        {
            let cache = self.cache.lock().expect("lock poisoned");
            if let Some((fetched_at, doc)) = cache.get(did) {
                if fetched_at.elapsed() < CACHE_TTL {
                    return Ok(doc.clone());
                }
            }
        } // guard dropped before the .await below

        let uri = did_to_uri(did).map_err(|e| ResolutionError::Resolution(e.to_string()))?;
        let doc = fetch(&self.client, did, &uri)
            .await
            .map_err(|e| ResolutionError::Resolution(e.to_string()))?;

        self.cache
            .lock()
            .expect("lock poisoned")
            .insert(did.to_string(), (Instant::now(), doc.clone()));
        Ok(doc)
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

    #[tokio::test]
    async fn maps_invalid_json_to_an_error() {
        let uri = serve_once("HTTP/1.1 200 OK", "not json");
        let err = fetch(&reqwest::Client::new(), "did:web:example.com", &uri)
            .await
            .unwrap_err();
        assert!(matches!(err, DidWebError::InvalidJson { .. }));
    }
}
