//! `did:webvh` resolution, wrapping the `didwebvh-rs` crate rather than
//! reimplementing it -- verifiable-history validation (SCID derivation, hash-chained
//! log entries, witness proofs) is real spec-compliance work, not a good candidate to
//! hand-roll, unlike the pure string/JSON manipulation `did:peer:2`/`did:peer:4`
//! needed. See `PLAN.md` §4 for the full rationale and the spike this crate is the
//! result of: `didwebvh-rs` is actively maintained, has no forced dependency on the
//! `ssi` crate (its `ssi` integration is feature-gated and left off here), and is
//! visibly wasm32-aware throughout its own source (`#[cfg(target_arch = "wasm32")]`
//! branches avoiding `tokio::spawn` in favor of sequential fetches) -- all good signs
//! for this workspace's eventual wasm target.
//!
//! There's no `didcomm_messaging.resolver`-equivalent for `did:webvh` to mirror or
//! check wire compatibility against -- the Python reference library doesn't implement
//! this method at all -- so the tests here validate this wrapper against
//! `didwebvh-rs`'s own writer API instead of a captured fixture from elsewhere.
//!
//! On wasm32 the fetching is this crate's own, not `didwebvh-rs`'s: its network
//! code doesn't build there (0.7.0 and 0.8.0 read a response with `Response::chunk()`, which
//! reqwest's wasm target lacks). Nothing about verification changes -- the log is
//! fetched here and handed to the same `resolve_log` that checks the SCID, the hash
//! chain, every entry's proof and the witnesses.

use async_trait::async_trait;
use didcomm_core::resolver::{DIDResolver, ResolutionError};
#[cfg(not(target_arch = "wasm32"))]
use didwebvh_rs::resolve::ResolveOptions;
use didwebvh_rs::{log_entry::LogEntryMethods, DIDWebVHState};
use serde_json::Value;

/// `did:webvh` as a [`DIDResolver`](didcomm_core::resolver::DIDResolver).
///
/// What a DID resolved to is kept for [`KEPT_FOR_MS`], process-wide (the struct
/// stays `Copy`): every message to a party at a `did:webvh`, and every one from it,
/// resolves it, and each resolution fetched and verified its whole log again --
/// twice per request to a community that speaks as one. `didwebvh-rs`'s own cache
/// lives in a `DIDWebVHState`, which is made afresh for each call here.
///
/// A change to the DID (its keys rotated) is seen once what was kept expires, as
/// `did:web`'s resolver sees one after its 30 minutes.
#[derive(Debug, Default, Clone, Copy)]
pub struct DidWebVh;

/// How long a resolved document is kept: five minutes.
pub const KEPT_FOR_MS: f64 = 5.0 * 60.0 * 1000.0;

/// At most this many documents are kept; past it, all are let go.
const MOST_KEPT: usize = 1000;

static KEPT: std::sync::Mutex<Option<std::collections::HashMap<String, (f64, Value)>>> = std::sync::Mutex::new(None);

/// Milliseconds since 1970, on every target: `std::time::Instant` panics on
/// `wasm32-unknown-unknown` (see `didcomm-resolver-web`'s `now_ms`).
#[cfg(not(target_arch = "wasm32"))]
fn now_ms() -> f64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH).map(|since| since.as_secs_f64() * 1000.0).unwrap_or(0.0)
}

#[cfg(target_arch = "wasm32")]
fn now_ms() -> f64 {
    js_sys::Date::now()
}

/// What `did` resolved to within [`KEPT_FOR_MS`], if anything.
fn kept(did: &str) -> Option<Value> {
    let kept = KEPT.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    kept.as_ref()?.get(did).filter(|(at, _)| now_ms() - at < KEPT_FOR_MS).map(|(_, document)| document.clone())
}

fn keep(did: &str, document: &Value) {
    let mut kept = KEPT.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let kept = kept.get_or_insert_with(std::collections::HashMap::new);
    if kept.len() >= MOST_KEPT {
        kept.clear();
    }
    kept.insert(did.to_string(), (now_ms(), document.clone()));
}

/// Lets go of every document kept, so that the next resolution of each fetches and
/// verifies its log again.
pub fn forget_kept() {
    *KEPT.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
}

fn is_did_webvh(did: &str) -> bool {
    did.starts_with("did:webvh:")
}

/// The document a `did:webvh` log resolves to, fully verified: `did`'s SCID against
/// the first entry, each entry against the one before it, every proof against the
/// keys allowed to update at that point, and `witness_proofs` (the contents of
/// `did-witness.json`, if the DID publishes one) against whatever witnessing the
/// log's own parameters require. No network involved -- the caller has the files.
pub async fn resolve_from_log(
    did: &str,
    log: &str,
    witness_proofs: Option<&str>,
) -> Result<Value, ResolutionError> {
    let mut state = DIDWebVHState::default();
    let (entry, _metadata) = state
        .resolve_log(did, log, witness_proofs)
        .await
        .map_err(|e| ResolutionError::Resolution(e.to_string()))?;
    entry
        .get_did_document()
        .map_err(|e| ResolutionError::Resolution(e.to_string()))
}

/// Whether this process resolves `did:webvh`s at private hosts (see
/// [`allow_private_hosts`]).
#[cfg(not(target_arch = "wasm32"))]
static PRIVATE_HOSTS: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// For tests and local development only: from now on this process resolves
/// `did:webvh`s at loopback and private-network hosts too, `localhost` and
/// `*.localhost` over plain `http://` (didwebvh-rs's `HostPolicy::AllowPrivate`).
/// By default only public hosts are fetched, so that a DID someone hands over
/// can't make a server fetch from its own network.
///
/// A call in code, never a setting: nothing a deployment is configured with can
/// turn it on.
#[cfg(not(target_arch = "wasm32"))]
pub fn allow_private_hosts() {
    PRIVATE_HOSTS.store(true, std::sync::atomic::Ordering::Relaxed);
}

#[cfg(not(target_arch = "wasm32"))]
fn resolve_options() -> ResolveOptions {
    if PRIVATE_HOSTS.load(std::sync::atomic::Ordering::Relaxed) {
        ResolveOptions::default().with_host_policy(didwebvh_rs::resolve::HostPolicy::AllowPrivate)
    } else {
        ResolveOptions::default()
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[async_trait]
impl DIDResolver for DidWebVh {
    async fn resolve(&self, did: &str) -> Result<Value, ResolutionError> {
        if let Some(document) = kept(did) {
            return Ok(document);
        }
        let mut state = DIDWebVHState::default();
        let (entry, _metadata) = state
            .resolve(did, resolve_options())
            .await
            .map_err(|e| ResolutionError::Resolution(e.to_string()))?;
        let document = entry
            .get_did_document()
            .map_err(|e| ResolutionError::Resolution(e.to_string()))?;
        keep(did, &document);
        Ok(document)
    }

    async fn is_resolvable(&self, did: &str) -> bool {
        is_did_webvh(did)
    }
}

/// See `didcomm-resolver-web`'s own `FETCH_TIMEOUT`: a fetch nothing answers must
/// fail, not hang whoever is waiting on the document.
#[cfg(target_arch = "wasm32")]
const FETCH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

/// A log this long is not a DID's history but something else, or an attempt to make
/// resolving one expensive. `didwebvh-rs`'s own fetch has the same kind of bound.
#[cfg(target_arch = "wasm32")]
const MAX_FILE_BYTES: usize = 2 * 1024 * 1024;

/// The text at `url`, or `None` if there is nothing there (a 404).
#[cfg(target_arch = "wasm32")]
async fn fetch_text(client: &reqwest::Client, url: &str) -> Result<Option<String>, ResolutionError> {
    let failed = |what: String| ResolutionError::Resolution(format!("fetching {url}: {what}"));
    let response = client
        .get(url)
        .timeout(FETCH_TIMEOUT)
        .send()
        .await
        .map_err(|e| failed(e.to_string()))?;
    if response.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    if !response.status().is_success() {
        return Err(failed(format!("HTTP {}", response.status().as_u16())));
    }
    let bytes = response.bytes().await.map_err(|e| failed(e.to_string()))?;
    if bytes.len() > MAX_FILE_BYTES {
        return Err(failed(format!("{} bytes is more than a DID log should be", bytes.len())));
    }
    String::from_utf8(bytes.to_vec())
        .map(Some)
        .map_err(|e| failed(e.to_string()))
}

// `?Send` for the same reason `didcomm-resolver-web`'s wasm impl is: reqwest's wasm
// implementation goes through JS promises, which aren't Send.
#[cfg(target_arch = "wasm32")]
#[async_trait(?Send)]
impl DIDResolver for DidWebVh {
    async fn resolve(&self, did: &str) -> Result<Value, ResolutionError> {
        use didwebvh_rs::url::WebVHURL;

        if let Some(document) = kept(did) {
            return Ok(document);
        }
        let invalid = |e: didwebvh_rs::DIDWebVHError| ResolutionError::Resolution(e.to_string());
        let parsed = WebVHURL::parse_did_url(did).map_err(invalid)?;
        let log_url = parsed.get_http_url(None).map_err(invalid)?;
        let witness_url = parsed.get_http_url(Some("did-witness.json")).map_err(invalid)?;

        let client = reqwest::Client::new();
        let log = fetch_text(&client, log_url.as_str())
            .await?
            .ok_or_else(|| ResolutionError::Resolution(format!("{log_url} has no DID log")))?;
        // Most DIDs have no witnesses and publish no such file. One that needs them
        // and doesn't publish them fails verification below, as it should; a file
        // that can't be fetched is treated the same as one that isn't there.
        let witnesses = fetch_text(&client, witness_url.as_str()).await.ok().flatten();

        let document = resolve_from_log(did, &log, witnesses.as_deref()).await?;
        keep(did, &document);
        Ok(document)
    }

    async fn is_resolvable(&self, did: &str) -> bool {
        is_did_webvh(did)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use affinidi_secrets_resolver::secrets::Secret;
    use serde_json::json;
    use std::sync::Arc;

    #[test]
    fn a_resolved_document_is_kept_for_a_while_and_can_be_let_go() {
        let did = "did:webvh:QmKeptTest:example.com";
        assert!(kept(did).is_none());
        keep(did, &json!({ "id": did }));
        assert_eq!(kept(did), Some(json!({ "id": did })));
        // Kept longer than it may be, it is as good as not kept.
        KEPT.lock().unwrap().as_mut().unwrap().get_mut(did).unwrap().0 -= KEPT_FOR_MS + 1.0;
        assert!(kept(did).is_none());
        keep(did, &json!({ "id": did }));
        forget_kept();
        assert!(kept(did).is_none());
    }

    #[test]
    fn resolves_a_locally_constructed_log_offline() {
        // No network involved: build a real, validly signed did:webvh log with
        // didwebvh-rs's own writer API, then resolve it back with resolve_log (the
        // same read path `resolve` uses, minus the HTTP fetch) -- proving this
        // wrapper's document extraction is correct without depending on any
        // particular DID being live on the network.
        let mut key = Secret::generate_ed25519(None, None);
        let pk = key.get_public_keymultibase().unwrap();
        key.id = format!("did:key:{pk}#{pk}");

        let doc_template = json!({
            "id": "did:webvh:{SCID}:example.com",
            "@context": ["https://www.w3.org/ns/did/v1"],
            "verificationMethod": [{
                "id": "did:webvh:{SCID}:example.com#key-0",
                "type": "Multikey",
                "publicKeyMultibase": pk,
                "controller": "did:webvh:{SCID}:example.com",
            }],
            "authentication": ["did:webvh:{SCID}:example.com#key-0"],
        });

        let parameters = didwebvh_rs::parameters::Parameters {
            update_keys: Some(Arc::new(vec![didwebvh_rs::Multibase::new(pk.clone())])),
            ..Default::default()
        };

        let mut writer_state = DIDWebVHState::default();
        pollster::block_on(writer_state.create_log_entry(None, &doc_template, &parameters, &key))
            .expect("creates a valid first log entry");

        let scid = writer_state.log_entries()[0]
            .log_entry
            .get_scid()
            .expect("first entry has a SCID")
            .to_string();
        let did = format!("did:webvh:{scid}:example.com");

        let raw_log = writer_state
            .log_entries()
            .iter()
            .map(|e| serde_json::to_string(&e.log_entry).unwrap())
            .collect::<Vec<_>>()
            .join("\n");

        let document = pollster::block_on(resolve_from_log(&did, &raw_log, None))
            .expect("resolves the locally-constructed log");

        assert_eq!(document["id"], did);
        assert_eq!(
            document["verificationMethod"][0]["publicKeyMultibase"],
            pk
        );

        // The same log is refused the moment it stops being what was signed: this is
        // the path the wasm build resolves through, so it is what stands between a
        // tampered `did.jsonl` and a caller believing its contents.
        let tampered = raw_log.replace("example.com#key-0", "example.com#key-9");
        assert_ne!(tampered, raw_log);
        assert!(pollster::block_on(resolve_from_log(&did, &tampered, None)).is_err());

        // And refused for a DID it isn't the log of.
        let other = format!("did:webvh:{scid}:elsewhere.example");
        assert!(pollster::block_on(resolve_from_log(&other, &raw_log, None)).is_err());
    }

    #[test]
    fn is_resolvable_checks_the_method_prefix() {
        pollster::block_on(async {
            let resolver = DidWebVh;
            assert!(resolver.is_resolvable("did:webvh:abc:example.com").await);
            assert!(!resolver.is_resolvable("did:web:example.com").await);
        });
    }
}
