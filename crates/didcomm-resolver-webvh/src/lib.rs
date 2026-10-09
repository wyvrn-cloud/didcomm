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
//! code doesn't build there (0.7.0 reads a response with `Response::chunk()`, which
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
/// Each call to `resolve` creates a fresh `DIDWebVHState` rather than caching one per
/// DID -- `didwebvh-rs` already does its own log-entry-level caching/expiry internally,
/// so there's no correctness reason to add a second cache layer here the way
/// `did:web`'s resolver does for its much simpler plain HTTP GET.
#[derive(Debug, Default, Clone, Copy)]
pub struct DidWebVh;

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

#[cfg(not(target_arch = "wasm32"))]
#[async_trait]
impl DIDResolver for DidWebVh {
    async fn resolve(&self, did: &str) -> Result<Value, ResolutionError> {
        let mut state = DIDWebVHState::default();
        let (entry, _metadata) = state
            .resolve(did, ResolveOptions::default())
            .await
            .map_err(|e| ResolutionError::Resolution(e.to_string()))?;
        entry
            .get_did_document()
            .map_err(|e| ResolutionError::Resolution(e.to_string()))
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

        resolve_from_log(did, &log, witnesses.as_deref()).await
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
