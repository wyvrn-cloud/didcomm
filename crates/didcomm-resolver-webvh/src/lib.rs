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
/// What a DID resolved to is kept, process-wide (the struct stays `Copy`): every
/// message to a party at a `did:webvh`, and every one from it, resolves it, and each
/// resolution used to fetch and verify its whole log again. Two limits:
///
/// - **Soft**: a document is used for its log's `ttl` (did:webvh: "how long, in
///   seconds, a resolver should cache the resolved DID", 3600 when not set, 0 "should
///   not be cached"), and never more than [`KEPT_FOR_MS`] (4 hours), unless something
///   asked of it isn't there -- a message naming a key it doesn't list. Then
///   [`resolve_fresh`](DIDResolver::resolve_fresh) fetches the log again at once, to
///   find out whether the DID really changed. Past that it is fetched again, so a
///   key taken out of the log (a device lost) stops being trusted within hours
///   (security review WYV-54); if the fetch fails, what is held is used for up to
///   [`STALE_AT_MOST_MS`] (24 hours), so that a host being down for a while
///   doesn't stop every message, while whoever can block the log's host keeps a
///   removed key trusted for a day at most, not a month. That day holds on every
///   path: for the one whose fetch failed, for whoever waited on that fetch, and for
///   whoever asks in the minute after it (security review WYV-104).
/// - **Hard**: a DID is fetched at most once in [`FETCHED_AT_MOST_EVERY_MS`] (a
///   minute), whatever happens -- including when that fetch failed or the DID isn't
///   there at all. Someone who claims to be the DID with keys its log doesn't have
///   can send as many messages as they like and cause one fetch a minute, so the
///   host isn't flooded on their account.
#[derive(Debug, Default, Clone, Copy)]
pub struct DidWebVh;

/// The longest a resolved document is used without asking again, whatever its
/// log's `ttl`: 4 hours.
pub const KEPT_FOR_MS: f64 = 4.0 * 60.0 * 60.0 * 1000.0;

/// A log's `ttl` when it sets none (did:webvh: "Defaults to 3600 (1 hour)"), in
/// seconds.
pub const DEFAULT_TTL_SECONDS: u32 = 3600;

/// How long a document is used past [`KEPT_FOR_MS`] while its log can't be
/// fetched: 24 hours (security review WYV-54).
pub const STALE_AT_MOST_MS: f64 = 24.0 * 60.0 * 60.0 * 1000.0;

/// The least time between two fetches of one DID's log: a minute.
pub const FETCHED_AT_MOST_EVERY_MS: f64 = 60.0 * 1000.0;

/// At most this many DIDs are kept. Past it, those with nothing worth keeping go
/// first (a document past [`STALE_AT_MOST_MS`] not asked for in the last minute),
/// then the least recently used -- never all of them at once, which let anyone
/// flush the cache with a thousand made-up DIDs (security review WYV-73).
pub const MOST_KEPT: usize = 1000;

/// What is known of one DID.
struct Known {
    /// When its log was last asked for, whether or not that worked. Set as the
    /// fetch starts, so that messages arriving meanwhile don't each start one.
    asked_at: f64,
    /// The document it last resolved to, and when.
    document: Option<(f64, Value)>,
    /// How long that document is used without asking again: its log's `ttl`, at
    /// most [`KEPT_FOR_MS`].
    kept_for: f64,
    /// A fetch of it is under way: whoever asks meanwhile waits for that one
    /// rather than being told it was asked for a moment ago (which, at an app's
    /// start, failed every request but the first to a DID asked for at once).
    fetching: bool,
    /// Who is waiting for that fetch.
    waiters: Vec<std::task::Waker>,
    /// When it was last used, by a counter: which to let go first when full.
    used: u64,
}

impl Known {
    fn new(now: f64) -> Self {
        Known {
            asked_at: now,
            document: None,
            kept_for: KEPT_FOR_MS,
            fetching: false,
            waiters: Vec::new(),
            used: 0,
        }
    }

    /// Whether it is worth keeping at `now`: being fetched, asked for within the
    /// minute (so asking again is still held off), or with a document still usable.
    fn worth_keeping(&self, now: f64) -> bool {
        self.fetching
            || now - self.asked_at < FETCHED_AT_MOST_EVERY_MS
            || self
                .document
                .as_ref()
                .is_some_and(|(at, _)| now - at < STALE_AT_MOST_MS)
    }
}

/// What is known, and a counter of uses (for letting the least recently used go).
#[derive(Default)]
struct Kept {
    known: std::collections::HashMap<String, Known>,
    uses: u64,
}

impl Kept {
    /// Marks `did` used now.
    fn touch(&mut self, did: &str) {
        self.uses += 1;
        let uses = self.uses;
        if let Some(known) = self.known.get_mut(did) {
            known.used = uses;
        }
    }

    /// Makes room for one more DID, if `did` would be one more and it is full.
    fn make_room_for(&mut self, did: &str, now: f64) {
        if self.known.contains_key(did) || self.known.len() < MOST_KEPT {
            return;
        }
        self.known.retain(|_, known| known.worth_keeping(now));
        if self.known.len() >= MOST_KEPT {
            // Never one being fetched: someone is waiting on it.
            let oldest = self
                .known
                .iter()
                .filter(|(_, known)| !known.fetching)
                .min_by_key(|(_, known)| known.used)
                .map(|(did, _)| did.clone());
            if let Some(oldest) = oldest {
                self.known.remove(&oldest);
            }
        }
    }
}

static KEPT: std::sync::Mutex<Option<Kept>> = std::sync::Mutex::new(None);

/// Milliseconds since 1970, on every target: `std::time::Instant` panics on
/// `wasm32-unknown-unknown` (see `didcomm-resolver-web`'s `now_ms`).
#[cfg(not(target_arch = "wasm32"))]
fn now_ms() -> f64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|since| since.as_secs_f64() * 1000.0)
        .unwrap_or(0.0)
}

#[cfg(target_arch = "wasm32")]
fn now_ms() -> f64 {
    js_sys::Date::now()
}

/// What to do about `did` now.
enum Next {
    /// Use this document.
    Use(Value),
    /// Fetch the log (and it has been noted as asked for).
    Fetch,
    /// It was asked for too recently to ask again, and there is nothing to use.
    Wait,
    /// It is being fetched now: wait for that.
    Join,
}

/// Decides, and notes the asking when it is to be fetched. `again`: the document
/// held lacks something asked of it, so it is only to be used if fetching isn't
/// allowed yet. A fetch is put to the [fetch gate](didcomm_core::resolver::check_fetch)
/// before anything is noted, so a refusal leaves nothing behind (and holds off no
/// one else's fetch for a minute).
fn next(did: &str, again: bool) -> Result<Next, ResolutionError> {
    let now = now_ms();
    let mut kept = KEPT.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let kept = kept.get_or_insert_with(Kept::default);
    kept.touch(did);
    let known = kept.known.get(did);
    let current = known
        .and_then(|known| {
            known
                .document
                .as_ref()
                .map(|document| (document, known.kept_for))
        })
        .filter(|((at, _), kept_for)| now - at < *kept_for)
        .map(|((_, document), _)| document.clone());
    if let (Some(document), false) = (&current, again) {
        return Ok(Next::Use(document.clone()));
    }
    if known.is_some_and(|known| now - known.asked_at < FETCHED_AT_MOST_EVERY_MS) {
        // Too soon to ask the host again: what is held, even past its ttl, but never
        // past the day a document is used for while its log can't be had (WYV-104).
        // (The minute is also how long a failed lookup is remembered: the negative
        // cache.)
        return Ok(match known {
            Some(known) if known.fetching => Next::Join,
            Some(Known {
                document: Some((at, document)),
                ..
            }) if !again && now - at < STALE_AT_MOST_MS => Next::Use(document.clone()),
            _ => Next::Wait,
        });
    }
    didcomm_core::resolver::check_fetch(did)?;
    kept.make_room_for(did, now);
    kept.uses += 1;
    let used = kept.uses;
    let known = kept
        .known
        .entry(did.to_string())
        .or_insert_with(|| Known::new(now));
    known.asked_at = now;
    known.fetching = true;
    known.used = used;
    Ok(Next::Fetch)
}

/// The fetch of `did` is over (done, failed, or dropped part-way): whoever waits
/// for it is woken.
fn fetch_over(did: &str) {
    let mut kept = KEPT.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(known) = kept.as_mut().and_then(|kept| kept.known.get_mut(did)) {
        known.fetching = false;
        for waker in known.waiters.drain(..) {
            waker.wake();
        }
    }
}

/// Ends the fetch however the fetching future ends, dropped included.
struct FetchGuard<'a>(&'a str);

impl Drop for FetchGuard<'_> {
    fn drop(&mut self) {
        fetch_over(self.0);
    }
}

/// Waits for the fetch of `did` under way, and gives the document held once it is
/// over, with when it was resolved (an old one if the fetch failed; none if there
/// is none). No runtime needed: the fetch wakes it (`fetch_over`).
struct Joined<'a>(&'a str);

impl std::future::Future for Joined<'_> {
    type Output = Option<(f64, Value)>;
    fn poll(
        self: std::pin::Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<(f64, Value)>> {
        let mut kept = KEPT.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        match kept.as_mut().and_then(|kept| kept.known.get_mut(self.0)) {
            Some(known) if known.fetching => {
                known.waiters.push(context.waker().clone());
                std::task::Poll::Pending
            }
            known => std::task::Poll::Ready(known.and_then(|known| known.document.clone())),
        }
    }
}

/// The document held for `did`, if it was resolved less than `within` ago.
fn held(did: &str, within: f64) -> Option<Value> {
    let now = now_ms();
    let kept = KEPT.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    kept.as_ref()?
        .known
        .get(did)?
        .document
        .as_ref()
        .filter(|(at, _)| now - at < within)
        .map(|(_, document)| document.clone())
}

#[cfg(test)]
fn keep(did: &str, document: &Value) {
    keep_for(did, document, KEPT_FOR_MS);
}

/// How long a document is used without asking again, for a log whose `ttl` is
/// `ttl_seconds`: that, at most [`KEPT_FOR_MS`].
fn kept_for(ttl_seconds: Option<u32>) -> f64 {
    (f64::from(ttl_seconds.unwrap_or(DEFAULT_TTL_SECONDS)) * 1000.0).min(KEPT_FOR_MS)
}

fn keep_for(did: &str, document: &Value, kept_for: f64) {
    let mut kept = KEPT.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let kept = kept.get_or_insert_with(Kept::default);
    let now = now_ms();
    kept.make_room_for(did, now);
    let known = kept
        .known
        .entry(did.to_string())
        .or_insert_with(|| Known::new(now));
    known.document = Some((now, document.clone()));
    known.kept_for = kept_for;
    kept.touch(did);
}

/// `did`'s document: what is kept, or its log fetched and verified. With `again`
/// (asked by `resolve_fresh`), `None` when it may not be fetched yet.
async fn resolve_kept(did: &str, again: bool) -> Result<Option<Value>, ResolutionError> {
    match next(did, again)? {
        Next::Use(document) => Ok(Some(document)),
        Next::Wait if again => Ok(None),
        Next::Wait => Err(ResolutionError::Resolution(format!(
            "{did} couldn't be resolved a moment ago; it is asked for again at most once a minute"
        ))),
        Next::Join => {
            let joined_at = now_ms();
            // What the fetch left: a document it brought, or (if it failed) one held
            // from before, used as the fetcher would, for a day at most (WYV-104).
            // `again` wants only a document that fetch brought.
            match Joined(did).await {
                Some((at, document)) if at >= joined_at => Ok(Some(document)),
                Some((at, document)) if !again && now_ms() - at < STALE_AT_MOST_MS => Ok(Some(document)),
                _ if again => Ok(None),
                _ => Err(ResolutionError::Resolution(format!(
                    "{did} couldn't be resolved a moment ago; it is asked for again at most once a minute"
                ))),
            }
        }
        Next::Fetch => {
            let _over = FetchGuard(did);
            match fetched(did).await {
                Ok((document, ttl)) => {
                    keep_for(did, &document, kept_for(ttl));
                    Ok(Some(document))
                }
                // Its host not answering is not the DID changing: what is held, if
                // it is not too old, rather than nothing.
                Err(error) => match held(did, STALE_AT_MOST_MS) {
                    Some(document) if !again => Ok(Some(document)),
                    _ => Err(error),
                },
            }
        }
    }
}

/// Lets go of everything kept, so that the next resolution of each DID fetches and
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
    Ok(resolve_from_log_with_ttl(did, log, witness_proofs).await?.0)
}

/// [`resolve_from_log`], and the log's `ttl` (seconds; `None` when it sets none).
pub async fn resolve_from_log_with_ttl(
    did: &str,
    log: &str,
    witness_proofs: Option<&str>,
) -> Result<(Value, Option<u32>), ResolutionError> {
    let mut state = DIDWebVHState::default();
    let (entry, metadata) = state
        .resolve_log(did, log, witness_proofs)
        .await
        .map_err(|e| ResolutionError::Resolution(e.to_string()))?;
    let document = entry
        .get_did_document()
        .map_err(|e| ResolutionError::Resolution(e.to_string()))?;
    Ok((document, ttl_of(&state, metadata.version_number)))
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
    // What was refused before is to be asked again.
    forget_kept();
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
        resolve_kept(did, false)
            .await?
            .ok_or_else(|| ResolutionError::Resolution(format!("{did} has no document")))
    }

    async fn resolve_fresh(&self, did: &str) -> Result<Option<Value>, ResolutionError> {
        resolve_kept(did, true).await
    }

    async fn is_resolvable(&self, did: &str) -> bool {
        is_did_webvh(did)
    }
}

/// `did`'s log fetched (by didwebvh-rs) and verified: its document, and its `ttl`.
#[cfg(not(target_arch = "wasm32"))]
async fn fetched(did: &str) -> Result<(Value, Option<u32>), ResolutionError> {
    let mut state = DIDWebVHState::default();
    let (entry, metadata) = state
        .resolve(did, resolve_options())
        .await
        .map_err(|e| ResolutionError::Resolution(e.to_string()))?;
    let document = entry
        .get_did_document()
        .map_err(|e| ResolutionError::Resolution(e.to_string()))?;
    Ok((document, ttl_of(&state, metadata.version_number)))
}

/// The `ttl` in force at the log entry resolved to (`version_number`): parameters
/// carry over from entry to entry, so it is that entry's validated one.
fn ttl_of(state: &DIDWebVHState, version_number: u32) -> Option<u32> {
    state
        .log_entries()
        .iter()
        .find(|entry| entry.version_number == version_number)
        .or_else(|| state.log_entries().last())
        .and_then(|entry| entry.validated_parameters.ttl)
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
async fn fetch_text(
    client: &reqwest::Client,
    url: &str,
) -> Result<Option<String>, ResolutionError> {
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
        return Err(failed(format!(
            "{} bytes is more than a DID log should be",
            bytes.len()
        )));
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
        resolve_kept(did, false)
            .await?
            .ok_or_else(|| ResolutionError::Resolution(format!("{did} has no document")))
    }

    async fn resolve_fresh(&self, did: &str) -> Result<Option<Value>, ResolutionError> {
        resolve_kept(did, true).await
    }

    async fn is_resolvable(&self, did: &str) -> bool {
        is_did_webvh(did)
    }
}

/// `did`'s log fetched (here: didwebvh-rs's own fetching doesn't build for wasm) and
/// verified by didwebvh-rs.
#[cfg(target_arch = "wasm32")]
async fn fetched(did: &str) -> Result<(Value, Option<u32>), ResolutionError> {
    use didwebvh_rs::url::WebVHURL;

    let invalid = |e: didwebvh_rs::DIDWebVHError| ResolutionError::Resolution(e.to_string());
    let parsed = WebVHURL::parse_did_url(did).map_err(invalid)?;
    let log_url = parsed.get_http_url(None).map_err(invalid)?;
    let witness_url = parsed
        .get_http_url(Some("did-witness.json"))
        .map_err(invalid)?;

    let client = reqwest::Client::new();
    let log = fetch_text(&client, log_url.as_str())
        .await?
        .ok_or_else(|| ResolutionError::Resolution(format!("{log_url} has no DID log")))?;
    // Most DIDs have no witnesses and publish no such file. One that needs them
    // and doesn't publish them fails verification below, as it should; a file
    // that can't be fetched is treated the same as one that isn't there.
    let witnesses = fetch_text(&client, witness_url.as_str())
        .await
        .ok()
        .flatten();

    resolve_from_log_with_ttl(did, &log, witnesses.as_deref()).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use affinidi_secrets_resolver::secrets::Secret;
    use serde_json::json;
    use std::sync::Arc;

    /// What is kept is process-wide: tests that read or change it take turns (one
    /// test's `forget_kept` once wiped another's state part-way).
    static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn serial() -> std::sync::MutexGuard<'static, ()> {
        SERIAL
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Moves what is known of `did` back in time by `ms`: its asking, and its document.
    fn age(did: &str, asked_ms: f64, document_ms: f64) {
        let mut kept = KEPT.lock().unwrap();
        let known = kept.as_mut().unwrap().known.get_mut(did).unwrap();
        known.asked_at -= asked_ms;
        if let Some((at, _)) = known.document.as_mut() {
            *at -= document_ms;
        }
    }

    /// Whether `did` is to be fetched now; if so, that fetch is taken to have ended
    /// (with nothing, unless `keep` follows).
    fn fetches(did: &str, again: bool) -> bool {
        let fetch = matches!(next(did, again), Ok(Next::Fetch));
        if fetch {
            fetch_over(did);
        }
        fetch
    }

    fn uses(did: &str, again: bool) -> Option<Value> {
        match next(did, again) {
            Ok(Next::Use(document)) => Some(document),
            _ => None,
        }
    }

    #[test]
    fn a_document_is_used_for_24_hours_past_its_4_asked_again_when_a_key_is_missing_but_never_more_than_once_a_minute(
    ) {
        let _serial = serial();
        let did = "did:webvh:QmKeptTest:example.com";
        let document = json!({ "id": did });

        // Never seen: fetched. A second message before the first fetch has
        // answered (or after it failed) doesn't fetch again.
        assert!(fetches(did, false));
        assert!(matches!(next(did, false), Ok(Next::Wait)));
        assert!(matches!(next(did, true), Ok(Next::Wait)));
        assert!(matches!(
            pollster::block_on(resolve_kept(did, true)),
            Ok(None)
        ));
        assert!(pollster::block_on(resolve_kept(did, false)).is_err());

        // Fetched: used, with no asking, for 4 hours.
        keep(did, &document);
        assert_eq!(uses(did, false), Some(document.clone()));
        age(did, KEPT_FOR_MS - 1000.0, KEPT_FOR_MS - 1000.0);
        assert_eq!(uses(did, false), Some(document.clone()));

        // A key it doesn't list: asked again at once, when the last asking was over a
        // minute ago...
        assert!(fetches(did, true));
        keep(did, &document);
        // ...and not again within the minute, however many messages name such a key.
        for _ in 0..100 {
            assert!(matches!(next(did, true), Ok(Next::Wait)));
        }
        assert_eq!(
            uses(did, false),
            Some(document.clone()),
            "what is held is still used meanwhile"
        );
        age(did, FETCHED_AT_MOST_EVERY_MS + 1.0, 0.0);
        assert!(fetches(did, true));

        // Past 4 hours it is fetched again; if that just failed, what was held is
        // used until a minute has passed.
        keep(did, &document);
        age(did, KEPT_FOR_MS + 1.0, KEPT_FOR_MS + 1.0);
        assert!(fetches(did, false));
        assert_eq!(uses(did, false), Some(document.clone()));

        // A failed re-fetch falls back on what is held for a day at most (WYV-54).
        let hour = 60.0 * 60.0 * 1000.0;
        age(did, 0.0, 19.0 * hour);
        assert_eq!(
            held(did, STALE_AT_MOST_MS),
            Some(document.clone()),
            "23 hours old"
        );
        age(did, 0.0, 2.0 * hour);
        assert_eq!(held(did, STALE_AT_MOST_MS), None, "25 hours old");

        forget_kept();
        assert!(fetches(did, false));
        forget_kept();
    }

    /// A wakeup that counts, for polling by hand.
    struct Counted(std::sync::atomic::AtomicUsize);
    impl std::task::Wake for Counted {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }

    #[test]
    fn whoever_asks_while_it_is_being_fetched_waits_for_that_fetch() {
        let _serial = serial();
        use std::future::Future;
        let did = "did:webvh:QmJoinTest:example.com";
        let document = json!({ "id": did });
        let woken = Arc::new(Counted(Default::default()));
        let waker = std::task::Waker::from(woken.clone());
        let mut context = std::task::Context::from_waker(&waker);

        // A fetch starts; a second asking meanwhile waits for it, not told it failed.
        assert!(matches!(next(did, false), Ok(Next::Fetch)));
        assert!(matches!(next(did, false), Ok(Next::Join)));
        let mut second = Box::pin(resolve_kept(did, false));
        assert!(second.as_mut().poll(&mut context).is_pending());
        // The fetch brings the document: the second is woken and given it.
        keep(did, &document);
        fetch_over(did);
        assert_eq!(woken.0.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert!(
            matches!(second.as_mut().poll(&mut context), std::task::Poll::Ready(Ok(Some(found))) if found == document)
        );

        // A fetch that fails (dropped here) wakes its waiters, who are told it failed.
        let other = "did:webvh:QmJoinFails:example.com";
        assert!(matches!(next(other, false), Ok(Next::Fetch)));
        let mut waiting = Box::pin(resolve_kept(other, false));
        assert!(waiting.as_mut().poll(&mut context).is_pending());
        drop(FetchGuard(other));
        assert!(matches!(
            waiting.as_mut().poll(&mut context),
            std::task::Poll::Ready(Err(_))
        ));
        // And then, as before, nothing more is fetched within the minute.
        assert!(matches!(next(other, false), Ok(Next::Wait)));
    }

    /// Security review WYV-104: a document past the day isn't handed out by the
    /// minute's hold-off after a failed fetch, nor to whoever waited on that fetch.
    #[test]
    fn past_a_day_a_document_is_used_on_no_path_while_its_log_cant_be_had() {
        let _serial = serial();
        use std::future::Future;
        let hour = 60.0 * 60.0 * 1000.0;
        let document = json!({ "id": "x" });

        // "Use": the fetch failed; within the minute after it, the old one isn't used.
        let did = "did:webvh:QmStaleUse:example.com";
        keep(did, &document);
        age(did, 25.0 * hour, 25.0 * hour);
        assert!(fetches(did, false), "past its keeping: fetched");
        assert!(
            matches!(next(did, false), Ok(Next::Wait)),
            "and, that having failed, nothing to use"
        );
        assert!(pollster::block_on(resolve_kept(did, false)).is_err());
        // A day-old one that is still under the day is used meanwhile, as before.
        let young = "did:webvh:QmStaleYoung:example.com";
        keep(young, &document);
        age(young, 23.0 * hour, 23.0 * hour);
        assert!(fetches(young, false));
        assert_eq!(uses(young, false), Some(document.clone()));

        // "Joined": a second resolution during a fetch that fails gets nothing either.
        let woken = Arc::new(Counted(Default::default()));
        let waker = std::task::Waker::from(woken.clone());
        let mut context = std::task::Context::from_waker(&waker);
        let joined = "did:webvh:QmStaleJoin:example.com";
        keep(joined, &document);
        age(joined, 25.0 * hour, 25.0 * hour);
        assert!(matches!(next(joined, false), Ok(Next::Fetch)));
        let mut waiting = Box::pin(resolve_kept(joined, false));
        assert!(waiting.as_mut().poll(&mut context).is_pending());
        drop(FetchGuard(joined));
        assert!(matches!(
            waiting.as_mut().poll(&mut context),
            std::task::Poll::Ready(Err(_))
        ));
        forget_kept();
    }

    /// A log's `ttl` is how long its document is used: 0 not at all past the minute's
    /// hold-off, 3600 s when it sets none, and never more than 4 hours.
    #[test]
    fn a_document_is_kept_for_its_logs_ttl_at_most_four_hours() {
        let _serial = serial();
        assert_eq!(kept_for(Some(0)), 0.0);
        assert_eq!(kept_for(None), 3_600_000.0);
        assert_eq!(kept_for(Some(600)), 600_000.0);
        assert_eq!(kept_for(Some(86_400)), KEPT_FOR_MS);

        let did = "did:webvh:QmTtl:example.com";
        let document = json!({ "id": did });
        keep_for(did, &document, kept_for(Some(600)));
        age(did, FETCHED_AT_MOST_EVERY_MS + 1.0, 599_000.0);
        assert_eq!(uses(did, false), Some(document.clone()), "within its ttl");
        age(did, 0.0, 2_000.0);
        assert!(
            fetches(did, false),
            "past its ttl, though well within 4 hours"
        );
        forget_kept();
    }

    /// Security review WYV-73: full, it lets go of what is past keeping, then the
    /// least recently used -- not everything, as it used to.
    #[test]
    fn when_full_the_least_recently_used_goes_not_everything() {
        let _serial = serial();
        forget_kept();
        let did = |n: usize| format!("did:webvh:QmFull{n}:example.com");
        for n in 0..MOST_KEPT {
            keep(&did(n), &json!({ "n": n }));
        }
        // 0 is used again; 1 is now the least recently used.
        assert!(uses(&did(0), false).is_some());
        keep(&did(MOST_KEPT), &json!({}));
        let count = || KEPT.lock().unwrap().as_ref().unwrap().known.len();
        assert_eq!(count(), MOST_KEPT);
        assert!(
            held(&did(1), KEPT_FOR_MS).is_none(),
            "the least recently used went"
        );
        assert!(held(&did(0), KEPT_FOR_MS).is_some());
        assert!(held(&did(2), KEPT_FOR_MS).is_some());

        // What is past keeping goes before anything still in use.
        for n in 2..12 {
            age(&did(n), STALE_AT_MOST_MS + 1.0, STALE_AT_MOST_MS + 1.0);
        }
        keep(&did(MOST_KEPT + 1), &json!({}));
        assert_eq!(count(), MOST_KEPT - 9);
        assert!(held(&did(0), KEPT_FOR_MS).is_some());
        forget_kept();
    }

    /// The fetch gate is asked before a fetch is noted: refused, nothing is
    /// recorded, so the next asking (gate willing) fetches at once.
    #[test]
    fn the_fetch_gate_is_asked_before_a_fetch() {
        let _serial = serial();
        let did = "did:webvh:QmGated:example.com";
        didcomm_core::resolver::set_fetch_gate(Some(Arc::new(|_: &str| {
            Err("over budget".to_string())
        })));
        assert!(matches!(
            next(did, false),
            Err(ResolutionError::FetchRefused { .. })
        ));
        didcomm_core::resolver::set_fetch_gate(None);
        assert!(fetches(did, false));
        forget_kept();
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
        // The same, with a ttl: read back from the log.
        {
            let mut with_ttl = DIDWebVHState::default();
            let parameters = didwebvh_rs::parameters::Parameters {
                ttl: Some(300),
                ..parameters.clone()
            };
            pollster::block_on(with_ttl.create_log_entry(None, &doc_template, &parameters, &key))
                .unwrap();
            let scid = with_ttl.log_entries()[0]
                .log_entry
                .get_scid()
                .unwrap()
                .to_string();
            let log = with_ttl
                .log_entries()
                .iter()
                .map(|e| serde_json::to_string(&e.log_entry).unwrap())
                .collect::<Vec<_>>()
                .join("\n");
            let (_, ttl) = pollster::block_on(resolve_from_log_with_ttl(
                &format!("did:webvh:{scid}:example.com"),
                &log,
                None,
            ))
            .unwrap();
            assert_eq!(ttl, Some(300));
        }

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
        assert_eq!(document["verificationMethod"][0]["publicKeyMultibase"], pk);

        // The same log is refused the moment it stops being what was signed: this is
        // the path the wasm build resolves through, so it is what stands between a
        // tampered `did.jsonl` and a caller believing its contents.
        let tampered = raw_log.replace("example.com#key-0", "example.com#key-9");
        assert_ne!(tampered, raw_log);
        assert!(pollster::block_on(resolve_from_log(&did, &tampered, None)).is_err());

        // A log that sets no ttl says none (the default, 3600, is the caller's).
        let (_, ttl) = pollster::block_on(resolve_from_log_with_ttl(&did, &raw_log, None)).unwrap();
        assert_eq!(ttl, None);

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
