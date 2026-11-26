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
///
/// And every log fetched is held to what was read before (multi-device/1.0, "A
/// receiver of an address"): it must continue the log last taken (no going back to
/// an older version), a key a log of the DID has dropped is never taken again, and
/// where the log names witnesses only witnessed entries count (didwebvh-rs verifies
/// the proofs, on both fetch paths). An app holding a message whose key isn't
/// listed asks again with [`read_again`].
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

/// Lets go of every document kept, so that the next resolution of each DID fetches
/// and verifies its log again. What is remembered of each DID's history (see
/// [`HISTORY`]'s rules: the log must continue the one held, a dropped key stays
/// dropped) is not let go of: that is what stops a host serving an old log to
/// whoever has just forgotten. [`forget_history`] lets go of that too.
pub fn forget_kept() {
    *KEPT.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
}

/// What a later read of `did` will be held to, remembered past the document itself
/// (multi-device/1.0, "A receiver of an address"; did-hosting/1.0, "Reading it"):
///
/// - **No going back.** The last log taken ended at `version` (its number and
///   `versionId`, which is `<n>-<entryHash>`). A log read again is taken only if it
///   has that very entry at that place: did:webvh 1.0's resolvers "SHOULD remember
///   the latest `versionId` previously observed". Since each entry's hash covers
///   the one before it, that one entry matching means every entry up to it does. A
///   log that ends before it, or differs there, is a failed read.
/// - **A key the log has dropped is dropped.** `keys` is what the last document
///   taken listed (each key, and each relationship it was under); whatever a newer
///   document no longer lists joins `dropped`, and is taken out of every document
///   handed back for the DID from then on, however the log goes on.
struct History {
    version: (u32, String),
    keys: std::collections::HashSet<String>,
    dropped: std::collections::HashSet<String>,
    used: u64,
}

/// At most this many DIDs' histories are remembered; past it, the least recently
/// read goes. Far more than [`MOST_KEPT`]: a history is small, and losing one is
/// what lets an old log back in.
pub const MOST_REMEMBERED: usize = 10_000;

#[derive(Default)]
struct Histories {
    of: std::collections::HashMap<String, History>,
    uses: u64,
}

static HISTORY: std::sync::Mutex<Option<Histories>> = std::sync::Mutex::new(None);

/// Lets go of what is remembered of every DID's history as well as every document
/// kept ([`forget_kept`]): from then on any log that verifies is taken again, and
/// keys once dropped may be. For tests, or an app wiping its state.
pub fn forget_history() {
    forget_kept();
    *HISTORY
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
}

/// The relationships a key can be listed under.
const RELATIONSHIPS: [&str; 5] = [
    "authentication",
    "assertionMethod",
    "keyAgreement",
    "capabilityInvocation",
    "capabilityDelegation",
];

/// A verification method's key, as text: its `publicKeyMultibase`, or its
/// `publicKeyJwk`'s JSON.
fn key_of(method: &Value) -> Option<String> {
    method
        .get("publicKeyMultibase")
        .and_then(Value::as_str)
        .map(|multibase| format!("mb:{multibase}"))
        .or_else(|| method.get("publicKeyJwk").map(|jwk| format!("jwk:{jwk}")))
}

/// `id` made absolute against the document's own.
fn absolute_id(document: &Value, id: &str) -> String {
    if id.starts_with('#') {
        format!(
            "{}{id}",
            document
                .get("id")
                .and_then(Value::as_str)
                .unwrap_or_default()
        )
    } else {
        id.to_string()
    }
}

/// The key a relationship's entry names: an embedded method's, or the one its
/// reference names in `verificationMethod`.
fn key_of_entry(document: &Value, entry: &Value) -> Option<String> {
    match entry {
        Value::String(reference) => {
            let reference = absolute_id(document, reference);
            document
                .get("verificationMethod")?
                .as_array()?
                .iter()
                .find(|method| {
                    method
                        .get("id")
                        .and_then(Value::as_str)
                        .is_some_and(|id| absolute_id(document, id) == reference)
                })
                .and_then(key_of)
        }
        method => key_of(method),
    }
}

/// Everything a document lists a key as: `method|<key>` for each verification
/// method, and `<relationship>|<key>` for each relationship it is under.
fn keys_listed(document: &Value) -> std::collections::HashSet<String> {
    let mut keys = std::collections::HashSet::new();
    for method in document
        .get("verificationMethod")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        if let Some(key) = key_of(method) {
            keys.insert(format!("method|{key}"));
        }
    }
    for relationship in RELATIONSHIPS {
        for entry in document
            .get(relationship)
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            if let Some(key) = key_of_entry(document, entry) {
                if entry.is_object() {
                    keys.insert(format!("method|{key}"));
                }
                keys.insert(format!("{relationship}|{key}"));
            }
        }
    }
    keys
}

/// `document` without what `dropped` says was dropped: a verification method whose
/// key was dropped altogether, and a key under a relationship it was dropped from.
fn without_dropped(mut document: Value, dropped: &std::collections::HashSet<String>) -> Value {
    if dropped.is_empty() {
        return document;
    }
    let original = document.clone();
    let gone = |relationship: &str, key: &Option<String>| {
        key.as_ref().is_some_and(|key| {
            dropped.contains(&format!("method|{key}"))
                || dropped.contains(&format!("{relationship}|{key}"))
        })
    };
    let mut removed = std::collections::HashSet::new();
    if let Some(methods) = document
        .get_mut("verificationMethod")
        .and_then(Value::as_array_mut)
    {
        methods.retain(|method| {
            let keep = !gone("method", &key_of(method));
            if !keep {
                if let Some(id) = method.get("id").and_then(Value::as_str) {
                    removed.insert(absolute_id(&original, id));
                }
            }
            keep
        });
    }
    for relationship in RELATIONSHIPS {
        if let Some(entries) = document.get_mut(relationship).and_then(Value::as_array_mut) {
            entries.retain(|entry| {
                let dangling = entry
                    .as_str()
                    .is_some_and(|id| removed.contains(&absolute_id(&original, id)));
                !dangling && !gone(relationship, &key_of_entry(&original, entry))
            });
        }
    }
    document
}

/// A log just fetched and verified (`state`, resolved to `document`), held to what
/// is remembered of `did` (see [`History`]): refused if it doesn't continue the log
/// taken last; otherwise remembered as the one taken, and its document handed back
/// without any key a log of this DID has dropped.
fn continued(did: &str, state: &DIDWebVHState, document: Value) -> Result<Value, ResolutionError> {
    let entries = state.log_entries();
    let last = entries
        .last()
        .ok_or_else(|| ResolutionError::Resolution(format!("{did}'s log has no entries")))?;
    let mut histories = HISTORY
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let histories = histories.get_or_insert_with(Histories::default);
    if let Some(history) = histories.of.get(did) {
        let (number, version_id) = &history.version;
        match entries.iter().find(|entry| entry.version_number == *number) {
            None => {
                return Err(ResolutionError::Resolution(format!(
                    "{did}'s log ends at {} before {version_id}, the entry it was last read at: \
                     not taken (an old log, served again)",
                    last.get_version_id()
                )))
            }
            Some(entry) if entry.get_version_id() != version_id => {
                return Err(ResolutionError::Resolution(format!(
                    "{did}'s log has {} where it was last read at {version_id}: not taken (a \
                     log that doesn't continue the one held)",
                    entry.get_version_id()
                )))
            }
            Some(_) => {}
        }
    }
    let listed = keys_listed(&document);
    if !histories.of.contains_key(did) && histories.of.len() >= MOST_REMEMBERED {
        let oldest = histories
            .of
            .iter()
            .min_by_key(|(_, history)| history.used)
            .map(|(did, _)| did.clone());
        if let Some(oldest) = oldest {
            histories.of.remove(&oldest);
        }
    }
    histories.uses += 1;
    let used = histories.uses;
    let history = histories
        .of
        .entry(did.to_string())
        .or_insert_with(|| History {
            version: (0, String::new()),
            keys: std::collections::HashSet::new(),
            dropped: std::collections::HashSet::new(),
            used,
        });
    let newly_dropped: Vec<String> = history.keys.difference(&listed).cloned().collect();
    history.dropped.extend(newly_dropped);
    history.keys = listed.difference(&history.dropped).cloned().collect();
    history.version = (last.version_number, last.get_version_id().to_string());
    history.used = used;
    Ok(without_dropped(document, &history.dropped))
}

/// What [`read_again`] found.
#[derive(Debug, Clone, PartialEq)]
pub enum ReadAgain {
    /// The log was fetched again just now, and verified: this is its document.
    Read(Value),
    /// The DID was read (or a read was tried) less than a minute ago: it may be read
    /// again in this many milliseconds. A message held back for this may be tried
    /// once more then, for up to 10 minutes from its arrival (multi-device/1.0, "At
    /// most once a minute").
    NotYet { retry_after_ms: u64 },
}

/// Reads `did`'s log again now, past the document held: for an app holding a
/// message signed or authenticated by a key the document doesn't list, once for
/// that message (multi-device/1.0, "A receiver of an address"). Packing and
/// unpacking do this by themselves (`resolve_fresh`); this is for the app's own
/// checks, and for trying a held-back message again.
///
/// At most once a minute per DID, whatever the reason or outcome: asked sooner,
/// it answers [`ReadAgain::NotYet`] and fetches nothing. A read that fails (the host
/// can't be reached, or serves a log that doesn't continue the one held) is an
/// error, never the document held: a key the copy doesn't list is never taken
/// while the log can't be read.
pub async fn read_again(did: &str) -> Result<ReadAgain, ResolutionError> {
    if !is_did_webvh(did) {
        return Err(ResolutionError::MethodNotSupported(did.to_string()));
    }
    match resolve_kept(did, true).await? {
        Some(document) => Ok(ReadAgain::Read(document)),
        None => Ok(ReadAgain::NotYet {
            retry_after_ms: retry_after_ms(did),
        }),
    }
}

/// How long until `did` may be fetched again: 0 if it may be now.
pub fn retry_after_ms(did: &str) -> u64 {
    let now = now_ms();
    let kept = KEPT.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    kept.as_ref()
        .and_then(|kept| kept.known.get(did))
        .map(|known| {
            (known.asked_at + FETCHED_AT_MOST_EVERY_MS - now)
                .max(0.0)
                .ceil() as u64
        })
        .unwrap_or(0)
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
///
/// Verified includes its witnesses: when the log names any, didwebvh-rs fetches
/// `did-witness.json` and refuses the log unless every entry has its threshold of
/// proofs (a log naming witnesses whose proofs can't be fetched is refused too).
/// So only witnessed entries count; an entry a witnessing host holds back isn't in
/// the log it serves, and one served without its proofs fails the read. Then held
/// to what was read before ([`continued`]).
#[cfg(not(target_arch = "wasm32"))]
async fn fetched(did: &str) -> Result<(Value, Option<u32>), ResolutionError> {
    #[cfg(test)]
    if let Some(served) = tests::served(did) {
        let (log, witnesses) = served?;
        return verified_log(did, &log, witnesses.as_deref()).await;
    }
    let mut state = DIDWebVHState::default();
    let (entry, metadata) = state
        .resolve(did, resolve_options())
        .await
        .map_err(|e| ResolutionError::Resolution(e.to_string()))?;
    let document = entry
        .get_did_document()
        .map_err(|e| ResolutionError::Resolution(e.to_string()))?;
    let ttl = ttl_of(&state, metadata.version_number);
    Ok((continued(did, &state, document)?, ttl))
}

/// A log fetched by this crate (the wasm path, and tests), verified as
/// [`resolve_from_log_with_ttl`] does, and held to what was read before
/// ([`continued`]).
#[cfg(any(test, target_arch = "wasm32"))]
async fn verified_log(
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
    let ttl = ttl_of(&state, metadata.version_number);
    Ok((continued(did, &state, document)?, ttl))
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
    // and doesn't publish them fails verification below, as it should (didwebvh-rs
    // refuses an entry short of its witness threshold); a file that can't be
    // fetched is treated the same as one that isn't there. Only witnessed entries
    // count, on this path as on didwebvh-rs's own.
    let witnesses = fetch_text(&client, witness_url.as_str())
        .await
        .ok()
        .flatten();

    verified_log(did, &log, witnesses.as_deref()).await
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

    /// What the stand-in host serves, by DID: a log and its `did-witness.json`, or
    /// a failure (the host down). A DID not here is fetched for real.
    /// A stand-in host's answer: `did.jsonl` and `did-witness.json`, or a failure.
    type Served = Result<(String, Option<String>), String>;

    static SERVED: std::sync::Mutex<Option<std::collections::HashMap<String, Served>>> =
        std::sync::Mutex::new(None);

    pub(super) fn served(did: &str) -> Option<Result<(String, Option<String>), ResolutionError>> {
        SERVED
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()?
            .get(did)
            .cloned()
            .map(|served| served.map_err(ResolutionError::Resolution))
    }

    fn serve(did: &str, served: Served) {
        SERVED
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get_or_insert_with(Default::default)
            .insert(did.to_string(), served);
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

    // ---- Speaking as a public address: what a receiver holds an address to. ----

    /// An address's log, written as its holder would: each version lists the
    /// devices' keys under ids made from the keys, as did-hosting/1.0 has them.
    struct Address {
        state: DIDWebVHState,
        signer: Secret,
        witness: Option<Secret>,
        did: String,
        domain: String,
        /// How many entries have been made, for their `versionTime`s.
        made: i64,
    }

    fn ed25519() -> (Secret, String) {
        let mut key = Secret::generate_ed25519(None, None);
        let pk = key.get_public_keymultibase().unwrap();
        key.id = format!("did:key:{pk}#{pk}");
        (key, pk)
    }

    fn document_listing(did: &str, keys: &[&str]) -> Value {
        let id = |key: &str| format!("{did}#{key}");
        json!({
            "id": did,
            "@context": ["https://www.w3.org/ns/did/v1"],
            "verificationMethod": keys.iter().map(|key| json!({
                "id": id(key), "type": "Multikey", "controller": did, "publicKeyMultibase": key,
            })).collect::<Vec<_>>(),
            "authentication": keys.iter().map(|key| id(key)).collect::<Vec<_>>(),
            "keyAgreement": keys.iter().map(|key| id(key)).collect::<Vec<_>>(),
        })
    }

    impl Address {
        /// A new address listing `keys`, witnessed by a host if `witnessed`.
        fn new(domain: &str, keys: &[&str], witnessed: bool) -> Address {
            let (signer, pk) = ed25519();
            let witness = witnessed.then(ed25519);
            let parameters = didwebvh_rs::parameters::Parameters {
                update_keys: Some(Arc::new(vec![didwebvh_rs::Multibase::new(pk)])),
                ttl: Some(600),
                witness: witness.as_ref().map(|(_, witness_pk)| {
                    Arc::new(
                        didwebvh_rs::witness::Witnesses::builder()
                            .threshold(1)
                            .witness(didwebvh_rs::Multibase::new(witness_pk.clone()))
                            .build()
                            .unwrap(),
                    )
                }),
                ..Default::default()
            };
            let mut address = Address {
                state: DIDWebVHState::default(),
                signer,
                witness: witness.map(|(secret, _)| secret),
                did: String::new(),
                domain: domain.to_string(),
                made: 0,
            };
            let template = format!("did:webvh:{{SCID}}:{domain}");
            address.entry(document_listing(&template, keys), &parameters, true);
            address.did = address.state.log_entries()[0]
                .log_entry
                .get_state()
                .get("id")
                .unwrap()
                .as_str()
                .unwrap()
                .to_string();
            address
        }

        fn entry(
            &mut self,
            document: Value,
            parameters: &didwebvh_rs::parameters::Parameters,
            witness_it: bool,
        ) {
            let at = chrono::Utc::now().fixed_offset() - chrono::Duration::hours(10)
                + chrono::Duration::minutes(self.made);
            self.made += 1;
            pollster::block_on(self.state.create_log_entry(
                Some(at),
                &document,
                parameters,
                &self.signer,
            ))
            .unwrap();
            if let (Some(witness), true) = (&self.witness, witness_it) {
                let mut secrets = std::collections::HashMap::default();
                let did = witness.id.split('#').next().unwrap().to_string();
                secrets.insert(did, witness.clone());
                let (entries, proofs) = self.state.log_entries_and_witness_proofs_mut();
                let entry = entries.last().unwrap();
                pollster::block_on(didwebvh_rs::create::sign_witness_proofs(
                    proofs,
                    entry,
                    &entry.get_active_witnesses(),
                    &secrets,
                ))
                .unwrap();
            }
        }

        /// The next version, listing `keys` (witnessed, at a host that witnesses,
        /// unless `witness_it` is false).
        fn publish(&mut self, keys: &[&str], witness_it: bool) {
            let parameters = self
                .state
                .log_entries()
                .last()
                .unwrap()
                .validated_parameters
                .clone();
            let did = self.did.clone();
            self.entry(document_listing(&did, keys), &parameters, witness_it);
        }

        /// `did.jsonl` up to entry `upto` (all of it with `None`).
        fn log(&self, upto: Option<usize>) -> String {
            let entries = self.state.log_entries();
            entries[..upto.unwrap_or(entries.len())]
                .iter()
                .map(|e| serde_json::to_string(&e.log_entry).unwrap())
                .collect::<Vec<_>>()
                .join("\n")
        }

        fn witness_file(&self) -> Option<String> {
            self.witness
                .as_ref()
                .map(|_| serde_json::to_string(self.state.witness_proofs()).unwrap())
        }

        /// The stand-in host serves the log as it is now.
        fn serve(&self) {
            serve(&self.did, Ok((self.log(None), self.witness_file())));
        }

        fn serve_upto(&self, upto: usize) {
            serve(&self.did, Ok((self.log(Some(upto)), self.witness_file())));
        }
    }

    fn listed(document: &Value) -> Vec<String> {
        document["verificationMethod"]
            .as_array()
            .unwrap()
            .iter()
            .map(|method| method["publicKeyMultibase"].as_str().unwrap().to_string())
            .collect()
    }

    fn authenticates(document: &Value, key: &str) -> bool {
        let did = document["id"].as_str().unwrap();
        document["authentication"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry.as_str() == Some(&format!("{did}#{key}")))
    }

    /// Lets the next read of `did` go ahead, as if the minute were up.
    fn minute_up(did: &str) {
        age(did, FETCHED_AT_MOST_EVERY_MS + 1.0, 0.0);
    }

    fn read(did: &str) -> Result<Value, ResolutionError> {
        pollster::block_on(DidWebVh.resolve(did))
    }

    fn read_again_now(did: &str) -> Result<ReadAgain, ResolutionError> {
        pollster::block_on(read_again(did))
    }

    /// No going back: a log that ends before the version held, or differs from it,
    /// is a failed read -- the copy held is used meanwhile, and nothing from the old
    /// log is taken.
    #[test]
    fn a_log_that_doesnt_continue_the_one_held_is_refused() {
        let _serial = serial();
        let (a, b, c) = ("z6MkA1", "z6MkB1", "z6MkC1");
        let mut address = Address::new("rollback.example", &[a, b], false);
        address.publish(&[a, c], false);
        address.serve();
        let did = address.did.clone();
        let current = read(&did).unwrap();
        assert_eq!(listed(&current), vec![a, c]);

        // The host serves the old log, which still lists b: not taken.
        address.serve_upto(1);
        minute_up(&did);
        assert!(
            matches!(read_again_now(&did), Err(ResolutionError::Resolution(why)) if why.contains("ends at")),
            "a log ending before the version held is a failed read"
        );
        // Forgetting the documents kept doesn't let it in either.
        forget_kept();
        assert!(read(&did).is_err());

        // A log that differs at the version held (another second entry, as a host
        // or a stolen key might write) is refused the same way.
        let mut forked = Address {
            state: DIDWebVHState::default(),
            signer: address.signer.clone(),
            witness: None,
            did: did.clone(),
            domain: address.domain.clone(),
            made: 0,
        };
        for entry in &address.state.log_entries()[..1] {
            forked.state.log_entries_mut().push(entry.clone());
        }
        forked.made = 5;
        forked.publish(&[a, b], false);
        assert_ne!(forked.log(None), address.log(None));
        forked.serve();
        minute_up(&did);
        assert!(
            matches!(read_again_now(&did), Err(ResolutionError::Resolution(why)) if why.contains("doesn't continue")),
        );

        // The log going on from the one held is taken.
        address.publish(&[a, c, "z6MkD1"], false);
        address.serve();
        minute_up(&did);
        assert!(
            matches!(read_again_now(&did), Ok(ReadAgain::Read(document)) if listed(&document).len() == 3)
        );
        forget_history();
    }

    /// A key the log has dropped is dropped: a later version listing it again
    /// doesn't bring it back, as a key or under a relationship.
    #[test]
    fn a_key_the_log_dropped_is_never_taken_again() {
        let _serial = serial();
        let (a, b) = ("z6MkA2", "z6MkB2");
        let mut address = Address::new("dropped.example", &[a, b], false);
        address.serve();
        let did = address.did.clone();
        assert_eq!(listed(&read(&did).unwrap()), vec![a, b]);

        // b removed (a device lost)...
        address.publish(&[a], false);
        address.serve();
        minute_up(&did);
        assert!(
            matches!(read_again_now(&did), Ok(ReadAgain::Read(document)) if listed(&document) == vec![a])
        );

        // ...and listed again by a later version (whoever holds an update key put it
        // back): still not taken.
        address.publish(&[a, b], false);
        address.serve();
        minute_up(&did);
        let ReadAgain::Read(document) = read_again_now(&did).unwrap() else {
            panic!("read again");
        };
        assert_eq!(listed(&document), vec![a]);
        assert!(authenticates(&document, a));
        assert!(!authenticates(&document, b));

        // A key taken out of one relationship only (a device untrusted) stays out of
        // it, while what it is still listed as stays.
        let mut document = document_listing(&did, &[a, b]);
        assert!(keys_listed(&document).contains(&format!("authentication|mb:{b}")));
        let dropped = [format!("authentication|mb:{b}")].into_iter().collect();
        document = without_dropped(document, &dropped);
        assert!(!authenticates(&document, b));
        assert_eq!(listed(&document), vec![a, b]);
        assert_eq!(document["keyAgreement"].as_array().unwrap().len(), 2);
        forget_history();
    }

    /// Where the log names a witness, only witnessed entries count: an entry served
    /// without its proof fails the read (the copy held is what is used), and a log
    /// whose proofs aren't served at all isn't taken.
    #[test]
    fn where_the_log_names_a_witness_only_witnessed_entries_count() {
        let _serial = serial();
        let (a, b) = ("z6MkA3", "z6MkB3");
        let mut address = Address::new("witnessed.example", &[a, b], true);
        address.serve();
        let did = address.did.clone();
        assert_eq!(listed(&read(&did).unwrap()), vec![a, b]);

        // An entry removing b, served before it is witnessed (a host that doesn't
        // hold it back as it should, or one tampered with): not taken.
        address.publish(&[a], false);
        address.serve();
        minute_up(&did);
        assert!(read_again_now(&did).is_err());
        assert_eq!(
            listed(&read(&did).unwrap()),
            vec![a, b],
            "the copy held is used meanwhile"
        );

        // No did-witness.json at all: nothing of the log is taken.
        serve(&did, Ok((address.log(None), None)));
        forget_kept();
        assert!(read(&did).is_err());

        // A fresh address whose entries are witnessed resolves.
        let mut fine = Address::new("witnessed-fine.example", &[a], true);
        fine.publish(&[a, b], true);
        fine.serve();
        assert_eq!(listed(&read(&fine.did).unwrap()), vec![a, b]);
        forget_history();
    }

    /// The caching rules, end to end through a fetch: the log's `ttl` (at most 4
    /// hours), a day past the last read while the host can't be reached and then
    /// nothing, never a key unseen while it can't be read, and a read again at most
    /// once a minute.
    #[test]
    fn a_copy_is_used_for_its_ttl_a_day_while_the_host_is_down_and_read_again_once_a_minute() {
        let _serial = serial();
        let hour = 60.0 * 60.0 * 1000.0;
        let a = "z6MkA4";
        let address = Address::new("caching.example", &[a], false);
        address.serve();
        let did = address.did.clone();
        read(&did).unwrap();

        // Read again within the minute: not yet, and how long until it may be.
        match read_again_now(&did).unwrap() {
            ReadAgain::NotYet { retry_after_ms } => {
                assert!(retry_after_ms > 0 && retry_after_ms <= 60_000)
            }
            other => panic!("{other:?}"),
        }
        // After it: read.
        minute_up(&did);
        assert!(matches!(read_again_now(&did), Ok(ReadAgain::Read(_))));
        assert!(matches!(read_again_now(&did), Ok(ReadAgain::NotYet { .. })));

        // The host goes down. Within the ttl (600 s) the copy is used as it is.
        serve(&did, Err("connection refused".into()));
        age(&did, FETCHED_AT_MOST_EVERY_MS + 1.0, 500_000.0);
        assert!(read(&did).is_ok(), "within its ttl, no fetch");
        // Past the ttl it is fetched, which fails: the copy is used, up to a day.
        age(&did, FETCHED_AT_MOST_EVERY_MS + 1.0, 23.0 * hour);
        assert!(read(&did).is_ok(), "23 hours since the last read");
        // But never a key it doesn't list: a read again fails, and fails closed.
        minute_up(&did);
        assert!(read_again_now(&did).is_err());
        // Past the day: nothing.
        age(&did, FETCHED_AT_MOST_EVERY_MS + 1.0, 2.0 * hour);
        assert!(read(&did).is_err(), "25 hours since the last read");

        // Up again: read, and used for its ttl.
        address.serve();
        minute_up(&did);
        assert!(read(&did).is_ok());
        assert_eq!(kept_for(Some(600)), 600_000.0);
        assert_eq!(kept_for(Some(100_000)), KEPT_FOR_MS);

        // Not a did:webvh: read_again says so.
        assert!(matches!(
            read_again_now("did:web:example.com"),
            Err(ResolutionError::MethodNotSupported(_))
        ));
        forget_history();
    }

    /// Past [`MOST_REMEMBERED`] DIDs the least recently read history goes, not all.
    #[test]
    fn histories_are_bounded() {
        let _serial = serial();
        forget_history();
        let address = Address::new("bounded.example", &["z6MkA5"], false);
        let did = address.did.clone();
        address.serve();
        read(&did).unwrap();
        {
            let mut histories = HISTORY.lock().unwrap();
            let histories = histories.as_mut().unwrap();
            for n in 0..MOST_REMEMBERED - 1 {
                histories.uses += 1;
                histories.of.insert(
                    format!("did:webvh:Qm{n}:example.com"),
                    History {
                        version: (1, "1-x".into()),
                        keys: Default::default(),
                        dropped: Default::default(),
                        used: histories.uses,
                    },
                );
            }
        }
        let other = Address::new("bounded-other.example", &["z6MkB5"], false);
        other.serve();
        read(&other.did).unwrap();
        {
            let guard = HISTORY.lock().unwrap();
            let histories = guard.as_ref().unwrap();
            assert_eq!(histories.of.len(), MOST_REMEMBERED);
            assert!(
                !histories.of.contains_key(&did),
                "the least recently read went"
            );
            assert!(histories.of.contains_key(&other.did));
        }
        forget_history();
    }
}
