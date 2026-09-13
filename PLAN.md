# Plan: DIDComm v1+v2 Rust library, with TypeScript (wasm), Node (napi), and Python bindings

Status: decisions locked, ready for scaffolding.
Sources reviewed: `./didcomm-messaging-python` (Indicio-tech, ~5.5k LOC total), `./didcomm-v2-test-util` (TheTechmage, ACA-Py interop harness).

Decisions:
- **Repo:** new repo under the `wyvern-cloud` GitHub org, named `wyrvn-didcomm` (spelling
  confirmed).
- **napi package name:** `didcomm-node`.
- **DID methods:** all five (`did:peer:2`, `did:peer:4`, `did:web`, `did:jwk`, `did:webvh`)
  confirmed relevant and stay in scope even with ACA-Py out of the interop loop.
- **ACA-Py interop:** confirmed not needed for now — no placeholder/tracking issue requested.
- **License:** Apache-2.0, matching `didcomm-messaging-python`.
- **Scope:** both DIDComm v1 and v2 (reversing the earlier "v1 out of scope" draft — the Python
  library supports both, so this port should too).
- **Bindings:** three first-class binding targets, all sharing the same `didcomm-core`/`didcomm-v1`
  Rust logic — wasm (browser + Node-via-wasm) for TypeScript, `napi-rs` (native addon) as a
  **separate** npm package for server-side Node, and PyO3 for Python (package name
  **`didcomm_fast`**), positioned as a drop-in replacement for `didcomm-messaging-python` in
  existing Python consumers (e.g. `didcomm-v2-test-util`'s own script). The name
  `didcomm_messaging` itself is left alone for now — can revisit later.
- **Interop testing:** ACA-Py is dropped from the loop (its DIDComm v2 support is still immature).
  Instead, test the new Rust library directly against `didcomm-messaging-python`'s own
  `didcomm-v2-test-util` script — the actual reference implementation — peer to peer. See §11.
- **Quickstart layer:** port `quickstart.py`'s non-transport-specific parts (DID generation,
  wiring up a default `DIDCommMessaging`/`V1DIDCommMessaging` instance) to Rust, then expose it
  through all three binding targets — not just core pack/unpack. Preserve what made the Python
  version valuable, not just its function signatures — see §14.
- **Crypto backends:** `askar-crypto` only for v2 (no `authlib`-equivalent second backend).
- **Process:** unit tests written continuously alongside implementation (not batched at the end
  of a milestone), frequent commits using Conventional Commits with detailed bodies, and commits
  at every major milestone boundary. See §15.
- **Versioning:** stay under `0.1.0` for the entire milestone-driven development period — bump
  only the patch component (`0.0.1`, `0.0.2`, ... up to `0.0.900` if needed) rather than jumping
  to `0.1.0` or `1.0.0`; `0.1.0` is reserved for when the library is actually considered a usable
  release, not a milestone marker. See §15.

## 1. Goal & scope

Build a Rust workspace that implements DIDComm Messaging v1 and v2 (pack/unpack, ECDH-ES/
ECDH-1PU for v2, Authcrypt/Anoncrypt for v1, DID resolution, forwarding/routing), with the same
swappable-backend architecture as `didcomm-messaging-python`, and that ships to three
destination environments: TypeScript/JS in the browser (wasm), Node.js natively (napi-rs), and
Python (PyO3) — the last explicitly so existing Python code (like `didcomm-v2-test-util`) can
swap to this library with minimal changes.

Still out of scope / deferred:
- Transport/networking beyond what's needed for a resolver to fetch a DID document (`did:web`,
  `did:webvh`) or for the quickstart layer's convenience helpers. Like the Python lib, the core
  packing/unpacking stays transport-agnostic: `pack()` returns bytes + a target service endpoint
  URI; sending it is the caller's job. See §4's quickstart row for exactly where the line is.
- The `authlib`-based second v2 crypto backend (not requested).

## 2. Key finding: reuse `askar-crypto` for v2, don't hand-roll ECDH-ES/1PU

`didcomm_messaging.crypto.backend.askar.AskarCryptoService` (the Python lib's recommended/default
v2 crypto backend) is a thin wrapper around the **Rust** crate `askar-crypto`
(part of [hyperledger/aries-askar](https://github.com/hyperledger/aries-askar), used via Python
FFI bindings). `askar-crypto`:

- Implements ECDH-ES and ECDH-1PU (draft 4) key agreement/wrapping exactly per the DIDComm v2 /
  JOSE spec this library targets.
- Is built entirely on pure-Rust RustCrypto primitives (`ed25519-dalek`, `x25519-dalek`,
  `p256`, `k256`, `aes-gcm`, `chacha20poly1305`, `aes-gcm-siv`, `hkdf`, `sha2`, `hmac`) — no
  `ring`, no OpenSSL, no C dependencies — so it's wasm32-friendly out of the box.
- Is a standalone crate on crates.io, independent of the storage/FFI layers of `aries-askar`.

Depending on `askar-crypto` directly for the v2 crypto backend means bit-for-bit wire
compatibility with the Python lib's default backend *and* with ACA-Py (which uses the same
crate) for free, and far less crypto code to write, review, and get wrong. This remains the
single highest-leverage decision in this plan — validate first (Milestone 0).

## 3. V1 crypto: no equivalent free lunch, plan for `crypto_box`

Unlike v2, `askar-crypto`'s public API only covers ECDH-ES/ECDH-1PU — it does not implement the
DIDComm v1 / Aries RFC 0019 "pack" wire format (`Authcrypt`/`Anoncrypt`, built on NaCl's
`crypto_box` — X25519 + XSalsa20-Poly1305 — plus base58/base64 framing), which is what
`didcomm_messaging/legacy/crypto.py` (616 LOC, using `PyNaCl`) and `v1/crypto/{nacl,askar}.py`
implement. For the Rust port, use the `crypto_box` crate — a pure-Rust, wasm-safe implementation
of the same NaCl primitive — plus `ed25519-dalek` (already a dependency via `askar-crypto`) for
any v1 signing needs, and hand-port the Authcrypt/Anoncrypt framing logic from
`legacy/crypto.py` directly (it's mostly base58/base64 bookkeeping around the crypto calls, not
novel cryptography). The Python lib has *two* v1 crypto backends (nacl-based and askar-based);
since `crypto_box` already covers exactly what's needed, this port only needs one v1 backend, not
two.

## 4. `did:webvh`: depend on `didwebvh-rs`, don't hand-roll it

`did:webvh` (did:web + Verifiable History, formerly `did:tdw`) resolution isn't a simple HTTP
GET like `did:web` — it involves fetching a JSONL history log, verifying a hash chain of DID
document versions, and checking a self-certifying identifier (SCID). This is real spec-compliance
work, not a good candidate to hand-roll. `decentralized-identity/didwebvh-rs` is an actively
maintained (pushed within the last day, as of this writing), complete Rust implementation of the
spec. Plan to depend on it rather than reimplementing resolution — with a spike task (see
Milestone 0) to confirm it builds cleanly for `wasm32-unknown-unknown` and to check whether its
HTTP fetching is pluggable (needed so the wasm target can use `fetch` instead of whatever native
HTTP client it defaults to, same concern as `did:web`).

## 5. Proposed crate layout (Cargo workspace)

```
wyrvn-didcomm/                    (workspace root, repo name as given in Decisions)
  crates/
    didcomm-core/                 # v2 transport-agnostic pack/unpack/route — mirrors
                                   #   didcomm_messaging/{crypto/base,jwe,packaging,routing,messaging}.py
    didcomm-crypto-askar/         # v2 CryptoService/SecretsManager impl backed by askar-crypto —
                                   #   mirrors crypto/backend/askar.py
    didcomm-v1/                   # v1 pack/unpack (Authcrypt/Anoncrypt) — mirrors
                                   #   didcomm_messaging/{v1/*,legacy/crypto.py}, built on crypto_box
    didcomm-multiformats/         # multibase/multicodec — mirrors multiformats/*.py
    didcomm-diddoc/               # minimal DID Document / VerificationMethod / DIDUrl model +
                                   #   dereference — mirrors what pydid provides today
    didcomm-resolver-peer/        # did:peer:2 / did:peer:4 — mirrors resolver/peer.py
    didcomm-resolver-web/         # did:web — mirrors resolver/web.py
    didcomm-resolver-jwk/         # did:jwk — mirrors resolver/jwk.py
    didcomm-resolver-webvh/       # did:webvh — wraps didwebvh-rs, new (no Python analog)
    didcomm-quickstart/           # DID generation + default-instance wiring — mirrors the
                                   #   non-transport parts of quickstart.py
    didcomm-wasm/                 # wasm-bindgen surface (browser + Node-via-wasm), cdylib crate
    didcomm-node/                 # napi-rs surface, separate native Node.js addon package
    didcomm-py/                   # PyO3 surface, separate Python package (see §8)
  examples/
    native-cli/                   # small Rust binary exercising pack/unpack, for quick manual testing
  Cargo.toml                      # workspace
```

`didcomm-wasm`, `didcomm-node`, and `didcomm-py` are thin bindings crates over the same
`didcomm-core`/`didcomm-v1`/resolver/quickstart crates — they should not duplicate logic. If any
of the three bindings layers needs behavior the others don't have, that's a signal the behavior
belongs in the shared crates instead, with the binding layer only adding language ergonomics
(Promises vs. asyncio coroutines vs. native `Future`s).

Splitting crypto/resolvers out of `didcomm-core`/`didcomm-v1` mirrors the Python package's
"swappable backend" philosophy and keeps each binding crate's dependency graph — and therefore
wasm bundle size / Python wheel size — under control, since not every consumer needs every DID
method.

## 6. Module-by-module port map

| Python file | LOC | Rust destination | Notes |
|---|---|---|---|
| `crypto/base.py` | 132 | `didcomm-core::crypto` (traits) | `CryptoService`/`SecretsManager`/`PublicKey`/`SecretKey` as traits; async via `async_trait` |
| `crypto/jwe.py` | 419 | `didcomm-core::jwe` | `JweEnvelope`/`JweBuilder`/`JweRecipient`, serde-based; shared by both v1 and v2 packagers, matching the Python lib. Port test-by-test against the Python doctest/unit tests. |
| `crypto/backend/askar.py` | 421 | `didcomm-crypto-askar` | Thin glue over `askar_crypto::{Key, ecdh}` |
| `crypto/backend/basic.py` | 99 | `didcomm-core::secrets::InMemorySecretsManager` | trivial |
| `multiformats/multibase.py`, `multicodec.py` | 152 + 78 | `didcomm-multiformats` | Consider the `multibase` crate for base encodings; multicodec table is ~10 entries, trivial to hand-roll for exact parity |
| `resolver/__init__.py` | 76 | `didcomm-core::resolver` (`DIDResolver` trait, `PrefixResolver`) | |
| `resolver/peer.py` | 39 | `didcomm-resolver-peer` | No mature `did:peer` crate exists — port `did_peer_2`/`did_peer_4`'s resolve logic directly, pure string/JSON manipulation, no network |
| `resolver/web.py` | 117 | `didcomm-resolver-web` | Needs an HTTP client; `fetch` (via `gloo-net`) for wasm, `reqwest` for native/napi/py. Feature-flag it. |
| `resolver/jwk.py` | 69 | `didcomm-resolver-jwk` | pure, no network |
| *(none — new method)* | — | `didcomm-resolver-webvh` | Wraps `didwebvh-rs`, see §4 |
| `packaging.py` | 191 | `didcomm-core::packaging` | Direct port |
| `routing.py` | 160 | `didcomm-core::routing` | Direct port |
| `messaging.py` | 213 | `didcomm-core::messaging` | `DIDCommMessaging`, `PackResult`, `UnpackResult` |
| `v1/crypto/base.py` | 64 | `didcomm-v1::crypto` (traits) | `V1CryptoService` trait |
| `legacy/crypto.py` | 616 | `didcomm-v1::legacy` | Authcrypt/Anoncrypt framing, built on `crypto_box` instead of `PyNaCl` — see §3 |
| `v1/crypto/nacl.py`, `v1/crypto/askar.py` | 222 + 144 | `didcomm-v1::crypto_box_backend` | Collapse the Python lib's two v1 backends into one, backed by `crypto_box` — see §3 |
| `v1/packaging.py` | 116 | `didcomm-v1::packaging` | Direct port |
| `v1/messaging.py` | 299 | `didcomm-v1::messaging` | `V1DIDCommMessaging`, forward-wrap logic |
| `v1/utils.py` | 13 | `didcomm-v1` (inline) | trivial |
| `quickstart.py` (DID-gen + `setup_default`, ~120 of the 502 LOC) | — | `didcomm-quickstart` | `generate_did`, wiring a default `DIDCommMessaging`/`V1DIDCommMessaging` with the askar/v1 crypto backend + `PrefixResolver` over all five DID methods |
| `quickstart.py` (relay setup, `send_http_message`, `fetch_relayed_messages`, ~380 LOC) | — | *binding-layer only, not shared Rust* | These are transport calls (`aiohttp`). Each binding exposes its own thin equivalent using the idiomatic HTTP client for that environment (`fetch` in the TS quickstart wrapper, `httpx`/`aiohttp`-equivalent in the Python bindings' quickstart wrapper, `reqwest` in the native example) rather than being forced through one Rust HTTP abstraction. |

Rough estimate: **~3,400–4,200 LOC of Rust** for the shared crates (core v2 + v1 + multiformats +
diddoc + resolvers + quickstart), plus **~900–1,400 LOC** of bindings code split across
`didcomm-wasm`, `didcomm-node`, and `didcomm-py` combined. This is meaningfully larger than the
v2-only draft of this plan — the v1 legacy-crypto port and three (not one) binding layers are
the main drivers.

## 7. Key architectural decisions

**DID Document model: hand-roll a minimal `didcomm-diddoc`, don't pull in `ssi`.**
The `ssi` crate is the closest Rust analog to `pydid`, but it's a large, VC/JOSE-suite-oriented
dependency tree with feature flags that don't all play nicely with `wasm32-unknown-unknown`.
`didcomm-messaging-python` only actually *uses* a small slice of `pydid`
(`DIDDocument.deserialize`, `.dereference`, `VerificationMethod`, `DIDUrl.parse`,
`DIDCommV1Service`/`DIDCommV2Service`). Hand-rolling exactly that slice with `serde`/`serde_json`
is small, fully wasm-safe, and removes a large unknown from the dependency graph.

**Async model.** Every trait in the Python lib (`CryptoService`, `V1CryptoService`,
`SecretsManager`, `DIDResolver`) is `async`. Use the `async-trait` crate for the shared Rust
trait objects, then adapt per binding: `wasm-bindgen-futures` → JS `Promise`s,
`pyo3-async-runtimes` → Python `asyncio` coroutines (this is what makes the Python bindings a
believable "drop-in" — existing `await dmp.pack(...)`-style call sites shouldn't need to change
shape), and native `async fn`/`tokio` for `didcomm-node` and the native example.

**Randomness on wasm32.** `x25519-dalek`/`ed25519-dalek`/`askar-crypto`/`crypto_box` pull in
`getrandom` transitively; on `wasm32-unknown-unknown` this requires enabling `getrandom`'s `js`
feature so it sources entropy from `window.crypto`/Node's `crypto` — must be pinned explicitly in
`didcomm-wasm`'s `Cargo.toml`.

**Error handling.** Port Python's exception hierarchies to `thiserror`-based error enums per
crate, then convert at each binding boundary: `JsValue`/`js_sys::Error` for wasm,
`napi::Error` for `didcomm-node`, and a `PyErr` hierarchy mirroring the Python lib's existing
exception names (`CryptoServiceError`, `PackagingServiceError`, `RoutingServiceError`,
`DIDResolutionError`, `V1CryptoServiceError`, `V1PackagingServiceError`,
`V1DIDCommMessagingError`) for `didcomm-py`, specifically *because* drop-in replacement means
existing `except CryptoServiceError:` call sites should keep working.

**JSON handling.** `didcomm-core`/`didcomm-v1` work in terms of `serde_json::Value` internally.
`didcomm-wasm` converts to/from native JS objects via `serde-wasm-bindgen` (not stringified
JSON); `didcomm-py` converts to/from Python `dict`/`str`/`bytes` the same way
`didcomm-messaging-python` already does, again for drop-in compatibility.

## 8. Python bindings (`didcomm-py`, package name `didcomm_fast`) — the drop-in-replacement target

This is new relative to the earlier v2-only draft. Publishes under the import name
**`didcomm_fast`** (not `didcomm_messaging` — that name can always be revisited/reclaimed later
once the library has proven itself; no need to touch the existing PyPI package's identity now).
Public class/method signatures should still match `didcomm-messaging-python` as closely as
possible (`DIDCommMessaging`, `PackagingService`, `RoutingService`, `PrefixResolver`,
`AskarCryptoService`-equivalent, `quickstart.generate_did`/`setup_default`, etc.), so swapping a
consumer over is close to a mechanical `import didcomm_messaging as dm` → `import didcomm_fast as
dm`-style change even though the package name itself is new. §11 below uses exactly this
property to validate compatibility directly against `didcomm-v2-test-util`'s own script.

Build via `pyo3` + `maturin`, producing wheels per-platform (same shape as most Rust-backed
Python packages today, e.g. `cryptography`, `pydantic-core`). `aries-askar`'s own Python bindings
(`aries_askar`) are themselves PyO3-based, so there's a directly relevant local example of this
exact pattern already in the dependency graph.

## 9. WASM / TypeScript packaging

- Build with `wasm-pack build --target web` (and `--target bundler` for bundler consumers) from
  `didcomm-wasm`. `wasm-bindgen` auto-generates the `.d.ts` — this *is* the "transpile to
  TypeScript" path; there's no separate manual TS port to maintain.
- Publish as a scoped npm package with wasm-pack's standard output layout.
- `wasm-opt` (via `wasm-pack`'s release profile) to keep bundle size down — worth watching
  closely given `askar-crypto` + `crypto_box` + `didwebvh-rs` all in the dependency graph; feature
  flags to let consumers opt out of curves/DID methods they don't need, mirroring how the Python
  lib lets you choose backends/resolvers piecemeal.
- A minimal browser smoke-test page (plain HTML + the built package) to prove the "runs in an
  actual browser" claim, since Node and browsers differ in crypto/fetch shims.
- The quickstart TS wrapper (thin, hand-written TS on top of the generated bindings — not itself
  wasm-bindgen output) provides `generateDid()`/`setupDefault()` plus a `fetch`-based
  `sendHttpMessage()` helper, per §6's binding-layer-only row.

## 10. Node native packaging (`didcomm-node`, napi-rs)

Separate npm package from the wasm build, named `didcomm-node`. Built via `@napi-rs/cli`, producing
prebuilt native binaries per OS/arch (napi-rs's standard cross-compilation + prebuild pattern) —
fully separate CI/build matrix from `wasm-pack`. API surface should track `didcomm-wasm`'s
TypeScript surface closely (same `.d.ts` shape where practical) so consumers can switch between
the two without relearning the library, even though under the hood one is a wasm blob and the
other a native addon.

## 11. Interoperability testing: drop ACA-Py, test directly against `didcomm-messaging-python`

**Revised direction:** ACA-Py's DIDComm v2 support (the `--experimental-didcomm-v2` branch
`didcomm-v2-test-util` currently depends on) is still immature, and routing everything through
ACA-Py's admin API/wallet/connections model adds a large, unreliable, ACA-Py-specific layer on
top of what we actually want to know: does the new Rust library correctly interoperate with
`didcomm-messaging-python` itself. So: remove ACA-Py from the interop loop entirely and test the
two libraries directly against each other, peer to peer.

Confirmed both source repos are on current, up-to-date code before planning against them:
`didcomm-v2-test-util` has only a `main` branch (no other branches exist). `didcomm-messaging-python`'s
`main` is its default branch and includes everything from `feature/7` (merged via PR #49,
2026-02-17); its other branches (`fix/didcommv1/routing-keys`, `release/0.1.x`,
a dependabot branch) are either already-merged stale feature branches or an older release line,
not ahead of `main` in any way that matters here. Both of our local clones are already on the
right commit.

**New shape of the harness** (changes land in the `didcomm-v2-test-util` repo, which is yours to
edit directly):

- Replace the `agent` service (currently the ACA-Py container) in `docker-compose.yml` with a
  small **Rust peer service** built from this project — a thin HTTP wrapper around
  `didcomm-core`/`didcomm-quickstart` (native, no bindings needed for this) that: generates its
  own DID + service endpoint on startup, exposes it (e.g. a `/did` endpoint or a fixed
  well-known value), accepts incoming packed DIDComm messages over HTTP, unpacks and logs them,
  and can pack+send a reply/message of its own to a peer DID given to it.
- Simplify `src/__main__.py` (still using `didcomm-messaging-python` unmodified) to drop the
  ACA-Py-specific bits — the `CONTROLLER`/admin-API wallet-DID-creation calls, the
  `connections-v2` polling, the name-tag exchange — and replace them with: fetch the Rust peer's
  DID from its `/did` endpoint, `pack`/send a `basicmessage/2.0` message to it directly, and
  verify receipt (e.g. via a `/received` endpoint on the Rust peer, or a reply message packed
  back). This is a much shorter, much more focused script than what's there today, and it's
  exercising `didcomm-messaging-python` exactly as intended — no ACA-Py wallet/connection-state
  model in between.
- This is now the primary interop target. ACA-Py interop is not being pursued for now — worth
  revisiting once ACA-Py's own DIDComm v2 support matures, as a separate, later effort layered on
  top of whatever this harness looks like by then.

Staged rollout, in increasing order of confidence-per-effort:

1. **Unit-level wire compatibility tests (no network, do this first and continuously), both v1
   and v2.** A small fixture set of DID + secrets + plaintext → pack with the Python lib, unpack
   with the Rust lib, and vice versa, for both the v2 (ECDH-ES/1PU) and v1 (Authcrypt/Anoncrypt)
   paths. Catches JWE-serialization/ECDH-agreement/legacy-framing mismatches immediately, before
   any docker/network involvement.
2. **Native Rust peer ↔ `didcomm-messaging-python` script.** Build the Rust peer service above,
   update `didcomm-v2-test-util` as described, get the round trip passing over real HTTP.
3. **`didcomm-py` (`didcomm_fast`) drop-in swap.** Take the now-ACA-Py-free
   `didcomm-v2-test-util` script and produce a second copy with only the import swapped from
   `didcomm_messaging` to `didcomm_fast`, confirming it still interoperates with the same Rust
   peer service (and, as a bonus, with the original unmodified script — `didcomm_fast` talking to
   `didcomm_messaging` directly, no Rust peer involved, is an even more direct compatibility
   check). This is the concrete validation of the "drop-in replacement" goal.
4. **Node.js (wasm) as the peer.** Swap the Rust peer service's binary for a small Node script
   importing the built `didcomm-wasm` npm package's `nodejs` target, same HTTP contract.
5. **Browser (wasm) as the peer, via a headless-browser test.** The real target environment for
   the TS package — Playwright driving a small page (built on the smoke-test page from §9) that
   performs the same pack/unpack/HTTP exchange against the `didcomm-messaging-python` script.
6. Keep steps 2–5 as their own test suite (own CI job / own `docker-compose`, living in
   `didcomm-v2-test-util`), separate from the fast fixture-based suite in step 1 — matches how
   `didcomm-messaging-python`'s own test suite already separates fast unit tests from this
   external test-util repo.

## 12. Milestones

- **M0 — Spikes (2–4 days):**
  - `askar-crypto` v2 spike: hand-produce one ECDH-ES and one ECDH-1PU JWE with the Python lib,
    decrypt with a throwaway Rust crate (and vice versa). Go/no-go gate for the v2 track.
  - `crypto_box` v1 spike: same idea for one Authcrypt and one Anoncrypt envelope against the
    Python lib's legacy backend.
  - `didwebvh-rs` wasm32 build check.
- **M1 — Core crates, native only, v2:** `didcomm-multiformats`, `didcomm-diddoc`,
  `didcomm-crypto-askar`, `didcomm-core`, `did:peer`/`did:web`/`did:jwk` resolvers. Unit tests
  ported from the Python test suite.
- **M1.5 — `didcomm-v1`, native only:** legacy framing + `crypto_box` backend, `V1` packaging/
  messaging, reusing `didcomm-core::jwe`.
- **M1.75 — `didcomm-resolver-webvh`** wrapping `didwebvh-rs`.
- **M2 — Wire compatibility suite:** §11 step 1, both v1 and v2, passing both directions against
  the Python library.
- **M2.5 — `didcomm-quickstart`:** native, both v1 and v2 default setups.
- **M2.75 — Rust peer service + `didcomm-v2-test-util` rework:** build the native HTTP peer
  service, replace the ACA-Py container in `docker-compose.yml`, simplify `src/__main__.py` down
  to the direct exchange described in §11. This is now the primary interop milestone — §11 step 2.
- **M3 — wasm target:** `didcomm-wasm` crate + TS quickstart wrapper, `wasm-pack build`, browser
  smoke-test page.
- **M3.5 — napi target:** `didcomm-node`, separate npm package, API surface kept in sync with
  `didcomm-wasm`. Can run in parallel with M3 once `didcomm-core`/`didcomm-v1`'s APIs are stable.
- **M3.75 — Python bindings:** `didcomm-py`, package name `didcomm_fast`, via PyO3/maturin,
  drop-in-shaped API per §8. Immediately followed by §11 step 3 (the drop-in swap test).
- **M4 — Remaining interop:** §11 steps 4–5 (Node/wasm and browser/wasm as the peer).
- **M5 — Publish:** crates.io for the Rust crates, npm for both the wasm and napi packages, PyPI
  for `didcomm_fast`, GitHub repo created under `wyvern-cloud`, docs.

## 13. Quickstart philosophy: hit-the-ground-running, then graduate out of it

What made `quickstart.py` genuinely useful wasn't just that it existed — it's that it's designed
to be *outgrown*. A new consumer calls `setup_default()`/`generate_did()` to get a working
`DIDCommMessaging` instance in a few lines, but the module is short and heavily commented enough
(see `quickstart.py:74-121`'s prose walking through what the `CryptoService`, `SecretsManager`,
`DIDResolver`, `PackagingService`, and `RoutingService` each do and why, phrased like an
explanation to someone new to the library, not just a docstring) that reading it top to bottom
teaches you how to assemble the same pieces yourself. The intent is that as an app matures, you
read the quickstart source, inline the parts you need with your own choices (your own secrets
storage, your own resolver set, maybe your own crypto backend), and eventually drop the
quickstart dependency entirely — the library doesn't force a one-way door into "the quickstart
way." This port should preserve that property deliberately, not just port the function
signatures:

- **Heavy, explanatory comments in `didcomm-quickstart`** (and in each binding's quickstart
  wrapper — the TS wrapper, the `didcomm_fast` quickstart module, the native example) — comments
  that teach the reader what each wired-up piece is for and how to swap it out, matching
  `quickstart.py`'s own tone, not terse Rustdoc.
- **Optional, not load-bearing, dependencies.** `didcomm-quickstart` should be behind an opt-in
  Cargo feature on `didcomm-wasm`/`didcomm-node`/`didcomm-py` (and a corresponding optional extra
  for the Python wheel / an optional npm entry point), not a mandatory dependency — a consumer
  who only wants `pack`/`unpack` shouldn't pay wasm-bundle-size or wheel-size cost for
  DID-generation conveniences they don't use, and a consumer who's graduated away from quickstart
  should be able to drop the feature flag cleanly.
- **Keep each quickstart wrapper short enough to read in one sitting.** If a binding's quickstart
  layer grows past being skimmable, that's a signal to split it or push logic back into
  `didcomm-quickstart` rather than letting any one binding's copy become its own bespoke,
  undocumented thing.

## 14. Development process: tests, commits, versioning

- **Unit tests land with the code, not after it.** Every milestone in §12 is incomplete until it
  has real test coverage, not just "compiles and runs once by hand." Where a Python unit test
  already exists for the module being ported (e.g. the `crypto/jwe.py` tests, the resolver tests
  under `tests/`), port it alongside the corresponding Rust module as a direct check that
  behavior matches, not as a follow-up task.
- **Commit frequently**, at the granularity of one logical unit of work (one crate, one module,
  one bugfix) rather than batching a whole milestone into a single commit — this keeps history
  reviewable and makes it easy to find where something changed later. Also commit explicitly at
  every milestone boundary from §12, so each milestone has a clear checkpoint in history.
- **Conventional Commits, with detailed bodies** — `feat:`, `fix:`, `test:`, `docs:`, `refactor:`,
  `chore:`, etc., with a body explaining *why* a change was made, not just restating the diff.
  This is on top of, not instead of, the existing project-wide git workflow (commits created
  locally and handed off for you to sign and push — see the global git guidance already in
  effect).
- **Versioning stays under `0.1.0` for the whole milestone-driven development period.** Bump only
  the patch component as work lands — `0.0.1`, `0.0.2`, and so on, up to `0.0.900` if that many
  increments happen — rather than jumping to `0.1.0` or `1.0.0` at a milestone boundary. Treat
  `0.1.0` as reserved for when the library is actually considered usable by outside consumers,
  which is a separate decision from "milestone N is done." Apply this consistently across the
  Cargo workspace crates, the npm packages, and the PyPI package.

## 15. Status

All open questions from earlier drafts are resolved (see the Decisions block at the top). This
plan is ready to move into scaffolding (Milestone 0) whenever you give the go-ahead.
