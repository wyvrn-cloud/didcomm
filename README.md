# wyvrn-didcomm

A DIDComm Messaging (v1 + v2) library in Rust, ported from
[`didcomm-messaging-python`](https://github.com/Indicio-tech/didcomm-messaging-python), with
bindings for TypeScript (via wasm), Node.js (via `napi-rs`, package `didcomm-node`), and Python
(via PyO3, package `didcomm_fast`).

See [`PLAN.md`](./PLAN.md) for the full design: scope, crate layout, why each crypto backend and
DID resolver was chosen, the interop-testing strategy, and the milestone sequence this repo's
history follows.

## Status

The full v2 core stack works end to end: `DIDCommMessaging::pack`/`unpack` sends an anonymous
(ECDH-ES) or authenticated (ECDH-1PU) message *to a DID*, transparently wrapping it in
`routing/2.0/forward` envelopes when the recipient sits behind a mediator, backed by real
`askar-crypto`-based cryptography that's proven wire-compatible with the actual
`didcomm-messaging-python` library in both directions for both encryption modes (see
`/fixtures/wire-compat`).

**All five DID methods from the plan are implemented**: `did:peer:2` (resolution and
generation, byte-identical to the real `did-peer-2` package's own output), `did:peer:4`
(long-form resolution, matching Python's own long-form-only restriction), `did:jwk`, `did:web`
(real HTTP resolution, with caching), and `did:webvh` (wrapping the `didwebvh-rs` crate rather
than reimplementing verifiable-history validation) -- see `/fixtures/did-peer-2`,
`/fixtures/did-peer-4`, `/fixtures/did-jwk` for the ones with a Python reference to check against.

`didcomm-quickstart` ties the v2 stack together: `generate_did()` + `setup_default()` get you a
working `DIDCommMessaging`, wired to all five resolvers, in two calls -- the same "hit the ground
running, then read the source and grow out of it" idea as the Python original.

**DIDComm v1 is done too, matching v2's full shape**: Anoncrypt and Authcrypt (the legacy Aries
"pack" format, RFC 0019) are proven wire-compatible with `didcomm-messaging-python`'s
`NaclV1CryptoService` in both directions (see `/fixtures/v1`) -- built entirely on
`askar-crypto`, no separate crypto dependency needed after all (see `crates/didcomm-v1`'s module
docs for how that turned out to already cover Ed25519/X25519 conversion and NaCl-compatible
`crypto_box`). `V1PackagingService` packs/unpacks by kid; `V1DIDCommMessaging` resolves a
recipient DID's v1 service and wraps in `routing/1.0/forward` envelopes through a mediator, same
idea as v2's `RoutingService` with the older wire format.

With that, every planned piece of the core Rust library -- both DIDComm versions, all five DID
methods, packaging, routing, and quickstart -- is in place.

**All three language bindings exist too, each with its own quickstart equivalent**
(`generateDid`/`setupDefault`/`pack`/`unpack`, or Python's `generate_did`/`setup_default`),
verified end to end with a smoke test packing and unpacking a real authenticated message between
two independently-generated peer DIDs: `didcomm-wasm` (wasm-bindgen, `did:peer:2`/`did:peer:4`/
`did:jwk` only -- `did:web` needs a `DIDResolver` Send-future fix not yet done, `did:webvh`'s
dependency has its own wasm bug), `didcomm-node` (napi-rs, package `didcomm-node`, all five DID
methods since it's a native addon), and `didcomm-python` (PyO3/maturin, package `didcomm_fast`,
also all five DID methods).

**The ACA-Py-based interop harness in `didcomm-v2-test-util` is gone too.** It's replaced by
`crates/didcomm-peer-service` -- a small standalone HTTP server (not a published binding) built
directly on `didcomm-core`/`didcomm-quickstart` that exchanges real DIDComm v2 messages with the
unmodified `didcomm-messaging-python` library over HTTP, no ACA-Py wallet/connection-state model
in the way. Verified with `docker compose up` performing a real ECDH-1PU pack/HTTP-POST/unpack/
ack/unpack round trip end to end.

**A real DIDComm v2 mediator role exists now too** (`crates/didcomm-mediator-core`) -- something
neither this workspace nor `didcomm-messaging-python` had ever implemented before (both only
ever shipped the sender-through-a-mediator and client-of-a-mediator sides, never the mediator
itself). Implements `coordinate-mediation/3.0` and `messagepickup/3.0` matching the exact
message shapes `didcomm_messaging.quickstart` already sends/expects; `didcomm-peer-service`
wraps it for HTTP behind a `ROLE=mediator` mode. Verified with a from-scratch three-party unit
test (sender, mediator, mediated recipient -- proving end-to-end encryption survives the
mediator) and all four combinations of direction x mediation against the unmodified
`didcomm-messaging-python` library over the real `docker-compose.yml` harness.

See `PLAN.md` §15 for exactly what's done vs. still open in each binding (the browser wasm
target, napi-rs's prebuild matrix, the `didcomm_fast` drop-in-replacement interop test, and
publishing are all still ahead).

## Workspace layout

- `crates/didcomm-multiformats` -- base64url, base58btc, multicodec, multikey.
- `crates/didcomm-diddoc` -- minimal DID Document model (parsing + dereferencing).
- `crates/didcomm-core` -- transport-agnostic DIDComm v2 core: JWE envelopes (both the v2 and v1
  layouts), the `DIDResolver`/`CryptoService`/`SecretsManager` traits, `PrefixResolver`,
  `InMemorySecretsManager`, `PackagingService`, `RoutingService`, and the top-level
  `DIDCommMessaging` entry point.
- `crates/didcomm-crypto-askar` -- the `askar-crypto`-backed v2 `CryptoService`.
- `crates/didcomm-v1` -- DIDComm v1 (legacy Aries pack format): pack/unpack,
  `V1PackagingService`, `V1DIDCommMessaging`.
- `crates/didcomm-resolver-peer` -- `did:peer:2` resolution and generation, `did:peer:4`
  resolution.
- `crates/didcomm-resolver-jwk` -- `did:jwk` resolution.
- `crates/didcomm-resolver-web` -- `did:web` resolution.
- `crates/didcomm-resolver-webvh` -- `did:webvh` resolution, wrapping `didwebvh-rs`.
- `crates/didcomm-quickstart` -- `generate_did`/`setup_default`, meant to be read and outgrown.
- `crates/didcomm-wasm` -- wasm-bindgen bindings (TypeScript/JS, browser + Node-via-wasm),
  published as `@wyvrn-cloud/didcomm-wasm`.
- `crates/didcomm-node` -- napi-rs bindings, published as `@wyvrn-cloud/didcomm-node`.
- `crates/didcomm-python` -- PyO3 bindings (Cargo package `didcomm-fast`, Python module
  `didcomm_fast`) -- not published to a package index, installable straight from this repo.

See "Installing the published packages" below for exactly how each of these is consumed.
- `crates/didcomm-mediator-core` -- DIDComm v2 mediator role (`coordinate-mediation`/
  `messagepickup` 3.0), transport-agnostic like `didcomm-core`.
- `crates/didcomm-agent` -- a small agent runtime on top of `didcomm-core`: a persistent
  `Identity` (JWK file) with DIDs derived from it, HTTP(S) `send`/`request` (with
  problem reports surfaced as errors), mediation and pickup (`coordinate-mediation/3.0`,
  `messagepickup/3.0`), and discover-features/trust-ping auto-replies. Verified against
  the Indicio public mediator as well as `didcomm-mediator-core`.
- `crates/didcomm-peer-service` -- HTTP DIDComm v2 peer (and, via `ROLE=mediator`, mediator)
  used by `didcomm-v2-test-util`'s interop harness; not a published binding, a test fixture.
  Its peer role is built on `didcomm-agent`.
- `fixtures/wire-compat`, `fixtures/v1`, `fixtures/did-peer-2`, `fixtures/did-peer-4`,
  `fixtures/did-jwk` -- fixtures captured from the real Python libraries, plus the scripts that
  generated them, used to test wire compatibility rather than just internal consistency.

## Installing the published packages

This repo is private, so none of these are on the public npm registry or PyPI --
each has its own way of dealing with that.

**TypeScript/JS (`@wyvrn-cloud/didcomm-wasm`, `@wyvrn-cloud/didcomm-node`)** -- both
publish to GitHub Packages' npm registry (via `.github/workflows/publish-packages.yml`,
triggered manually from the Actions tab after a version bump). A consumer needs a
GitHub personal access token with `read:packages` scope, and this in their `.npmrc`:

```
@wyvrn-cloud:registry=https://npm.pkg.github.com
//npm.pkg.github.com/:_authToken=${GITHUB_TOKEN}
```

then `npm install @wyvrn-cloud/didcomm-wasm @wyvrn-cloud/didcomm-node` as normal.
`didcomm-node` currently ships as a single package with one prebuilt binary
(`linux-x64-gnu`) rather than the usual napi-rs per-platform split -- it will fail to
load on any other platform until that's expanded.

**Python (`didcomm_fast`)** -- no PyPI publish; install straight from the repo (needs
a Rust toolchain locally, since this triggers a real `maturin`/`cargo` build, not a
prebuilt wheel):

```sh
pip install "git+ssh://git@github.com/wyvrn-cloud/didcomm.git#subdirectory=crates/didcomm-python"
```

(or `git+https://<token>@github.com/wyvrn-cloud/didcomm.git#subdirectory=crates/didcomm-python`
if SSH isn't set up). Prebuilt wheels would remove the local Rust-toolchain
requirement but need real cross-platform CI (`cibuildwheel`-style) -- not set up yet.

**Docker (`wyvrn-chat`)** -- see that repo's own README; it publishes to
`ghcr.io/wyvrn-cloud/chat` via its own workflow, which installs
`@wyvrn-cloud/didcomm-wasm` from here rather than checking this repo out, so it isn't
documented here.

## Development

```sh
cargo test --workspace
```

Versioning stays under `0.1.0` for the whole milestone-driven development period (see `PLAN.md`
§14) -- `0.1.0` is reserved for the first release actually considered usable by outside
consumers.
