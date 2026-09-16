# wyrvn-didcomm

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
also all five DID methods). See `PLAN.md` §15 for exactly what's done vs. still open in each
(the browser wasm target, napi-rs's prebuild matrix, the drop-in-replacement interop test, and
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
- `crates/didcomm-wasm` -- wasm-bindgen bindings (TypeScript/JS, browser + Node-via-wasm).
- `crates/didcomm-node` -- napi-rs bindings, published as the npm package `didcomm-node`.
- `crates/didcomm-python` -- PyO3 bindings (Cargo package `didcomm-fast`), published as the PyPI
  package `didcomm_fast`.
- `fixtures/wire-compat`, `fixtures/v1`, `fixtures/did-peer-2`, `fixtures/did-peer-4`,
  `fixtures/did-jwk` -- fixtures captured from the real Python libraries, plus the scripts that
  generated them, used to test wire compatibility rather than just internal consistency.

## Development

```sh
cargo test --workspace
```

Versioning stays under `0.1.0` for the whole milestone-driven development period (see `PLAN.md`
§14) -- `0.1.0` is reserved for the first release actually considered usable by outside
consumers.
