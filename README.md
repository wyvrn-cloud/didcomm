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
(ECDH-ES) or authenticated (ECDH-1PU) message *to a DID* (`did:peer:2` or `did:jwk` today),
transparently wrapping it in `routing/2.0/forward` envelopes when the recipient sits behind a
mediator, backed by real `askar-crypto`-based cryptography that's proven wire-compatible with
the actual `didcomm-messaging-python` library in both directions for both encryption modes (see
`/fixtures/wire-compat`, `/fixtures/did-peer-2`, `/fixtures/did-jwk`).

`did:web` (real HTTP resolution, with caching), `did:jwk`, and `did:peer:2` (both resolution and
generation, byte-identical to the real `did-peer-2` package's own output) round out DID method
coverage so far, and `didcomm-quickstart` ties it all together: `generate_did()` +
`setup_default()` get you a working `DIDCommMessaging` in two calls, the same "hit the ground
running, then read the source and grow out of it" idea as the Python original.

Not yet started: `did:peer:4`, `did:webvh`, v1, and all three language bindings -- see `PLAN.md`
for the full sequence.

## Workspace layout

- `crates/didcomm-multiformats` -- base64url, base58btc, multicodec, multikey.
- `crates/didcomm-diddoc` -- minimal DID Document model (parsing + dereferencing).
- `crates/didcomm-core` -- transport-agnostic DIDComm v2 core: JWE envelopes, the
  `DIDResolver`/`CryptoService`/`SecretsManager` traits, `PrefixResolver`,
  `InMemorySecretsManager`, `PackagingService`, `RoutingService`, and the top-level
  `DIDCommMessaging` entry point.
- `crates/didcomm-crypto-askar` -- the `askar-crypto`-backed `CryptoService`.
- `crates/didcomm-resolver-peer` -- `did:peer:2` resolution and generation.
- `crates/didcomm-resolver-jwk` -- `did:jwk` resolution.
- `crates/didcomm-resolver-web` -- `did:web` resolution.
- `crates/didcomm-quickstart` -- `generate_did`/`setup_default`, meant to be read and outgrown.
- `fixtures/wire-compat`, `fixtures/did-peer-2`, `fixtures/did-jwk` -- fixtures captured from the
  real Python libraries, plus the scripts that generated them, used to test wire compatibility
  rather than just internal consistency.

## Development

```sh
cargo test --workspace
```

Versioning stays under `0.1.0` for the whole milestone-driven development period (see `PLAN.md`
§14) -- `0.1.0` is reserved for the first release actually considered usable by outside
consumers.
