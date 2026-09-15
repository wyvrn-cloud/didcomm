# wyrvn-didcomm

A DIDComm Messaging (v1 + v2) library in Rust, ported from
[`didcomm-messaging-python`](https://github.com/Indicio-tech/didcomm-messaging-python), with
bindings for TypeScript (via wasm), Node.js (via `napi-rs`, package `didcomm-node`), and Python
(via PyO3, package `didcomm_fast`).

See [`PLAN.md`](./PLAN.md) for the full design: scope, crate layout, why each crypto backend and
DID resolver was chosen, the interop-testing strategy, and the milestone sequence this repo's
history follows.

## Status

Core v2 pack/unpack works end to end: `PackagingService::pack`/`unpack` can send an anonymous
(ECDH-ES) or authenticated (ECDH-1PU) message *to a DID*, resolving keys through any
`DIDResolver` (`did:peer:2` is implemented; others are still ahead), backed by real
`askar-crypto`-based cryptography that's proven wire-compatible with the actual
`didcomm-messaging-python` library in both directions for both encryption modes (see
`/fixtures/wire-compat` and `/fixtures/did-peer-2`).

Not yet started: `did:peer:4`/`did:web`/`did:jwk`/`did:webvh`, `RoutingService` (mediator
forwarding), the top-level `DIDCommMessaging` convenience wrapper, `quickstart`, v1, and all
three language bindings -- see `PLAN.md` for the full sequence.

## Workspace layout

- `crates/didcomm-multiformats` -- base64url, base58btc, multicodec.
- `crates/didcomm-diddoc` -- minimal DID Document model (parsing + dereferencing).
- `crates/didcomm-core` -- transport-agnostic DIDComm v2 core: JWE envelopes, the
  `DIDResolver`/`CryptoService`/`SecretsManager` traits, `PrefixResolver`,
  `InMemorySecretsManager`, and `PackagingService`.
- `crates/didcomm-crypto-askar` -- the `askar-crypto`-backed `CryptoService`.
- `crates/didcomm-resolver-peer` -- `did:peer:2` resolution.
- `fixtures/wire-compat`, `fixtures/did-peer-2` -- fixtures captured from the real Python
  libraries, plus the scripts that generated them, used to test wire compatibility rather than
  just internal consistency.

## Development

```sh
cargo test --workspace
```

Versioning stays under `0.1.0` for the whole milestone-driven development period (see `PLAN.md`
§14) -- `0.1.0` is reserved for the first release actually considered usable by outside
consumers.
