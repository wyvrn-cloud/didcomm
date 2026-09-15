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

**DIDComm v1's core cryptography is also done**: Anoncrypt and Authcrypt (the legacy Aries "pack"
format, RFC 0019), proven wire-compatible with `didcomm-messaging-python`'s
`NaclV1CryptoService` in both directions (see `/fixtures/v1`) -- built entirely on
`askar-crypto`, no separate crypto dependency needed after all (see `crates/didcomm-v1`'s module
docs for how that turned out to already cover Ed25519/X25519 conversion and NaCl-compatible
`crypto_box`). The `V1PackagingService`/`V1DIDCommMessaging` layers on top (mirroring v2's
`PackagingService`/`DIDCommMessaging`) aren't built yet.

Not yet started: the v1 packaging/messaging layers, and all three language bindings -- see
`PLAN.md` for the full sequence.

## Workspace layout

- `crates/didcomm-multiformats` -- base64url, base58btc, multicodec, multikey.
- `crates/didcomm-diddoc` -- minimal DID Document model (parsing + dereferencing).
- `crates/didcomm-core` -- transport-agnostic DIDComm v2 core: JWE envelopes (both the v2 and v1
  layouts), the `DIDResolver`/`CryptoService`/`SecretsManager` traits, `PrefixResolver`,
  `InMemorySecretsManager`, `PackagingService`, `RoutingService`, and the top-level
  `DIDCommMessaging` entry point.
- `crates/didcomm-crypto-askar` -- the `askar-crypto`-backed v2 `CryptoService`.
- `crates/didcomm-v1` -- DIDComm v1 (legacy Aries pack format) pack/unpack.
- `crates/didcomm-resolver-peer` -- `did:peer:2` resolution and generation, `did:peer:4`
  resolution.
- `crates/didcomm-resolver-jwk` -- `did:jwk` resolution.
- `crates/didcomm-resolver-web` -- `did:web` resolution.
- `crates/didcomm-resolver-webvh` -- `did:webvh` resolution, wrapping `didwebvh-rs`.
- `crates/didcomm-quickstart` -- `generate_did`/`setup_default`, meant to be read and outgrown.
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
