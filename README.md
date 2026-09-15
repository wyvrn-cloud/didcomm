# wyrvn-didcomm

A DIDComm Messaging (v1 + v2) library in Rust, ported from
[`didcomm-messaging-python`](https://github.com/Indicio-tech/didcomm-messaging-python), with
bindings for TypeScript (via wasm), Node.js (via `napi-rs`, package `didcomm-node`), and Python
(via PyO3, package `didcomm_fast`).

See [`PLAN.md`](./PLAN.md) for the full design: scope, crate layout, why each crypto backend and
DID resolver was chosen, the interop-testing strategy, and the milestone sequence this repo's
history follows.

## Status

Early days. `didcomm-crypto-askar` implements both of DIDComm v2's encryption modes -- ECDH-ES
(anonymous) and ECDH-1PU (authenticated) -- and both are proven wire-compatible with the actual
`didcomm-messaging-python` library in both directions (Python packs/Rust decrypts is automatic,
part of `cargo test`; Rust packs/Python decrypts is a manual check, see `/fixtures/wire-compat`).
Not yet started: DID resolution, the `PackagingService`/`RoutingService`/`DIDCommMessaging`
layers, v1, and all three language bindings -- see `PLAN.md` for the full sequence.

## Workspace layout

- `crates/didcomm-multiformats` -- base64url today; the rest of `multibase`/`multicodec` later.
- `crates/didcomm-core` -- transport-agnostic DIDComm v2 core (JWE envelope handling so far).
- `crates/didcomm-crypto-askar` -- the `askar-crypto`-backed crypto service.
- `fixtures/wire-compat` -- fixtures captured from the real Python library, plus the scripts that
  generated them, used to test wire compatibility rather than just internal consistency.

## Development

```sh
cargo test --workspace
```

Versioning stays under `0.1.0` for the whole milestone-driven development period (see `PLAN.md`
§14) -- `0.1.0` is reserved for the first release actually considered usable by outside
consumers.
