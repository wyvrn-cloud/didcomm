# wyrvn-didcomm

A DIDComm Messaging (v1 + v2) library in Rust, ported from
[`didcomm-messaging-python`](https://github.com/Indicio-tech/didcomm-messaging-python), with
bindings for TypeScript (via wasm), Node.js (via `napi-rs`, package `didcomm-node`), and Python
(via PyO3, package `didcomm_fast`).

See [`PLAN.md`](./PLAN.md) for the full design: scope, crate layout, why each crypto backend and
DID resolver was chosen, the interop-testing strategy, and the milestone sequence this repo's
history follows.

## Status

Early days. `didcomm-crypto-askar` can decrypt a real DIDComm v2 ECDH-ES envelope produced by the
actual `didcomm-messaging-python` library (see `crates/didcomm-crypto-askar/tests/hello_world_es.rs`
and `/fixtures/wire-compat`) -- the first concrete proof that this port is wire-compatible with
the reference implementation, not just internally self-consistent. Everything else in `PLAN.md`
is still ahead.

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
