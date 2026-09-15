# Wire-compatibility fixtures

Four directions, both algorithms, all verified as of this writing:

| Algorithm | Python packs, Rust decrypts | Rust packs, Python decrypts |
|---|---|---|
| ECDH-ES (anonymous) | `hello_world_es.json` -- automatic (`cargo test`) | `hello_world_es_from_rust.json` -- manual |
| ECDH-1PU (authenticated) | `hello_world_1pu.json` -- automatic (`cargo test`) | `hello_world_1pu_from_rust.json` -- manual |

The "automatic" column runs every `cargo test` as part of `didcomm-crypto-askar`'s test
suite (`tests/hello_world_es.rs`, `tests/hello_world_1pu.rs`). The "manual" column needs a
Python environment, so it isn't part of the Rust test suite -- re-run the relevant
`verify_*.py` script after touching the matching `encrypt` function.

Neither implementation reads the other's code or shares a process -- only the JSON fixture
and, in the Python-verifies-Rust direction, the relevant key material (the recipient's
secret key always; the sender's public key too, for ECDH-1PU). See `PLAN.md` §11 in the
repo root for the full interop-testing rationale.

## Regenerating `hello_world_es.json` (Python packs)

```sh
python3 -m venv .venv
source .venv/bin/activate
pip install "didcomm-messaging[askar]"
python generate_hello_world_es.py > hello_world_es.json
```

The script uses `didcomm_messaging.crypto.backend.askar.AskarCryptoService.ecdh_es_encrypt`
directly (the same backend `didcomm-messaging-python` recommends by default) to pack a
`"Hello world!"` plaintext to a freshly generated X25519 key, and dumps that key's raw JWK
secret material alongside the packed JWE so the Rust side can reconstruct the same key and
decrypt independently, with no shared process/state between the two languages.

## Regenerating and verifying `hello_world_es_from_rust.json` (Rust packs)

```sh
# from the repo root
cargo run --example generate_hello_world_es_from_rust -p didcomm-crypto-askar \
    > fixtures/wire-compat/hello_world_es_from_rust.json

# then, from this directory, with the same venv as above
python verify_hello_world_es_from_rust.py
```

The example uses a fixed recipient secret (not a fresh random one) so the fixture is
reproducible: re-running it only changes the ephemeral key and nonce (both are supposed to
be random per DIDComm's spec), which doesn't affect Python's ability to decrypt.

## ECDH-1PU (authenticated encryption)

Same idea, one more key involved (the sender's, since 1PU authenticates the sender):

```sh
# Python packs, from this directory with the venv from above
python generate_hello_world_1pu.py > hello_world_1pu.json

# Rust packs, from the repo root, then verify from this directory
cargo run --example generate_hello_world_1pu_from_rust -p didcomm-crypto-askar \
    > fixtures/wire-compat/hello_world_1pu_from_rust.json
python verify_hello_world_1pu_from_rust.py
```
