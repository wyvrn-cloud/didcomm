# Wire-compatibility fixtures

Two directions, both verified as of this writing:

- **Python packs, Rust decrypts** (`hello_world_es.json`) -- checked automatically, every
  `cargo test`, by `crates/didcomm-crypto-askar/tests/hello_world_es.rs`.
- **Rust packs, Python decrypts** (`hello_world_es_from_rust.json`) -- checked manually, by
  `verify_hello_world_es_from_rust.py` (needs a Python environment, so it isn't part of the
  Rust test suite; re-run it after touching `ecdh_es_encrypt`).

Neither implementation reads the other's code or shares a process -- only the JSON fixture
and, in the Python-verifies-Rust direction, the recipient's raw key material. See `PLAN.md`
§11 in the repo root for the full interop-testing rationale.

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
