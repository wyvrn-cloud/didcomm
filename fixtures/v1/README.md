# DIDComm v1 wire-compatibility fixtures

Same idea as `/fixtures/wire-compat` (v2), for the legacy Aries "pack" format (RFC 0019):

- **Python packs, Rust decrypts** (`fixture.json`, both Anoncrypt and Authcrypt) -- checked
  automatically, every `cargo test`, by `crates/didcomm-v1/tests/hello_world.rs`.
- **Rust packs, Python decrypts** (`hello_world_from_rust.json`) -- checked manually, by
  `verify_hello_world_from_rust.py` (needs a Python environment with the `legacy` extra, so
  isn't part of the Rust test suite).

## Regenerating `fixture.json` (Python packs)

```sh
pip install -e "<path-to-didcomm-messaging-python-checkout>[legacy]"
python generate_fixture.py > fixture.json
```

## Regenerating and verifying `hello_world_from_rust.json` (Rust packs)

```sh
# from the repo root
cargo run --example generate_hello_world_from_rust -p didcomm-v1 \
    > fixtures/v1/hello_world_from_rust.json

# then, from this directory, with the same venv as above
python verify_hello_world_from_rust.py
```
