# Wire-compatibility fixtures

These JSON files are captured output from the actual `didcomm-messaging-python` reference
library, used to prove the Rust implementation decrypts (and, once implemented, encrypts)
byte-for-byte compatible envelopes -- not just internally self-consistent ones. See
`PLAN.md` §11 in the repo root for the full interop-testing rationale.

## Regenerating `hello_world_es.json`

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
