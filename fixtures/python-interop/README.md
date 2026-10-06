# Interop with didcomm-messaging-python

`run_interop.py` exchanges real messages between
[didcomm-messaging-python](https://github.com/Indicio-tech/didcomm-messaging-python) and
this workspace in both directions. Each message is packed by one implementation's
messaging code and unpacked by the other's. They share only DID documents, keys, and the
bytes on the wire. The Rust side is `crates/didcomm-quickstart/examples/interop_peer.rs`,
driven one JSON line at a time over stdin.

```sh
# from the repo root
cargo build --release -p didcomm-quickstart --example interop_peer

# from this directory
python -m venv .venv
.venv/bin/pip install "didcomm-messaging[askar,authlib,legacy]"    # or a checkout of main
.venv/bin/python run_interop.py ../../target/release/examples/interop_peer
```

It exits non-zero on any FAIL. A SKIP means didcomm-messaging-python itself can't load
that key setup, checked before any message is sent, so it isn't an interop result.

## What it covers

Python only speaks JSON (`didcomm/v2`) and DIDComm v1, so that's what this tests:

- **Direct messages, both directions:** the askar and authlib backends × anoncrypt and
  authcrypt × X25519, P-256 and P-384 keys, as Multikey and as JsonWebKey2020.
- **Two recipients listed out of sorted order** (one DID, two devices), both directions.
  Python verifies `apv` against the recipients in wire order.
- **Forwards:**
  - a Python sender through a Rust mediator;
  - a Rust sender through a Python mediator to a Python recipient;
  - a Rust sender through a JSON-only Python mediator to a CBOR Rust recipient
    (`data.base64` around a COSE_Encrypt);
  - two forward layers via the mediator's `routingKeys`, both directions.
- **Flattened JWE** from Python.
- **A signed message** (`anoncrypt(sign(plaintext))`) to Python.
- **DIDComm v1 (RFC 0019):** anoncrypt and authcrypt, one or two recipients, both
  directions.

## Results (October 2026)

| Python version | Passed | Failed | Skipped |
|---|--:|--:|--:|
| didcomm-messaging 0.1.1 (PyPI) | 38 | 0 | 44 |
| didcomm-messaging 0.1.2a3 (`main` @ 8e82476) | 50 | 0 | 32 |

A negative control confirms the harness catches regressions. Run against this branch
before recipients were emitted in sorted order (commit `146adba`), the four
"2 recipients, unsorted | rust -> python" cases fail with Python's `Invalid apv value`.

### Where didcomm-messaging-python can't follow

These are limits of the Python library, shown as SKIP:

- **0.1.1 askar backend:** no P-256 or P-384 keys at all.
- **0.1.1 authlib backend:** no JsonWebKey2020 verification methods. Its error message
  prints a literal `{vm_type}`.
- **main askar backend:** no P-384 keys.
- **Signed messages:** Python decrypts a signed message but has no JWS support. It hands
  back the JWS as the message, unverified.
- **P-256 Multikey prefix:** Python's table encodes P-256 Multikeys with the raw code
  bytes `12 00`, not the varint `80 24` that real P-256 keys (`zDn…`) carry. So it can't
  read correctly encoded P-256 multikeys. This workspace reads Python's `12 00` form as
  P-256 (decode only), so Python-made P-256 documents still work here.
