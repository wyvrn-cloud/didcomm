"""Verify the reverse direction: decrypt a "Hello world!" ECDH-ES envelope packed by
*this repo's Rust code* using the actual didcomm-messaging-python library.

This is a one-off manual check, not something the Rust test suite runs automatically
(it needs a Python environment with didcomm-messaging[askar] installed) -- see the
regeneration instructions in README.md. Run it after any change to
didcomm-crypto-askar's ecdh_es_encrypt to confirm nothing broke wire compatibility in
the encrypt direction.
"""
import asyncio
import json
from pathlib import Path

from aries_askar import Key, KeyAlg

from didcomm_messaging.crypto.backend.askar import AskarCryptoService, AskarSecretKey


async def main():
    fixture = json.loads(
        (Path(__file__).parent / "hello_world_es_from_rust.json").read_text()
    )

    recipient_key = Key.from_jwk(
        json.dumps(fixture["recipient_x25519_secret_jwk"])
    )
    recipient_secret = AskarSecretKey(recipient_key, fixture["recipient_kid"])

    crypto = AskarCryptoService()
    packed = json.dumps(fixture["packed_jwe"]).encode()
    plaintext = await crypto.ecdh_es_decrypt(packed, recipient_secret)

    assert plaintext.decode() == fixture["plaintext"], (
        f"expected {fixture['plaintext']!r}, got {plaintext!r}"
    )
    print(f"OK: didcomm-messaging-python decrypted: {plaintext.decode()!r}")


asyncio.run(main())
