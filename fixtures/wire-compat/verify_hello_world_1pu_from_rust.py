"""Verify the reverse direction for ECDH-1PU: decrypt a "Hello world!" authenticated
envelope packed by *this repo's Rust code* using the actual didcomm-messaging-python
library. See verify_hello_world_es_from_rust.py for the ECDH-ES equivalent and
README.md for when/how to run this.
"""
import asyncio
import json
from pathlib import Path

from aries_askar import Key

from didcomm_messaging.crypto.backend.askar import AskarCryptoService, AskarKey, AskarSecretKey


async def main():
    fixture = json.loads(
        (Path(__file__).parent / "hello_world_1pu_from_rust.json").read_text()
    )

    sender_key = Key.from_jwk(json.dumps(fixture["sender_x25519_public_jwk"]))
    sender_public = AskarKey(sender_key, fixture["sender_kid"])

    recipient_key = Key.from_jwk(json.dumps(fixture["recipient_x25519_secret_jwk"]))
    recipient_secret = AskarSecretKey(recipient_key, fixture["recipient_kid"])

    crypto = AskarCryptoService()
    packed = json.dumps(fixture["packed_jwe"]).encode()
    plaintext = await crypto.ecdh_1pu_decrypt(packed, recipient_secret, sender_public)

    assert plaintext.decode() == fixture["plaintext"], (
        f"expected {fixture['plaintext']!r}, got {plaintext!r}"
    )
    print(f"OK: didcomm-messaging-python decrypted: {plaintext.decode()!r}")


asyncio.run(main())
