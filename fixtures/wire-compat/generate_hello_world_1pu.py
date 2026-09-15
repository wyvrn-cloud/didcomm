"""Spike: pack a 'Hello world!' DIDComm v2 ECDH-1PU (authenticated) message with the
Python reference library, dumping enough raw key material for a Rust program to decrypt
it independently. See README.md.
"""
import asyncio
import json

from aries_askar import Key, KeyAlg

from didcomm_messaging.crypto.backend.askar import AskarKey, AskarSecretKey, AskarCryptoService


async def main():
    crypto = AskarCryptoService()

    sender_key = Key.generate(KeyAlg.X25519)
    sender_kid = "did:example:sender#key-1"
    sender_secret = AskarSecretKey(sender_key, sender_kid)

    recipient_key = Key.generate(KeyAlg.X25519)
    recipient_kid = "did:example:recipient#key-1"
    recipient_public = AskarKey(recipient_key, recipient_kid)

    plaintext = b"Hello world!"

    packed = await crypto.ecdh_1pu_encrypt([recipient_public], sender_secret, plaintext)

    fixture = {
        "plaintext": plaintext.decode(),
        "sender_kid": sender_kid,
        "sender_x25519_public_jwk": json.loads(sender_key.get_jwk_public()),
        "recipient_kid": recipient_kid,
        "recipient_x25519_secret_jwk": json.loads(recipient_key.get_jwk_secret()),
        "packed_jwe": json.loads(packed),
    }
    print(json.dumps(fixture, indent=2))


asyncio.run(main())
