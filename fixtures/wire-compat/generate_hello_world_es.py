"""Spike: pack a 'Hello world!' DIDComm v2 ECDH-ES message with the Python reference
library, dumping enough raw key material for a Rust program to decrypt it independently.

This is throwaway validation code for the wyrvn-didcomm M0 spike -- not part of any
shipped package.
"""
import asyncio
import json

from aries_askar import Key, KeyAlg

from didcomm_messaging.crypto.backend.askar import AskarKey, AskarCryptoService


async def main():
    crypto = AskarCryptoService()

    # Recipient key (X25519, used for the ECDH-ES key agreement)
    recip_key = Key.generate(KeyAlg.X25519)
    recip_kid = "did:example:recipient#key-1"
    recip_public = AskarKey(recip_key, recip_kid)

    plaintext = b"Hello world!"

    packed = await crypto.ecdh_es_encrypt([recip_public], plaintext)

    fixture = {
        "plaintext": plaintext.decode(),
        "recipient_kid": recip_kid,
        "recipient_x25519_secret_jwk": json.loads(recip_key.get_jwk_secret()),
        "packed_jwe": json.loads(packed),
    }
    print(json.dumps(fixture, indent=2))


asyncio.run(main())
