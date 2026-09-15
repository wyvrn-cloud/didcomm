"""Generates real DIDComm v1 (RFC 0019 legacy pack) envelopes -- one Anoncrypt, one
Authcrypt -- via the reference `didcomm_messaging.v1.crypto.nacl.NaclV1CryptoService`,
so a Rust pack_message/unpack_message implementation can be checked against the actual
reference output in both directions.

Note: NaCl's "sigkey" is a 64-byte value (32-byte seed || 32-byte public key), but the
Rust side (askar-crypto's Ed25519KeyPair) works from the bare 32-byte seed -- so this
dumps the seed each keypair was generated from, not nacl's 64-byte secret key value.

Needs: pip install -e ".[legacy]" (from the didcomm-messaging-python checkout)
"""
import asyncio
import json

import nacl.bindings
import nacl.utils

from didcomm_messaging.v1.crypto.nacl import NaclV1CryptoService, KeyPair, EdPublicKey


def make_keypair():
    seed = nacl.utils.random(32)
    pk, sk = nacl.bindings.crypto_sign_seed_keypair(seed)
    return KeyPair(verkey=pk, sigkey=sk), seed


async def main():
    service = NaclV1CryptoService()

    recipient, recipient_seed = make_keypair()
    sender, sender_seed = make_keypair()
    plaintext = b"Hello world!"

    anoncrypt = await service.pack_message([EdPublicKey(recipient.verkey)], None, plaintext)
    authcrypt = await service.pack_message([EdPublicKey(recipient.verkey)], sender, plaintext)

    fixture = {
        "plaintext": plaintext.decode(),
        "recipient_kid": recipient.kid,
        "recipient_seed_hex": recipient_seed.hex(),
        "sender_kid": sender.kid,
        "sender_seed_hex": sender_seed.hex(),
        "anoncrypt": anoncrypt.serialize(),
        "authcrypt": authcrypt.serialize(),
    }
    print(json.dumps(fixture, indent=2))


asyncio.run(main())
