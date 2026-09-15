"""Verify the reverse direction for DIDComm v1: decrypt real Anoncrypt and Authcrypt
"Hello world!" envelopes packed by *this repo's Rust code* using the actual
didcomm-messaging-python library.
"""
import asyncio
import json
from pathlib import Path

import nacl.bindings

from didcomm_messaging.v1.crypto.nacl import KeyPair, NaclV1CryptoService, InMemSecretsManager
from didcomm_messaging.v1.packaging import V1PackagingService


def keypair_from_seed(seed_hex: str) -> KeyPair:
    seed = bytes.fromhex(seed_hex)
    pk, sk = nacl.bindings.crypto_sign_seed_keypair(seed)
    return KeyPair(verkey=pk, sigkey=sk)


async def main():
    fixture = json.loads(
        (Path(__file__).parent / "hello_world_from_rust.json").read_text()
    )

    recipient = keypair_from_seed(fixture["recipient_seed_hex"])
    crypto = NaclV1CryptoService()
    secrets = InMemSecretsManager()
    secrets.secrets[recipient.kid] = recipient
    packaging = V1PackagingService()

    for label in ("anoncrypt", "authcrypt"):
        packed = json.dumps(fixture[label]).encode()
        result = await packaging.unpack(crypto, secrets, packed)
        plaintext = result.unpacked.decode()
        assert plaintext == fixture["plaintext"], f"{label}: expected {fixture['plaintext']!r}, got {plaintext!r}"
        if label == "authcrypt":
            assert result.sender == fixture["sender_kid"], (
                f"authcrypt: expected sender {fixture['sender_kid']!r}, got {result.sender!r}"
            )
        print(f"OK ({label}): didcomm-messaging-python decrypted: {plaintext!r}")


asyncio.run(main())
