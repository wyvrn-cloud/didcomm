"""Generates a real did:jwk resolution, via the reference `didcomm_messaging.resolver.jwk`
module's own `JWKResolver.resolve()`, so a Rust resolve() implementation can be checked
against the actual reference output.

Note: JWKResolver isn't in the didcomm-messaging PyPI release as of this writing -- it's
only on the main branch. Install from a git checkout of
https://github.com/Indicio-tech/didcomm-messaging-python rather than `pip install
didcomm-messaging`.
"""
import asyncio
import json

from didcomm_messaging.resolver.jwk import JWKResolver
from didcomm_messaging.multiformats.multibase import Base64UrlEncoder

b64 = Base64UrlEncoder()
jwk = {
    "kty": "OKP",
    "crv": "X25519",
    "use": "enc",
    "x": "9xMLxAm6EDNx9E2_9Z6AtV10tNfI1O5NhenUI1felxw",
}
encoded = b64.encode(json.dumps(jwk, separators=(",", ":")).encode())
did = f"did:jwk:{encoded}"


async def main():
    resolver = JWKResolver()
    document = await resolver.resolve(did)
    print(json.dumps({"did": did, "jwk": jwk, "document": document}, indent=2))


asyncio.run(main())
