"""Generates a real did:peer:2 DID (via the reference `did-peer-2` library's own
`generate()`) and its resolved DID Document, so a Rust `resolve()` implementation can be
checked against the actual reference output rather than just its own round trip.

Needs: pip install did-peer-2
"""
import json

from did_peer_2 import KeySpec, generate, resolve

did = generate(
    [
        KeySpec.verification("z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH"),
        KeySpec.key_agreement("z6LSbuUXWSgPfpiDBjUK6E7yiCKMN2eKJsjSFse4wUxU4wuc"),
    ],
    [
        {
            "type": "DIDCommMessaging",
            "serviceEndpoint": {
                "uri": "http://example.com/didcomm",
                "accept": ["didcomm/v2"],
                "routingKeys": [],
            },
        }
    ],
)

print(json.dumps({"did": did, "document": resolve(did)}, indent=2))
