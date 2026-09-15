"""Generates a real did:peer:4 (long and short form) and its resolved documents, via
the reference `did-peer-4` library's own `encode()`/`resolve()`/`resolve_short()`, so a
Rust decode()/resolve() implementation can be checked against the actual reference
output.

Needs: pip install did-peer-4
"""
import json

from did_peer_4 import encode, long_to_short, resolve, resolve_short

document = {
    "verificationMethod": [
        {
            "id": "#key-1",
            "type": "Multikey",
            "publicKeyMultibase": "z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH",
        },
        {
            "id": "#key-2",
            "type": "Multikey",
            "publicKeyMultibase": "z6LSbuUXWSgPfpiDBjUK6E7yiCKMN2eKJsjSFse4wUxU4wuc",
        },
    ],
    "authentication": ["#key-1"],
    "keyAgreement": ["#key-2"],
    "service": [
        {
            "id": "#service",
            "type": "DIDCommMessaging",
            "serviceEndpoint": {
                "uri": "http://example.com/didcomm",
                "accept": ["didcomm/v2"],
                "routingKeys": [],
            },
        },
    ],
}

long_did = encode(document)
short_did = long_to_short(long_did)
long_doc = resolve(long_did)
short_doc = resolve_short(long_did)

print(
    json.dumps(
        {
            "input_document": document,
            "long_did": long_did,
            "short_did": short_did,
            "long_document": long_doc,
            "short_document": short_doc,
        },
        indent=2,
    )
)
