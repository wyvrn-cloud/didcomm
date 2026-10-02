"""Python smoke test for didcomm_fast's quickstart flow: two peers, each generated and
set up entirely from Python, pack/unpack a real message to each other."""
import asyncio

from didcomm_fast import DidcommMessaging, generate_did


async def main() -> None:
    alice = generate_did()
    bob = generate_did()

    print("alice:", alice.did)
    print("bob:", bob.did)

    alice_dmp = DidcommMessaging.setup_default(alice)
    bob_dmp = DidcommMessaging.setup_default(bob)

    message = {
        "type": "https://didcomm.org/basicmessage/2.0/message",
        "body": {"content": "Hello world!"},
    }

    packed = await alice_dmp.pack(message, bob.did, alice.did)
    print("packed.target_services:", [(s.uri, s.accept, s.routing_keys) for s in packed.target_services])
    assert isinstance(packed.message, bytes)
    assert len(packed.target_services) == 1
    assert packed.target_services[0].uri == "didcomm:transport/queue"

    unpacked = await bob_dmp.unpack(packed.message)
    print("unpacked.message:", unpacked.message)
    assert unpacked.message["body"]["content"] == "Hello world!"
    assert unpacked.authenticated is True
    assert unpacked.sender_kid == f"{alice.did}#key-2"

    # pack completes the standard headers by default...
    assert alice_dmp.verbatim_headers is False
    for header in ("id", "from", "to", "created_time"):
        assert header in unpacked.message, header
    assert unpacked.message["from"] == alice.did and unpacked.message["to"] == [bob.did]

    # ...and packs the message exactly as given once opted out.
    alice_dmp.verbatim_headers = True
    assert alice_dmp.verbatim_headers is True
    verbatim = await bob_dmp.unpack((await alice_dmp.pack(message, bob.did, alice.did)).message)
    assert verbatim.message == message, verbatim.message

    print("OK: didcomm_fast quickstart flow packed and unpacked a real authenticated message")


if __name__ == "__main__":
    asyncio.run(main())
