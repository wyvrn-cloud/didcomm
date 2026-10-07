"""Cross-implementation interop: didcomm-messaging-python <-> wyvrn-didcomm, both ways.

Every message is packed by one implementation's real messaging code and unpacked by the
other's -- no shared process state, only DID documents, keys and the bytes on the wire.
The Rust side is `examples/interop_peer.rs` (didcomm-quickstart), driven over stdin.

    cargo build --release -p didcomm-quickstart --example interop_peer
    python -m venv .venv && .venv/bin/pip install "didcomm-messaging[askar,authlib,legacy]"
    .venv/bin/python run_interop.py ../../target/release/examples/interop_peer

Covers JSON (didcomm/v2) only on the Python side, which is all it speaks: anoncrypt and
authcrypt; X25519, P-256 and P-384; Multikey and JsonWebKey2020 verification methods; the
askar and authlib backends; multi-recipient envelopes; forwards through a mediator on
either side; the flattened JWE form; signed messages; and DIDComm v1 (RFC 0019).
"""

import asyncio
import base64
import importlib.metadata
import json
import subprocess
import sys
import uuid

import base58
from aries_askar import Key, KeyAlg
from didcomm_messaging import DIDCommMessaging
from didcomm_messaging.crypto import SecretsManager
from didcomm_messaging.crypto.backend.askar import AskarCryptoService, AskarSecretKey
from didcomm_messaging.packaging import PackagingService
from didcomm_messaging.resolver import DIDResolver
from didcomm_messaging.routing import RoutingService

try:
    from authlib.jose import JsonWebKey
    from didcomm_messaging.crypto.backend.authlib import AuthlibCryptoService, AuthlibSecretKey
except ImportError:  # pragma: no cover - authlib extra not installed
    AuthlibCryptoService = None

PY_VERSION = importlib.metadata.version("didcomm-messaging")
BASIC = "https://didcomm.org/basicmessage/2.0/message"
JSON_ONLY = ["didcomm/v2"]
CBOR = ["didcomm/v2+cbor", "didcomm/v2"]

# multicodec prefixes: the real varints, and didcomm-messaging-python's p256 entry.
PREFIX = {
    "X25519": bytes([0xEC, 0x01]),
    "P-256": bytes([0x80, 0x24]),
    "P-384": bytes([0x81, 0x24]),
    "P-256 (python table)": bytes([0x12, 0x00]),
}
ALG = {"X25519": KeyAlg.X25519, "P-256": KeyAlg.P256, "P-384": KeyAlg.P384}


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


class Peer:
    """The Rust interop peer, one JSON request/response per line."""

    def __init__(self, path):
        self.proc = subprocess.Popen(
            [path], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True
        )

    def call(self, **req):
        self.proc.stdin.write(json.dumps(req) + "\n")
        self.proc.stdin.flush()
        resp = json.loads(self.proc.stdout.readline())
        if not resp.pop("ok"):
            raise RuntimeError(f"rust: {resp['error']}")
        return resp


class StaticResolver(DIDResolver):
    def __init__(self, docs):
        self.docs = docs

    async def resolve(self, did):
        return self.docs[did]

    async def is_resolvable(self, did):
        return did in self.docs


class Secrets(SecretsManager):
    def __init__(self, secrets):
        self.secrets = {s.kid: s for s in secrets}

    async def get_secret_by_kid(self, kid):
        return self.secrets.get(kid)


class Party:
    """A DID with one or more key-agreement keys of one curve, plus an Ed25519 key."""

    def __init__(self, name, curve="X25519", vm="multikey", n_keys=1, endpoint=None,
                 accept=JSON_ONLY, key_ids=None, codec=None):
        self.did = f"did:example:{name}-{uuid.uuid4().hex[:8]}"
        self.curve = curve
        ids = key_ids or [f"#key-{i + 1}" for i in range(n_keys)]
        self.keys = [(f"{self.did}{i}", Key.generate(ALG[curve])) for i in ids]
        self.auth = Key.generate(KeyAlg.ED25519)
        vms = []
        for vm_id, (_, key) in zip(ids, self.keys):
            if vm == "jwk":
                vms.append({"id": vm_id, "type": "JsonWebKey2020", "controller": self.did,
                            "publicKeyJwk": json.loads(key.get_jwk_public())})
            else:
                prefix = PREFIX[codec or curve]
                vms.append({"id": vm_id, "type": "Multikey", "controller": self.did,
                            "publicKeyMultibase": "z" + base58.b58encode(prefix + key.get_public_bytes()).decode()})
        vms.append({"id": "#auth", "type": "JsonWebKey2020", "controller": self.did,
                    "publicKeyJwk": json.loads(self.auth.get_jwk_public())})
        self.doc = {
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": self.did,
            "verificationMethod": vms,
            "keyAgreement": ids,
            "authentication": ["#auth"],
            "service": [{
                "id": "#didcomm", "type": "DIDCommMessaging",
                "serviceEndpoint": {"uri": endpoint or f"https://{name}.example/didcomm",
                                    "accept": accept, "routingKeys": []},
            }],
        }

    def rust_spec(self):
        return {
            "secrets": [{"kid": kid, "jwk": json.loads(key.get_jwk_secret())} for kid, key in self.keys],
            "signing": [{"kid": f"{self.did}#auth", "jwk": json.loads(self.auth.get_jwk_secret())}],
        }

    def py_secrets(self, backend):
        if backend == "askar":
            return [AskarSecretKey(key, kid) for kid, key in self.keys]
        return [AuthlibSecretKey(JsonWebKey.import_key(json.loads(key.get_jwk_secret())), kid)
                for kid, key in self.keys]


def py_dmp(backend, docs, *parties):
    crypto = AskarCryptoService() if backend == "askar" else AuthlibCryptoService()
    secrets = Secrets([s for p in parties for s in p.py_secrets(backend)])
    return DIDCommMessaging(crypto, secrets, StaticResolver(docs), PackagingService(), RoutingService())


def setup(peer, *parties, rust_actors=()):
    docs = {p.did: p.doc for p in parties}
    peer.call(op="setup", docs=docs, actors={p.did: p.rust_spec() for p in rust_actors})
    return docs


def message(sender, recipient, content="Hello world!", authcrypt=True):
    msg = {"id": str(uuid.uuid4()), "type": BASIC, "to": [recipient.did], "body": {"content": content}}
    if authcrypt:
        msg["from"] = sender.did
    return msg


results = []


class PythonUnsupported(Exception):
    """didcomm-messaging-python itself can't handle this key setup (not an interop bug)."""


async def python_supports(backend, docs, *parties):
    """Raise PythonUnsupported if Python can't load these parties' keys at all."""
    dmp = py_dmp(backend, docs)
    for party in parties:
        try:
            party.py_secrets(backend)
            for kid, _ in party.keys:
                vm = await dmp.resolver.resolve_and_dereference_verification_method(kid)
                dmp.crypto.verification_method_to_public_key(vm)
        except Exception as err:  # noqa: BLE001
            raise PythonUnsupported(f"{type(err).__name__}: {err}") from err


async def check(name, coro):
    try:
        detail = await coro
        results.append((name, "PASS", detail or ""))
    except PythonUnsupported as err:
        results.append((name, "SKIP", f"python can't load these keys: {err}"))
    except Exception as err:  # noqa: BLE001 - every failure is a result row
        results.append((name, "FAIL", f"{type(err).__name__}: {err}"))


# --- direct messages --------------------------------------------------------------


async def py_to_rust(peer, backend, curve, vm, authcrypt, codec=None):
    alice = Party("alice", curve, vm, codec=codec)
    bob = Party("bob", curve, vm, codec=codec)
    docs = setup(peer, alice, bob, rust_actors=[bob])
    await python_supports(backend, docs, alice, bob)
    packed = await py_dmp(backend, docs, alice).pack(
        message(alice, bob, authcrypt=authcrypt), bob.did, alice.did if authcrypt else None)
    got = peer.call(op="unpack", **{"as": bob.did}, packed=packed.message.decode())
    assert got["message"]["body"]["content"] == "Hello world!", got
    assert got["authenticated"] == authcrypt, got
    if authcrypt:
        assert got["sender_kid"] == alice.keys[0][0], got
    typ = json.loads(base64.urlsafe_b64decode(json.loads(packed.message)["protected"] + "=="))["typ"]
    return f"python typ {typ}"


async def rust_to_py(peer, backend, curve, vm, authcrypt, codec=None):
    alice = Party("alice", curve, vm, codec=codec)
    bob = Party("bob", curve, vm, codec=codec)
    docs = setup(peer, alice, bob, rust_actors=[alice])
    await python_supports(backend, docs, alice, bob)
    packed = peer.call(op="pack", **{"as": alice.did}, message=message(alice, bob, authcrypt=authcrypt),
                       to=bob.did, frm=alice.did if authcrypt else None)
    assert packed["encoding"] == "json", packed
    got = await py_dmp(backend, docs, bob).unpack(packed["packed"].encode())
    assert got.message["body"]["content"] == "Hello world!", got.message
    assert got.authenticated == authcrypt
    if authcrypt:
        assert got.sender_kid == alice.keys[0][0], got.sender_kid
    return ""


# --- multi-recipient (multi-device) ---------------------------------------------------


async def rust_to_py_multi(peer, backend, authcrypt):
    # Listed out of sorted order on purpose: Python checks apv in wire order.
    alice = Party("alice")
    bob = Party("bob", key_ids=["#z-phone", "#a-laptop"])
    docs = setup(peer, alice, bob, rust_actors=[alice])
    packed = peer.call(op="pack", **{"as": alice.did}, message=message(alice, bob, authcrypt=authcrypt),
                       to=bob.did, frm=alice.did if authcrypt else None)
    for kid, key in bob.keys:
        device = Party.__new__(Party)
        device.keys = [(kid, key)]
        got = await py_dmp(backend, docs, device).unpack(packed["packed"].encode())
        assert got.recipient_kid == kid and got.message["body"]["content"] == "Hello world!"
    return "both devices decrypt"


async def py_to_rust_multi(peer, backend, authcrypt):
    # Python's packaging packs to keyAgreement[0] only; its crypto layer takes a list,
    # in the order given, which is what a multi-recipient Python sender produces.
    alice = Party("alice")
    bob = Party("bob", key_ids=["#z-phone", "#a-laptop"])
    docs = setup(peer, alice, bob, rust_actors=[bob])
    dmp = py_dmp(backend, docs, alice)
    vms = [await dmp.resolver.resolve_and_dereference_verification_method(kid) for kid, _ in bob.keys]
    recips = [dmp.crypto.verification_method_to_public_key(vm) for vm in vms]
    plaintext = json.dumps(message(alice, bob, authcrypt=authcrypt)).encode()
    if authcrypt:
        sender = (await dmp.secrets.get_secret_by_kid(alice.keys[0][0]))
        packed = await dmp.crypto.ecdh_1pu_encrypt(recips, sender, plaintext)
    else:
        packed = await dmp.crypto.ecdh_es_encrypt(recips, plaintext)
    for kid, key in bob.keys:
        name = f"{bob.did}-{kid[-6:]}"
        peer.call(op="setup", actors={name: {"secrets": [{"kid": kid, "jwk": json.loads(key.get_jwk_secret())}]}})
        got = peer.call(op="unpack", **{"as": name}, packed=packed.decode())
        assert got["recipient_kid"] == kid and got["message"]["body"]["content"] == "Hello world!", got
    return "both devices decrypt"


# --- forwards -----------------------------------------------------------------------


async def py_sender_rust_mediator(peer, backend):
    mediator = Party("mediator")
    alice = Party("alice")
    bob = Party("bob", endpoint=mediator.did)
    docs = setup(peer, mediator, alice, bob, rust_actors=[mediator, bob])
    packed = await py_dmp(backend, docs, alice).pack(message(alice, bob), bob.did, alice.did)
    fwd = peer.call(op="unpack", **{"as": mediator.did}, packed=packed.message.decode())["message"]
    assert fwd["type"] == "https://didcomm.org/routing/2.0/forward" and fwd["body"]["next"] == bob.did, fwd
    inner = fwd["attachments"][0]["data"]["json"]
    got = peer.call(op="unpack", **{"as": bob.did}, packed=json.dumps(inner))
    assert got["message"]["body"]["content"] == "Hello world!" and got["sender_kid"] == alice.keys[0][0]
    return "forward data.json"


async def rust_sender_py_mediator(peer, backend, bob_accept):
    mediator = Party("mediator", accept=JSON_ONLY)
    alice = Party("alice")
    bob = Party("bob", endpoint=mediator.did, accept=bob_accept)
    docs = setup(peer, mediator, alice, bob, rust_actors=[alice, bob])
    packed = peer.call(op="pack", **{"as": alice.did}, message=message(alice, bob), to=bob.did, frm=alice.did)
    fwd = (await py_dmp(backend, docs, mediator).unpack(packed["packed"].encode())).message
    assert fwd["type"] == "https://didcomm.org/routing/2.0/forward" and fwd["body"]["next"] == bob.did, fwd
    data = fwd["attachments"][0]["data"]
    if "json" in data:
        inner = json.dumps(data["json"]).encode()
        got = await py_dmp(backend, docs, bob).unpack(inner)
        assert got.message["body"]["content"] == "Hello world!"
        return "forward data.json, Python recipient"
    # A CBOR recipient behind a JSON-only mediator: the standard data.base64.
    assert set(data) == {"base64"}, data
    inner = base64.urlsafe_b64decode(data["base64"] + "==")
    assert inner[:2] == b"\xd8\x60", inner[:4]
    got = peer.call(op="unpack", **{"as": bob.did}, packed_b64=data["base64"])
    assert got["message"]["body"]["content"] == "Hello world!" and got["plaintext_encoding"] == "cbor"
    return "forward data.base64 around a COSE_Encrypt"


async def forward_with_routing_keys(peer, backend, python_sends):
    """Two forward layers: the mediator's service lists a relay's key as a routing key,
    so the sender wraps for the relay, then for the mediator."""
    relay = Party("relay")
    mediator = Party("mediator")
    mediator.doc["service"][0]["serviceEndpoint"]["routingKeys"] = [relay.keys[0][0]]
    alice = Party("alice")
    bob = Party("bob", endpoint=mediator.did)
    hops = [mediator, relay, bob]
    docs = setup(peer, relay, mediator, alice, bob, rust_actors=[alice] + ([] if not python_sends else hops))
    if python_sends:
        packed = (await py_dmp(backend, docs, alice).pack(message(alice, bob), bob.did, alice.did)).message
        unwrap = lambda party, data: peer.call(op="unpack", **{"as": party.did}, packed=data)["message"]  # noqa: E731
    else:
        packed = peer.call(op="pack", **{"as": alice.did}, message=message(alice, bob), to=bob.did, frm=alice.did)["packed"].encode()

        async def unwrap_py(party, data):
            return (await py_dmp(backend, docs, party).unpack(data)).message
    data = packed.decode() if isinstance(packed, bytes) and python_sends else packed
    for hop, expected_next in [(mediator, relay.keys[0][0]), (relay, bob.did)]:
        fwd = unwrap(hop, data) if python_sends else await unwrap_py(hop, data)
        assert fwd["type"] == "https://didcomm.org/routing/2.0/forward", fwd
        assert fwd["body"]["next"] == expected_next, (fwd["body"]["next"], expected_next)
        inner = json.dumps(fwd["attachments"][0]["data"]["json"])
        data = inner if python_sends else inner.encode()
    final = unwrap(bob, data) if python_sends else await unwrap_py(bob, data)
    assert final["body"]["content"] == "Hello world!", final
    return "mediator -> relay -> recipient"


# --- other shapes -------------------------------------------------------------------


async def flattened_from_py(peer, backend):
    alice, bob = Party("alice"), Party("bob")
    docs = setup(peer, alice, bob, rust_actors=[bob])
    packed = json.loads((await py_dmp(backend, docs, alice).pack(message(alice, bob), bob.did, alice.did)).message)
    (recip,) = packed.pop("recipients")
    packed.update(encrypted_key=recip["encrypted_key"], header=recip["header"])
    got = peer.call(op="unpack", **{"as": bob.did}, packed=json.dumps(packed))
    assert got["message"]["body"]["content"] == "Hello world!"
    return ""


async def signed_rust_to_py(peer, backend):
    alice, bob = Party("alice"), Party("bob")
    docs = setup(peer, alice, bob, rust_actors=[alice])
    packed = peer.call(op="pack", **{"as": alice.did}, message=message(alice, bob, authcrypt=False),
                       to=bob.did, mode="signed", signer=f"{alice.did}#auth")
    got = (await py_dmp(backend, docs, bob).unpack(packed["packed"].encode())).message
    # didcomm-messaging-python has no JWS support: it decrypts and hands back the JWS.
    assert "payload" in got and "signatures" in got, got
    payload = json.loads(base64.urlsafe_b64decode(got["payload"] + "=="))
    assert payload["body"]["content"] == "Hello world!"
    return "decrypts; Python can't verify the JWS (no signing support)"


async def v1_both_ways(peer, authcrypt, multi):
    import nacl.bindings
    import nacl.utils

    def keypair():
        seed = nacl.utils.random(32)
        vk, sk = nacl.bindings.crypto_sign_seed_keypair(seed)
        return seed, vk, sk

    sender = keypair()
    recips = [keypair() for _ in range(2 if multi else 1)]
    plaintext = {"@type": "https://didcomm.org/basicmessage/1.0/message", "content": "Hello world!"}
    b58 = lambda vk: base58.b58encode(vk).decode()  # noqa: E731

    # Python packs, Rust unpacks.
    try:  # upstream main
        from didcomm_messaging.v1.crypto.nacl import EdPublicKey, KeyPair, NaclV1CryptoService
        svc = NaclV1CryptoService()
        packed = (await svc.pack_message(
            [EdPublicKey(vk) for _, vk, _ in recips],
            KeyPair(verkey=sender[1], sigkey=sender[2]) if authcrypt else None,
            json.dumps(plaintext).encode())).to_json()
        py_unpack = None
    except ImportError:  # 0.1.1: the legacy module
        from didcomm_messaging.legacy import crypto as legacy
        packed = json.dumps(legacy.pack_message(
            json.dumps(plaintext), [vk for _, vk, _ in recips],
            sender[1] if authcrypt else None, sender[2] if authcrypt else None))
        py_unpack = legacy.unpack_message
    for seed, vk, _ in recips:
        got = peer.call(op="v1_unpack", seeds_hex=[seed.hex()], packed=packed)
        assert got["message"]["content"] == "Hello world!" and got["recipient_kid"] == b58(vk), got
        assert (got["sender_kid"] == b58(sender[1])) if authcrypt else got["sender_kid"] is None, got

    # Rust packs, Python unpacks.
    packed = peer.call(op="v1_pack", to_verkeys=[b58(vk) for _, vk, _ in recips],
                       from_seed_hex=sender[0].hex() if authcrypt else None, message=plaintext)["packed"]
    for seed, vk, sk in recips:
        if py_unpack:
            msg, sender_vk, recip_vk = py_unpack(packed.encode(), vk, sk)
        else:
            from didcomm_messaging.v1.crypto.nacl import InMemSecretsManager
            from didcomm_messaging.v1.packaging import V1PackagingService
            secrets = InMemSecretsManager()
            secrets.create(seed)
            res = await V1PackagingService().unpack(NaclV1CryptoService(), secrets, packed)
            msg, sender_vk, recip_vk = res.unpacked, res.sender, res.recip
        assert recip_vk == b58(vk), recip_vk
        msg = json.loads(msg)
        assert msg["content"] == "Hello world!", msg
        if authcrypt:
            assert sender_vk == b58(sender[1]), sender_vk
    return ""


async def main(peer_path):
    peer = Peer(peer_path)
    backends = ["askar"] + (["authlib"] if AuthlibCryptoService else [])
    for backend in backends:
        for curve, vm, codec in [
            ("X25519", "multikey", None), ("X25519", "jwk", None),
            ("P-256", "jwk", None), ("P-384", "jwk", None),
            ("P-256", "multikey", None), ("P-256", "multikey", "P-256 (python table)"),
            ("P-384", "multikey", None),
        ]:
            label = f"{curve} {vm}" + (" (python p256 prefix)" if codec else "")
            for authcrypt in (False, True):
                mode = "authcrypt" if authcrypt else "anoncrypt"
                await check(f"{backend} | {mode} | {label} | python -> rust",
                            py_to_rust(peer, backend, curve, vm, authcrypt, codec))
                await check(f"{backend} | {mode} | {label} | rust -> python",
                            rust_to_py(peer, backend, curve, vm, authcrypt, codec))
        for authcrypt in (False, True):
            mode = "authcrypt" if authcrypt else "anoncrypt"
            await check(f"{backend} | {mode} | 2 recipients, unsorted | rust -> python",
                        rust_to_py_multi(peer, backend, authcrypt))
            await check(f"{backend} | {mode} | 2 recipients, unsorted | python -> rust",
                        py_to_rust_multi(peer, backend, authcrypt))
        await check(f"{backend} | forward | python sender -> rust mediator -> rust", py_sender_rust_mediator(peer, backend))
        await check(f"{backend} | forward | rust -> python mediator -> python (JSON)",
                    rust_sender_py_mediator(peer, backend, JSON_ONLY))
        await check(f"{backend} | forward | rust -> python mediator (JSON) -> rust (CBOR)",
                    rust_sender_py_mediator(peer, backend, CBOR))
        await check(f"{backend} | forward + routingKeys | python -> rust hops",
                    forward_with_routing_keys(peer, backend, python_sends=True))
        await check(f"{backend} | forward + routingKeys | rust -> python hops",
                    forward_with_routing_keys(peer, backend, python_sends=False))
        await check(f"{backend} | flattened JWE | python -> rust", flattened_from_py(peer, backend))
        await check(f"{backend} | signed + anoncrypt | rust -> python", signed_rust_to_py(peer, backend))
    for authcrypt in (False, True):
        for multi in (False, True):
            await check(f"v1 | {'authcrypt' if authcrypt else 'anoncrypt'} | {'2 recipients' if multi else '1 recipient'} | both ways",
                        v1_both_ways(peer, authcrypt, multi))

    width = max(len(n) for n, _, _ in results)
    print(f"didcomm-messaging {PY_VERSION}")
    for name, status, detail in results:
        print(f"{status}  {name:<{width}}  {detail}")
    count = {s: sum(r[1] == s for r in results) for s in ("PASS", "FAIL", "SKIP")}
    print(f"\n{count['PASS']} passed, {count['FAIL']} failed, {count['SKIP']} skipped (python can't load the keys)")
    return count["FAIL"]


if __name__ == "__main__":
    sys.exit(1 if asyncio.run(main(sys.argv[1])) else 0)
