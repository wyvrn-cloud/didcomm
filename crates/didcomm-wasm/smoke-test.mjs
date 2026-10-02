// Node.js smoke test for the wasm package's quickstart flow: two peers, each generated
// and set up entirely from JS, pack/unpack a real message to each other.
//
// (Wrapped in an async main() out of habit, not because it matters here -- top-level
// await works fine too. If this ever starts failing with askar-crypto's "Encryption
// error" again, see the workspace root Cargo.toml's `[profile.release]` comment: it was
// previously traced to a release-profile-only wasm32 codegen bug, not anything about how
// this script calls into the package.)
import assert from "node:assert/strict";
import { generateDid, generateDidWithEndpoint, DidcommMessaging } from "./pkg-node/didcomm_wasm.js";

async function checkFromSecrets() {
  const alice = generateDid();
  const bob = generateDid();
  // Simulate an app restart: rebuild a DidcommMessaging from persisted JWK strings
  // alone (no GeneratedDid instance in hand), as wyvrn-chat's worker does on every
  // load after the first.
  const reloadedAlice = DidcommMessaging.fromSecrets(
    alice.did,
    alice.verificationSecretJwk,
    alice.keyAgreementSecretJwk
  );
  const bobDmp = DidcommMessaging.setupDefault(bob);

  const packed = await reloadedAlice.pack(
    { type: "https://didcomm.org/basicmessage/2.0/message", body: { content: "reloaded" } },
    bob.did,
    alice.did
  );
  const unpacked = await bobDmp.unpack(packed.message);
  assert.equal(unpacked.message.body.content, "reloaded");
  assert.equal(unpacked.authenticated, true);
  assert.equal(unpacked.senderKid, `${alice.did}#key-2`);
  // pack completes the standard headers by default...
  assert.equal(reloadedAlice.verbatimHeaders, false);
  for (const header of ["id", "from", "to", "created_time"]) {
    assert.ok(header in unpacked.message, header);
  }
  assert.equal(unpacked.message.from, alice.did);
  assert.deepEqual(unpacked.message.to, [bob.did]);

  // ...and packs the message exactly as given once opted out.
  reloadedAlice.verbatimHeaders = true;
  assert.equal(reloadedAlice.verbatimHeaders, true);
  const message = { type: "https://didcomm.org/basicmessage/2.0/message", body: { content: "as is" } };
  const verbatim = await bobDmp.unpack((await reloadedAlice.pack(message, bob.did, alice.did)).message);
  assert.deepEqual(verbatim.message, message);

  console.log("OK: DidcommMessaging.fromSecrets rebuilds a working identity from persisted JWKs");
}

async function main() {
  const alice = generateDid();
  const bob = generateDid();

  const routed = generateDidWithEndpoint("https://example.com/mediator-routing-did");
  assert.ok(routed.did.length > 0);
  const packedToRouted = await DidcommMessaging.setupDefault(alice).pack(
    { type: "https://didcomm.org/basicmessage/2.0/message", body: { content: "hi" } },
    routed.did,
    alice.did
  );
  assert.equal(packedToRouted.targetServices[0].uri, "https://example.com/mediator-routing-did");
  console.log("OK: generateDidWithEndpoint sets the caller-chosen service endpoint");

  console.log("alice:", alice.did);
  console.log("bob:", bob.did);

  const aliceDmp = DidcommMessaging.setupDefault(alice);
  const bobDmp = DidcommMessaging.setupDefault(bob);

  const message = {
    type: "https://didcomm.org/basicmessage/2.0/message",
    body: { content: "Hello world!" },
  };

  const packed = await aliceDmp.pack(message, bob.did, alice.did);
  console.log("packed.targetServices:", packed.targetServices);
  assert.ok(packed.message instanceof Uint8Array);
  assert.equal(packed.targetServices.length, 1);
  assert.equal(packed.targetServices[0].uri, "didcomm:transport/queue"); // generateDid's default endpoint

  const unpacked = await bobDmp.unpack(packed.message);
  console.log("unpacked:", unpacked);
  assert.equal(unpacked.message.body.content, "Hello world!");
  assert.equal(unpacked.authenticated, true);
  assert.equal(unpacked.senderKid, `${alice.did}#key-2`);

  console.log("OK: wasm quickstart flow packed and unpacked a real authenticated message");
}

checkFromSecrets()
  .then(main)
  .catch((e) => {
  console.error("FAILED:", e);
  process.exit(1);
});
