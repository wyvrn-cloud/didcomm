// Node.js smoke test for the napi-rs package's quickstart flow: two peers, each
// generated and set up entirely from JS, pack/unpack a real message to each other.
import assert from "node:assert/strict";
import { generateDid, generateDidWithEndpoint, restoreDid, DidcommMessaging } from "./index.js";

async function main() {
  const alice = generateDid();
  const bob = generateDid();

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
  assert.ok(Buffer.isBuffer(packed.message));
  assert.equal(packed.targetServices.length, 1);
  assert.equal(packed.targetServices[0].uri, "didcomm:transport/queue");

  const unpacked = await bobDmp.unpack(packed.message);
  console.log("unpacked:", unpacked);
  assert.equal(unpacked.message.body.content, "Hello world!");
  assert.equal(unpacked.authenticated, true);
  assert.equal(unpacked.senderKid, `${alice.did}#key-2`);

  // pack completes the standard headers by default...
  assert.equal(aliceDmp.verbatimHeaders, false);
  for (const header of ["id", "from", "to", "created_time"]) {
    assert.ok(header in unpacked.message, header);
  }
  assert.equal(unpacked.message.from, alice.did);
  assert.deepEqual(unpacked.message.to, [bob.did]);

  // ...and packs the message exactly as given once opted out.
  aliceDmp.verbatimHeaders = true;
  assert.equal(aliceDmp.verbatimHeaders, true);
  const verbatim = await bobDmp.unpack((await aliceDmp.pack(message, bob.did, alice.did)).message);
  assert.deepEqual(verbatim.message, message);

  // The same keys and endpoint give the same DID back, and it reads what was sent to it.
  const kept = generateDidWithEndpoint("https://bot.example/");
  const restored = restoreDid(kept.verificationSecretJwk, kept.keyAgreementSecretJwk, "https://bot.example/");
  assert.equal(restored.did, kept.did);
  const toKept = await bobDmp.pack(message, kept.did, bob.did);
  const readBack = await DidcommMessaging.setupDefault(restored).unpack(toKept.message);
  assert.equal(readBack.message.body.content, "Hello world!");
  // Another endpoint, the same keys: another DID.
  assert.notEqual(restoreDid(kept.verificationSecretJwk, kept.keyAgreementSecretJwk, "https://other.example/").did, kept.did);

  // A from_prior (DIDComm v2.1, DID Rotation): alice moves to carol, signed by
  // alice's authentication key (a did:peer:4's is #key-1), verified by bob.
  const carol = generateDid();
  const jwt = await aliceDmp.buildFromPrior(alice.did, carol.did, alice.verificationSecretJwk, `${alice.did}#key-1`, 1700000000);
  const rotation = await bobDmp.verifyRotation(jwt);
  assert.deepEqual(rotation, { priorDid: alice.did, newDid: carol.did, iat: 1700000000 });
  // Signed by a key that isn't alice's: refused.
  const forged = await aliceDmp.buildFromPrior(alice.did, carol.did, carol.verificationSecretJwk, `${alice.did}#key-1`, 1700000000);
  await assert.rejects(bobDmp.verifyRotation(forged));
  await assert.rejects(bobDmp.verifyRotation("not.a.jwt"));

  console.log("OK: napi-rs quickstart flow packed and unpacked a real authenticated message");
}

main().catch((e) => {
  console.error("FAILED:", e);
  process.exit(1);
});
