// Node.js smoke test for the wasm package's quickstart flow: two peers, each generated
// and set up entirely from JS, pack/unpack a real message to each other.
//
// (Wrapped in an async main() out of habit, not because it matters here -- top-level
// await works fine too. If this ever starts failing with askar-crypto's "Encryption
// error" again, see the workspace root Cargo.toml's `[profile.release]` comment: it was
// previously traced to a release-profile-only wasm32 codegen bug, not anything about how
// this script calls into the package.)
import assert from "node:assert/strict";
import { generateDid, DidcommMessaging } from "./pkg-node/didcomm_wasm.js";

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

main().catch((e) => {
  console.error("FAILED:", e);
  process.exit(1);
});
