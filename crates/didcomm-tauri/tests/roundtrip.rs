//! Integration tests for `didcomm-tauri`'s real logic, exercised through
//! `DidcommMessagingStore`'s own methods directly (not the `#[tauri::command]`
//! wrappers, which need a live `tauri::App` to construct their `tauri::State`
//! argument -- see `commands.rs`'s own doc comment for why the split exists). A true
//! integration test binary (not a `#[cfg(test)]` module inside the crate) for the same
//! reason `didcomm-core`'s own `rotation.rs` integration test is one: depending on
//! `didcomm-crypto-askar` from a unit test module inside a crate that crypto crate
//! itself depends on (via `didcomm-quickstart`) hits Cargo's "multiple different
//! versions of crate didcomm_core" duplicate-trait error, which a separate test binary
//! avoids.

use didcomm_tauri::commands::{DidcommMessagingStore, GeneratedDid};
use serde_json::json;

fn generated_did_input(g: didcomm_tauri::commands::GeneratedDid) -> GeneratedDid {
    g
}

#[tokio::test]
async fn generate_pack_unpack_round_trip() {
    let alice_store = DidcommMessagingStore::default();
    let bob_store = DidcommMessagingStore::default();

    let alice_generated = didcomm_tauri::commands::generate_did().expect("generate alice did");
    let bob_generated = didcomm_tauri::commands::generate_did().expect("generate bob did");
    let bob_did = bob_generated.did.clone();
    let alice_did = alice_generated.did.clone();

    let alice_handle = alice_store
        .setup_default(generated_did_input(alice_generated))
        .expect("setup alice messaging");
    let bob_handle = bob_store
        .setup_default(generated_did_input(bob_generated))
        .expect("setup bob messaging");

    let message = json!({
        "type": "https://didcomm.org/basicmessage/2.0/message",
        "body": { "content": "hi from didcomm-tauri" },
    });

    let packed = alice_store
        .pack(&alice_handle, &message, &bob_did, Some(&alice_did))
        .await
        .expect("pack message");
    assert!(!packed.message.is_empty());

    let unpacked = bob_store
        .unpack(&bob_handle, &packed.message)
        .await
        .expect("unpack message");
    assert!(unpacked.encrypted);
    assert!(unpacked.authenticated);
    assert_eq!(unpacked.message["body"]["content"], "hi from didcomm-tauri");
}

#[tokio::test]
async fn from_prior_build_and_verify_round_trip() {
    let store = DidcommMessagingStore::default();

    // A device rotating its own Identity DID needs a messaging handle for the *new*
    // DID to sign with -- build_from_prior/verify_from_prior only need `inner.crypto`/
    // `inner.resolver`, which any handle carries identically.
    let prior_generated = didcomm_tauri::commands::generate_did().expect("generate prior did");
    let prior_did = prior_generated.did.clone();
    let signing_secret_jwk = prior_generated.verification_secret_jwk.clone();

    let new_generated = didcomm_tauri::commands::generate_did().expect("generate new did");
    let new_did = new_generated.did.clone();
    let handle = store.setup_default(generated_did_input(new_generated)).expect("setup messaging");

    // did:peer:4's own authentication verification method is always `{did}#key-1`
    // (the first entry `didcomm_quickstart::generate_did` lists) for a freshly
    // generated single-key document.
    let signing_kid = format!("{prior_did}#key-1");

    let jwt = store
        .build_from_prior(&handle, &prior_did, &new_did, &signing_secret_jwk, &signing_kid, 1_700_000_000)
        .await
        .expect("build from_prior");

    let verified = store.verify_from_prior(&handle, &jwt).await.expect("verify from_prior");
    assert_eq!(verified.prior_did, prior_did);
    assert_eq!(verified.new_did, new_did);
}

#[tokio::test]
async fn unknown_handle_is_a_clean_error_not_a_panic() {
    let store = DidcommMessagingStore::default();
    let message = json!({ "type": "https://didcomm.org/basicmessage/2.0/message", "body": {} });
    let err = store
        .pack("not-a-real-handle", &message, "did:example:123", None)
        .await
        .expect_err("packing with an unknown handle must fail, not panic");
    assert!(err.contains("unknown DidcommMessaging handle"));
}

/// A signed message (`anoncrypt(sign(plaintext))`) has no authcrypt sender; what
/// vouches for it is the signature, reported as `signer_kid`.
#[tokio::test]
async fn pack_signed_round_trip_reports_the_signer() {
    let alice_store = DidcommMessagingStore::default();
    let bob_store = DidcommMessagingStore::default();

    let alice_generated = didcomm_tauri::commands::generate_did().expect("generate alice did");
    let bob_generated = didcomm_tauri::commands::generate_did().expect("generate bob did");
    let alice_did = alice_generated.did.clone();
    let bob_did = bob_generated.did.clone();
    let alice_signing_secret = alice_generated.verification_secret_jwk.clone();
    // quickstart's did:peer:4 lists its authentication key at #key-1.
    let alice_signing_kid = format!("{alice_did}#key-1");

    let alice_handle = alice_store
        .setup_default(generated_did_input(alice_generated))
        .expect("setup alice messaging");
    let bob_handle = bob_store
        .setup_default(generated_did_input(bob_generated))
        .expect("setup bob messaging");

    let message = json!({
        "type": "https://example.org/roster/1.0/change",
        "body": { "seq": 7 },
    });
    let packed = alice_store
        .pack_signed(&alice_handle, &message, &bob_did, &alice_signing_secret, &alice_signing_kid)
        .await
        .expect("pack signed message");

    let unpacked = bob_store
        .unpack(&bob_handle, &packed.message)
        .await
        .expect("unpack signed message");
    assert!(unpacked.encrypted);
    assert_eq!(unpacked.sender_kid, None, "anoncrypt has no authcrypt sender");
    assert_eq!(unpacked.signer_kid.as_deref(), Some(alice_signing_kid.as_str()));
    assert_eq!(unpacked.message["from"], alice_did);
    assert_eq!(unpacked.message["body"]["seq"], 7);
}

/// A key can vouch for a DID with the same JWT shape `from_prior` uses, issued under
/// its own `did:key` -- how a device proves it holds the private half of a key it is
/// asking to have listed (multi-device/1.0's `device-promote-request`).
#[tokio::test]
async fn a_did_key_issued_jwt_proves_possession_of_that_key() {
    let store = DidcommMessagingStore::default();
    let device = didcomm_tauri::commands::generate_did().expect("generate device did");
    let device_did = device.did.clone();
    let handle = store
        .setup_default(generated_did_input(device))
        .expect("setup messaging");

    let keypair = didcomm_tauri::commands::generate_authentication_keypair().expect("generate keypair");
    let key_did = format!("did:key:{}", keypair.public_multikey);
    let kid = format!("{key_did}#{}", keypair.public_multikey);

    let proof = store
        .build_from_prior(&handle, &key_did, &device_did, &keypair.secret_jwk, &kid, 1_700_000_000)
        .await
        .expect("sign proof");
    let verified = store.verify_from_prior(&handle, &proof).await.expect("verify proof");
    assert_eq!(verified.prior_did, key_did);
    assert_eq!(verified.new_did, device_did);

    // Signed by some other key than the one it claims to speak for: rejected.
    let other = didcomm_tauri::commands::generate_authentication_keypair().expect("generate keypair");
    let forged = store
        .build_from_prior(&handle, &key_did, &device_did, &other.secret_jwk, &kid, 1_700_000_000)
        .await
        .expect("sign forged proof");
    assert!(store.verify_from_prior(&handle, &forged).await.is_err());
}
