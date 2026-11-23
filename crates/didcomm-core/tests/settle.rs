//! `didcomm_core::settle::verify_identity_settle` against settles the Wyvrn app made,
//! and against real did:peer:4 documents and keys.
//!
//! `fixtures/multi-device/identity-settle.json` was made by wyvrn-chat's own code
//! (`recoveryKeys.ts`: `recoveryKeyFromCode`, `settleBytes`, `proofByCode`,
//! `passkeyProof`; a WebCrypto P-256 key standing in for an authenticator), and
//! checked there by `verifyRecoveryProof` and `settleNoticeHolds` before it was
//! written: `bytes` is what the app signed, `passkey_high_s_signature` the same
//! assertion's signature with `n - s`, which the app takes too.

use askar_crypto::alg::{ed25519::Ed25519KeyPair, p256::P256KeyPair, x25519::X25519KeyPair};
use askar_crypto::repr::{KeyGen, KeyPublicBytes};
use askar_crypto::sign::KeySign;
use didcomm_core::settle::{
    settle_bytes, verify_identity_settle, IdentitySettle, SettleError, SETTLE_PURPOSE,
};
use didcomm_crypto_askar::AskarCryptoService;
use didcomm_multiformats::{multibase, multicodec, multikey};
use didcomm_resolver_peer::peer4::{self, CredentialKey, Dates, UnboundKey};
use didcomm_resolver_peer::KeyPurpose;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const VECTORS: &str = include_str!("../../../fixtures/multi-device/identity-settle.json");

fn vectors() -> Value {
    serde_json::from_str(VECTORS).unwrap()
}

/// The prior DID's document as the app would list the vector's keys: under no
/// relationship, `#<id>`.
fn prior_document(vectors: &Value) -> Value {
    let keys = vectors["code_settle"]["recovery_keys"].as_array().unwrap();
    let mut methods = vec![
        json!({"id": "#key-1", "type": "Multikey", "publicKeyMultibase": "z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH"}),
    ];
    methods.extend(keys.iter().map(|key| {
        json!({"id": format!("#{}", key["id"].as_str().unwrap()), "type": "Multikey", "publicKeyMultibase": key["public_key"]})
    }));
    json!({"id": vectors["prior_did"], "verificationMethod": methods, "authentication": ["#key-1"]})
}

fn check(vectors: &Value, document: &Value, settle: &Value) -> Result<IdentitySettle, SettleError> {
    pollster::block_on(verify_identity_settle(
        &AskarCryptoService,
        vectors["prior_did"].as_str().unwrap(),
        document,
        vectors["identity_did"].as_str().unwrap(),
        settle,
    ))
}

#[test]
fn the_bytes_are_the_apps() {
    let v = vectors();
    let settle = IdentitySettle::from_value(&v["code_settle"]).unwrap();
    let bytes = settle_bytes(
        settle.rotation_seq,
        v["prior_did"].as_str().unwrap(),
        v["identity_did"].as_str().unwrap(),
        &settle.roster_digest,
        &settle.recovery_keys,
    );
    assert_eq!(
        String::from_utf8(bytes).unwrap(),
        v["bytes"].as_str().unwrap()
    );
}

#[test]
fn the_apps_recovery_code_and_passkey_settles_verify() {
    let v = vectors();
    let document = prior_document(&v);
    check(&v, &document, &v["code_settle"]).expect("the recovery code's");
    check(&v, &document, &v["passkey_settle"]).expect("the passkey's");
    let mut high_s = v["passkey_settle"].clone();
    high_s["recovery_proof"]["signature"] = v["passkey_high_s_signature"].clone();
    check(&v, &document, &high_s).expect("the passkey's, with n - s");
}

#[test]
fn a_forged_or_misdirected_proof_is_refused() {
    let v = vectors();
    let document = prior_document(&v);
    for which in ["code_settle", "passkey_settle"] {
        let mut forged = v[which].clone();
        let mut signature =
            multibase::decode(forged["recovery_proof"]["signature"].as_str().unwrap()).unwrap();
        let last = signature.len() - 3;
        signature[last] ^= 1;
        forged["recovery_proof"]["signature"] = json!(multibase::encode(&signature));
        assert_eq!(
            check(&v, &document, &forged).unwrap_err(),
            SettleError::InvalidProof,
            "{which}"
        );

        // Another move than the one proved.
        let elsewhere = pollster::block_on(verify_identity_settle(
            &AskarCryptoService,
            v["prior_did"].as_str().unwrap(),
            &document,
            "did:example:thief",
            &v[which],
        ));
        assert_eq!(elsewhere.unwrap_err(), SettleError::InvalidProof, "{which}");

        // Any field of what was proved changed.
        let mut later = v[which].clone();
        later["rotation_seq"] = json!(8);
        assert_eq!(
            check(&v, &document, &later).unwrap_err(),
            SettleError::InvalidProof,
            "{which}"
        );
        let mut fewer = v[which].clone();
        fewer["recovery_keys"]
            .as_array_mut()
            .unwrap()
            .retain(|key| key["id"] == v[which]["recovery_proof"]["key"]);
        assert_eq!(
            check(&v, &document, &fewer).unwrap_err(),
            SettleError::InvalidProof,
            "{which}"
        );

        let mut purpose = v[which].clone();
        purpose["recovery_proof"]["purpose"] = json!("wyvrn-roster-settle/1");
        assert_eq!(
            check(&v, &document, &purpose).unwrap_err(),
            SettleError::WrongPurpose,
            "{which}"
        );
    }
}

#[test]
fn a_proof_by_the_wrong_key_is_refused() {
    let v = vectors();
    let document = prior_document(&v);
    // The recovery code's signature, said to be the passkey's.
    let mut wrong = v["code_settle"].clone();
    wrong["recovery_proof"]["key"] = json!("passkey-9z8y");
    assert_eq!(
        check(&v, &document, &wrong).unwrap_err(),
        SettleError::InvalidProof
    );
    // A key the list doesn't have.
    let mut unknown = v["code_settle"].clone();
    unknown["recovery_proof"]["key"] = json!("recovery-other");
    assert_eq!(
        check(&v, &document, &unknown).unwrap_err(),
        SettleError::UnknownKey
    );
    // A key the list has under another public key than the document's: the
    // settle's own list is not taken on trust.
    let mut swapped = v["code_settle"].clone();
    swapped["recovery_keys"][0]["public_key"] =
        json!("z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK");
    assert_eq!(
        check(&v, &document, &swapped).unwrap_err(),
        SettleError::NotListed
    );
}

#[test]
fn a_key_the_prior_document_doesnt_list_under_no_relationship_is_refused() {
    let v = vectors();
    // Not listed at all.
    let mut bare = prior_document(&v);
    bare["verificationMethod"]
        .as_array_mut()
        .unwrap()
        .truncate(1);
    assert_eq!(
        check(&v, &bare, &v["code_settle"]).unwrap_err(),
        SettleError::NotListed
    );
    // Listed, but named by a relationship: not a recovery key.
    for relationship in [
        "authentication",
        "assertionMethod",
        "keyAgreement",
        "capabilityInvocation",
        "capabilityDelegation",
    ] {
        let mut named = prior_document(&v);
        named[relationship] = json!([format!(
            "{}#recovery-1a2b3c4d",
            v["prior_did"].as_str().unwrap()
        )]);
        assert_eq!(
            check(&v, &named, &v["code_settle"]).unwrap_err(),
            SettleError::NotListed,
            "{relationship}"
        );
    }
    // Listed with another public key.
    let mut other = prior_document(&v);
    other["verificationMethod"][1]["publicKeyMultibase"] =
        json!("z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK");
    assert_eq!(
        check(&v, &other, &v["code_settle"]).unwrap_err(),
        SettleError::NotListed
    );
}

#[test]
fn a_malformed_settle_is_refused_by_shape() {
    let v = vectors();
    let document = prior_document(&v);
    for (field, value) in [
        ("rotation_seq", json!("7")),
        ("rotation_seq", json!(1u64 << 60)),
        ("roster_digest", json!("short")),
        ("recovery_keys", json!({})),
        ("recovery_proof", json!({"key": "recovery-1a2b3c4d"})),
    ] {
        let mut bad = v["code_settle"].clone();
        bad[field] = value;
        assert!(
            matches!(check(&v, &document, &bad), Err(SettleError::Malformed(_))),
            "{field}"
        );
    }
}

/// A passkey assertion over `bytes`, signed by `key`, with `flags` and `type`.
fn assertion(key: &P256KeyPair, rp_id: &str, bytes: &[u8], flags: u8, kind: &str) -> Value {
    let mut authenticator_data = Sha256::digest(rp_id.as_bytes()).to_vec();
    authenticator_data.extend([flags, 0, 0, 0, 1]);
    let client_data_json = serde_json::to_vec(&json!({
        "type": kind,
        "challenge": multibase::encode(Sha256::digest(bytes)),
        "origin": "https://anywhere.example",
    }))
    .unwrap();
    let mut signed = authenticator_data.clone();
    signed.extend(Sha256::digest(&client_data_json));
    let raw = key.create_signature(&signed, None).unwrap();
    let der_int = |half: &[u8]| {
        let start = half.iter().position(|&b| b != 0).unwrap_or(31);
        let mut value = half[start..].to_vec();
        if value[0] >= 0x80 {
            value.insert(0, 0);
        }
        let mut out = vec![0x02, value.len() as u8];
        out.extend(value);
        out
    };
    let mut body = der_int(&raw[..32]);
    body.extend(der_int(&raw[32..]));
    let mut der = vec![0x30, body.len() as u8];
    der.extend(body);
    json!({
        "key": "passkey-1",
        "purpose": SETTLE_PURPOSE,
        "signature": multibase::encode(der),
        "authenticator_data": multibase::encode(authenticator_data),
        "client_data_json": multibase::encode(client_data_json),
    })
}

#[test]
fn a_passkey_assertion_needs_the_challenge_rp_id_user_present_and_verified() {
    let passkey = P256KeyPair::random().unwrap();
    let public_key = multikey::encode(
        multicodec::P256_PUB,
        &passkey.with_public_bytes(<[u8]>::to_vec),
    );
    let keys = json!([{"id": "passkey-1", "kind": "passkey", "public_key": public_key, "credential_id": "Y3JlZA", "rp_id": "wyvrn.app"}]);
    let prior = "did:example:p";
    let document =
        json!({"verificationMethod": [{"id": "#passkey-1", "publicKeyMultibase": public_key}]});
    let digest = multibase::encode(Sha256::digest(b"[]"));
    let parsed = IdentitySettle::from_value(&json!({"rotation_seq": 2, "roster_digest": digest, "recovery_keys": keys, "recovery_proof": {"key": "passkey-1", "purpose": SETTLE_PURPOSE, "signature": "AA"}})).unwrap();
    let bytes = settle_bytes(2, prior, "did:example:s", &digest, &parsed.recovery_keys);
    let settle = |proof: Value| json!({"rotation_seq": 2, "roster_digest": digest, "recovery_keys": keys, "recovery_proof": proof});
    let run = |proof: Value| {
        pollster::block_on(verify_identity_settle(
            &AskarCryptoService,
            prior,
            &document,
            "did:example:s",
            &settle(proof),
        ))
    };

    run(assertion(
        &passkey,
        "wyvrn.app",
        &bytes,
        0x05,
        "webauthn.get",
    ))
    .expect("user present and verified");
    for (what, proof) in [
        (
            "user not verified",
            assertion(&passkey, "wyvrn.app", &bytes, 0x01, "webauthn.get"),
        ),
        (
            "user not present",
            assertion(&passkey, "wyvrn.app", &bytes, 0x04, "webauthn.get"),
        ),
        (
            "another RP ID",
            assertion(&passkey, "evil.example", &bytes, 0x05, "webauthn.get"),
        ),
        (
            "a registration, not an assertion",
            assertion(&passkey, "wyvrn.app", &bytes, 0x05, "webauthn.create"),
        ),
        (
            "another challenge",
            assertion(
                &passkey,
                "wyvrn.app",
                b"something else",
                0x05,
                "webauthn.get",
            ),
        ),
        (
            "another key",
            assertion(
                &P256KeyPair::random().unwrap(),
                "wyvrn.app",
                &bytes,
                0x05,
                "webauthn.get",
            ),
        ),
    ] {
        assert_eq!(run(proof).unwrap_err(), SettleError::InvalidProof, "{what}");
    }
}

/// A real did:peer:4 Identity DID with a recovery key, and a settle made for it
/// here the way the app makes one.
#[test]
fn a_settle_of_a_real_peer4_identity_verifies_and_its_kind_must_match_its_key() {
    let auth = Ed25519KeyPair::random().unwrap();
    let agreement = X25519KeyPair::random().unwrap();
    let recovery = Ed25519KeyPair::random().unwrap();
    let auth_multikey = multikey::encode(
        multicodec::ED25519_PUB,
        &auth.with_public_bytes(<[u8]>::to_vec),
    );
    let agreement_multikey = multikey::encode(
        multicodec::X25519_PUB,
        &agreement.with_public_bytes(<[u8]>::to_vec),
    );
    let recovery_multikey = multikey::encode(
        multicodec::ED25519_PUB,
        &recovery.with_public_bytes(<[u8]>::to_vec),
    );
    let credential = multikey::encode(
        multicodec::ED25519_PUB,
        &Ed25519KeyPair::random()
            .unwrap()
            .with_public_bytes(<[u8]>::to_vec),
    );
    let prior = peer4::generate_with_unbound_keys(
        &[
            (KeyPurpose::Authentication, auth_multikey.as_str()),
            (KeyPurpose::KeyAgreement, agreement_multikey.as_str()),
        ],
        &[CredentialKey {
            multikey: &credential,
            controller: "did:example:device",
        }],
        &[UnboundKey {
            id: "recovery-1a2b3c4d",
            multikey: &recovery_multikey,
        }],
        &[],
        &[],
        Dates::default(),
    )
    .unwrap();
    let document = peer4::resolve(&prior).unwrap();
    let settled = "did:example:settled";
    let digest = multibase::encode(Sha256::digest(b"[{\"device_did\":\"did:example:device\"}]"));
    let keys =
        json!([{"id": "recovery-1a2b3c4d", "kind": "recovery", "public_key": recovery_multikey}]);
    let parsed = IdentitySettle::from_value(&json!({"rotation_seq": 4, "roster_digest": digest, "recovery_keys": keys, "recovery_proof": {"key": "recovery-1a2b3c4d", "purpose": SETTLE_PURPOSE, "signature": "AA"}})).unwrap();
    let bytes = settle_bytes(4, &prior, settled, &digest, &parsed.recovery_keys);
    let signature = multibase::encode(recovery.create_signature(&bytes, None).unwrap());
    let settle = json!({"rotation_seq": 4, "roster_digest": digest, "recovery_keys": keys, "recovery_proof": {"key": "recovery-1a2b3c4d", "purpose": SETTLE_PURPOSE, "signature": signature}});
    let run = |settle: &Value| {
        pollster::block_on(verify_identity_settle(
            &AskarCryptoService,
            &prior,
            &document,
            settled,
            settle,
        ))
    };
    run(&settle).expect("a proof by the document's recovery key");

    // Signed by the device's own authentication key instead: not a recovery key,
    // even with the list naming it.
    let mut by_auth = settle.clone();
    by_auth["recovery_keys"][0]["public_key"] = json!(auth_multikey);
    by_auth["recovery_proof"]["signature"] = json!(multibase::encode(
        auth.create_signature(&bytes, None).unwrap()
    ));
    assert_eq!(run(&by_auth).unwrap_err(), SettleError::NotListed);

    // A recovery key said to be a passkey isn't checked as one.
    let mut as_passkey = settle.clone();
    as_passkey["recovery_keys"][0] = json!({"id": "recovery-1a2b3c4d", "kind": "passkey", "public_key": recovery_multikey, "credential_id": "eA", "rp_id": "wyvrn.app"});
    assert_eq!(run(&as_passkey).unwrap_err(), SettleError::InvalidProof);
}
