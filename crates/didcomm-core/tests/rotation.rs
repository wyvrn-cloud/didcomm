//! Proves `from_prior` DID rotation end to end against real key material and a real
//! resolver (`Peer4`), not mocks.

use askar_crypto::alg::{ed25519::Ed25519KeyPair, x25519::X25519KeyPair};
use askar_crypto::repr::{KeyGen, KeyPublicBytes};
use didcomm_core::rotation::{build_from_prior, verify_from_prior, RotationError};
use didcomm_crypto_askar::{AskarCryptoService, AskarSigningKey};
use didcomm_multiformats::{multicodec, multikey};
use didcomm_resolver_peer::peer4::{self, Peer4};
use didcomm_resolver_peer::KeyPurpose;

fn generate_peer4_with_auth_key() -> (String, Ed25519KeyPair) {
    let auth_key = Ed25519KeyPair::random().unwrap();
    let key_agreement_key = X25519KeyPair::random().unwrap();
    let auth_multikey = multikey::encode(
        multicodec::ED25519_PUB,
        &auth_key.with_public_bytes(<[u8]>::to_vec),
    );
    let key_agreement_multikey = multikey::encode(
        multicodec::X25519_PUB,
        &key_agreement_key.with_public_bytes(<[u8]>::to_vec),
    );
    let did = peer4::generate(
        &[
            (KeyPurpose::Authentication, auth_multikey.as_str()),
            (KeyPurpose::KeyAgreement, key_agreement_multikey.as_str()),
        ],
        &[],
    )
    .unwrap();
    (did, auth_key)
}

#[test]
fn build_and_verify_round_trip() {
    pollster::block_on(async {
        let (prior_did, auth_key) = generate_peer4_with_auth_key();
        let resolver = Peer4;
        let crypto = AskarCryptoService;
        let signing_key = AskarSigningKey::new(format!("{prior_did}#key-1"), auth_key);

        let new_did = "did:peer:4zQmNewIdentityPlaceholder";
        let jwt = build_from_prior(&crypto, &prior_did, new_did, &signing_key, 1_735_689_600)
            .await
            .unwrap();

        let (verified_prior, verified_new) =
            verify_from_prior(&crypto, &resolver, &jwt).await.unwrap();
        assert_eq!(verified_prior, prior_did);
        assert_eq!(verified_new, new_did);
    });
}

#[test]
fn verify_rejects_a_jwt_signed_by_an_unrelated_dids_key() {
    pollster::block_on(async {
        let (prior_did, _real_key) = generate_peer4_with_auth_key();
        let (_attacker_did, attacker_key) = generate_peer4_with_auth_key();
        let resolver = Peer4;
        let crypto = AskarCryptoService;
        // Forged: claims to be `iss: prior_did`, but signed with a completely
        // different identity's key -- resolving prior_did for real still finds the
        // *real* key-1, so the signature (made with a different key entirely) fails.
        let forged_signing_key = AskarSigningKey::new(format!("{prior_did}#key-1"), attacker_key);

        let jwt = build_from_prior(
            &crypto,
            &prior_did,
            "did:peer:4zQmForged",
            &forged_signing_key,
            1_735_689_600,
        )
        .await
        .unwrap();

        let err = verify_from_prior(&crypto, &resolver, &jwt).await.unwrap_err();
        assert!(matches!(err, RotationError::InvalidSignature));
    });
}

#[test]
fn verify_rejects_a_kid_that_does_not_belong_to_the_claimed_iss() {
    pollster::block_on(async {
        let (prior_did, _real_key) = generate_peer4_with_auth_key();
        let (attacker_did, attacker_key) = generate_peer4_with_auth_key();
        let resolver = Peer4;
        let crypto = AskarCryptoService;
        // The kid names the attacker's own DID (where this key genuinely is
        // key-1), but the payload's iss claims to be prior_did -- a forged rotation
        // trying to hijack an identity it never controlled.
        let attacker_signing_key = AskarSigningKey::new(format!("{attacker_did}#key-1"), attacker_key);

        let jwt = build_from_prior(
            &crypto,
            &prior_did,
            "did:peer:4zQmForged",
            &attacker_signing_key,
            1_735_689_600,
        )
        .await
        .unwrap();

        let err = verify_from_prior(&crypto, &resolver, &jwt).await.unwrap_err();
        assert!(matches!(err, RotationError::Malformed(_)));
    });
}
