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

/// A key the prior DID lists only for credentials (assertionMethod: an untrusted
/// device's), or a JWT dated in the future, moves nothing (security review WYV-27).
#[test]
fn verify_rejects_a_key_not_listed_for_authentication_and_a_future_jwt() {
    pollster::block_on(async {
        let (auth_key, credential_key) = (Ed25519KeyPair::random().unwrap(), Ed25519KeyPair::random().unwrap());
        let key_agreement = X25519KeyPair::random().unwrap();
        let encode = |codec, bytes: Vec<u8>| multikey::encode(codec, &bytes);
        let did = peer4::generate(
            &[
                (KeyPurpose::Authentication, encode(multicodec::ED25519_PUB, auth_key.with_public_bytes(<[u8]>::to_vec)).as_str()),
                (KeyPurpose::Assertion, encode(multicodec::ED25519_PUB, credential_key.with_public_bytes(<[u8]>::to_vec)).as_str()),
                (KeyPurpose::KeyAgreement, encode(multicodec::X25519_PUB, key_agreement.with_public_bytes(<[u8]>::to_vec)).as_str()),
            ],
            &[],
        )
        .unwrap();
        let crypto = AskarCryptoService;
        let by_credential_key = AskarSigningKey::new(format!("{did}#key-2"), credential_key);
        let jwt = build_from_prior(&crypto, &did, "did:peer:4zQmElsewhere", &by_credential_key, 1_735_689_600).await.unwrap();
        assert!(matches!(verify_from_prior(&crypto, &Peer4, &jwt).await, Err(RotationError::Malformed(_))));

        let by_auth_key = AskarSigningKey::new(format!("{did}#key-1"), auth_key);
        let future = 4_102_444_800; // 2100
        let jwt = build_from_prior(&crypto, &did, "did:peer:4zQmElsewhere", &by_auth_key, future).await.unwrap();
        assert!(matches!(verify_from_prior(&crypto, &Peer4, &jwt).await, Err(RotationError::Malformed(_))));
    });
}

/// A key the document names under no verification relationship (multi-device/1.0's
/// recovery keys; DID Core 1.0 §5.3: usable for none) moves nothing either.
#[test]
fn verify_rejects_a_key_the_document_binds_to_no_relationship() {
    pollster::block_on(async {
        let (auth_key, recovery_key) = (Ed25519KeyPair::random().unwrap(), Ed25519KeyPair::random().unwrap());
        let key_agreement = X25519KeyPair::random().unwrap();
        let encode = |codec, bytes: Vec<u8>| multikey::encode(codec, &bytes);
        let recovery = encode(multicodec::ED25519_PUB, recovery_key.with_public_bytes(<[u8]>::to_vec));
        let did = peer4::generate_with_unbound_keys(
            &[
                (KeyPurpose::Authentication, encode(multicodec::ED25519_PUB, auth_key.with_public_bytes(<[u8]>::to_vec)).as_str()),
                (KeyPurpose::KeyAgreement, encode(multicodec::X25519_PUB, key_agreement.with_public_bytes(<[u8]>::to_vec)).as_str()),
            ],
            &[],
            &[recovery.as_str()],
            &[],
            &[],
            peer4::Dates::default(),
        )
        .unwrap();
        let crypto = AskarCryptoService;
        let by_recovery_key = AskarSigningKey::new(format!("{did}#recovery-1"), recovery_key);
        let jwt = build_from_prior(&crypto, &did, "did:peer:4zQmElsewhere", &by_recovery_key, 1_735_689_600).await.unwrap();
        assert!(matches!(verify_from_prior(&crypto, &Peer4, &jwt).await, Err(RotationError::Malformed(_))));
    });
}

// ---- spec conformance: DIDComm v2.1, DID Rotation ("JWT Details", "Ending a
// Relationship"). The header shown is an example; a standard JWT library writes
// {alg, kid}, and ES256/ES256K keys rotate too. ----

use askar_crypto::alg::{k256::K256KeyPair, p256::P256KeyPair};
use didcomm_core::rotation::{build_ending_from_prior, verify_rotation, FromPrior};
use didcomm_multiformats::multibase;
use serde_json::{json, Value};

/// A did:peer:4 whose one authentication key is `auth_multikey`.
fn peer4_with(auth_multikey: &str) -> String {
    let key_agreement = X25519KeyPair::random().unwrap();
    let ka = multikey::encode(multicodec::X25519_PUB, &key_agreement.with_public_bytes(<[u8]>::to_vec));
    peer4::generate(&[(KeyPurpose::Authentication, auth_multikey), (KeyPurpose::KeyAgreement, ka.as_str())], &[]).unwrap()
}

/// A JWT of `header` and `payload`, signed by `sign` over the signing input.
fn jwt(header: Value, payload: Value, sign: impl Fn(&[u8]) -> Vec<u8>) -> String {
    let input = format!("{}.{}", multibase::encode(header.to_string()), multibase::encode(payload.to_string()));
    let signature = sign(input.as_bytes());
    format!("{input}.{}", multibase::encode(signature))
}

fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64
}

fn verify(token: &str) -> Result<FromPrior, RotationError> {
    pollster::block_on(verify_rotation(&AskarCryptoService, &Peer4, token))
}

fn ed25519_did() -> (String, Ed25519KeyPair) {
    let key = Ed25519KeyPair::random().unwrap();
    let did = peer4_with(&multikey::encode(multicodec::ED25519_PUB, &key.with_public_bytes(<[u8]>::to_vec)));
    (did, key)
}

#[test]
fn a_jwt_without_typ_or_crv_is_accepted() {
    let (did, key) = ed25519_did();
    let token = jwt(
        json!({"alg": "EdDSA", "kid": format!("{did}#key-1")}),
        json!({"iss": did, "sub": "did:example:new", "iat": now()}),
        |input| key.sign(input).unwrap().to_vec(),
    );
    let verified = verify(&token).unwrap();
    assert_eq!(verified, FromPrior { prior_did: did, new_did: Some("did:example:new".into()), iat: verified.iat });
}

#[test]
fn typ_and_crv_are_checked_when_present() {
    let (did, key) = ed25519_did();
    let with = |extra: Value| {
        let mut header = json!({"alg": "EdDSA", "kid": format!("{did}#key-1")});
        header.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
        jwt(header, json!({"iss": did, "sub": "did:example:new", "iat": now()}), |input| key.sign(input).unwrap().to_vec())
    };
    assert!(verify(&with(json!({"typ": "jwt", "crv": "Ed25519"}))).is_ok(), "case-insensitive");
    assert!(verify(&with(json!({"typ": "JWT", "crv": "ED25519"}))).is_ok(), "the spec's own example");
    assert!(matches!(verify(&with(json!({"typ": "JOSE+JSON"}))), Err(RotationError::Malformed(_))));
    assert!(matches!(verify(&with(json!({"crv": "P-256"}))), Err(RotationError::Malformed(_))));
}

#[test]
fn es256_and_es256k_keys_rotate() {
    let p256 = P256KeyPair::random().unwrap();
    let did = peer4_with(&multikey::encode(multicodec::P256_PUB, &p256.with_public_bytes(<[u8]>::to_vec)));
    let token = jwt(
        json!({"typ": "JWT", "alg": "ES256", "crv": "P-256", "kid": format!("{did}#key-1")}),
        json!({"iss": did, "sub": "did:example:new", "iat": now()}),
        |input| p256.sign(input).unwrap().to_vec(),
    );
    assert_eq!(verify(&token).unwrap().new_did.as_deref(), Some("did:example:new"));

    let k256 = K256KeyPair::random().unwrap();
    let did = peer4_with(&multikey::encode(multicodec::SECP256K1_PUB, &k256.with_public_bytes(<[u8]>::to_vec)));
    let token = jwt(
        json!({"alg": "ES256K", "kid": format!("{did}#key-1")}),
        json!({"iss": did, "sub": "did:example:new", "iat": now()}),
        |input| k256.sign(input).unwrap().to_vec(),
    );
    assert_eq!(verify(&token).unwrap().new_did.as_deref(), Some("did:example:new"));
}

/// `alg` must be the key's: an ES256 header over an Ed25519 key, or EdDSA over a
/// P-256 one, is refused before any signature is checked; so is an unknown alg.
#[test]
fn an_alg_that_is_not_the_keys_is_refused() {
    let (did, key) = ed25519_did();
    for alg in ["ES256", "ES256K", "none", "HS256"] {
        let token = jwt(
            json!({"alg": alg, "kid": format!("{did}#key-1")}),
            json!({"iss": did, "sub": "did:example:new", "iat": now()}),
            |input| key.sign(input).unwrap().to_vec(),
        );
        assert!(matches!(verify(&token), Err(RotationError::Malformed(_))), "{alg}");
    }
    let p256 = P256KeyPair::random().unwrap();
    let did = peer4_with(&multikey::encode(multicodec::P256_PUB, &p256.with_public_bytes(<[u8]>::to_vec)));
    let token = jwt(
        json!({"alg": "EdDSA", "kid": format!("{did}#key-1")}),
        json!({"iss": did, "sub": "did:example:new", "iat": now()}),
        |input| p256.sign(input).unwrap().to_vec(),
    );
    assert!(matches!(verify(&token), Err(RotationError::Malformed(_))));
}

/// "Ending a Relationship": no `sub`. verify_rotation gives no new DID;
/// verify_from_prior, whose answer has room for none, says so as an error.
#[test]
fn a_jwt_without_sub_ends_the_relationship() {
    pollster::block_on(async {
        let (did, key) = generate_peer4_with_auth_key();
        let signing_key = AskarSigningKey::new(format!("{did}#key-1"), key);
        let token = build_ending_from_prior(&AskarCryptoService, &did, &signing_key, 1_735_689_600).await.unwrap();
        let verified = verify_rotation(&AskarCryptoService, &Peer4, &token).await.unwrap();
        assert_eq!(verified, FromPrior { prior_did: did.clone(), new_did: None, iat: 1_735_689_600 });
        assert!(matches!(
            verify_from_prior(&AskarCryptoService, &Peer4, &token).await,
            Err(RotationError::EndsRelationship { prior_did }) if prior_did == did
        ));
    });
}

/// What this library writes stays the spec's example header.
#[test]
fn build_from_prior_writes_the_spec_example_header() {
    pollster::block_on(async {
        let (did, key) = generate_peer4_with_auth_key();
        let signing_key = AskarSigningKey::new(format!("{did}#key-1"), key);
        let token = build_from_prior(&AskarCryptoService, &did, "did:example:new", &signing_key, 1_735_689_600).await.unwrap();
        let header: Value = serde_json::from_slice(&multibase::decode(token.split('.').next().unwrap()).unwrap()).unwrap();
        assert_eq!(header, json!({"typ": "JWT", "alg": "EdDSA", "crv": "ED25519", "kid": format!("{did}#key-1")}));
        let payload: Value = serde_json::from_slice(&multibase::decode(token.split('.').nth(1).unwrap()).unwrap()).unwrap();
        assert_eq!(payload, json!({"sub": "did:example:new", "iss": did, "iat": 1_735_689_600}));
    });
}
