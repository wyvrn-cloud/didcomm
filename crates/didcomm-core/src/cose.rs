//! COSE ([RFC 9052](https://www.rfc-editor.org/rfc/rfc9052)) structures for the
//! `didcomm/v2+cbor` profile: `COSE_Encrypt` (tag 96) for encrypted messages and
//! `COSE_Sign1` (tag 18) for signed ones -- the CBOR counterparts of this crate's JWE
//! ([`crate::jwe`]) and JWS ([`crate::signed`]) envelopes, per
//! [decentralized-identity/didcomm-messaging#463](https://github.com/decentralized-identity/didcomm-messaging/pull/463).
//!
//! This module only knows the *shapes*: building and parsing the CBOR, and computing
//! the exact byte strings COSE's cryptography is defined over (`Enc_structure`,
//! `Sig_structure`, `COSE_KDF_Context`). The cryptography itself lives in a crypto
//! backend (`didcomm-crypto-askar`), the same split as for JWE.
//!
//! # Profile choices #463 leaves open
//!
//! #463 says "the equivalent COSE algorithm" for each JWA DIDComm uses, but three of
//! them have no IANA COSE registration: `ECDH-1PU+A256KW`, `A256CBC-HS512` (COSE only
//! registers unauthenticated AES-CBC, RFC 9459) and `XC20P` (COSE only registers the
//! 12-byte-nonce ChaCha20/Poly1305, value 24). RFC 9052 §3.1 allows a text-string
//! `alg`, so those use their JWA names as text; registered ones use their integer
//! (`ECDH-ES + A256KW` = -31, `A256GCM` = 3, `EdDSA` = -8). See [`Alg`].
//!
//! Header placement mirrors COSE's layering: the content-encryption `alg` and `typ`
//! (label 16, RFC 9596) in the body's protected header, `IV` in its unprotected one;
//! every key-agreement parameter -- `alg`, `ephemeral key` (-1), `PartyU identity`
//! (-21, JWE's `apu`), `PartyV identity` (-24, `apv`), `static key id` (-3, `skid`) --
//! in each recipient's *protected* header, which [`kdf_context`] binds into the derived
//! key-wrapping key. The recipient's `kid` (4) is unprotected, as in JWE. ECDH-1PU
//! gives every recipient the same ephemeral key, `apu` and `apv`, which is what
//! #463's "common headers for all recipient keys" asks for.

use ciborium::value::Integer;
use ciborium::Value as CborValue;

/// CBOR tag for `COSE_Encrypt` (RFC 9052 §2).
pub const TAG_COSE_ENCRYPT: u64 = 96;
/// CBOR tag for `COSE_Sign1` (RFC 9052 §2).
pub const TAG_COSE_SIGN1: u64 = 18;

/// COSE header labels used by this profile (RFC 9052 §3.1, RFC 9053 §6.3, RFC 9596).
pub mod label {
    pub const ALG: i64 = 1;
    pub const KID: i64 = 4;
    pub const IV: i64 = 5;
    pub const TYP: i64 = 16;
    pub const EPHEMERAL_KEY: i64 = -1;
    pub const STATIC_KEY_ID: i64 = -3;
    pub const PARTY_U_IDENTITY: i64 = -21;
    pub const PARTY_V_IDENTITY: i64 = -24;
}

/// COSE algorithm identifiers used by this profile -- see the module docs for why
/// some are text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Alg {
    /// `ECDH-ES + A256KW` (-31): ECDH-ES, HKDF-SHA-256, AES-256 key wrap.
    EcdhEsA256Kw,
    /// `"ECDH-1PU+A256KW"`: ECDH-1PU, HKDF-SHA-256, AES-256 key wrap.
    Ecdh1PuA256Kw,
    /// `A256GCM` (3).
    A256Gcm,
    /// `"XC20P"`: XChaCha20-Poly1305, 24-byte nonce.
    Xc20p,
    /// `"A256CBC-HS512"`: AES-256-CBC + HMAC-SHA-512/256, as JWA defines it.
    A256CbcHs512,
    /// `EdDSA` (-8).
    EdDsa,
}

impl Alg {
    pub fn to_cbor(self) -> CborValue {
        match self {
            Self::EcdhEsA256Kw => int(-31),
            Self::A256Gcm => int(3),
            Self::EdDsa => int(-8),
            Self::Ecdh1PuA256Kw => CborValue::Text("ECDH-1PU+A256KW".into()),
            Self::Xc20p => CborValue::Text("XC20P".into()),
            Self::A256CbcHs512 => CborValue::Text("A256CBC-HS512".into()),
        }
    }

    pub fn from_cbor(value: &CborValue) -> Option<Self> {
        match value {
            CborValue::Integer(i) => match i128::from(*i) {
                -31 => Some(Self::EcdhEsA256Kw),
                3 => Some(Self::A256Gcm),
                -8 => Some(Self::EdDsa),
                _ => None,
            },
            CborValue::Text(t) => match t.as_str() {
                "ECDH-1PU+A256KW" => Some(Self::Ecdh1PuA256Kw),
                "XC20P" => Some(Self::Xc20p),
                "A256CBC-HS512" => Some(Self::A256CbcHs512),
                _ => None,
            },
            _ => None,
        }
    }

    /// The equivalent JWA name, for error messages and for code shared with the JWE
    /// path that dispatches on algorithm names.
    pub fn jwa_name(self) -> &'static str {
        match self {
            Self::EcdhEsA256Kw => "ECDH-ES+A256KW",
            Self::Ecdh1PuA256Kw => "ECDH-1PU+A256KW",
            Self::A256Gcm => "A256GCM",
            Self::Xc20p => "XC20P",
            Self::A256CbcHs512 => "A256CBC-HS512",
            Self::EdDsa => "EdDSA",
        }
    }
}

/// `A256KW`'s COSE algorithm identifier -- the `AlgorithmID` both key-agreement
/// algorithms feed [`kdf_context`], per RFC 9053 §5.2 ("the algorithm the derived key
/// is used with", i.e. the key wrap, not the key agreement).
pub const A256KW_ALG_ID: i64 = -5;

/// Errors parsing or building a COSE structure.
#[derive(Debug, thiserror::Error)]
pub enum CoseError {
    #[error("invalid CBOR: {0}")]
    Decode(String),
    #[error("failed to encode CBOR: {0}")]
    Encode(String),
    #[error("invalid COSE structure: {0}")]
    Invalid(&'static str),
    #[error("unknown recipient: {0}")]
    UnknownRecipient(String),
}

/// A COSE header map, kept as raw `(label, value)` pairs -- labels may be integers or
/// text, so there's no natural typed map for it.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct HeaderMap(pub Vec<(CborValue, CborValue)>);

impl HeaderMap {
    pub fn get(&self, label: i64) -> Option<&CborValue> {
        self.0
            .iter()
            .find(|(k, _)| matches!(k, CborValue::Integer(i) if i128::from(*i) == label as i128))
            .map(|(_, v)| v)
    }

    pub fn insert(&mut self, label: i64, value: CborValue) {
        self.0.retain(|(k, _)| !matches!(k, CborValue::Integer(i) if i128::from(*i) == label as i128));
        self.0.push((int(label), value));
    }

    pub fn bytes(&self, label: i64) -> Option<&[u8]> {
        match self.get(label)? {
            CborValue::Bytes(b) => Some(b),
            _ => None,
        }
    }

    pub fn text(&self, label: i64) -> Option<&str> {
        match self.get(label)? {
            CborValue::Text(t) => Some(t),
            _ => None,
        }
    }

    pub fn alg(&self) -> Option<Alg> {
        self.get(label::ALG).and_then(Alg::from_cbor)
    }

    /// `kid`/`static key id` values are byte strings in COSE; this profile's are always
    /// a DID URL's UTF-8 bytes.
    pub fn kid_str(&self, label: i64) -> Option<String> {
        self.bytes(label).and_then(|b| String::from_utf8(b.to_vec()).ok())
    }

    /// Serialize as a protected header: the bstr-wrapped encoding of the map, or the
    /// empty bstr for an empty map (RFC 9052 §3).
    pub fn to_protected_bytes(&self) -> Result<Vec<u8>, CoseError> {
        if self.0.is_empty() {
            return Ok(Vec::new());
        }
        to_vec(&CborValue::Map(self.0.clone()))
    }

    pub fn from_protected_bytes(bytes: &[u8]) -> Result<Self, CoseError> {
        if bytes.is_empty() {
            return Ok(Self::default());
        }
        match from_slice(bytes)? {
            CborValue::Map(entries) => Ok(Self(entries)),
            _ => Err(CoseError::Invalid("protected header is not a map")),
        }
    }

    fn from_value(value: &CborValue) -> Result<Self, CoseError> {
        match value {
            CborValue::Map(entries) => Ok(Self(entries.clone())),
            _ => Err(CoseError::Invalid("unprotected header is not a map")),
        }
    }
}

/// One `COSE_recipient` of a [`CoseEncrypt`]: its headers and its wrapped
/// content-encryption key.
#[derive(Debug, Clone)]
pub struct CoseRecipient {
    /// The exact received/sent bytes -- what [`kdf_context`] binds, so never
    /// re-serialized from [`protected`](Self::protected).
    pub protected_bytes: Vec<u8>,
    pub protected: HeaderMap,
    pub unprotected: HeaderMap,
    pub encrypted_key: Vec<u8>,
}

impl CoseRecipient {
    pub fn new(protected: HeaderMap, unprotected: HeaderMap, encrypted_key: Vec<u8>) -> Result<Self, CoseError> {
        Ok(Self {
            protected_bytes: protected.to_protected_bytes()?,
            protected,
            unprotected,
            encrypted_key,
        })
    }

    /// The recipient key id (unprotected `kid`).
    pub fn kid(&self) -> Option<String> {
        self.unprotected.kid_str(label::KID)
    }

    /// A header parameter from the protected header, falling back to the unprotected
    /// one -- RFC 9052 lets a sender put most parameters in either bucket.
    pub fn header(&self, label: i64) -> Option<&CborValue> {
        self.protected.get(label).or_else(|| self.unprotected.get(label))
    }

    fn to_value(&self) -> CborValue {
        CborValue::Array(vec![
            CborValue::Bytes(self.protected_bytes.clone()),
            CborValue::Map(self.unprotected.0.clone()),
            CborValue::Bytes(self.encrypted_key.clone()),
        ])
    }

    fn from_value(value: &CborValue) -> Result<Self, CoseError> {
        let CborValue::Array(items) = value else {
            return Err(CoseError::Invalid("COSE_recipient is not an array"));
        };
        // A 4th element would be nested recipients -- never produced by this profile.
        let [CborValue::Bytes(protected_bytes), unprotected, CborValue::Bytes(encrypted_key)] = items.as_slice()
        else {
            return Err(CoseError::Invalid("COSE_recipient must be [bstr, map, bstr]"));
        };
        Ok(Self {
            protected: HeaderMap::from_protected_bytes(protected_bytes)?,
            protected_bytes: protected_bytes.clone(),
            unprotected: HeaderMap::from_value(unprotected)?,
            encrypted_key: encrypted_key.clone(),
        })
    }
}

/// A `COSE_Encrypt` message: `[protected, unprotected, ciphertext, recipients]`,
/// tagged 96 on the wire. `ciphertext` carries the AEAD tag appended, per COSE.
#[derive(Debug, Clone)]
pub struct CoseEncrypt {
    pub protected_bytes: Vec<u8>,
    pub protected: HeaderMap,
    pub unprotected: HeaderMap,
    pub ciphertext: Vec<u8>,
    pub recipients: Vec<CoseRecipient>,
}

impl CoseEncrypt {
    /// Parse a (tagged or untagged) `COSE_Encrypt`.
    pub fn from_cbor(message: &[u8]) -> Result<Self, CoseError> {
        let value = untag(from_slice(message)?, TAG_COSE_ENCRYPT)?;
        let CborValue::Array(items) = value else {
            return Err(CoseError::Invalid("COSE_Encrypt is not an array"));
        };
        let [CborValue::Bytes(protected_bytes), unprotected, CborValue::Bytes(ciphertext), CborValue::Array(recipients)] =
            items.as_slice()
        else {
            return Err(CoseError::Invalid("COSE_Encrypt must be [bstr, map, bstr, [+recipient]]"));
        };
        if recipients.is_empty() {
            return Err(CoseError::Invalid("COSE_Encrypt has no recipients"));
        }
        Ok(Self {
            protected: HeaderMap::from_protected_bytes(protected_bytes)?,
            protected_bytes: protected_bytes.clone(),
            unprotected: HeaderMap::from_value(unprotected)?,
            ciphertext: ciphertext.clone(),
            recipients: recipients
                .iter()
                .map(CoseRecipient::from_value)
                .collect::<Result<_, _>>()?,
        })
    }

    /// Serialize as a tagged `COSE_Encrypt`.
    pub fn to_cbor(&self) -> Result<Vec<u8>, CoseError> {
        to_vec(&CborValue::Tag(
            TAG_COSE_ENCRYPT,
            Box::new(CborValue::Array(vec![
                CborValue::Bytes(self.protected_bytes.clone()),
                CborValue::Map(self.unprotected.0.clone()),
                CborValue::Bytes(self.ciphertext.clone()),
                CborValue::Array(self.recipients.iter().map(CoseRecipient::to_value).collect()),
            ])),
        ))
    }

    /// The recipient entry for a given kid.
    pub fn get_recipient(&self, kid: &str) -> Result<&CoseRecipient, CoseError> {
        self.recipients
            .iter()
            .find(|r| r.kid().as_deref() == Some(kid))
            .ok_or_else(|| CoseError::UnknownRecipient(kid.to_string()))
    }

    /// The content-encryption algorithm (body protected `alg`).
    pub fn content_alg(&self) -> Option<Alg> {
        self.protected.alg()
    }

    /// `typ` (label 16) from the body protected header.
    pub fn typ(&self) -> Option<&str> {
        self.protected.text(label::TYP)
    }

    /// `IV` from the body headers.
    pub fn iv(&self) -> Option<&[u8]> {
        self.unprotected.bytes(label::IV).or_else(|| self.protected.bytes(label::IV))
    }

    /// The AEAD additional data: the encoded `Enc_structure`
    /// `["Encrypt", protected, external_aad]` (RFC 9052 §5.3), with an empty
    /// `external_aad`.
    pub fn enc_structure(&self) -> Vec<u8> {
        enc_structure(&self.protected_bytes)
    }
}

/// The encoded `Enc_structure` for a body protected header -- see
/// [`CoseEncrypt::enc_structure`]. Free-standing because a sender needs it before the
/// `CoseEncrypt` it belongs to exists.
pub fn enc_structure(protected_bytes: &[u8]) -> Vec<u8> {
    to_vec(&CborValue::Array(vec![
        CborValue::Text("Encrypt".into()),
        CborValue::Bytes(protected_bytes.to_vec()),
        CborValue::Bytes(Vec::new()),
    ]))
    .expect("encoding an in-memory CBOR array cannot fail")
}

/// The encoded `COSE_KDF_Context` (RFC 9053 §5.2) a recipient's key-wrapping key is
/// derived with (as HKDF-SHA-256's `info`):
///
/// ```text
/// [ AlgorithmID: -5 (A256KW),
///   PartyUInfo: [identity / nil, nil, nil],
///   PartyVInfo: [identity / nil, nil, nil],
///   SuppPubInfo: [256, recipient protected header, ? other] ]
/// ```
///
/// `other` is ECDH-1PU's `cc_tag` (the content AEAD tag), which draft-madden-jose-ecdh-1pu
/// binds into the key derivation for authcrypt; absent for ECDH-ES.
pub fn kdf_context(
    party_u_identity: Option<&[u8]>,
    party_v_identity: Option<&[u8]>,
    recipient_protected_bytes: &[u8],
    other: Option<&[u8]>,
) -> Vec<u8> {
    let party = |identity: Option<&[u8]>| {
        CborValue::Array(vec![
            identity.map_or(CborValue::Null, |b| CborValue::Bytes(b.to_vec())),
            CborValue::Null,
            CborValue::Null,
        ])
    };
    let mut supp_pub = vec![int(256), CborValue::Bytes(recipient_protected_bytes.to_vec())];
    if let Some(other) = other {
        supp_pub.push(CborValue::Bytes(other.to_vec()));
    }
    to_vec(&CborValue::Array(vec![
        int(A256KW_ALG_ID),
        party(party_u_identity),
        party(party_v_identity),
        CborValue::Array(supp_pub),
    ]))
    .expect("encoding an in-memory CBOR array cannot fail")
}

/// An X25519 public key as a `COSE_Key` (`{1: 1 (OKP), -1: 4 (X25519), -2: x}`), the
/// form an `ephemeral key` header takes.
pub fn x25519_cose_key(public_bytes: &[u8]) -> CborValue {
    CborValue::Map(vec![
        (int(1), int(1)),
        (int(-1), int(4)),
        (int(-2), CborValue::Bytes(public_bytes.to_vec())),
    ])
}

/// The raw public key out of an X25519 `COSE_Key`.
pub fn x25519_from_cose_key(value: &CborValue) -> Result<Vec<u8>, CoseError> {
    let CborValue::Map(_) = value else {
        return Err(CoseError::Invalid("ephemeral key is not a COSE_Key map"));
    };
    let key = HeaderMap::from_value(value)?;
    let int_of = |l| match key.get(l) {
        Some(CborValue::Integer(i)) => Some(i128::from(*i)),
        _ => None,
    };
    if int_of(1) != Some(1) || int_of(-1) != Some(4) {
        return Err(CoseError::Invalid("ephemeral key is not an OKP X25519 COSE_Key"));
    }
    key.bytes(-2)
        .map(<[u8]>::to_vec)
        .ok_or(CoseError::Invalid("ephemeral key has no x coordinate"))
}

/// A `COSE_Sign1` message: `[protected, unprotected, payload, signature]`, tagged 18.
#[derive(Debug, Clone)]
pub struct CoseSign1 {
    pub protected_bytes: Vec<u8>,
    pub protected: HeaderMap,
    pub unprotected: HeaderMap,
    pub payload: Vec<u8>,
    pub signature: Vec<u8>,
}

impl CoseSign1 {
    pub fn from_cbor(message: &[u8]) -> Result<Self, CoseError> {
        let value = untag(from_slice(message)?, TAG_COSE_SIGN1)?;
        let CborValue::Array(items) = value else {
            return Err(CoseError::Invalid("COSE_Sign1 is not an array"));
        };
        let [CborValue::Bytes(protected_bytes), unprotected, CborValue::Bytes(payload), CborValue::Bytes(signature)] =
            items.as_slice()
        else {
            // A nil payload would be detached content -- not used for DIDComm messages.
            return Err(CoseError::Invalid("COSE_Sign1 must be [bstr, map, bstr, bstr]"));
        };
        Ok(Self {
            protected: HeaderMap::from_protected_bytes(protected_bytes)?,
            protected_bytes: protected_bytes.clone(),
            unprotected: HeaderMap::from_value(unprotected)?,
            payload: payload.clone(),
            signature: signature.clone(),
        })
    }

    pub fn to_cbor(&self) -> Result<Vec<u8>, CoseError> {
        to_vec(&CborValue::Tag(
            TAG_COSE_SIGN1,
            Box::new(CborValue::Array(vec![
                CborValue::Bytes(self.protected_bytes.clone()),
                CborValue::Map(self.unprotected.0.clone()),
                CborValue::Bytes(self.payload.clone()),
                CborValue::Bytes(self.signature.clone()),
            ])),
        ))
    }
}

/// The encoded `Sig_structure` `["Signature1", protected, external_aad, payload]`
/// (RFC 9052 §4.4) -- the bytes a `COSE_Sign1` signature is computed over.
pub fn sig_structure1(protected_bytes: &[u8], payload: &[u8]) -> Vec<u8> {
    to_vec(&CborValue::Array(vec![
        CborValue::Text("Signature1".into()),
        CborValue::Bytes(protected_bytes.to_vec()),
        CborValue::Bytes(Vec::new()),
        CborValue::Bytes(payload.to_vec()),
    ]))
    .expect("encoding an in-memory CBOR array cannot fail")
}

/// Which COSE structure a CBOR message is, from its tag (or, untagged, its shape).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoseKind {
    Encrypt,
    Sign1,
    /// Not a COSE structure: a CBOR map, i.e. a `didcomm-plain+cbor` plaintext.
    Plaintext,
}

/// Classify a CBOR-encoded DIDComm message without fully parsing it.
pub fn classify(message: &[u8]) -> Result<CoseKind, CoseError> {
    match from_slice(message)? {
        CborValue::Tag(TAG_COSE_ENCRYPT, _) => Ok(CoseKind::Encrypt),
        CborValue::Tag(TAG_COSE_SIGN1, _) => Ok(CoseKind::Sign1),
        CborValue::Map(_) => Ok(CoseKind::Plaintext),
        CborValue::Array(items) if items.len() == 4 && matches!(items[3], CborValue::Array(_)) => {
            Ok(CoseKind::Encrypt)
        }
        CborValue::Array(items) if items.len() == 4 => Ok(CoseKind::Sign1),
        _ => Err(CoseError::Invalid("not a DIDComm CBOR message")),
    }
}

pub(crate) fn int(value: i64) -> CborValue {
    CborValue::Integer(Integer::from(value))
}

fn untag(value: CborValue, expected: u64) -> Result<CborValue, CoseError> {
    match value {
        CborValue::Tag(tag, inner) if tag == expected => Ok(*inner),
        CborValue::Tag(..) => Err(CoseError::Invalid("unexpected CBOR tag")),
        other => Ok(other),
    }
}

pub(crate) fn from_slice(bytes: &[u8]) -> Result<CborValue, CoseError> {
    ciborium::from_reader(bytes).map_err(|e| CoseError::Decode(e.to_string()))
}

pub(crate) fn to_vec(value: &CborValue) -> Result<Vec<u8>, CoseError> {
    let mut out = Vec::new();
    ciborium::into_writer(value, &mut out).map_err(|e| CoseError::Encode(e.to_string()))?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cose_encrypt_round_trips_and_is_tagged_96() {
        let mut protected = HeaderMap::default();
        protected.insert(label::ALG, Alg::Xc20p.to_cbor());
        protected.insert(label::TYP, CborValue::Text("application/didcomm-encrypted+cbor".into()));
        let mut unprotected = HeaderMap::default();
        unprotected.insert(label::IV, CborValue::Bytes(vec![7; 24]));
        let mut r_protected = HeaderMap::default();
        r_protected.insert(label::ALG, Alg::EcdhEsA256Kw.to_cbor());
        r_protected.insert(label::EPHEMERAL_KEY, x25519_cose_key(&[1; 32]));
        let mut r_unprotected = HeaderMap::default();
        r_unprotected.insert(label::KID, CborValue::Bytes(b"did:example:bob#key-1".to_vec()));

        let msg = CoseEncrypt {
            protected_bytes: protected.to_protected_bytes().unwrap(),
            protected,
            unprotected,
            ciphertext: vec![9; 40],
            recipients: vec![CoseRecipient::new(r_protected, r_unprotected, vec![3; 40]).unwrap()],
        };
        let bytes = msg.to_cbor().unwrap();
        // Tag 96 encodes as 0xd8 0x60 -- inside #463's 0x80..=0xFF "CBOR" first-byte range.
        assert_eq!(&bytes[..2], &[0xd8, 0x60]);
        assert_eq!(classify(&bytes).unwrap(), CoseKind::Encrypt);

        let parsed = CoseEncrypt::from_cbor(&bytes).unwrap();
        assert_eq!(parsed.content_alg(), Some(Alg::Xc20p));
        assert_eq!(parsed.typ(), Some("application/didcomm-encrypted+cbor"));
        assert_eq!(parsed.iv(), Some(&[7u8; 24][..]));
        assert_eq!(parsed.protected_bytes, msg.protected_bytes);
        let r = parsed.get_recipient("did:example:bob#key-1").unwrap();
        assert_eq!(r.protected.alg(), Some(Alg::EcdhEsA256Kw));
        assert_eq!(x25519_from_cose_key(r.header(label::EPHEMERAL_KEY).unwrap()).unwrap(), vec![1; 32]);
        assert_eq!(r.encrypted_key, vec![3; 40]);
    }

    #[test]
    fn cose_sign1_round_trips_and_is_tagged_18() {
        let mut protected = HeaderMap::default();
        protected.insert(label::ALG, Alg::EdDsa.to_cbor());
        let msg = CoseSign1 {
            protected_bytes: protected.to_protected_bytes().unwrap(),
            protected,
            unprotected: HeaderMap::default(),
            payload: b"payload".to_vec(),
            signature: vec![5; 64],
        };
        let bytes = msg.to_cbor().unwrap();
        assert_eq!(bytes[0], 0xd2);
        assert_eq!(classify(&bytes).unwrap(), CoseKind::Sign1);
        let parsed = CoseSign1::from_cbor(&bytes).unwrap();
        assert_eq!(parsed.protected.alg(), Some(Alg::EdDsa));
        assert_eq!(parsed.payload, b"payload");
    }

    #[test]
    fn registered_algorithms_are_integers_and_unregistered_are_text() {
        assert_eq!(Alg::EcdhEsA256Kw.to_cbor(), int(-31));
        assert_eq!(Alg::A256Gcm.to_cbor(), int(3));
        assert_eq!(Alg::EdDsa.to_cbor(), int(-8));
        for alg in [Alg::Ecdh1PuA256Kw, Alg::Xc20p, Alg::A256CbcHs512] {
            assert!(matches!(alg.to_cbor(), CborValue::Text(_)));
            assert_eq!(Alg::from_cbor(&alg.to_cbor()), Some(alg));
        }
    }
}
