//! Python (PyO3) bindings for `wyvrn-didcomm`, published as `didcomm_fast` -- the
//! Python-side equivalent of `didcomm-quickstart`'s "hit the ground running" flow (and,
//! by name, a faster-but-compatible companion to the reference `didcomm-messaging-python`
//! library this whole workspace is verified against):
//!
//! ```python
//! from didcomm_fast import generate_did, DidcommMessaging
//!
//! me = generate_did()
//! dmp = DidcommMessaging.setup_default(me)
//!
//! packed = await dmp.pack({"type": "https://didcomm.org/basicmessage/2.0/message", "body": {"content": "hi"}}, some_other_did)
//! # packed.message is bytes ready to send; packed.target_services tells you where
//!
//! unpacked = await dmp.unpack(received_bytes)
//! print(unpacked.message)  # a plain dict, not a JSON string
//! ```
//!
//! Like the Rust `didcomm-quickstart` crate this wraps, the point isn't that this is the
//! *only* way to use the library from Python -- PyO3's generated classes expose this
//! crate's full public surface, so once an application's needs outgrow
//! `generate_did`/`setup_default`'s fixed defaults, `DidcommMessaging`'s `pack`/`unpack`
//! work the same way against a resolver/secrets setup built by hand in Rust and exposed
//! the same way, if this crate grows that surface later.
//!
//! Unlike `didcomm-wasm`, this is a native extension module (no wasm32 Send-future
//! limitation, no wasm-targeting bug in `didwebvh-rs`), so it depends on
//! `didcomm-quickstart` with its default features -- `did:web` and `did:webvh` both work
//! here, matching `didcomm-node`.

use std::sync::Arc;

use askar_crypto::{
    alg::{ed25519::Ed25519KeyPair, x25519::X25519KeyPair},
    jwk::{FromJwk, ToJwk},
};
use didcomm_core::messaging::HeaderPolicy;
use didcomm_quickstart::{DefaultDIDCommMessaging, GeneratedDid as CoreGeneratedDid};
use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;
use pythonize::{depythonize, pythonize};
use serde_json::Value;

fn to_py_err(e: impl std::fmt::Display) -> PyErr {
    PyRuntimeError::new_err(e.to_string())
}

/// A freshly generated `did:peer:4` and its raw key material (as JWK JSON strings, so
/// they're plain, storable data rather than opaque handles) -- the Python-facing mirror
/// of [`didcomm_quickstart::GeneratedDid`].
#[pyclass]
pub struct GeneratedDid {
    #[pyo3(get)]
    did: String,
    #[pyo3(get)]
    verification_secret_jwk: String,
    #[pyo3(get)]
    key_agreement_secret_jwk: String,
}

/// Generate a fresh `did:peer:4`, ready to hand to
/// [`DidcommMessaging.setup_default`](DidcommMessaging::setup_default). Mirrors
/// `didcomm_quickstart::generate_did`.
#[pyfunction]
fn generate_did() -> PyResult<GeneratedDid> {
    generated_did_from_core(didcomm_quickstart::generate_did().map_err(to_py_err)?)
}

/// Like [`generate_did`], but with a caller-chosen `serviceEndpoint.uri` instead of the
/// unset-transport placeholder -- for a DID meant to be directly reachable, or routed
/// through a specific mediator (that mediator's own DID as the endpoint). Mirrors
/// `didcomm_quickstart::generate_did_with_endpoint`.
#[pyfunction]
fn generate_did_with_endpoint(endpoint_uri: String) -> PyResult<GeneratedDid> {
    generated_did_from_core(
        didcomm_quickstart::generate_did_with_endpoint(&endpoint_uri).map_err(to_py_err)?,
    )
}

/// The identity [`generate_did_with_endpoint`] made, back from the two secret JWKs it
/// gave (`verification_secret_jwk`, `key_agreement_secret_jwk`), with `endpoint_uri`
/// as its service: the same keys and endpoint always give the same `did:peer:4`. For
/// an app that stores its keys and must keep its DID across restarts; a new endpoint
/// (a mediator's routing DID, say) gives the same keys' DID there. Mirrors
/// `didcomm_quickstart::did_for_keys`.
#[pyfunction]
fn restore_did(
    verification_secret_jwk: String,
    key_agreement_secret_jwk: String,
    endpoint_uri: String,
) -> PyResult<GeneratedDid> {
    let verification_key = Ed25519KeyPair::from_jwk(&verification_secret_jwk).map_err(to_py_err)?;
    let key_agreement_key =
        X25519KeyPair::from_jwk(&key_agreement_secret_jwk).map_err(to_py_err)?;
    let did =
        didcomm_quickstart::did_for_keys(&verification_key, &key_agreement_key, &endpoint_uri)
            .map_err(to_py_err)?;
    generated_did_from_core(CoreGeneratedDid {
        did,
        verification_key,
        key_agreement_key,
    })
}

fn generated_did_from_core(generated: CoreGeneratedDid) -> PyResult<GeneratedDid> {
    let verification_secret_jwk = generated
        .verification_key
        .to_jwk_secret(None)
        .map_err(to_py_err)?;
    let key_agreement_secret_jwk = generated
        .key_agreement_key
        .to_jwk_secret(None)
        .map_err(to_py_err)?;
    Ok(GeneratedDid {
        did: generated.did,
        verification_secret_jwk: String::from_utf8(verification_secret_jwk.to_vec())
            .map_err(to_py_err)?,
        key_agreement_secret_jwk: String::from_utf8(key_agreement_secret_jwk.to_vec())
            .map_err(to_py_err)?,
    })
}

/// One entry of [`PackResult::target_services`]: a resolved DIDComm v2 service endpoint
/// to actually deliver the packed message to.
#[pyclass]
pub struct TargetService {
    #[pyo3(get)]
    uri: String,
    #[pyo3(get)]
    accept: Vec<String>,
    #[pyo3(get)]
    routing_keys: Vec<String>,
}

/// Return value of [`DidcommMessaging::pack`].
#[pyclass]
pub struct PackResult {
    #[pyo3(get)]
    message: Vec<u8>,
    #[pyo3(get)]
    target_services: Vec<Py<TargetService>>,
}

/// Return value of [`DidcommMessaging::unpack`].
#[pyclass]
pub struct UnpackResult {
    /// A plain Python value (not a JSON string).
    #[pyo3(get)]
    message: Py<PyAny>,
    #[pyo3(get)]
    encrypted: bool,
    #[pyo3(get)]
    authenticated: bool,
    #[pyo3(get)]
    recipient_kid: String,
    #[pyo3(get)]
    sender_kid: Option<String>,
    /// The key that signed it, for a signed message (security review WYV-59).
    #[pyo3(get)]
    signer_kid: Option<String>,
    /// The one DID it proves it is from: the authcrypt sender's, else the
    /// signer's. What to act on, rather than `authenticated` alone.
    #[pyo3(get)]
    authenticated_as: Option<String>,
    /// More than 300 s past its `expires_time`. Returned all the same (DIDComm v2.1:
    /// expiry is the sender's to act on); the handler decides what that means.
    #[pyo3(get)]
    expired: bool,
    /// Its `expires_time` isn't an integer of epoch seconds: malformed, for an
    /// `e.p.msg` problem-report.
    #[pyo3(get)]
    expires_time_invalid: bool,
}

/// A verified `from_prior` (DIDComm v2.1, DID Rotation), from
/// [`DidcommMessaging::verify_rotation`]: `new_did` is `None` when the JWT has no
/// `sub` ("Ending a Relationship"), and the relationship with `prior_did` is to be
/// ended.
#[pyclass]
pub struct RotationResult {
    #[pyo3(get)]
    prior_did: String,
    #[pyo3(get)]
    new_did: Option<String>,
    /// When it was made, Unix seconds.
    #[pyo3(get)]
    iat: i64,
}

/// A ready-to-use DIDComm v2 messaging instance. Mirrors
/// `didcomm_core::messaging::DIDCommMessaging`, specialized to the `askar-crypto` backend
/// and the default resolver set (`did:peer:2`, `did:peer:4`, `did:jwk`, `did:web`,
/// `did:webvh`).
#[pyclass]
pub struct DidcommMessaging {
    inner: Arc<DefaultDIDCommMessaging>,
}

#[pymethods]
impl DidcommMessaging {
    /// Wire up a default `DidcommMessaging` from a [`GeneratedDid`]. Mirrors
    /// `didcomm_quickstart::setup_default`.
    #[staticmethod]
    fn setup_default(generated: &GeneratedDid) -> PyResult<DidcommMessaging> {
        let key_agreement_key =
            X25519KeyPair::from_jwk(&generated.key_agreement_secret_jwk).map_err(to_py_err)?;
        let verification_key =
            Ed25519KeyPair::from_jwk(&generated.verification_secret_jwk).map_err(to_py_err)?;
        let core_generated = CoreGeneratedDid {
            did: generated.did.clone(),
            verification_key,
            key_agreement_key,
        };
        let dmp = didcomm_quickstart::setup_default(&core_generated);
        Ok(DidcommMessaging {
            inner: Arc::new(dmp),
        })
    }

    /// `True` packs messages exactly as given -- the same plaintext
    /// `didcomm-messaging-python` produces. `False` (the default) fills in a missing
    /// `id`, `from` (authcrypt only), `to` and `created_time`, and refuses a `from` or
    /// `to` that contradicts the `pack` call (see `didcomm_core::messaging::HeaderPolicy`).
    #[getter]
    fn verbatim_headers(&self) -> bool {
        self.inner.header_policy() == HeaderPolicy::Verbatim
    }

    #[setter]
    fn set_verbatim_headers(&self, verbatim: bool) {
        self.inner.set_header_policy(if verbatim {
            HeaderPolicy::Verbatim
        } else {
            HeaderPolicy::Complete
        });
    }

    /// Pack a message (a plain Python value, not a JSON string) to a recipient DID,
    /// optionally authenticated by a sender DID/kid. Returns an awaitable resolving to a
    /// [`PackResult`].
    fn pack<'py>(
        &self,
        py: Python<'py>,
        message: Bound<'py, PyAny>,
        to: String,
        frm: Option<String>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let message_value: Value = depythonize(&message).map_err(to_py_err)?;
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let result = inner
                .pack(&message_value, &to, frm.as_deref())
                .await
                .map_err(to_py_err)?;

            Python::attach(|py| {
                let target_services = result
                    .target_services
                    .into_iter()
                    .map(|service| {
                        Py::new(
                            py,
                            TargetService {
                                uri: service.uri,
                                accept: service.accept,
                                routing_keys: service.routing_keys,
                            },
                        )
                    })
                    .collect::<PyResult<Vec<_>>>()?;

                Py::new(
                    py,
                    PackResult {
                        message: result.message,
                        target_services,
                    },
                )
            })
        })
    }

    /// Sign a `from_prior` DID rotation JWT (multi-device/1.0 Key Rotation): `sub` is
    /// `new_did`, `iss` is `prior_did`, signed by `signing_secret_jwk` (an Ed25519 JWK)
    /// under `signing_kid`, an `authentication` key the *prior* DID's own document
    /// lists. `iat_seconds` is Unix seconds. Returns an awaitable resolving to the JWT.
    /// As `didcomm-wasm`'s `buildFromPrior`.
    fn build_from_prior<'py>(
        &self,
        py: Python<'py>,
        prior_did: String,
        new_did: String,
        signing_secret_jwk: String,
        signing_kid: String,
        iat_seconds: i64,
    ) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        let key = Ed25519KeyPair::from_jwk(&signing_secret_jwk).map_err(to_py_err)?;
        let signing_key = didcomm_crypto_askar::AskarSigningKey::new(signing_kid, key);
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            didcomm_core::rotation::build_from_prior(
                &inner.crypto,
                &prior_did,
                &new_did,
                &signing_key,
                iat_seconds,
            )
            .await
            .map_err(to_py_err)
        })
    }

    /// Verify a `from_prior` JWT (DIDComm v2.1, DID Rotation: EdDSA, ES256 or ES256K by
    /// the key's type), resolving its `iss` through this instance's resolver to check
    /// the signing key is one of the prior DID's `authentication` keys. Also takes one
    /// that ends the relationship (no `sub`): then `new_did` is `None`. Returns an
    /// awaitable resolving to a [`RotationResult`]; raises if it is malformed or
    /// doesn't verify. As `didcomm-wasm`'s `verifyRotation`.
    fn verify_rotation<'py>(&self, py: Python<'py>, jwt: String) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let verified = didcomm_core::rotation::verify_rotation(
                &inner.crypto,
                inner.resolver.as_ref(),
                &jwt,
            )
            .await
            .map_err(to_py_err)?;
            Python::attach(|py| {
                Py::new(
                    py,
                    RotationResult {
                        prior_did: verified.prior_did,
                        new_did: verified.new_did,
                        iat: verified.iat,
                    },
                )
            })
        })
    }

    /// Unpack a received message. Returns an awaitable resolving to an [`UnpackResult`].
    fn unpack<'py>(&self, py: Python<'py>, encoded: Vec<u8>) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let result = inner.unpack_verified(&encoded).await.map_err(to_py_err)?;
            let message_value = result.message().map_err(to_py_err)?;

            Python::attach(|py| {
                let message = pythonize(py, &message_value).map_err(to_py_err)?.unbind();
                Py::new(
                    py,
                    UnpackResult {
                        message,
                        encrypted: result.encrypted,
                        authenticated: result.authenticated,
                        recipient_kid: result.recipient_kid,
                        authenticated_as: result
                            .sender_kid
                            .as_deref()
                            .or(result.signer_kid.as_deref())
                            .map(|kid| kid.split('#').next().unwrap_or(kid).to_string()),
                        sender_kid: result.sender_kid,
                        signer_kid: result.signer_kid,
                        expired: result.expired,
                        expires_time_invalid: result.expires_time_invalid,
                    },
                )
            })
        })
    }
}

#[pymodule]
fn didcomm_fast(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<GeneratedDid>()?;
    m.add_class::<DidcommMessaging>()?;
    m.add_class::<PackResult>()?;
    m.add_class::<TargetService>()?;
    m.add_class::<UnpackResult>()?;
    m.add_class::<RotationResult>()?;
    m.add_function(wrap_pyfunction!(generate_did, m)?)?;
    m.add_function(wrap_pyfunction!(generate_did_with_endpoint, m)?)?;
    m.add_function(wrap_pyfunction!(restore_did, m)?)?;
    Ok(())
}
