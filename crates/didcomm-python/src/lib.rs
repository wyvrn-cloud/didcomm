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

    /// Unpack a received message. Returns an awaitable resolving to an [`UnpackResult`].
    fn unpack<'py>(&self, py: Python<'py>, encoded: Vec<u8>) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let result = inner.unpack(&encoded).await.map_err(to_py_err)?;
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
                        sender_kid: result.sender_kid,
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
    m.add_function(wrap_pyfunction!(generate_did, m)?)?;
    m.add_function(wrap_pyfunction!(generate_did_with_endpoint, m)?)?;
    Ok(())
}
