//! HTTP DIDComm v2 peer for `didcomm-v2-test-util`'s interop harness.
//!
//! This is not a published binding -- it's a small standalone binary built directly on
//! `didcomm-core`/`didcomm-quickstart` (see PLAN.md §11/§12's M2.75) that stands in for
//! the ACA-Py container the test-util used to depend on. It exists purely so
//! `didcomm-messaging-python` (via `didcomm-v2-test-util`'s script) has a real HTTP peer
//! to exchange DIDComm v2 messages with, without ACA-Py's wallet/connection-state model
//! in between.
//!
//! Protocol: `GET /did` returns this peer's DID as plain text. `POST /` takes a packed
//! DIDComm message as the raw request body and returns either an empty 200 (no reply) or
//! a packed reply message as the raw response body -- this is exactly the contract
//! `didcomm_messaging.quickstart.send_http_message` on the Python side already expects
//! (`return_route: all`), so the test-util script needs no protocol-level changes here.

use std::env;
use std::sync::Arc;

use askar_crypto::{
    alg::{ed25519::Ed25519KeyPair, x25519::X25519KeyPair},
    repr::{KeyGen, KeyPublicBytes},
};
use axum::{
    body::Bytes,
    extract::State,
    http::StatusCode,
    routing::{get, post},
    Router,
};
use didcomm_multiformats::{multicodec, multikey};
use didcomm_quickstart::{DefaultDIDCommMessaging, GeneratedDid};
use didcomm_resolver_peer::KeyPurpose;
use serde_json::json;

struct AppState {
    did: String,
    dmp: DefaultDIDCommMessaging,
}

/// Like `didcomm_quickstart::generate_did`, but with a real, reachable HTTP service
/// endpoint instead of the quickstart default's `"didcomm:transport/queue"` -- see that
/// function's own doc comment ("swap it for a real endpoint... before actually using
/// this DID"). This is exactly that swap, for exactly the reason it anticipates: this
/// peer needs to actually receive messages other peers send it.
fn generate_did_with_endpoint(endpoint_uri: &str) -> anyhow::Result<GeneratedDid> {
    let verification_key = Ed25519KeyPair::random()?;
    let key_agreement_key = X25519KeyPair::random()?;

    let verification_material = multikey::encode(
        multicodec::ED25519_PUB,
        &verification_key.with_public_bytes(<[u8]>::to_vec),
    );
    let key_agreement_material = multikey::encode(
        multicodec::X25519_PUB,
        &key_agreement_key.with_public_bytes(<[u8]>::to_vec),
    );

    let did = didcomm_resolver_peer::generate(
        &[
            (KeyPurpose::Authentication, verification_material.as_str()),
            (KeyPurpose::KeyAgreement, key_agreement_material.as_str()),
        ],
        &[json!({
            "type": "DIDCommMessaging",
            "serviceEndpoint": {
                "uri": endpoint_uri,
                "accept": ["didcomm/v2"],
                "routingKeys": [],
            },
        })],
    )?;

    Ok(GeneratedDid {
        did,
        verification_key,
        key_agreement_key,
    })
}

async fn get_did(State(state): State<Arc<AppState>>) -> String {
    state.did.clone()
}

async fn receive(State(state): State<Arc<AppState>>, body: Bytes) -> Result<Vec<u8>, (StatusCode, String)> {
    let unpacked = state
        .dmp
        .unpack(&body)
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("unpack failed: {e}")))?;
    let message = unpacked
        .message()
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("invalid message JSON: {e}")))?;

    tracing::info!(
        authenticated = unpacked.authenticated,
        sender_kid = ?unpacked.sender_kid,
        message = %message,
        "received message"
    );

    let (Some(sender_kid), true) = (&unpacked.sender_kid, unpacked.authenticated) else {
        // Anonymous messages have no return address to reply to.
        return Ok(Vec::new());
    };
    if message.get("type").and_then(|t| t.as_str()) != Some("https://didcomm.org/basicmessage/2.0/message") {
        return Ok(Vec::new());
    }

    let content = message
        .get("body")
        .and_then(|b| b.get("content"))
        .and_then(|c| c.as_str())
        .unwrap_or_default();
    let sender_did = sender_kid.split('#').next().unwrap_or(sender_kid);
    let reply = json!({
        "type": "https://didcomm.org/basicmessage/2.0/message",
        "body": {"content": format!("ack: {content}")},
    });

    let packed = state
        .dmp
        .pack(&reply, sender_did, Some(&state.did))
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("pack failed: {e}")))?;
    Ok(packed.message)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let port: u16 = env::var("PORT").ok().and_then(|p| p.parse().ok()).unwrap_or(8080);
    let endpoint_uri =
        env::var("PEER_ENDPOINT_URI").unwrap_or_else(|_| format!("http://localhost:{port}/"));

    let generated = generate_did_with_endpoint(&endpoint_uri)?;
    let did = generated.did.clone();
    let dmp = didcomm_quickstart::setup_default(&generated);
    tracing::info!(%did, %endpoint_uri, "peer ready");

    let state = Arc::new(AppState { did, dmp });
    let app = Router::new()
        .route("/did", get(get_did))
        .route("/", post(receive))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(("0.0.0.0", port)).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
