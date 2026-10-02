//! HTTP DIDComm v2 peer (and, in `ROLE=mediator` mode, mediator) for
//! `didcomm-v2-test-util`'s interop harness.
//!
//! This is not a published binding -- it's a small standalone binary built directly on
//! `didcomm-core`/`didcomm-quickstart`/`didcomm-mediator-core` (see PLAN.md §11/§12's
//! M2.75) that stands in for the ACA-Py container the test-util used to depend on. It
//! exists purely so `didcomm-messaging-python` has real HTTP peers to exchange DIDComm
//! v2 messages with -- directly and through mediation -- without ACA-Py's
//! wallet/connection-state model in between.
//!
//! # Peer role (`ROLE=peer`, the default)
//!
//! - `GET /did` -- this peer's DID, as plain text.
//! - `POST /` -- a packed DIDComm message as the raw request body; returns either an
//!   empty 200 (no reply) or a packed reply as the raw response body. This is exactly
//!   the contract `didcomm_messaging.quickstart.send_http_message` already expects
//!   (`return_route: all`), unchanged from before mediation support existed.
//! - `POST /send` -- `{"to": "<did>", "content": "<string>"}`. Packs and sends an
//!   authenticated basicmessage to an arbitrary DID (mediated or not -- routing is
//!   resolved the same way `pack` always resolves it) and returns `{"reply": <decoded
//!   message or null>}`. This is what lets a test script make this peer *initiate* a
//!   message, needed to test the direction Python can't otherwise trigger (it can only
//!   ever be the one sending `send_http_message`).
//! - `POST /mediate` -- `{"mediator_did": "<did>"}`. Requests mediation, generates a
//!   fresh mediated identity whose service endpoint is the mediator's own DID, and
//!   registers it. Returns `{"mediated_did": "<did>"}`.
//! - `POST /pickup` -- `{"mediator_did": "<did>"}`. Runs the full
//!   status-request/delivery-request/messages-received cycle against a mediator this
//!   peer previously mediated with, decrypting whatever it retrieves. Returns
//!   `{"messages": [<decoded message>, ...]}`.
//!
//! # Mediator role (`ROLE=mediator`)
//!
//! - `GET /did` -- this mediator's DID, as plain text.
//! - `POST /` -- dispatches to [`didcomm_mediator_core::MediatorService::handle_message`].

use std::env;
use std::sync::Arc;

use axum::{
    body::Bytes,
    extract::State,
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use didcomm_agent::{Agent, Identity, Received};
use didcomm_crypto_askar::{AskarCryptoService, AskarSecretKey};
use didcomm_core::secrets::InMemorySecretsManager;
use didcomm_mediator_core::MediatorService;
use didcomm_quickstart::generate_did_with_endpoint;
use serde::Deserialize;
use serde_json::{json, Value};

const BASICMESSAGE: &str = "https://didcomm.org/basicmessage/2.0/message";

fn internal_err(e: impl std::fmt::Display) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
}

// ---- peer role ----

async fn get_did(State(agent): State<Arc<Agent>>) -> String {
    agent.base_did().to_string()
}

/// Replies to authenticated basicmessages with `ack: <content>`, and to the standard
/// protocols (trust-ping, discover-features) via `Agent::auto_reply`.
async fn receive(State(agent): State<Arc<Agent>>, body: Bytes) -> Result<Vec<u8>, (StatusCode, String)> {
    let received = agent
        .receive(&body)
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("unpack failed: {e}")))?;

    tracing::info!(
        sender = ?received.sender,
        message = %received.message,
        "received message"
    );

    // Anonymous messages have no return address to reply to.
    if received.sender.is_none() {
        return Ok(Vec::new());
    }
    let Some(reply) = agent.auto_reply(&received).or_else(|| ack(&received)) else {
        return Ok(Vec::new());
    };
    // Always on the connection, return_route or not: the contract this endpoint has
    // always had (and what `/send` relies on to get its reply back).
    agent.pack_reply(&received, &reply).await.map_err(internal_err)
}

fn ack(received: &Received) -> Option<Value> {
    if received.message_type() != BASICMESSAGE {
        return None;
    }
    let content = received.message["body"]["content"].as_str().unwrap_or_default();
    Some(received.reply(BASICMESSAGE, json!({"content": format!("ack: {content}")})))
}

#[derive(Deserialize)]
struct SendRequest {
    to: String,
    content: String,
}

async fn send(
    State(agent): State<Arc<Agent>>,
    Json(req): Json<SendRequest>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let message = json!({
        "type": BASICMESSAGE,
        "body": {"content": req.content},
    });
    // From the base DID, as this endpoint always has, mediated or not.
    let reply = agent
        .send_as(agent.base_did(), &req.to, &message)
        .await
        .map_err(internal_err)?;
    Ok(Json(json!({"reply": reply.map(|r| r.message)})))
}

#[derive(Deserialize)]
struct MediatorRequest {
    mediator_did: String,
}

async fn mediate(
    State(agent): State<Arc<Agent>>,
    Json(req): Json<MediatorRequest>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let mediation = agent.mediate(&req.mediator_did).await.map_err(internal_err)?;
    Ok(Json(json!({"mediated_did": mediation.did})))
}

async fn pickup(
    State(agent): State<Arc<Agent>>,
    Json(req): Json<MediatorRequest>,
) -> Result<Json<Value>, (StatusCode, String)> {
    match agent.mediation() {
        Some(m) if m.mediator_did == req.mediator_did => {}
        _ => return Err(internal_err(format!("not mediated by {}", req.mediator_did))),
    }
    let mut messages = Vec::new();
    loop {
        let batch = agent.pickup(100).await.map_err(internal_err)?;
        if let Some((id, error)) = batch.failed.first() {
            return Err(internal_err(format!("couldn't unpack delivered message {id}: {error}")));
        }
        if batch.messages.is_empty() {
            break;
        }
        messages.extend(batch.messages.into_iter().map(|r| r.message));
    }
    Ok(Json(json!({"messages": messages})))
}

async fn run_peer(port: u16, endpoint_uri: String) -> anyhow::Result<()> {
    let agent = Arc::new(Agent::with_endpoint(Identity::generate()?, &endpoint_uri)?);
    tracing::info!(did = %agent.base_did(), %endpoint_uri, "peer ready");

    let app = Router::new()
        .route("/did", get(get_did))
        .route("/", post(receive))
        .route("/send", post(send))
        .route("/mediate", post(mediate))
        .route("/pickup", post(pickup))
        .with_state(agent);

    let listener = tokio::net::TcpListener::bind(("0.0.0.0", port)).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

// ---- mediator role ----

type Mediator = MediatorService<AskarCryptoService, InMemorySecretsManager<AskarSecretKey>>;

struct MediatorState {
    did: String,
    mediator: Mediator,
}

async fn mediator_get_did(State(state): State<Arc<MediatorState>>) -> String {
    state.did.clone()
}

async fn mediator_receive(
    State(state): State<Arc<MediatorState>>,
    body: Bytes,
) -> Result<Vec<u8>, (StatusCode, String)> {
    match state.mediator.handle_message(&body).await {
        Ok(Some(reply)) => Ok(reply),
        Ok(None) => Ok(Vec::new()),
        Err(e) => Err((StatusCode::BAD_REQUEST, e.to_string())),
    }
}

async fn run_mediator(port: u16, endpoint_uri: String) -> anyhow::Result<()> {
    let generated = generate_did_with_endpoint(&endpoint_uri)?;
    let did = generated.did.clone();
    let dmp = didcomm_quickstart::setup_default(&generated);
    tracing::info!(%did, %endpoint_uri, "mediator ready");

    let state = Arc::new(MediatorState { did: did.clone(), mediator: MediatorService::new(did, dmp) });
    let app = Router::new()
        .route("/did", get(mediator_get_did))
        .route("/", post(mediator_receive))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(("0.0.0.0", port)).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let port: u16 = env::var("PORT").ok().and_then(|p| p.parse().ok()).unwrap_or(8080);
    let endpoint_uri =
        env::var("PEER_ENDPOINT_URI").unwrap_or_else(|_| format!("http://localhost:{port}/"));
    let role = env::var("ROLE").unwrap_or_else(|_| "peer".to_string());

    match role.as_str() {
        "mediator" => run_mediator(port, endpoint_uri).await,
        "peer" => run_peer(port, endpoint_uri).await,
        other => anyhow::bail!("unknown ROLE: {other} (expected \"peer\" or \"mediator\")"),
    }
}
