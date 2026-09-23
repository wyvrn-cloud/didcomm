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

use anyhow::Context;
use axum::{
    body::Bytes,
    extract::State,
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use didcomm_crypto_askar::{AskarCryptoService, AskarSecretKey};
use didcomm_core::secrets::InMemorySecretsManager;
use didcomm_mediator_core::MediatorService;
use didcomm_quickstart::{generate_did_with_endpoint, DefaultDIDCommMessaging};
use serde::Deserialize;
use serde_json::{json, Value};

fn internal_err(e: impl std::fmt::Display) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
}

// ---- peer role ----

struct PeerState {
    did: String,
    dmp: DefaultDIDCommMessaging,
    http: reqwest::Client,
}

/// Pack `message` to `to` and POST it to whatever endpoint `pack` resolves for it
/// (direct, or a mediator's, depending on `to`'s DID document -- the caller doesn't
/// need to know which). Mirrors `didcomm_messaging.quickstart.send_http_message`.
/// Returns the decoded reply, if the recipient sent one back synchronously.
async fn pack_and_post(
    dmp: &DefaultDIDCommMessaging,
    http: &reqwest::Client,
    message: &Value,
    to: &str,
    frm: Option<&str>,
) -> anyhow::Result<Option<Value>> {
    let packed = dmp.pack(message, to, frm).await?;
    let uri = packed
        .target_services
        .first()
        .map(|s| s.uri.as_str())
        .with_context(|| format!("no target service endpoint resolved for {to}"))?;

    let resp = http.post(uri).body(packed.message).send().await?;
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("{uri} responded with {status}: {body}");
    }
    let body = resp.bytes().await?;
    if body.is_empty() {
        return Ok(None);
    }
    Ok(Some(dmp.unpack(&body).await?.message()?))
}

async fn get_did(State(state): State<Arc<PeerState>>) -> String {
    state.did.clone()
}

async fn receive(State(state): State<Arc<PeerState>>, body: Bytes) -> Result<Vec<u8>, (StatusCode, String)> {
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

#[derive(Deserialize)]
struct SendRequest {
    to: String,
    content: String,
}

async fn send(
    State(state): State<Arc<PeerState>>,
    Json(req): Json<SendRequest>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let message = json!({
        "type": "https://didcomm.org/basicmessage/2.0/message",
        "body": {"content": req.content},
    });
    let reply = pack_and_post(&state.dmp, &state.http, &message, &req.to, Some(&state.did))
        .await
        .map_err(internal_err)?;
    Ok(Json(json!({"reply": reply})))
}

#[derive(Deserialize)]
struct MediatorRequest {
    mediator_did: String,
}

async fn mediate(
    State(state): State<Arc<PeerState>>,
    Json(req): Json<MediatorRequest>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let mediate_request = json!({
        "type": "https://didcomm.org/coordinate-mediation/3.0/mediate-request",
        "body": {},
    });
    let grant = pack_and_post(&state.dmp, &state.http, &mediate_request, &req.mediator_did, Some(&state.did))
        .await
        .map_err(internal_err)?
        .ok_or_else(|| internal_err("mediator sent no mediate-grant reply"))?;
    let routing_did = grant["body"]["routing_did"][0]
        .as_str()
        .ok_or_else(|| internal_err("mediate-grant missing body.routing_did[0]"))?;

    let mediated = generate_did_with_endpoint(routing_did).map_err(internal_err)?;
    state.dmp.secrets.add_secret(AskarSecretKey::new(
        format!("{}#key-2", mediated.did),
        mediated.key_agreement_key.clone(),
    ));

    let recipient_update = json!({
        "type": "https://didcomm.org/coordinate-mediation/3.0/recipient-update",
        "body": {"updates": [{"recipient_did": mediated.did, "action": "add"}]},
    });
    pack_and_post(&state.dmp, &state.http, &recipient_update, &req.mediator_did, Some(&state.did))
        .await
        .map_err(internal_err)?;

    Ok(Json(json!({"mediated_did": mediated.did})))
}

async fn pickup(
    State(state): State<Arc<PeerState>>,
    Json(req): Json<MediatorRequest>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let status_request = json!({
        "type": "https://didcomm.org/messagepickup/3.0/status-request",
        "body": {},
    });
    let status = pack_and_post(&state.dmp, &state.http, &status_request, &req.mediator_did, Some(&state.did))
        .await
        .map_err(internal_err)?
        .ok_or_else(|| internal_err("mediator sent no status reply"))?;
    let count = status["body"]["message_count"].as_u64().unwrap_or(0);
    if count == 0 {
        return Ok(Json(json!({"messages": []})));
    }

    let delivery_request = json!({
        "type": "https://didcomm.org/messagepickup/3.0/delivery-request",
        "body": {"limit": count},
    });
    let delivery = pack_and_post(&state.dmp, &state.http, &delivery_request, &req.mediator_did, Some(&state.did))
        .await
        .map_err(internal_err)?
        .ok_or_else(|| internal_err("mediator sent no delivery reply"))?;
    let attachments = delivery["attachments"].as_array().cloned().unwrap_or_default();

    let mut messages = Vec::with_capacity(attachments.len());
    let mut ids = Vec::with_capacity(attachments.len());
    for attachment in &attachments {
        if let Some(id) = attachment["id"].as_str() {
            ids.push(id.to_string());
        }
        let inner = serde_json::to_vec(&attachment["data"]["json"]).map_err(internal_err)?;
        let unpacked = state.dmp.unpack(&inner).await.map_err(internal_err)?;
        messages.push(unpacked.message().map_err(internal_err)?);
    }

    let ack = json!({
        "type": "https://didcomm.org/messagepickup/3.0/messages-received",
        "body": {"message_id_list": ids},
    });
    pack_and_post(&state.dmp, &state.http, &ack, &req.mediator_did, Some(&state.did))
        .await
        .map_err(internal_err)?;

    Ok(Json(json!({"messages": messages})))
}

async fn run_peer(port: u16, endpoint_uri: String) -> anyhow::Result<()> {
    let generated = generate_did_with_endpoint(&endpoint_uri)?;
    let did = generated.did.clone();
    let dmp = didcomm_quickstart::setup_default(&generated);
    tracing::info!(%did, %endpoint_uri, "peer ready");

    let state = Arc::new(PeerState { did, dmp, http: reqwest::Client::new() });
    let app = Router::new()
        .route("/did", get(get_did))
        .route("/", post(receive))
        .route("/send", post(send))
        .route("/mediate", post(mediate))
        .route("/pickup", post(pickup))
        .with_state(state);

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
