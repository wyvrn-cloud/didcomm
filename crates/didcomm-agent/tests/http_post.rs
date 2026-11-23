//! The agent's POSTs (security review WYV-15): redirects followed as DIDComm v2.1's
//! HTTPS transport says (307 only, a few hops, never https to http), and no more
//! of a response body read into an error than `MAX_ERROR_BODY_BYTES`.

use std::sync::Arc;

use axum::{
    body::Bytes,
    extract::State,
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
    Router,
};
use didcomm_agent::{features, Agent, AgentError, Identity, MAX_ERROR_BODY_BYTES};
use serde_json::json;

fn redirect(status: StatusCode, to: &str) -> Response {
    (status, [(header::LOCATION, to.to_string())]).into_response()
}

async fn answer(State(bob): State<Arc<Agent>>, body: Bytes) -> Response {
    let received = bob.receive(&body).await.unwrap();
    match bob.auto_reply(&received) {
        Some(reply) => bob.respond(&received, &reply).await.unwrap().unwrap_or_default().into_response(),
        None => StatusCode::ACCEPTED.into_response(),
    }
}

/// Bob, at `http://<addr>/<path>`, where the routes below answer.
async fn bob_at(path: &str) -> Arc<Agent> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let bob = Arc::new(Agent::with_endpoint(Identity::generate().unwrap(), &format!("{base}/{path}")).unwrap());
    let app = Router::new()
        .route("/inbox", post(answer))
        .route("/temporary", post(|| async { redirect(StatusCode::TEMPORARY_REDIRECT, "/inbox") }))
        .route("/permanent", post(|| async { redirect(StatusCode::PERMANENT_REDIRECT, "/inbox") }))
        .route("/found", post(|| async { redirect(StatusCode::FOUND, "/inbox") }))
        .route("/r1", post(|| async { redirect(StatusCode::TEMPORARY_REDIRECT, "/r2") }))
        .route("/r2", post(|| async { redirect(StatusCode::TEMPORARY_REDIRECT, "/r3") }))
        .route("/r3", post(|| async { redirect(StatusCode::TEMPORARY_REDIRECT, "/r4") }))
        .route("/r4", post(|| async { redirect(StatusCode::TEMPORARY_REDIRECT, "/inbox") }))
        .route("/huge-error", post(|| async { (StatusCode::INTERNAL_SERVER_ERROR, "x".repeat(1024 * 1024)) }))
        .with_state(bob.clone());
    tokio::spawn(async move { axum::serve(listener, app).await });
    bob
}

fn ping() -> serde_json::Value {
    json!({"type": features::TRUST_PING_PING, "body": {}})
}

fn alice() -> Agent {
    Agent::new(Identity::generate().unwrap()).unwrap()
}

#[tokio::test]
async fn temporary_redirects_are_followed() {
    // r2: three hops, the most followed.
    for path in ["temporary", "r2"] {
        let bob = bob_at(path).await;
        let pong = alice().request(&bob.did(), &ping()).await.unwrap_or_else(|e| panic!("{path}: {e}"));
        assert_eq!(pong.message_type(), features::TRUST_PING_RESPONSE);
    }
}

#[tokio::test]
async fn other_redirects_and_long_chains_are_not_followed() {
    let bob = bob_at("found").await;
    match alice().request(&bob.did(), &ping()).await {
        Err(AgentError::HttpStatus { status: 302, .. }) => {}
        other => panic!("a 302 is the answer, not followed: {other:?}"),
    }
    // A permanent move is the DID document's to say (v2.1: "Only temporary
    // redirects (307) are acceptable").
    let bob = bob_at("permanent").await;
    match alice().request(&bob.did(), &ping()).await {
        Err(AgentError::HttpStatus { status: 308, .. }) => {}
        other => panic!("a 308 is the answer, not followed: {other:?}"),
    }
    let bob = bob_at("r1").await;
    match alice().request(&bob.did(), &ping()).await {
        Err(AgentError::Http(e)) => assert!(e.is_redirect(), "{e}"),
        other => panic!("four redirects are too many: {other:?}"),
    }
}

#[tokio::test]
async fn an_error_body_is_read_no_further_than_the_cap() {
    let bob = bob_at("huge-error").await;
    match alice().send(&bob.did(), &ping()).await {
        Err(AgentError::HttpStatus { status: 500, body, .. }) => assert_eq!(body.len(), MAX_ERROR_BODY_BYTES),
        other => panic!("expected a 500: {other:?}"),
    }
}
