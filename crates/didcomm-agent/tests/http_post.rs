//! The agent's POSTs (security review WYV-15): redirects followed as DIDComm v2.1's
//! HTTPS transport says (307 only, a few hops, never https to http), and no more
//! of a response body read into an error than `MAX_ERROR_BODY_BYTES`; a success
//! body read only when a return route was asked for, and no further than
//! `MAX_REPLY_BODY_BYTES` (WYV-93); an invitation fetched from a URL no larger than
//! `MAX_INVITATION_BYTES`.

use std::sync::Arc;

use axum::{
    body::Bytes,
    extract::State,
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
    Router,
};
use didcomm_agent::{features, Agent, AgentError, Identity, MAX_ERROR_BODY_BYTES, MAX_INVITATION_BYTES, MAX_REPLY_BODY_BYTES};
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
        .route("/endless", post(|| async { endless() }))
        .route("/big", post(answer_big))
        .with_state(bob.clone());
    tokio::spawn(async move { axum::serve(listener, app).await });
    bob
}

/// A ping-response padded so its packed body is about 18 MiB: the size of a
/// mediator's pickup reply carrying one 10 MiB message (WYV-119). The body's size
/// is kept in `BIG_BODY_BYTES`.
async fn answer_big(State(bob): State<Arc<Agent>>, body: Bytes) -> Response {
    let received = bob.receive(&body).await.unwrap();
    let reply = received.reply(features::TRUST_PING_RESPONSE, json!({"padding": "x".repeat(BIG_PADDING)}));
    let packed = bob.pack_reply(&received, &reply).await.unwrap();
    BIG_BODY_BYTES.store(packed.len(), std::sync::atomic::Ordering::SeqCst);
    packed.into_response()
}

/// Enough padding for an ~18 MiB body whether the reply is packed as JSON (whose
/// ciphertext is base64url, 4/3) or as COSE (binary).
const BIG_PADDING: usize = 18 * 1024 * 1024;
static BIG_BODY_BYTES: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// 200, and bytes without end.
fn endless() -> Response {
    let chunk = Bytes::from(vec![b'x'; 64 * 1024]);
    axum::body::Body::from_stream(futures_util::stream::repeat_with(move || Ok::<_, std::io::Error>(chunk.clone()))).into_response()
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

/// A peer that answers 200 and streams without end: a send that asked for a reply
/// on the connection fails once the cap is passed, long before the timeout; one
/// that didn't ask reads no more than the small cap and is done (WYV-93).
#[tokio::test]
async fn an_endless_success_body_is_not_read_past_the_cap() {
    let bob = bob_at("endless").await;
    let started = std::time::Instant::now();
    match alice().request(&bob.did(), &ping()).await {
        Err(AgentError::TooLarge { limit, .. }) => assert_eq!(limit, MAX_REPLY_BODY_BYTES),
        other => panic!("expected TooLarge: {other:?}"),
    }
    assert!(started.elapsed() < std::time::Duration::from_secs(20), "failed at the cap, not at the timeout");
    // No return_route: nothing is read back as a reply.
    let started = std::time::Instant::now();
    assert!(alice().send(&bob.did(), &ping()).await.unwrap().is_none());
    assert!(started.elapsed() < std::time::Duration::from_secs(10));
}

/// A reply as large as a spec-valid mediator's pickup of one message at its
/// disclosed `max_receive_bytes` of 10 MiB (~17.8 MiB once base64 and the JWE are
/// added) is read; a smaller cap set with `with_max_reply_bytes` refuses it (WYV-119).
#[tokio::test]
async fn a_reply_the_size_of_a_mediators_pickup_is_read() {
    assert!(MAX_REPLY_BODY_BYTES >= 10 * 1024 * 1024 * 16 / 9 + 256 * 1024);
    let bob = bob_at("big").await;
    let pong = alice().request(&bob.did(), &ping()).await.unwrap();
    assert_eq!(pong.message_type(), features::TRUST_PING_RESPONSE);
    assert_eq!(pong.message["body"]["padding"].as_str().map(str::len), Some(BIG_PADDING));
    let read = BIG_BODY_BYTES.load(std::sync::atomic::Ordering::SeqCst);
    assert!(read > 10 * 1024 * 1024 * 16 / 9, "the reply read was {read} bytes");
    let small = alice().with_max_reply_bytes(16 * 1024 * 1024);
    match small.request(&bob.did(), &ping()).await {
        Err(AgentError::TooLarge { limit, .. }) => assert_eq!(limit, 16 * 1024 * 1024),
        other => panic!("expected TooLarge: {other:?}"),
    }
}

/// A reply on the connection is unpacked only when the message asked for one.
#[tokio::test]
async fn a_reply_is_read_back_only_when_a_return_route_was_asked_for() {
    let bob = bob_at("inbox").await;
    let asked = json!({"type": features::TRUST_PING_PING, "body": {"response_requested": true}, "return_route": "all"});
    assert!(alice().send(&bob.did(), &asked).await.unwrap().is_some());
    // Bob doesn't answer on the connection unasked, and would not be listened to.
    let unasked = json!({"type": features::TRUST_PING_PING, "body": {"response_requested": false}});
    assert!(alice().send(&bob.did(), &unasked).await.unwrap().is_none());
}

/// An invitation URL is followed through a short URL's redirect, and no more than
/// an invitation's worth of what it answers is read.
#[tokio::test]
async fn an_invitation_url_is_followed_and_its_body_capped() {
    use axum::routing::get;
    let invitation = json!({"@type": "https://didcomm.org/out-of-band/1.1/invitation", "@id": "i1", "services": []});
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let shown = invitation.clone();
    let app = Router::new()
        .route("/short", get(|| async { redirect(StatusCode::FOUND, "/full") }))
        .route("/full", get(move || async move { axum::Json(shown) }))
        .route("/endless", get(|| async { endless() }));
    tokio::spawn(async move { axum::serve(listener, app).await });
    let fetched = alice().fetch_invitation(&format!("{base}/short")).await.unwrap();
    assert_eq!(fetched, invitation);
    match alice().fetch_invitation(&format!("{base}/endless")).await {
        Err(AgentError::TooLarge { limit, .. }) => assert_eq!(limit, MAX_INVITATION_BYTES),
        other => panic!("expected TooLarge: {other:?}"),
    }
}
