//! `Agent` end to end over real HTTP on localhost: a mediator (`didcomm-mediator-core`
//! behind axum), a directly reachable "Bob" agent server, and an "Alice" agent with no
//! endpoint of her own who mediates and picks up.

use std::sync::Arc;

use axum::{body::Bytes, extract::State, http::StatusCode, routing::post, Router};
use didcomm_agent::{features, Agent, AgentError, Identity};
use didcomm_mediator_core::MediatorService;
use didcomm_quickstart::{generate_did_with_endpoint, setup_default};
use serde_json::json;

const BASICMESSAGE: &str = "https://didcomm.org/basicmessage/2.0/message";

/// Bind a localhost port first, so the server's DID can name its own endpoint.
async fn listener() -> (tokio::net::TcpListener, String) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}/", listener.local_addr().unwrap());
    (listener, endpoint)
}

/// A mediator; returns its DID.
async fn start_mediator() -> String {
    let (listener, endpoint) = listener().await;
    let generated = generate_did_with_endpoint(&endpoint).unwrap();
    let did = generated.did.clone();
    let mediator = Arc::new(MediatorService::new(did.clone(), setup_default(&generated)));
    let app = Router::new().route(
        "/",
        post(|State(m): State<Arc<MediatorService<_, _>>>, body: Bytes| async move {
            match m.handle_message(&body).await {
                Ok(reply) => Ok(reply.unwrap_or_default()),
                Err(e) => Err((StatusCode::BAD_REQUEST, e.to_string())),
            }
        }),
    );
    tokio::spawn(async move { axum::serve(listener, app.with_state(mediator)).await });
    did
}

/// Bob: answers the standard protocols, acks basicmessages, and reports a problem for
/// anything else -- replying on the connection or to the sender's endpoint, as asked.
async fn bob_receive(State(bob): State<Arc<Agent>>, body: Bytes) -> Result<Vec<u8>, (StatusCode, String)> {
    let bad = |e: AgentError| (StatusCode::BAD_REQUEST, e.to_string());
    let received = bob.receive(&body).await.map_err(bad)?;
    let reply = bob.auto_reply(&received).unwrap_or_else(|| match received.message_type() {
        BASICMESSAGE => {
            let content = received.message["body"]["content"].as_str().unwrap_or_default();
            received.reply(BASICMESSAGE, json!({"content": format!("ack: {content}")}))
        }
        other => received.problem_report("e.p.msg.unsupported", "Unsupported message type {1}", &[other]),
    });
    Ok(bob.respond(&received, &reply).await.map_err(bad)?.unwrap_or_default())
}

/// Bob, directly reachable over HTTP.
async fn start_bob() -> Arc<Agent> {
    let (listener, endpoint) = listener().await;
    let bob = Arc::new(Agent::with_endpoint(Identity::generate().unwrap(), &endpoint).unwrap());
    let app = Router::new().route("/", post(bob_receive)).with_state(bob.clone());
    tokio::spawn(async move { axum::serve(listener, app).await });
    bob
}

fn alice() -> Agent {
    Agent::new(Identity::generate().unwrap()).unwrap()
}

#[tokio::test]
async fn trust_ping_gets_a_response_on_the_same_thread() {
    let bob = start_bob().await;

    let pong = alice()
        .request(&bob.did(), &json!({"id": "ping-1", "type": features::TRUST_PING_PING, "body": {}}))
        .await
        .unwrap();

    assert_eq!(pong.message_type(), features::TRUST_PING_RESPONSE);
    assert_eq!(pong.message["thid"], "ping-1");
    assert_eq!(pong.sender.as_deref(), Some(bob.did().as_str()));
}

#[tokio::test]
async fn discover_features_discloses_the_standard_protocols() {
    let bob = start_bob().await;
    let query = json!({
        "type": features::DISCOVER_FEATURES_QUERIES,
        "body": {"queries": [{"feature-type": "protocol", "match": "https://didcomm.org/trust-ping/*"}]},
    });

    let disclose = alice().request(&bob.did(), &query).await.unwrap();

    assert_eq!(disclose.message_type(), features::DISCOVER_FEATURES_DISCLOSE);
    assert_eq!(
        disclose.message["body"]["disclosures"],
        json!([{"feature-type": "protocol", "id": features::TRUST_PING, "roles": ["receiver"]}])
    );
}

#[tokio::test]
async fn a_problem_report_reply_is_an_error() {
    let bob = start_bob().await;

    let error = alice()
        .request(&bob.did(), &json!({"type": "https://example.org/nonsense/1.0/what", "body": {}}))
        .await
        .unwrap_err();

    match error {
        AgentError::Problem { code, report, .. } => {
            assert_eq!(code, "e.p.msg.unsupported");
            assert_eq!(report["body"]["args"], json!(["https://example.org/nonsense/1.0/what"]));
        }
        other => panic!("expected a problem report, got {other:?}"),
    }
}

#[tokio::test]
async fn a_mediated_agent_receives_replies_through_pickup() {
    let mediator_did = start_mediator().await;
    let bob = start_bob().await;
    let alice = alice();

    let mediation = alice.mediate(&mediator_did).await.unwrap();
    assert_eq!(mediation.routing_did, mediator_did);
    assert_eq!(alice.did(), mediation.did);
    assert_ne!(alice.did(), alice.base_did());

    // No return_route: Bob replies to Alice's mediated DID, i.e. through the mediator.
    let direct_reply = alice
        .send(&bob.did(), &json!({"type": BASICMESSAGE, "body": {"content": "hello"}}))
        .await
        .unwrap();
    assert!(direct_reply.is_none());

    let pickup = alice.pickup(10).await.unwrap();
    assert!(pickup.failed.is_empty(), "{:?}", pickup.failed);
    assert_eq!(pickup.messages.len(), 1);
    let reply = &pickup.messages[0];
    assert_eq!(reply.message["body"]["content"], "ack: hello");
    assert_eq!(reply.sender.as_deref(), Some(bob.did().as_str()));
    assert_eq!(reply.message["to"], json!([alice.did()]));

    // Acknowledged, so the mediator deleted it.
    assert!(alice.pickup(10).await.unwrap().messages.is_empty());
}

/// A mediator replies to whatever DID wrote to it -- and a mediated DID's endpoint is
/// the mediator itself, so a reply addressed there would be routed back into the
/// mediator, encrypted to its own key. Messages to the agent's own mediator therefore
/// go from the base DID, whichever DID the caller is using for everyone else.
#[tokio::test]
async fn messages_to_the_own_mediator_come_from_the_base_did() {
    let mediator_did = start_mediator().await;
    let alice = alice();
    alice.mediate(&mediator_did).await.unwrap();

    let status_request = json!({"type": "https://didcomm.org/messagepickup/3.0/status-request", "body": {}});
    let status = alice.request(&mediator_did, &status_request).await.unwrap();

    assert_eq!(status.message_type(), "https://didcomm.org/messagepickup/3.0/status");
    assert_eq!(status.message["to"], json!([alice.base_did()]));
}

#[tokio::test]
async fn mediating_again_is_idempotent() {
    let mediator_did = start_mediator().await;
    let alice = alice();

    let first = alice.mediate(&mediator_did).await.unwrap();
    let second = alice.mediate(&mediator_did).await.unwrap();

    assert_eq!(first, second);
}

#[tokio::test]
async fn pickup_requires_mediation() {
    assert!(matches!(alice().pickup(10).await, Err(AgentError::NotMediated)));
}

#[test]
fn a_saved_identity_reloads_to_the_same_dids() {
    let dir = std::env::temp_dir().join(format!("didcomm-agent-test-{}", uuid_like()));
    let path = dir.join("identity.json");

    let identity = Identity::load_or_generate(&path).unwrap();
    let reloaded = Identity::load_or_generate(&path).unwrap();

    assert_eq!(identity.did("https://a.example/").unwrap(), reloaded.did("https://a.example/").unwrap());
    assert_ne!(identity.did("https://a.example/").unwrap(), identity.did("did:example:mediator").unwrap());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
    }
    // Debug output never contains the private key.
    let secret = serde_json::from_str::<serde_json::Value>(&std::fs::read_to_string(&path).unwrap()).unwrap()
        ["key_agreement_key"]["d"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(!format!("{identity:?}").contains(&secret));

    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn a_did_document_matches_the_keys_the_agent_registers() {
    let identity = Identity::generate().unwrap();
    let did = "did:web:docs.example";
    // Same keys under a derived DID: its document's key material must be identical.
    let derived = identity.did("https://docs.example/").unwrap();
    let derived_doc = didcomm_resolver_peer::peer4::resolve(&derived).unwrap();

    let doc = identity.did_document(did, "https://docs.example/");

    assert_eq!(doc["keyAgreement"], json!([format!("{did}#key-2")]));
    assert_eq!(doc["verificationMethod"][1]["id"], format!("{did}#key-2"));
    assert_eq!(doc["verificationMethod"][1]["publicKeyMultibase"], derived_doc["verificationMethod"][1]["publicKeyMultibase"]);
    assert_eq!(doc["service"][0]["serviceEndpoint"]["uri"], "https://docs.example/");
    let agent = Agent::with_did(identity, did);
    assert_eq!(agent.did(), did);
    assert_eq!(agent.base_did(), did);
}

fn uuid_like() -> String {
    format!("{}-{:?}", std::process::id(), std::time::SystemTime::now())
        .replace(|c: char| !c.is_ascii_alphanumeric(), "")
}

/// Against the real Indicio public mediator. Needs network access, so not run by
/// default: `cargo test -p didcomm-agent -- --ignored`.
#[tokio::test]
#[ignore]
async fn live_indicio_mediation_and_pickup() {
    const INDICIO: &str = "did:web:us-east2.public.mediator.indiciotech.io";
    let alice = alice();

    let pong = alice.request(INDICIO, &json!({"type": features::TRUST_PING_PING, "body": {}})).await.unwrap();
    assert_eq!(pong.message_type(), features::TRUST_PING_RESPONSE);

    let mediation = alice.mediate(INDICIO).await.unwrap();
    assert_eq!(alice.did(), mediation.did);

    // Send ourselves a message through the mediator, then pick it up.
    let to_self = alice.did();
    alice
        .send(&to_self, &json!({"type": BASICMESSAGE, "body": {"content": "via indicio"}}))
        .await
        .unwrap();
    let pickup = alice.pickup(10).await.unwrap();
    assert!(pickup.failed.is_empty(), "{:?}", pickup.failed);
    assert!(pickup.messages.iter().any(|m| m.message["body"]["content"] == "via indicio"));
}
