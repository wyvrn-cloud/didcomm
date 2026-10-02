//! DIDComm v1 end to end over real HTTP on localhost: out-of-band invitations, DID
//! Exchange (1.1 and 1.0) in both roles, v1 messages on a connection, and a v1 mediator
//! (coordinate-mediation/1.0, messagepickup/2.0, routing/1.0 forward) for an agent with
//! no endpoint of its own.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use axum::{body::Bytes, extract::State, http::StatusCode, routing::post, Router};
use base64::Engine as _;
use didcomm_agent::connections::{DIDEXCHANGE_1_0, DIDEXCHANGE_1_1};
use didcomm_agent::v1::{normalize_type, TRUST_PING_V1_PING, TRUST_PING_V1_RESPONSE};
use didcomm_agent::{Agent, AgentError, ConnectionRole, ConnectionState, DidcommVersion, Features, Identity, Received};
use serde_json::{json, Value};

const BASICMESSAGE_V1: &str = "https://didcomm.org/basicmessage/1.0/message";

async fn listener() -> (tokio::net::TcpListener, String) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}/", listener.local_addr().unwrap());
    (listener, endpoint)
}

fn bad(e: AgentError) -> (StatusCode, String) {
    (StatusCode::BAD_REQUEST, e.to_string())
}

/// What a v1 agent does with a message: DID Exchange, then trust ping, then
/// basicmessage (acked as `ack: <content>`); `None` for anything else.
async fn react(agent: &Agent, received: &Received) -> Result<Option<Value>, AgentError> {
    if Agent::is_connection_message(received) {
        return agent.handle_connection_message(received).await;
    }
    if let Some(reply) = agent.auto_reply(received) {
        return Ok(Some(reply));
    }
    if normalize_type(received.message_type()) == BASICMESSAGE_V1 && !received.message["content"].as_str().unwrap_or_default().starts_with("ack: ") {
        let content = received.message["content"].as_str().unwrap_or_default();
        return Ok(Some(received.reply(BASICMESSAGE_V1, json!({"content": format!("ack: {content}"), "sent_time": "2026-10-02T00:00:00Z"}))));
    }
    Ok(None)
}

async fn agent_receive(State(agent): State<Arc<Agent>>, body: Bytes) -> Result<Vec<u8>, (StatusCode, String)> {
    let received = agent.receive(&body).await.map_err(bad)?;
    match react(&agent, &received).await.map_err(bad)? {
        Some(reply) => Ok(agent.respond(&received, &reply).await.map_err(bad)?.unwrap_or_default()),
        None => Ok(Vec::new()),
    }
}

/// Bob: directly reachable over HTTP, speaks v1.
async fn start_bob() -> Arc<Agent> {
    let (listener, endpoint) = listener().await;
    let bob = Arc::new(
        Agent::with_endpoint(Identity::generate().unwrap(), &endpoint)
            .unwrap()
            .with_features(Features::standard().with_v1()),
    );
    let app = Router::new().route("/", post(agent_receive)).with_state(bob.clone());
    tokio::spawn(async move { axum::serve(listener, app).await });
    bob
}

fn alice() -> Agent {
    Agent::new(Identity::generate().unwrap()).unwrap().with_features(Features::standard().with_v1())
}

#[tokio::test]
async fn accepting_an_invitation_url_connects_both_sides() {
    let bob = start_bob().await;
    let alice = alice();

    let invitation = bob.create_invitation("Bob").unwrap();
    let url = Agent::invitation_url("https://bob.example/invite", &invitation);
    let parsed = alice.fetch_invitation(&url).await.unwrap();
    let connection = alice.accept_invitation(&parsed, "Alice").await.unwrap();

    // Bob answered on the same connection, and Alice sent complete.
    assert_eq!(connection.state, ConnectionState::Completed);
    assert_eq!(connection.role, ConnectionRole::Requester);
    assert_eq!(connection.didcomm_version, DidcommVersion::V1);
    assert_eq!(connection.protocol.as_deref(), Some(DIDEXCHANGE_1_1));
    assert_eq!(connection.their_label.as_deref(), Some("Bob"));
    assert_eq!(connection.their_did.as_deref(), Some(bob.v1_did().as_str()));
    assert_eq!(connection.their_service.as_ref().unwrap(), &bob.v1_service());

    let bobs = bob.connections();
    assert_eq!(bobs.len(), 1);
    assert_eq!(bobs[0].id, connection.id);
    assert_eq!(bobs[0].role, ConnectionRole::Responder);
    assert_eq!(bobs[0].state, ConnectionState::Completed);
    assert_eq!(bobs[0].their_label.as_deref(), Some("Alice"));
    assert_eq!(bobs[0].their_did.as_deref(), Some(alice.v1_did().as_str()));
}

#[tokio::test]
async fn v1_messages_flow_on_a_connection() {
    let bob = start_bob().await;
    let alice = alice();
    let connection = alice.accept_invitation(&bob.create_invitation("Bob").unwrap(), "Alice").await.unwrap();

    let pong = alice
        .request(&connection.id, &json!({"@type": TRUST_PING_V1_PING, "@id": "ping-1", "response_requested": true}))
        .await
        .unwrap();
    assert_eq!(pong.version, DidcommVersion::V1);
    assert_eq!(pong.message_type(), TRUST_PING_V1_RESPONSE);
    assert_eq!(pong.message["~thread"]["thid"], "ping-1");
    assert_eq!(pong.sender.as_deref(), Some(bob.v1_did().as_str()));
    assert_eq!(pong.sender_key.as_deref(), Some(bob.v1_verkey().as_str()));

    // Addressed by the peer's DID as well as by connection id; legacy type prefix too.
    let reply = alice
        .request(
            &bob.v1_did(),
            &json!({"@type": "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/basicmessage/1.0/message", "content": "hi", "sent_time": "2026-10-02T00:00:00Z"}),
        )
        .await
        .unwrap();
    assert_eq!(reply.message["content"], "ack: hi");

    // Bob can't reach Alice unprompted: she has no endpoint.
    let bobs = &bob.connections()[0];
    let error = bob
        .send(&bobs.id, &json!({"@type": BASICMESSAGE_V1, "content": "anyone?", "sent_time": "2026-10-02T00:00:00Z"}))
        .await
        .unwrap_err();
    assert!(matches!(error, AgentError::NoHttpEndpoint(_)), "{error:?}");

    // A v2 message can't go over a v1 connection.
    let error = alice
        .send(&connection.id, &json!({"type": "https://didcomm.org/basicmessage/2.0/message", "body": {"content": "x"}}))
        .await
        .unwrap_err();
    assert!(matches!(error, AgentError::VersionMismatch(..)), "{error:?}");
}

#[tokio::test]
async fn did_exchange_1_0_attaches_signed_documents() {
    let bob = start_bob().await;
    let alice = alice();
    let mut invitation = bob.create_invitation("Bob").unwrap();
    invitation["handshake_protocols"] = json!([DIDEXCHANGE_1_0]);

    let connection = alice.accept_invitation(&invitation, "Alice").await.unwrap();

    assert_eq!(connection.state, ConnectionState::Completed);
    assert_eq!(connection.protocol.as_deref(), Some(DIDEXCHANGE_1_0));
    assert_eq!(connection.their_service.as_ref().unwrap(), &bob.v1_service());
    assert_eq!(bob.connections()[0].protocol.as_deref(), Some(DIDEXCHANGE_1_0));
}

#[tokio::test]
async fn a_request_for_an_unknown_invitation_is_refused() {
    let bob = start_bob().await;
    let alice = alice();
    let mut invitation = bob.create_invitation("Bob").unwrap();
    invitation["@id"] = json!("not-bobs");

    let error = alice.accept_invitation(&invitation, "Alice").await.unwrap_err();

    match error {
        AgentError::Problem { code, .. } => assert_eq!(code, "request_not_accepted"),
        other => panic!("expected a problem report, got {other:?}"),
    }
    assert!(alice.connections().is_empty());
    assert!(bob.connections().is_empty());
}

#[tokio::test]
async fn an_agent_without_an_endpoint_cannot_invite() {
    assert!(matches!(alice().create_invitation("Alice"), Err(AgentError::NotReachable)));
}

#[tokio::test]
async fn an_oob_2_0_invitation_connects_to_its_from_did() {
    let bob = start_bob().await;
    let alice = alice();
    let invitation = json!({
        "type": "https://didcomm.org/out-of-band/2.0/invitation",
        "id": "inv-2",
        "from": bob.did(),
        "body": {"goal_code": "chat", "accept": ["didcomm/v2"]},
    });

    let connection = alice.accept_invitation(&invitation, "Alice").await.unwrap();

    assert_eq!(connection.didcomm_version, DidcommVersion::V2);
    assert_eq!(connection.their_did.as_deref(), Some(bob.did().as_str()));
    let pong = alice
        .request(&connection.id, &json!({"type": "https://didcomm.org/trust-ping/2.0/ping", "body": {}}))
        .await
        .unwrap();
    assert_eq!(pong.version, DidcommVersion::V2);
}

#[tokio::test]
async fn connections_survive_export_and_import() {
    let bob = start_bob().await;
    let alice = alice();
    let connection = alice.accept_invitation(&bob.create_invitation("Bob").unwrap(), "Alice").await.unwrap();

    let saved = serde_json::to_string(&alice.export_connections()).unwrap();
    let restarted = Agent::new(alice.identity().clone()).unwrap();
    restarted.import_connections(serde_json::from_str(&saved).unwrap());

    assert_eq!(restarted.connection(&connection.id), Some(connection.clone()));
    let pong = restarted
        .request(&connection.id, &json!({"@type": TRUST_PING_V1_PING, "response_requested": true}))
        .await
        .unwrap();
    assert_eq!(pong.message_type(), TRUST_PING_V1_RESPONSE);
}

/// A v1 mediator: an agent that, besides connecting, grants mediation, queues what's
/// forwarded to its routing key for the one recipient it mediates for, and delivers
/// the queue through messagepickup/2.0.
struct Mediator {
    agent: Agent,
    queue: Mutex<VecDeque<(String, Value)>>,
}

async fn mediator_receive(State(m): State<Arc<Mediator>>, body: Bytes) -> Result<Vec<u8>, (StatusCode, String)> {
    let received = m.agent.receive(&body).await.map_err(bad)?;
    let message_type = normalize_type(received.message_type());
    let reply = match message_type.as_str() {
        "https://didcomm.org/routing/1.0/forward" => {
            let id = uuid::Uuid::new_v4().to_string();
            m.queue.lock().unwrap().push_back((id, received.message["msg"].clone()));
            None
        }
        "https://didcomm.org/coordinate-mediation/1.0/mediate-request" => Some(received.reply(
            "https://didcomm.org/coordinate-mediation/1.0/mediate-grant",
            json!({"endpoint": m.agent.endpoint(), "routing_keys": [m.agent.v1_did_key()]}),
        )),
        "https://didcomm.org/coordinate-mediation/1.0/keylist-update" => {
            let updated: Vec<Value> = received.message["updates"]
                .as_array()
                .unwrap()
                .iter()
                .map(|u| json!({"recipient_key": u["recipient_key"], "action": u["action"], "result": "success"}))
                .collect();
            Some(received.reply("https://didcomm.org/coordinate-mediation/1.0/keylist-update-response", json!({"updated": updated})))
        }
        "https://didcomm.org/messagepickup/2.0/delivery-request" => {
            let queue = m.queue.lock().unwrap();
            if queue.is_empty() {
                Some(received.reply("https://didcomm.org/messagepickup/2.0/status", json!({"message_count": 0})))
            } else {
                let attachments: Vec<Value> = queue
                    .iter()
                    .map(|(id, msg)| {
                        let b64 = base64::engine::general_purpose::STANDARD.encode(msg.to_string());
                        json!({"@id": id, "data": {"base64": b64}})
                    })
                    .collect();
                Some(received.reply("https://didcomm.org/messagepickup/2.0/delivery", json!({"~attach": attachments})))
            }
        }
        "https://didcomm.org/messagepickup/2.0/messages-received" => {
            let ids: Vec<&str> = received.message["message_id_list"].as_array().unwrap().iter().filter_map(Value::as_str).collect();
            let mut queue = m.queue.lock().unwrap();
            queue.retain(|(id, _)| !ids.contains(&id.as_str()));
            Some(received.reply("https://didcomm.org/messagepickup/2.0/status", json!({"message_count": queue.len()})))
        }
        _ => react(&m.agent, &received).await.map_err(bad)?,
    };
    match reply {
        Some(reply) => Ok(m.agent.respond(&received, &reply).await.map_err(bad)?.unwrap_or_default()),
        None => Ok(Vec::new()),
    }
}

async fn start_mediator() -> Arc<Mediator> {
    let (listener, endpoint) = listener().await;
    let mediator = Arc::new(Mediator {
        agent: Agent::with_endpoint(Identity::generate().unwrap(), &endpoint).unwrap(),
        queue: Mutex::new(VecDeque::new()),
    });
    let app = Router::new().route("/", post(mediator_receive)).with_state(mediator.clone());
    tokio::spawn(async move { axum::serve(listener, app).await });
    mediator
}

/// Picks up and reacts to everything queued, the way an application's receive loop
/// would; returns what was picked up.
async fn pickup_and_react(agent: &Agent) -> Vec<Received> {
    let pickup = agent.pickup_v1(10).await.unwrap();
    assert!(pickup.failed.is_empty(), "{:?}", pickup.failed);
    for received in &pickup.messages {
        if let Some(reply) = react(agent, received).await.unwrap() {
            assert!(agent.respond(received, &reply).await.unwrap().is_none());
        }
    }
    pickup.messages
}

#[tokio::test]
async fn a_v1_mediated_agent_invites_and_receives_through_pickup() {
    let mediator = start_mediator().await;
    let bob = start_bob().await;
    let alice = alice();

    let to_mediator = alice.accept_invitation(&mediator.agent.create_invitation("Mediator").unwrap(), "Alice").await.unwrap();
    let mediation = alice.mediate_v1(&to_mediator.id).await.unwrap();
    assert_eq!(mediation.endpoint, mediator.agent.endpoint());
    assert_eq!(mediation.routing_keys, [mediator.agent.v1_verkey()]);
    assert!(alice.v1_reachable());
    assert!(alice.resolve_v1_service(&alice.v1_did()).await.unwrap().routing_keys == [mediator.agent.v1_verkey()]);
    assert!(alice.pickup_v1(10).await.unwrap().messages.is_empty());

    // Bob accepts Alice's invitation: his request goes through the mediator, so his
    // side waits for the response.
    let invitation = alice.create_invitation("Alice").unwrap();
    let bobs = bob.accept_invitation(&invitation, "Bob").await.unwrap();
    assert_eq!(bobs.state, ConnectionState::RequestSent);

    // Alice picks up the request; her response goes to Bob's endpoint, and Bob
    // completes -- through the mediator again.
    let picked = pickup_and_react(&alice).await;
    assert_eq!(picked.len(), 1);
    assert_eq!(bob.connection(&bobs.id).unwrap().state, ConnectionState::Completed);
    assert_eq!(alice.connection(&bobs.id).unwrap().state, ConnectionState::ResponseSent);
    pickup_and_react(&alice).await;
    assert_eq!(alice.connection(&bobs.id).unwrap().state, ConnectionState::Completed);

    // Now Bob can message Alice unprompted, and her ack reaches him directly.
    bob.send(&bobs.id, &json!({"@type": BASICMESSAGE_V1, "content": "hello", "sent_time": "2026-10-02T00:00:00Z"}))
        .await
        .unwrap();
    let picked = pickup_and_react(&alice).await;
    assert_eq!(picked.len(), 1);
    assert_eq!(picked[0].message["content"], "hello");
    assert_eq!(picked[0].sender.as_deref(), Some(bob.v1_did().as_str()));
    assert!(alice.pickup_v1(10).await.unwrap().messages.is_empty());
}

/// Against Indicio's public mediator (ACA-Py), over the internet, so ignored by
/// default: `cargo test -p didcomm-agent -- --ignored`. Connects with an implicit
/// invitation (its public DID), gets v1 mediation, and routes a message to itself.
#[tokio::test]
#[ignore]
async fn live_indicio_v1_connection_mediation_and_pickup() {
    const INDICIO: &str = "did:web:us-east2.public.mediator.indiciotech.io";
    let alice = alice();
    let implicit = json!({
        "@type": "https://didcomm.org/out-of-band/1.1/invitation",
        "@id": INDICIO,
        "handshake_protocols": [DIDEXCHANGE_1_1],
        "services": [INDICIO],
    });

    let connection = alice.accept_invitation(&implicit, "didcomm-agent live test").await.unwrap();
    assert_eq!(connection.state, ConnectionState::Completed, "{connection:?}");

    let pong = alice
        .request(&connection.id, &json!({"@type": TRUST_PING_V1_PING, "response_requested": true}))
        .await
        .unwrap();
    assert_eq!(normalize_type(pong.message_type()), TRUST_PING_V1_RESPONSE);
    // Without asking for it, ACA-Py still answers on the connection: this agent's DID
    // names no endpoint.
    let pong = alice
        .send(&connection.id, &json!({"@type": TRUST_PING_V1_PING, "response_requested": true}))
        .await
        .unwrap()
        .expect("the ping_response on the connection");
    assert_eq!(normalize_type(pong.message_type()), TRUST_PING_V1_RESPONSE);

    alice.mediate_v1(&connection.id).await.unwrap();
    let to_self = alice.v1_service();
    alice
        .send_v1(&to_self, &json!({"@type": BASICMESSAGE_V1, "@id": "live-1", "content": "via indicio", "sent_time": "2026-10-02T00:00:00Z"}))
        .await
        .unwrap();
    // The mediator queues forwarded messages asynchronously.
    let mut picked = Vec::new();
    for _ in 0..10 {
        let pickup = alice.pickup_v1(10).await.unwrap();
        assert!(pickup.failed.is_empty(), "{:?}", pickup.failed);
        picked.extend(pickup.messages);
        if picked.iter().any(|m| m.message["content"] == "via indicio") {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
    panic!("never picked up the message: {picked:?}");
}
