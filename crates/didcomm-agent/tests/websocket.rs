//! `WsConnection` against a local WebSocket server: an `Agent` advertising a `ws://`
//! endpoint that answers on the socket, implements just enough of messagepickup/3.0
//! live mode, and pushes what a test feeds it -- single packed messages, and `delivery`
//! batches whose acknowledgement it reports back.

use std::sync::Arc;

use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        State,
    },
    response::Response,
    routing::get,
    Router,
};
use didcomm_agent::{
    features,
    mediation::{DELIVERY, MESSAGES_RECEIVED, STATUS},
    websocket::LIVE_DELIVERY_CHANGE,
    Agent, AgentError, Identity,
};
use serde_json::{json, Value};
use tokio::sync::{mpsc, Mutex};

const BASICMESSAGE: &str = "https://didcomm.org/basicmessage/2.0/message";

struct Server {
    agent: Agent,
    /// Packed messages to push once a client turns live delivery on.
    to_push: Mutex<mpsc::Receiver<Vec<u8>>>,
    /// `message_id_list`s of the `messages-received` acks clients send.
    acks: mpsc::Sender<Value>,
}

async fn upgrade(State(server): State<Arc<Server>>, ws: WebSocketUpgrade) -> Response {
    ws.on_upgrade(move |socket| session(server, socket))
}

async fn session(server: Arc<Server>, mut socket: WebSocket) {
    loop {
        let mut to_push = server.to_push.lock().await;
        tokio::select! {
            frame = socket.recv() => {
                drop(to_push);
                let Some(Ok(frame)) = frame else { return };
                let packed = match frame {
                    Message::Text(text) => text.as_bytes().to_vec(),
                    Message::Binary(bytes) => bytes.to_vec(),
                    _ => continue,
                };
                let received = server.agent.receive(&packed).await.unwrap();
                let reply = match received.message_type() {
                    LIVE_DELIVERY_CHANGE => Some(received.reply(STATUS, json!({"message_count": 0, "live_delivery": true}))),
                    MESSAGES_RECEIVED => {
                        server.acks.send(received.message["body"]["message_id_list"].clone()).await.unwrap();
                        None
                    }
                    _ => server.agent.auto_reply(&received),
                };
                if let Some(reply) = reply {
                    let packed = server.agent.pack_reply(&received, &reply).await.unwrap();
                    socket.send(to_frame(packed)).await.unwrap();
                }
            }
            Some(packed) = to_push.recv() => {
                socket.send(to_frame(packed)).await.unwrap();
            }
        }
    }
}

/// One packed message as a frame: text for a JSON envelope, binary otherwise (the
/// workspace's `didcomm/v2+cbor` profile, which agents here negotiate with each other).
fn to_frame(packed: Vec<u8>) -> Message {
    match String::from_utf8(packed) {
        Ok(json) => Message::Text(json.into()),
        Err(e) => Message::Binary(e.into_bytes().into()),
    }
}

/// The server; returns it, the pusher, and the ack receiver.
async fn start_server() -> (Arc<Server>, mpsc::Sender<Vec<u8>>, mpsc::Receiver<Value>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("ws://{}/", listener.local_addr().unwrap());
    let (push, to_push) = mpsc::channel(8);
    let (acks, ack_rx) = mpsc::channel(8);
    let server = Arc::new(Server {
        agent: Agent::with_endpoint(Identity::generate().unwrap(), &endpoint).unwrap(),
        to_push: Mutex::new(to_push),
        acks,
    });
    let app = Router::new().route("/", get(upgrade)).with_state(server.clone());
    tokio::spawn(async move { axum::serve(listener, app).await });
    (server, push, ack_rx)
}

fn agent() -> Agent {
    Agent::new(Identity::generate().unwrap()).unwrap()
}

/// What Bob would send Alice: a message packed to her DID.
async fn from_bob(bob: &Agent, alice: &Agent, content: &str) -> Vec<u8> {
    let message = json!({"type": BASICMESSAGE, "body": {"content": content}});
    bob.messaging().pack(&message, &alice.did(), Some(&bob.did())).await.unwrap().message
}

#[tokio::test]
async fn requests_get_their_reply_on_the_socket() {
    let (server, _, _) = start_server().await;
    let alice = agent();
    let mut ws = alice.connect_websocket(&server.agent.did()).await.unwrap();

    let pong = ws.request(&json!({"id": "ping-ws", "type": features::TRUST_PING_PING, "body": {}})).await.unwrap();

    assert_eq!(pong.message_type(), features::TRUST_PING_RESPONSE);
    assert_eq!(pong.message["thid"], "ping-ws");
    assert_eq!(pong.sender.as_deref(), Some(server.agent.did().as_str()));
    ws.close().await.unwrap();
}

#[tokio::test]
async fn live_delivery_pushes_messages_down_the_socket() {
    let (server, push, _) = start_server().await;
    let (alice, bob) = (agent(), agent());
    let mut ws = alice.connect_websocket(&server.agent.did()).await.unwrap();

    let status = ws.enable_live_delivery().await.unwrap();
    assert_eq!(status.message["body"]["live_delivery"], true);

    push.send(from_bob(&bob, &alice, "live!").await).await.unwrap();
    let received = ws.next_message().await.unwrap().unwrap();

    assert_eq!(received.message["body"]["content"], "live!");
    assert_eq!(received.sender.as_deref(), Some(bob.did().as_str()));
}

#[tokio::test]
async fn pushed_delivery_batches_are_opened_and_acknowledged() {
    let (server, push, mut acks) = start_server().await;
    let (alice, bob) = (agent(), agent());
    let mut ws = alice.connect_websocket(&server.agent.did()).await.unwrap();
    ws.enable_live_delivery().await.unwrap();

    // Delivery attachments carry a JSON envelope as data.json and anything else (CBOR)
    // as data.base64 -- the same split didcomm-mediator-core makes.
    let attachment = |id: &str, packed: Vec<u8>| match serde_json::from_slice::<Value>(&packed) {
        Ok(envelope) => json!({"id": id, "data": {"json": envelope}}),
        Err(_) => json!({"id": id, "data": {"base64": didcomm_multiformats::multibase::encode(&packed)}}),
    };
    let delivery = json!({
        "type": DELIVERY,
        "body": {},
        "attachments": [
            attachment("m1", from_bob(&bob, &alice, "one").await),
            attachment("m2", from_bob(&bob, &alice, "two").await),
        ],
    });
    let packed = server.agent.messaging().pack(&delivery, &alice.did(), Some(&server.agent.did())).await.unwrap();
    push.send(packed.message).await.unwrap();

    let first = ws.next_message().await.unwrap().unwrap();
    let second = ws.next_message().await.unwrap().unwrap();
    assert_eq!([&first.message["body"]["content"], &second.message["body"]["content"]], ["one", "two"]);
    assert_eq!(acks.recv().await.unwrap(), json!(["m1", "m2"]));
}

#[tokio::test]
async fn an_agent_without_a_websocket_endpoint_is_an_error() {
    let http_only = Agent::with_endpoint(Identity::generate().unwrap(), "https://example.invalid/").unwrap();

    let alice = agent();

    let result = alice.connect_websocket(&http_only.did()).await;

    assert!(matches!(result, Err(AgentError::NoWebSocketEndpoint(_))));
}

/// Live delivery from the real Indicio public mediator. Needs network access that
/// allows WebSocket upgrades, so not run by default:
/// `cargo test -p didcomm-agent --test websocket -- --ignored`.
#[tokio::test]
#[ignore]
async fn live_indicio_live_delivery() {
    const INDICIO: &str = "did:web:us-east2.public.mediator.indiciotech.io";
    let (alice, bob) = (agent(), agent());
    alice.mediate(INDICIO).await.unwrap();
    let mut ws = alice.connect_websocket(INDICIO).await.unwrap();
    ws.enable_live_delivery().await.unwrap();

    bob.send(&alice.did(), &json!({"type": BASICMESSAGE, "body": {"content": "live via indicio"}}))
        .await
        .unwrap();
    let received = tokio::time::timeout(std::time::Duration::from_secs(30), ws.next_message())
        .await
        .expect("delivered within 30 s")
        .unwrap()
        .unwrap();

    assert_eq!(received.message["body"]["content"], "live via indicio");
}
