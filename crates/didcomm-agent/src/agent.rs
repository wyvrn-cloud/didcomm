//! [`Agent`]: one identity's `DIDCommMessaging`, plus an HTTP client to deliver what
//! it packs.

use std::sync::RwLock;

use didcomm_core::messaging::MessagingError;
use didcomm_core::secrets::InMemorySecretsManager;
use didcomm_quickstart::{default_resolver, setup_with_key_agreement_kid, DefaultDIDCommMessaging};
use didcomm_v1::messaging::{V1DIDCommMessaging, V1MessagingError};
use didcomm_v1::packaging::V1SecretKey;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::connections::ConnectionBook;
use crate::features::{self, Features};
use crate::identity::{Identity, IdentityError};
use crate::mediation::{Mediation, V1Mediation};
use crate::v1::{self as v1, normalize_type};

/// The DIDComm v1 messaging stack [`Agent`] uses next to its v2 one.
pub type V1Messaging = V1DIDCommMessaging<InMemorySecretsManager<V1SecretKey>>;

/// The service endpoint of an agent that has no transport address of its own -- it
/// sends, and receives replies on the same connection (`return_route`) or through a
/// mediator. The same placeholder `didcomm-quickstart` uses.
pub const NO_ENDPOINT: &str = "didcomm:transport/queue";

pub const PROBLEM_REPORT: &str = "https://didcomm.org/report-problem/2.0/problem-report";

/// Errors from [`Agent`] operations.
#[derive(Debug, thiserror::Error)]
pub enum AgentError {
    #[error(transparent)]
    Messaging(#[from] MessagingError),
    #[error(transparent)]
    Identity(#[from] IdentityError),
    #[error("HTTP: {0}")]
    Http(#[from] reqwest::Error),
    #[error("{uri} responded {status}: {body}")]
    HttpStatus { uri: String, status: u16, body: String },
    #[error("{0} has no HTTP(S) service endpoint")]
    NoHttpEndpoint(String),
    #[error("{0} has no WebSocket (ws:// or wss://) service endpoint")]
    NoWebSocketEndpoint(String),
    #[error("WebSocket: {0}")]
    WebSocket(String),
    #[error("message must be a JSON object")]
    NotAnObject,
    #[error("{to} sent no reply to {message_type}")]
    NoReply { to: String, message_type: String },
    #[error("problem report {code}: {}", comment.as_deref().unwrap_or("(no comment)"))]
    Problem { code: String, comment: Option<String>, report: Value },
    #[error("expected {expected}, got {got}")]
    UnexpectedReply { expected: &'static str, got: String },
    #[error("can't reply to an anonymous (anoncrypted) message")]
    NoReturnAddress,
    #[error("mediation denied by {0}")]
    MediationDenied(String),
    #[error("mediator did not register {did}: {result}")]
    RecipientUpdateFailed { did: String, result: String },
    #[error("not mediated; call Agent::mediate first")]
    NotMediated,
    #[error("DIDComm v1: {0}")]
    V1(#[from] V1MessagingError),
    #[error("DIDComm v1: {0}")]
    V1Pack(#[from] didcomm_v1::V1Error),
    #[error("resolving: {0}")]
    Resolution(String),
    #[error("key: {0}")]
    Key(String),
    #[error("{0} has no DIDComm v1 service")]
    NoV1Service(String),
    #[error("attachment: {0}")]
    Attachment(String),
    #[error("invitation: {0}")]
    Invitation(String),
    #[error("connection: {0}")]
    Connection(String),
    #[error("no connection {0}")]
    UnknownConnection(String),
    #[error("this agent has no address peers can send to: give it an endpoint or a v1 mediator")]
    NotReachable,
    #[error("{uri} answered with something other than a DIDComm message: {body}")]
    NotDidcomm { uri: String, body: String },
    #[error("{0} is a DIDComm {1} connection; the message is DIDComm {2}")]
    VersionMismatch(String, DidcommVersion, DidcommVersion),
}

/// Which DIDComm a message or connection uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DidcommVersion {
    V1,
    V2,
}

impl DidcommVersion {
    /// v1 messages carry `@type`; v2 messages `type`.
    pub fn of_message(message: &Value) -> Self {
        if message.get("@type").is_some() {
            Self::V1
        } else {
            Self::V2
        }
    }
}

impl std::fmt::Display for DidcommVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::V1 => "v1",
            Self::V2 => "v2",
        })
    }
}

/// A message this agent unpacked.
#[derive(Debug, Clone)]
pub struct Received {
    pub message: Value,
    /// v2: the DID whose key authcrypted the message. v1: the DID of the
    /// [connection](crate::connections) whose key did. `None` if it was anoncrypted
    /// (or, for v1, came from no known connection).
    pub sender: Option<String>,
    /// Which of this agent's keys it was encrypted to (for v1, its verkey).
    pub recipient_kid: String,
    pub version: DidcommVersion,
    /// v1: the verkey that authcrypted the message.
    pub sender_key: Option<String>,
}

impl Received {
    /// The message's `type` (v2) or `@type` (v1), as written.
    pub fn message_type(&self) -> &str {
        self.message["type"].as_str().or(self.message["@type"].as_str()).unwrap_or_default()
    }

    /// The thread this message belongs to: its `thid` (v1: `~thread.thid`), or its own
    /// id if it started the thread.
    pub fn thread_id(&self) -> Option<&str> {
        match self.version {
            DidcommVersion::V1 => self.message["~thread"]["thid"].as_str().or_else(|| self.message["@id"].as_str()),
            DidcommVersion::V2 => self.message["thid"].as_str().or_else(|| self.message["id"].as_str()),
        }
    }

    /// The thread the message says it replies on (`thid`; v1: `~thread.thid`), if any.
    fn reply_thread(&self) -> Option<&str> {
        match self.version {
            DidcommVersion::V1 => self.message["~thread"]["thid"].as_str(),
            DidcommVersion::V2 => self.message["thid"].as_str(),
        }
    }

    /// Whether the sender asked for replies on the same connection
    /// (`return_route: "all"`; v1: `~transport.return_route` `"all"` or `"thread"`).
    pub fn wants_reply_on_connection(&self) -> bool {
        match self.version {
            DidcommVersion::V1 => matches!(self.message["~transport"]["return_route"].as_str(), Some("all" | "thread")),
            DidcommVersion::V2 => self.message["return_route"] == "all",
        }
    }

    /// Whether this is a problem report (v2 `report-problem/2.0`, or any v1
    /// `problem-report`/`problem_report`).
    pub fn is_problem_report(&self) -> bool {
        let message_type = normalize_type(self.message_type());
        message_type == PROBLEM_REPORT || message_type.ends_with("/problem-report") || message_type.ends_with("/problem_report")
    }

    /// This problem report as an [`AgentError::Problem`].
    pub fn into_problem(self) -> AgentError {
        let m = &self.message;
        let code = m["body"]["code"]
            .as_str()
            .or(m["description"]["code"].as_str())
            .or(m["problem-code"].as_str())
            .or(m["problem_code"].as_str())
            .unwrap_or_default()
            .to_string();
        let comment = m["body"]["comment"]
            .as_str()
            .or(m["description"]["en"].as_str())
            .or(m["explain"].as_str())
            .map(str::to_string);
        AgentError::Problem { code, comment, report: self.message }
    }

    /// A reply on this message's thread. v2: `{"type", "thid", "body"}`, and `pack`
    /// fills in the rest of the headers. v1: `body`'s fields with `@type`, a fresh
    /// `@id` and `~thread`.
    pub fn reply(&self, message_type: &str, body: Value) -> Value {
        if self.version == DidcommVersion::V1 {
            let mut reply = match body {
                Value::Object(fields) => Value::Object(fields),
                _ => json!({}),
            };
            reply["@type"] = json!(message_type);
            reply["@id"] = json!(uuid::Uuid::new_v4().to_string());
            if let Some(thid) = self.thread_id() {
                reply["~thread"] = json!({"thid": thid});
            }
            return reply;
        }
        let mut reply = json!({"type": message_type, "body": body});
        if let Some(thid) = self.thread_id() {
            reply["thid"] = json!(thid);
        }
        reply
    }

    /// A problem report replying to this message: `report-problem/2.0` (`pthid` = this
    /// message's thread), or for v1 `report-problem/1.0` (on this message's thread, with
    /// `{1}`, `{2}`, ... in `comment` filled in from `args`).
    pub fn problem_report(&self, code: &str, comment: &str, args: &[&str]) -> Value {
        if self.version == DidcommVersion::V1 {
            let mut explained = comment.to_string();
            for (i, arg) in args.iter().enumerate() {
                explained = explained.replace(&format!("{{{}}}", i + 1), arg);
            }
            return self.reply(v1::PROBLEM_REPORT_V1, json!({"description": {"code": code, "en": explained}}));
        }
        let mut report = json!({
            "type": PROBLEM_REPORT,
            "body": {"code": code, "comment": comment},
        });
        if !args.is_empty() {
            report["body"]["args"] = json!(args);
        }
        if let Some(thid) = self.thread_id() {
            report["pthid"] = json!(thid);
        }
        if let Some(id) = self.message["id"].as_str() {
            report["ack"] = json!([id]);
        }
        report
    }
}

/// One identity's DIDComm v2 agent: packs, sends over HTTP(S), receives, mediates and
/// picks up. Cheap to share: every method takes `&self`, so wrap it in an `Arc`.
pub struct Agent {
    identity: Identity,
    did: String,
    endpoint: String,
    dmp: DefaultDIDCommMessaging,
    v1: V1Messaging,
    http: reqwest::Client,
    features: Features,
    pub(crate) mediation: RwLock<Option<Mediation>>,
    pub(crate) v1_mediation: RwLock<Option<V1Mediation>>,
    pub(crate) connections: RwLock<ConnectionBook>,
}

impl Agent {
    /// An agent with no transport address of its own ([`NO_ENDPOINT`]): it can send,
    /// get replies on the same connection, and receive through a mediator once
    /// [`mediate`](Self::mediate)d. Answers discover-features and trust-ping
    /// ([`Features::standard`]).
    pub fn new(identity: Identity) -> Result<Self, AgentError> {
        Self::with_endpoint(identity, NO_ENDPOINT)
    }

    /// An agent directly reachable at `endpoint_uri` (e.g. an HTTPS URL it serves).
    pub fn with_endpoint(identity: Identity, endpoint_uri: &str) -> Result<Self, AgentError> {
        let did = identity.did(endpoint_uri)?;
        Ok(Self::with_did(identity, &did).with_v1_endpoint(endpoint_uri))
    }

    /// An agent known by a DID it doesn't derive from its keys -- typically a `did:web`
    /// whose document ([`Identity::did_document`]) it publishes itself. The document
    /// must list this identity's key-agreement key as `<did>#key-2`, as
    /// `Identity::did_document` does. Its [v1 service](Self::v1_service) has no
    /// endpoint unless given one with [`with_v1_endpoint`](Self::with_v1_endpoint).
    pub fn with_did(identity: Identity, did: &str) -> Self {
        let dmp = setup_with_key_agreement_kid(identity.key_agreement_key().clone(), &format!("{did}#key-2"));
        let v1_secrets = InMemorySecretsManager::new();
        v1_secrets.add_secret(V1SecretKey::new(identity.verification_key().clone()));
        Self {
            identity,
            did: did.to_string(),
            endpoint: NO_ENDPOINT.to_string(),
            dmp,
            v1: V1DIDCommMessaging::new(v1_secrets, default_resolver()),
            http: default_http_client(),
            features: Features::standard(),
            mediation: RwLock::new(None),
            v1_mediation: RwLock::new(None),
            connections: RwLock::new(ConnectionBook::default()),
        }
    }

    /// The endpoint this agent's [v1 DID](Self::v1_did) names (until it's
    /// [mediated](Self::mediate_v1)). [`with_endpoint`](Self::with_endpoint) sets it to
    /// that endpoint.
    pub fn with_v1_endpoint(mut self, endpoint_uri: &str) -> Self {
        self.endpoint = endpoint_uri.to_string();
        self
    }

    /// This agent's own transport endpoint ([`NO_ENDPOINT`] if it has none).
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// Use `http` for everything this agent sends, instead of the default client (whose
    /// requests time out after [`DEFAULT_TIMEOUT`]).
    pub fn with_http_client(mut self, http: reqwest::Client) -> Self {
        self.http = http;
        self
    }

    /// Replace what this agent discloses (and auto-answers); see [`Features`].
    pub fn with_features(mut self, features: Features) -> Self {
        self.features = features;
        self
    }

    pub fn identity(&self) -> &Identity {
        &self.identity
    }

    pub fn features(&self) -> &Features {
        &self.features
    }

    /// The underlying `DIDCommMessaging`, for anything this type doesn't wrap.
    pub fn messaging(&self) -> &DefaultDIDCommMessaging {
        &self.dmp
    }

    /// The underlying DIDComm v1 stack.
    pub fn v1_messaging(&self) -> &V1Messaging {
        &self.v1
    }

    pub(crate) fn http(&self) -> &reqwest::Client {
        &self.http
    }

    /// The DID for this agent's own endpoint -- what it uses to talk to its mediator.
    pub fn base_did(&self) -> &str {
        &self.did
    }

    /// The DID peers should use to reach this agent: the mediated DID once
    /// [`mediate`](Self::mediate)d, otherwise [`base_did`](Self::base_did). Messages
    /// this agent [`send`](Self::send)s come from this DID.
    pub fn did(&self) -> String {
        self.mediation()
            .map(|m| m.did)
            .unwrap_or_else(|| self.did.clone())
    }

    /// The DID to send to `to` from: [`did`](Self::did), except to this agent's own
    /// mediator, which gets [`base_did`](Self::base_did). The mediated DID's endpoint
    /// *is* the mediator, so a mediator replying to it would route the reply back into
    /// itself, encrypted to its own key.
    pub fn did_for(&self, to: &str) -> String {
        match self.mediation() {
            Some(m) if did_of(to) == m.mediator_did => self.did.clone(),
            _ => self.did(),
        }
    }

    pub fn mediation(&self) -> Option<Mediation> {
        self.mediation.read().expect("mediation lock poisoned").clone()
    }

    /// Pack `message` from [`did_for(to)`](Self::did_for) to `to` and POST it to `to`'s HTTP(S)
    /// endpoint (or its mediator's). Returns the reply if the recipient sent one back
    /// on the same connection. `pack` fills in `id`, `from`, `to` and `created_time`.
    ///
    /// `to` is a DID or a [connection](crate::connections) (by id or the peer's DID).
    /// A v1 message (one with `@type`) goes out as DIDComm v1, from this agent's
    /// [verkey](Self::v1_verkey), to the connection's service or `to`'s v1 service.
    pub async fn send(&self, to: &str, message: &Value) -> Result<Option<Received>, AgentError> {
        self.send_as(&self.did_for(to), to, message).await
    }

    /// Like [`send`](Self::send), but asks for the reply on the same connection
    /// (`return_route: "all"`) and requires one. A `problem-report` reply comes back as
    /// [`AgentError::Problem`], and a reply whose `thid` names a different thread as
    /// [`AgentError::UnexpectedReply`] (a reply with no `thid` is accepted: it arrived
    /// on the request's own connection).
    pub async fn request(&self, to: &str, message: &Value) -> Result<Received, AgentError> {
        self.request_as(&self.did_for(to), to, message).await
    }

    /// [`send`](Self::send) from a specific one of this agent's DIDs (e.g.
    /// [`base_did`](Self::base_did) after mediation) rather than [`did`](Self::did).
    pub async fn send_as(&self, from: &str, to: &str, message: &Value) -> Result<Option<Received>, AgentError> {
        let version = DidcommVersion::of_message(message);
        let connection = self.connection(to);
        if let Some(connection) = &connection {
            if connection.didcomm_version != version {
                return Err(AgentError::VersionMismatch(to.to_string(), connection.didcomm_version, version));
            }
        }
        if version == DidcommVersion::V1 {
            let service = self.v1_service_for(to).await?;
            return self.send_v1(&service, message).await;
        }
        let to = connection.and_then(|c| c.their_did).unwrap_or_else(|| to.to_string());
        let packed = self.dmp.pack(message, &to, Some(from)).await?;
        let uri = packed
            .get_endpoint("http")
            .ok_or_else(|| AgentError::NoHttpEndpoint(to.to_string()))?
            .to_string();
        self.post(&uri, "application/didcomm-encrypted+json", packed.message).await
    }

    /// POST a packed message; unpack what comes back on the connection, if anything.
    pub(crate) async fn post(&self, uri: &str, content_type: &str, packed: Vec<u8>) -> Result<Option<Received>, AgentError> {
        let uri = uri.to_string();
        let response = self
            .http
            .post(&uri)
            .header("content-type", content_type)
            .body(packed)
            .send()
            .await?;
        let status = response.status();
        let body = response.bytes().await?;
        if !status.is_success() {
            return Err(AgentError::HttpStatus {
                uri,
                status: status.as_u16(),
                body: String::from_utf8_lossy(&body).into_owned(),
            });
        }
        if body.is_empty() {
            return Ok(None);
        }
        if !looks_packed(&body) {
            return Err(AgentError::NotDidcomm { uri, body: String::from_utf8_lossy(&body).into_owned() });
        }
        Ok(Some(self.receive(&body).await?))
    }

    /// [`request`](Self::request) from a specific one of this agent's DIDs.
    pub async fn request_as(&self, from: &str, to: &str, message: &Value) -> Result<Received, AgentError> {
        let mut message = message.clone();
        let v1 = DidcommVersion::of_message(&message) == DidcommVersion::V1;
        let headers = message.as_object_mut().ok_or(AgentError::NotAnObject)?;
        if v1 {
            let transport = headers.entry("~transport").or_insert_with(|| json!({}));
            if let Some(transport) = transport.as_object_mut() {
                transport.entry("return_route").or_insert_with(|| json!("all"));
            }
        } else {
            headers.entry("return_route").or_insert_with(|| json!("all"));
        }
        // Set here rather than left to `pack`, so the reply's thread can be checked.
        let id = headers
            .entry(if v1 { "@id" } else { "id" })
            .or_insert_with(|| json!(uuid::Uuid::new_v4().to_string()))
            .as_str()
            .unwrap_or_default()
            .to_string();
        let message_type = headers
            .get(if v1 { "@type" } else { "type" })
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();

        let reply = self
            .send_as(from, to, &message)
            .await?
            .ok_or_else(|| AgentError::NoReply { to: to.to_string(), message_type })?;
        if reply.is_problem_report() {
            return Err(reply.into_problem());
        }
        if let Some(thid) = reply.reply_thread() {
            if thid != id {
                return Err(AgentError::UnexpectedReply {
                    expected: "a reply on the request's thread",
                    got: format!("thid {thid} (request id {id})"),
                });
            }
        }
        Ok(reply)
    }

    /// Unpack a message received by any means (an HTTP request body, a pickup
    /// delivery, ...).
    /// DIDComm v1 and v2 alike.
    pub async fn receive(&self, packed: &[u8]) -> Result<Received, AgentError> {
        if v1::is_v1_packed(packed) {
            return self.receive_v1(packed).await;
        }
        let unpacked = self.dmp.unpack(packed).await?;
        Ok(Received {
            message: unpacked.message().map_err(MessagingError::from)?,
            sender: unpacked.sender_kid.as_deref().map(|kid| did_of(kid).to_string()),
            recipient_kid: unpacked.recipient_kid,
            version: DidcommVersion::V2,
            sender_key: None,
        })
    }

    /// The reply this agent gives on its own to the standard protocols it
    /// [supports](Self::features): a `ping-response` to a trust-ping `ping` (unless
    /// `response_requested` is `false`), a `disclose` to a discover-features `queries`.
    /// `None` for anything else.
    /// For v1, a `ping_response` to a trust_ping/1.0 `ping` if the agent's features
    /// include [`TRUST_PING_V1`](v1::TRUST_PING_V1) (see [`Features::with_v1`]).
    pub fn auto_reply(&self, received: &Received) -> Option<Value> {
        if received.version == DidcommVersion::V1 {
            let message_type = normalize_type(received.message_type());
            return (message_type == v1::TRUST_PING_V1_PING
                && self.features.supports(v1::TRUST_PING_V1)
                && received.message["response_requested"] != false)
                .then(|| received.reply(v1::TRUST_PING_V1_RESPONSE, json!({})));
        }
        match received.message_type() {
            features::TRUST_PING_PING if self.features.supports(features::TRUST_PING) => {
                (received.message["body"]["response_requested"] != false)
                    .then(|| received.reply(features::TRUST_PING_RESPONSE, json!({})))
            }
            features::DISCOVER_FEATURES_QUERIES if self.features.supports(features::DISCOVER_FEATURES) => {
                let disclosures = self.features.disclose(&received.message["body"]);
                Some(received.reply(features::DISCOVER_FEATURES_DISCLOSE, json!({"disclosures": disclosures})))
            }
            _ => None,
        }
    }

    /// Deliver `reply` to `received`'s sender, from the DID `received` was addressed
    /// to. If the sender asked for replies on the same connection, returns the packed
    /// reply for the caller to write back on it (e.g. as the HTTP response body);
    /// otherwise sends it to the sender's endpoint and returns `None`.
    ///
    /// Only reply to messages that call for a reply: two agents that both answer
    /// *every* message this way (e.g. acking acks) will bounce messages between each
    /// other forever.
    pub async fn respond(&self, received: &Received, reply: &Value) -> Result<Option<Vec<u8>>, AgentError> {
        if received.wants_reply_on_connection() {
            return Ok(Some(self.pack_reply(received, reply).await?));
        }
        if received.version == DidcommVersion::V1 {
            let key = received.sender_key.as_deref().ok_or(AgentError::NoReturnAddress)?;
            let service = self
                .connection_by_key(key)
                .and_then(|c| c.their_service)
                .ok_or(AgentError::NoReturnAddress)?;
            self.send_v1(&service, reply).await?;
            return Ok(None);
        }
        let to = received.sender.as_deref().ok_or(AgentError::NoReturnAddress)?;
        self.send_as(did_of(&received.recipient_kid), to, reply).await?;
        Ok(None)
    }

    /// Pack `reply` to `received`'s sender, from the DID `received` was addressed to,
    /// for writing back on the connection `received` arrived on -- whether or not the
    /// sender asked for that. Never forward-wrapped (see `pack_direct`).
    /// [`respond`](Self::respond) uses this when the sender asked for
    /// `return_route: "all"`.
    pub async fn pack_reply(&self, received: &Received, reply: &Value) -> Result<Vec<u8>, AgentError> {
        if received.version == DidcommVersion::V1 {
            return self.pack_reply_v1(received, reply);
        }
        let to = received.sender.as_deref().ok_or(AgentError::NoReturnAddress)?;
        let from = did_of(&received.recipient_kid);
        Ok(self.dmp.pack_direct(reply, to, Some(from)).await?.message)
    }
}

/// How long the default HTTP client waits for a whole request (connect, send, and the
/// synchronous reply) before giving up -- so an unresponsive peer surfaces as an error
/// instead of hanging the caller.
pub const DEFAULT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

fn default_http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(DEFAULT_TIMEOUT)
        .build()
        .expect("a reqwest client with only a timeout configured always builds")
}

/// Whether an HTTP body is a packed (encrypted) message rather than, say, an error
/// document: a JSON object with `protected` and `ciphertext`, or anything not JSON (a
/// CBOR envelope).
fn looks_packed(body: &[u8]) -> bool {
    match serde_json::from_slice::<Value>(body) {
        Ok(value) => value.get("protected").is_some() && value.get("ciphertext").is_some(),
        Err(_) => body.first() != Some(&b'{'),
    }
}

/// The DID part of a DID or DID URL.
pub(crate) fn did_of(did_or_url: &str) -> &str {
    did_or_url.split('#').next().unwrap_or(did_or_url)
}
