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

impl AgentError {
    /// Whether a DID couldn't be resolved because the process's
    /// [fetch gate](didcomm_core::resolver::set_fetch_gate) refused the fetch (a
    /// server's resolution budget for unauthenticated senders, security review
    /// WYV-73). A server answers such a message with HTTP 429 or an `e.p.me.res`
    /// problem-report, not as one it couldn't open.
    pub fn is_fetch_refused(&self) -> bool {
        match self {
            Self::Messaging(e) => e.is_fetch_refused(),
            Self::V1(V1MessagingError::Resolution(e)) => e.is_fetch_refused(),
            _ => false,
        }
    }
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
    /// v2: more than 300 s past its `expires_time`. It is received all the same:
    /// DIDComm v2.1 (Message Headers) makes expiry the sender's to act on, and lets
    /// each protocol say what it means. [`Agent::auto_reply`] doesn't answer an
    /// expired trust-ping or discover-features query (the sender has stopped
    /// waiting); anything else is the application's call -- content is usually
    /// kept, a request may be dropped or answered with an `e.p.req.time`
    /// problem-report. Always `false` for v1 (whose `~timing` decorator this doesn't
    /// read).
    pub expired: bool,
    /// v2: its `expires_time` isn't an integer of epoch seconds: a malformed message.
    /// [`Received::header_problem`] is the `e.p.msg` problem-report to answer it with.
    pub expires_time_invalid: bool,
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

    /// The `e.p.msg` problem-report this message's headers call for, if they are
    /// malformed (an `expires_time` that isn't an integer): DIDComm v2.1, Problem
    /// Reports, scope `p`, descriptor `msg`. `None` for a well-formed message.
    pub fn header_problem(&self) -> Option<Value> {
        self.expires_time_invalid.then(|| {
            self.problem_report(
                "e.p.msg.invalid-expires-time",
                "expires_time must be an integer of UTC epoch seconds",
                &[],
            )
        })
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
    /// What packed messages are POSTed with: [`redirect_policy`]'s rules.
    post_http: reqwest::Client,
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
            post_http: default_post_client(),
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

    /// Use `http` for everything this agent sends, instead of the default clients
    /// (whose requests time out after [`DEFAULT_TIMEOUT`], and whose POSTs follow
    /// redirects only as [`redirect_policy`] says). Its own redirect policy then
    /// applies to POSTs too: build it with `.redirect(didcomm_agent::redirect_policy())`
    /// to keep DIDComm's.
    pub fn with_http_client(mut self, http: reqwest::Client) -> Self {
        self.post_http = http.clone();
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
        self.send_as_reading(from, to, message, ReadBack::Reply).await
    }

    /// [`send_as`](Self::send_as), reading what comes back as `read_back` says.
    async fn send_as_reading(&self, from: &str, to: &str, message: &Value, read_back: ReadBack) -> Result<Option<Received>, AgentError> {
        let version = DidcommVersion::of_message(message);
        let connection = self.connection(to);
        if let Some(connection) = &connection {
            if connection.didcomm_version != version {
                return Err(AgentError::VersionMismatch(to.to_string(), connection.didcomm_version, version));
            }
        }
        if version == DidcommVersion::V1 {
            let service = self.v1_service_for(to).await?;
            let from = connection.as_ref().map(|c| self.my_v1_verkey(c)).unwrap_or_else(|| self.v1_verkey());
            return self.send_v1_reading(&service, message, &from, read_back).await;
        }
        let to = connection.and_then(|c| c.their_did).unwrap_or_else(|| to.to_string());
        let packed = self.dmp.pack(message, &to, Some(from)).await?;
        let uri = packed
            .get_endpoint("http")
            .ok_or_else(|| AgentError::NoHttpEndpoint(to.to_string()))?
            .to_string();
        // The media type pack() actually produced: JSON or COSE, negotiated per recipient.
        let content_type = didcomm_core::jwe::peek_typ(&packed.message)
            .unwrap_or_else(|_| "application/didcomm-encrypted+json".to_string());
        self.post(&uri, &content_type, packed.message, read_back).await
    }

    /// POST a packed message; unpack what comes back on the connection, if anything
    /// and if `read_back` asks for it. Redirects are [`redirect_policy`]'s; an error
    /// body, or one that isn't a DIDComm message, is read no further than
    /// [`MAX_ERROR_BODY_BYTES`].
    pub(crate) async fn post(&self, uri: &str, content_type: &str, packed: Vec<u8>, read_back: ReadBack) -> Result<Option<Received>, AgentError> {
        let uri = uri.to_string();
        let mut response = self
            .post_http
            .post(&uri)
            .header("content-type", content_type)
            .body(packed)
            .send()
            .await?;
        let status = response.status();
        if !status.is_success() {
            let body = read_at_most(&mut response, MAX_ERROR_BODY_BYTES).await?;
            return Err(AgentError::HttpStatus { uri, status: status.as_u16(), body: shown(&body) });
        }
        if read_back == ReadBack::Ignore {
            // A reply's own POST: the HTTPS transport's answer is its status. Whatever
            // body comes with it is read no further than the cap, and let go.
            read_at_most(&mut response, MAX_ERROR_BODY_BYTES).await?;
            return Ok(None);
        }
        let body = read_at_most(&mut response, usize::MAX).await?;
        if body.is_empty() {
            return Ok(None);
        }
        if !looks_packed(&body) {
            let shown = shown(&body[..body.len().min(MAX_ERROR_BODY_BYTES)]);
            return Err(AgentError::NotDidcomm { uri, body: shown });
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
        let unpacked = self.dmp.unpack_verified(packed).await?;
        Ok(Received {
            message: unpacked.message().map_err(MessagingError::from)?,
            sender: unpacked.sender_kid.as_deref().map(|kid| did_of(kid).to_string()),
            recipient_kid: unpacked.recipient_kid,
            version: DidcommVersion::V2,
            sender_key: None,
            expired: unpacked.expired,
            expires_time_invalid: unpacked.expires_time_invalid,
        })
    }

    /// The reply this agent gives on its own to the standard protocols it
    /// [supports](Self::features): a `ping-response` to a trust-ping `ping` (unless
    /// `response_requested` is `false`), a `disclose` to a discover-features `queries`.
    /// `None` for anything else.
    /// For v1, a `ping_response` to a trust_ping/1.0 `ping` if the agent's features
    /// include [`TRUST_PING_V1`](v1::TRUST_PING_V1) (see [`Features::with_v1`]).
    ///
    /// A v2 ping or query that is [expired](Received::expired) is left unanswered:
    /// the sender said it would stop waiting by then (DIDComm v2.1, Message Headers,
    /// `expires_time`'s default meaning), so an answer would only arrive to nobody.
    /// One whose `expires_time` is malformed is answered with
    /// [`header_problem`](Received::header_problem)'s `e.p.msg` problem-report.
    pub fn auto_reply(&self, received: &Received) -> Option<Value> {
        if received.version == DidcommVersion::V1 {
            let message_type = normalize_type(received.message_type());
            return (message_type == v1::TRUST_PING_V1_PING
                && self.features.supports(v1::TRUST_PING_V1)
                && received.message["response_requested"] != false)
                .then(|| received.reply(v1::TRUST_PING_V1_RESPONSE, json!({})));
        }
        let ours = matches!(received.message_type(), features::TRUST_PING_PING | features::DISCOVER_FEATURES_QUERIES);
        if ours && received.expires_time_invalid {
            return received.header_problem();
        }
        if received.expired {
            return None;
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
            let service = self.connection_of(received).and_then(|c| c.their_service).ok_or(AgentError::NoReturnAddress)?;
            // From the key it was sent to (a connection's own, or the agent's).
            let from = didcomm_v1::kid_for_verkey(&self.v1_key_for(&received.recipient_kid));
            self.send_v1_reading(&service, reply, &from, ReadBack::Ignore).await?;
            return Ok(None);
        }
        let to = received.sender.as_deref().ok_or(AgentError::NoReturnAddress)?;
        self.send_as_reading(did_of(&received.recipient_kid), to, reply, ReadBack::Ignore).await?;
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

fn default_post_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(DEFAULT_TIMEOUT)
        .redirect(redirect_policy())
        .build()
        .expect("a reqwest client with a timeout and a redirect policy always builds")
}

/// The most of a response body read into an error ([`AgentError::HttpStatus`],
/// [`AgentError::NotDidcomm`]), and of the body answering a reply's own POST
/// ([`Agent::respond`]), which is let go (security review WYV-15).
pub const MAX_ERROR_BODY_BYTES: usize = 64 * 1024;

/// The most redirects a POST follows.
pub const MAX_REDIRECTS: usize = 3;

/// How the agent's POSTs follow redirects. DIDComm v2.1, HTTPS transport:
/// "Redirects SHOULD be followed. Only temporary redirects (307) are acceptable.
/// Permanent endpoint relocation should be managed with a DID Document update." So:
/// 307 only (a 301/302/303/308 is not followed, and its status is the answer), at most
/// [`MAX_REDIRECTS`] hops, and each hop's target checked as the endpoint itself is:
/// `http` or `https`, and never from `https` down to `http`. (Which addresses may be
/// posted to at all is the deferred outbound policy's, WYV-15.)
pub fn redirect_policy() -> reqwest::redirect::Policy {
    reqwest::redirect::Policy::custom(|attempt| {
        if attempt.status().as_u16() != 307 {
            return attempt.stop();
        }
        if attempt.previous().len() > MAX_REDIRECTS {
            return attempt.error(format!("more than {MAX_REDIRECTS} redirects"));
        }
        let scheme = attempt.url().scheme().to_string();
        if scheme != "http" && scheme != "https" {
            return attempt.error(format!("a redirect to a {scheme}: address"));
        }
        let downgrade = scheme == "http" && attempt.previous().last().is_some_and(|from| from.scheme() == "https");
        if downgrade {
            return attempt.error("a redirect from https to http");
        }
        attempt.follow()
    })
}

/// What to do with the body a POST is answered with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReadBack {
    /// A message on the same connection: unpacked and returned.
    Reply,
    /// Nothing is expected: read up to the cap and let go.
    Ignore,
}

/// The body, read no further than `limit` bytes (what is past it is not read).
async fn read_at_most(response: &mut reqwest::Response, limit: usize) -> Result<Vec<u8>, AgentError> {
    let mut body = Vec::new();
    while body.len() < limit {
        let Some(chunk) = response.chunk().await? else { break };
        let take = chunk.len().min(limit - body.len());
        body.extend_from_slice(&chunk[..take]);
    }
    Ok(body)
}

/// A body as text for an error.
fn shown(body: &[u8]) -> String {
    String::from_utf8_lossy(body).into_owned()
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
