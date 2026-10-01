//! [`Agent`]: one identity's `DIDCommMessaging`, plus an HTTP client to deliver what
//! it packs.

use std::sync::RwLock;

use didcomm_core::messaging::MessagingError;
use didcomm_quickstart::{setup_with_key_agreement_kid, DefaultDIDCommMessaging};
use serde_json::{json, Value};

use crate::features::{self, Features};
use crate::identity::{Identity, IdentityError};
use crate::mediation::Mediation;

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
}

/// A message this agent unpacked.
#[derive(Debug, Clone)]
pub struct Received {
    pub message: Value,
    /// The DID whose key authcrypted the message, or `None` if it was anoncrypted.
    pub sender: Option<String>,
    /// Which of this agent's keys it was encrypted to.
    pub recipient_kid: String,
}

impl Received {
    pub fn message_type(&self) -> &str {
        self.message["type"].as_str().unwrap_or_default()
    }

    /// The thread this message belongs to: its `thid`, or its own `id` if it started
    /// the thread.
    pub fn thread_id(&self) -> Option<&str> {
        self.message["thid"].as_str().or_else(|| self.message["id"].as_str())
    }

    /// Whether the sender asked for replies on the same connection
    /// (`return_route: "all"`).
    pub fn wants_reply_on_connection(&self) -> bool {
        self.message["return_route"] == "all"
    }

    /// A reply on this message's thread: `{"type", "thid", "body"}`. `pack` fills in
    /// the rest of the headers.
    pub fn reply(&self, message_type: &str, body: Value) -> Value {
        let mut reply = json!({"type": message_type, "body": body});
        if let Some(thid) = self.thread_id() {
            reply["thid"] = json!(thid);
        }
        reply
    }

    /// A `report-problem/2.0` reply to this message (`pthid` = this message's thread).
    pub fn problem_report(&self, code: &str, comment: &str, args: &[&str]) -> Value {
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
    dmp: DefaultDIDCommMessaging,
    http: reqwest::Client,
    features: Features,
    pub(crate) mediation: RwLock<Option<Mediation>>,
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
        let dmp = setup_with_key_agreement_kid(identity.key_agreement_key().clone(), &format!("{did}#key-2"));
        Ok(Self {
            identity,
            did,
            dmp,
            http: reqwest::Client::new(),
            features: Features::standard(),
            mediation: RwLock::new(None),
        })
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

    pub fn mediation(&self) -> Option<Mediation> {
        self.mediation.read().expect("mediation lock poisoned").clone()
    }

    /// Pack `message` from [`did`](Self::did) to `to` and POST it to `to`'s HTTP(S)
    /// endpoint (or its mediator's). Returns the reply if the recipient sent one back
    /// on the same connection. `pack` fills in `id`, `from`, `to` and `created_time`.
    pub async fn send(&self, to: &str, message: &Value) -> Result<Option<Received>, AgentError> {
        self.send_as(&self.did(), to, message).await
    }

    /// Like [`send`](Self::send), but asks for the reply on the same connection
    /// (`return_route: "all"`) and requires one. A `problem-report` reply comes back as
    /// [`AgentError::Problem`], and a reply whose `thid` names a different thread as
    /// [`AgentError::UnexpectedReply`] (a reply with no `thid` is accepted: it arrived
    /// on the request's own connection).
    pub async fn request(&self, to: &str, message: &Value) -> Result<Received, AgentError> {
        self.request_as(&self.did(), to, message).await
    }

    /// [`send`](Self::send) from a specific one of this agent's DIDs (e.g.
    /// [`base_did`](Self::base_did) after mediation) rather than [`did`](Self::did).
    pub async fn send_as(&self, from: &str, to: &str, message: &Value) -> Result<Option<Received>, AgentError> {
        let packed = self.dmp.pack(message, to, Some(from)).await?;
        let uri = packed
            .get_endpoint("http")
            .ok_or_else(|| AgentError::NoHttpEndpoint(to.to_string()))?
            .to_string();

        let response = self
            .http
            .post(&uri)
            .header("content-type", "application/didcomm-encrypted+json")
            .body(packed.message)
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
        Ok(Some(self.receive(&body).await?))
    }

    /// [`request`](Self::request) from a specific one of this agent's DIDs.
    pub async fn request_as(&self, from: &str, to: &str, message: &Value) -> Result<Received, AgentError> {
        let mut message = message.clone();
        let headers = message.as_object_mut().ok_or(AgentError::NotAnObject)?;
        headers.entry("return_route").or_insert_with(|| json!("all"));
        // Set here rather than left to `pack`, so the reply's thread can be checked.
        let id = headers
            .entry("id")
            .or_insert_with(|| json!(uuid::Uuid::new_v4().to_string()))
            .as_str()
            .unwrap_or_default()
            .to_string();
        let message_type = headers.get("type").and_then(Value::as_str).unwrap_or_default().to_string();

        let reply = self
            .send_as(from, to, &message)
            .await?
            .ok_or_else(|| AgentError::NoReply { to: to.to_string(), message_type })?;
        if reply.message_type() == PROBLEM_REPORT {
            return Err(AgentError::Problem {
                code: reply.message["body"]["code"].as_str().unwrap_or_default().to_string(),
                comment: reply.message["body"]["comment"].as_str().map(str::to_string),
                report: reply.message,
            });
        }
        if let Some(thid) = reply.message["thid"].as_str() {
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
    pub async fn receive(&self, packed: &[u8]) -> Result<Received, AgentError> {
        let unpacked = self.dmp.unpack(packed).await?;
        Ok(Received {
            message: unpacked.message().map_err(MessagingError::from)?,
            sender: unpacked.sender_kid.as_deref().map(|kid| did_of(kid).to_string()),
            recipient_kid: unpacked.recipient_kid,
        })
    }

    /// The reply this agent gives on its own to the standard protocols it
    /// [supports](Self::features): a `ping-response` to a trust-ping `ping` (unless
    /// `response_requested` is `false`), a `disclose` to a discover-features `queries`.
    /// `None` for anything else.
    pub fn auto_reply(&self, received: &Received) -> Option<Value> {
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
        let to = received.sender.as_deref().ok_or(AgentError::NoReturnAddress)?;
        let from = did_of(&received.recipient_kid);
        Ok(self.dmp.pack_direct(reply, to, Some(from)).await?.message)
    }
}

/// The DID part of a DID or DID URL.
pub(crate) fn did_of(did_or_url: &str) -> &str {
    did_or_url.split('#').next().unwrap_or(did_or_url)
}
