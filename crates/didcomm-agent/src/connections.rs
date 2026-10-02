//! Connections: [out-of-band] invitations and the [DID Exchange] handshake they name,
//! in both roles.
//!
//! - Invitee/requester: [`Agent::accept_invitation`] takes an OOB 1.x invitation (or
//!   an invitation URL, see [`Agent::fetch_invitation`]), sends a DID Exchange
//!   `request` to the inviter's service, processes the `response` (on the same
//!   connection, or later through [`Agent::handle_connection_message`]) and sends
//!   `complete`. An OOB 2.0 invitation needs no handshake: its `from` DID is the
//!   connection.
//! - Inviter/responder: [`Agent::create_invitation`], then
//!   [`Agent::handle_connection_message`] answers each `request` with a `response`
//!   and marks the connection completed on `complete` (or on any later message).
//!
//! DID Exchange 1.1 is preferred, 1.0 accepted. This agent presents its one
//! [v1 DID](Agent::v1_did) on every connection.
//!
//! [out-of-band]: https://github.com/hyperledger/aries-rfcs/tree/main/features/0434-outofband
//! [DID Exchange]: https://github.com/hyperledger/aries-rfcs/tree/main/features/0023-did-exchange

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::agent::{Agent, AgentError, DidcommVersion, Received};
use crate::v1::{normalize_type, verify_attachment, V1Service};

pub const OOB_1_0_INVITATION: &str = "https://didcomm.org/out-of-band/1.0/invitation";
pub const OOB_1_1_INVITATION: &str = "https://didcomm.org/out-of-band/1.1/invitation";
pub const OOB_2_0_INVITATION: &str = "https://didcomm.org/out-of-band/2.0/invitation";
pub const DIDEXCHANGE_1_0: &str = "https://didcomm.org/didexchange/1.0";
pub const DIDEXCHANGE_1_1: &str = "https://didcomm.org/didexchange/1.1";

/// Where a connection's handshake is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ConnectionState {
    /// Requester: `request` sent, waiting for the `response`.
    RequestSent,
    /// Requester: `response` processed, but `complete` couldn't be delivered.
    ResponseReceived,
    /// Responder: `response` sent, waiting for `complete` (or any message).
    ResponseSent,
    Completed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ConnectionRole {
    /// Accepted the peer's invitation.
    Requester,
    /// Invited the peer.
    Responder,
}

/// A connection to a peer. Serializable, for keeping across restarts
/// ([`Agent::export_connections`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Connection {
    /// The handshake's thread id (the DID Exchange `request`'s `@id`), or the OOB 2.0
    /// invitation's `id`.
    pub id: String,
    pub state: ConnectionState,
    pub role: ConnectionRole,
    pub didcomm_version: DidcommVersion,
    /// The handshake protocol, e.g. `https://didcomm.org/didexchange/1.1`; `None` for
    /// an OOB 2.0 connection.
    pub protocol: Option<String>,
    pub invitation_id: Option<String>,
    pub their_label: Option<String>,
    pub their_did: Option<String>,
    /// How to reach the peer over v1: from its DID once known, the invitation's
    /// service before that.
    pub their_service: Option<V1Service>,
    pub my_did: String,
    /// Requester: the key the inviter's invitation named, which signs its new DID.
    pub invitation_key: Option<String>,
}

/// Everything [`Agent`] keeps about connections: the connections, and the ids of the
/// invitations it created (which stay usable for any number of requests).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectionBook {
    pub connections: Vec<Connection>,
    pub invitations: Vec<String>,
}

impl Agent {
    pub fn connections(&self) -> Vec<Connection> {
        self.book().connections.clone()
    }

    /// A connection by id, or by the peer's DID.
    pub fn connection(&self, id_or_did: &str) -> Option<Connection> {
        let book = self.book();
        book.connections
            .iter()
            .find(|c| c.id == id_or_did)
            .or_else(|| book.connections.iter().find(|c| c.their_did.as_deref() == Some(id_or_did)))
            .cloned()
    }

    /// The connection whose peer uses `verkey`.
    pub fn connection_by_key(&self, verkey: &str) -> Option<Connection> {
        self.book()
            .connections
            .iter()
            .find(|c| c.their_service.as_ref().is_some_and(|s| s.recipient_keys.iter().any(|k| k == verkey)))
            .cloned()
    }

    /// Everything to persist to keep connections (and created invitations) across
    /// restarts; restore it with [`import_connections`](Self::import_connections).
    pub fn export_connections(&self) -> ConnectionBook {
        self.book().clone()
    }

    pub fn import_connections(&self, book: ConnectionBook) {
        *self.connections.write().expect("connections lock poisoned") = book;
    }

    /// Drop a connection; `false` if there was none with that id.
    pub fn forget_connection(&self, id: &str) -> bool {
        let mut book = self.connections.write().expect("connections lock poisoned");
        let before = book.connections.len();
        book.connections.retain(|c| c.id != id);
        book.connections.len() != before
    }

    fn book(&self) -> std::sync::RwLockReadGuard<'_, ConnectionBook> {
        self.connections.read().expect("connections lock poisoned")
    }

    fn save_connection(&self, connection: &Connection) {
        let mut book = self.connections.write().expect("connections lock poisoned");
        match book.connections.iter_mut().find(|c| c.id == connection.id) {
            Some(existing) => *existing = connection.clone(),
            None => book.connections.push(connection.clone()),
        }
    }

    /// A responder's handshake completes with `complete`, or with any other message
    /// from the peer (RFC 0023).
    pub(crate) fn note_activity(&self, received: &Received) {
        let Some(key) = received.sender_key.as_deref() else { return };
        if let Some(mut connection) = self.connection_by_key(key) {
            if connection.state == ConnectionState::ResponseSent {
                connection.state = ConnectionState::Completed;
                self.save_connection(&connection);
            }
        }
    }

    /// The v1 service to send to for `to`: a connection's (by id or the peer's DID),
    /// or the v1 service in `to`'s resolved DID document.
    pub async fn v1_service_for(&self, to: &str) -> Result<V1Service, AgentError> {
        if let Some(connection) = self.connection(to) {
            return connection.their_service.ok_or_else(|| AgentError::NoV1Service(to.to_string()));
        }
        if to.starts_with("did:") {
            return self.resolve_v1_service(to).await;
        }
        Err(AgentError::UnknownConnection(to.to_string()))
    }

    /// An OOB 1.1 invitation to connect with this agent through DID Exchange (1.1 or
    /// 1.0), with an inline service for [`v1_service`](Self::v1_service). Needs an
    /// address peers can send to ([`v1_reachable`](Self::v1_reachable)). Any number
    /// of peers can accept it.
    pub fn create_invitation(&self, label: &str) -> Result<Value, AgentError> {
        if !self.v1_reachable() {
            return Err(AgentError::NotReachable);
        }
        let service = self.v1_service();
        let did_key_url = |verkey: &str| {
            let did = crate::v1::verkey_to_did_key(verkey)?;
            let fragment = did.trim_start_matches("did:key:").to_string();
            Ok::<_, AgentError>(format!("{did}#{fragment}"))
        };
        let id = uuid::Uuid::new_v4().to_string();
        let invitation = json!({
            "@type": OOB_1_1_INVITATION,
            "@id": id,
            "label": label,
            "handshake_protocols": [DIDEXCHANGE_1_1, DIDEXCHANGE_1_0],
            "accept": ["didcomm/aip1", "didcomm/aip2;env=rfc19"],
            "services": [{
                "id": "#inline",
                "type": "did-communication",
                "recipientKeys": service.recipient_keys.iter().map(|k| did_key_url(k)).collect::<Result<Vec<_>, _>>()?,
                "routingKeys": service.routing_keys.iter().map(|k| did_key_url(k)).collect::<Result<Vec<_>, _>>()?,
                "serviceEndpoint": service.endpoint,
            }],
        });
        self.connections.write().expect("connections lock poisoned").invitations.push(id);
        Ok(invitation)
    }

    /// An invitation as a URL: `base` with the invitation in its `oob` parameter.
    pub fn invitation_url(base: &str, invitation: &Value) -> String {
        let separator = if base.contains('?') { '&' } else { '?' };
        format!("{base}{separator}oob={}", didcomm_multiformats::multibase::encode(invitation.to_string()))
    }

    /// An invitation from text: invitation JSON, an invitation URL (`oob`, `c_i` or
    /// `_oob` parameter), or a short URL that redirects to one or answers with the
    /// invitation's JSON.
    pub async fn fetch_invitation(&self, text: &str) -> Result<Value, AgentError> {
        if let Some(invitation) = parse_invitation(text) {
            return Ok(invitation);
        }
        let text = text.trim();
        if !text.starts_with("http") {
            return Err(AgentError::Invitation("neither invitation JSON nor an invitation URL".into()));
        }
        let response = self.http().get(text).header("accept", "application/json").send().await?;
        let final_url = response.url().to_string();
        let body = response.text().await?;
        parse_invitation(&final_url)
            .or_else(|| parse_invitation(&body))
            .ok_or_else(|| AgentError::Invitation(format!("{text} led to no invitation")))
    }

    /// Connect through an invitation: DID Exchange for an OOB 1.x invitation (see the
    /// [module docs](self)), the inviter's `from` DID for an OOB 2.0 one. `label` is
    /// how this agent introduces itself. If the inviter answers the request on the same
    /// connection, the returned connection is already completed; otherwise its
    /// response arrives later (pass it to
    /// [`handle_connection_message`](Self::handle_connection_message)).
    pub async fn accept_invitation(&self, invitation: &Value, label: &str) -> Result<Connection, AgentError> {
        let invitation_type = invitation["@type"].as_str().or(invitation["type"].as_str()).unwrap_or_default();
        let invitation_type = normalize_type(invitation_type);
        let invitation_id = invitation["@id"].as_str().or(invitation["id"].as_str()).map(str::to_string);

        if invitation_type == OOB_2_0_INVITATION {
            let from = invitation["from"]
                .as_str()
                .ok_or_else(|| AgentError::Invitation("OOB 2.0 invitation without from".into()))?;
            let connection = Connection {
                id: invitation_id.clone().unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
                state: ConnectionState::Completed,
                role: ConnectionRole::Requester,
                didcomm_version: DidcommVersion::V2,
                protocol: None,
                invitation_id,
                their_label: invitation["body"]["label"].as_str().map(str::to_string),
                their_did: Some(from.to_string()),
                their_service: None,
                my_did: self.did(),
                invitation_key: None,
            };
            self.save_connection(&connection);
            return Ok(connection);
        }
        if !invitation_type.starts_with("https://didcomm.org/out-of-band/1.") {
            return Err(AgentError::Invitation(format!(
                "unsupported invitation type {invitation_type:?} (connections/1.0 invitations aren't supported; \
                 ask for an out-of-band invitation)"
            )));
        }
        let invitation_id = invitation_id.ok_or_else(|| AgentError::Invitation("invitation without @id".into()))?;
        let offered: Vec<String> = invitation["handshake_protocols"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .map(|p| normalize_type(p.trim_end_matches('/')))
            .collect();
        let protocol = [DIDEXCHANGE_1_1, DIDEXCHANGE_1_0]
            .into_iter()
            .find(|p| offered.iter().any(|o| o == p))
            .ok_or_else(|| AgentError::Invitation(format!("no DID Exchange among handshake_protocols {offered:?}")))?;

        let service = match invitation["services"].as_array().and_then(|s| s.first()) {
            Some(Value::String(did)) => self.resolve_v1_service(did).await?,
            Some(inline @ Value::Object(_)) => {
                let mut inline = inline.clone();
                inline.as_object_mut().expect("matched an object").entry("type").or_insert(json!("did-communication"));
                self.v1_service_of_doc(&json!({"id": invitation_id, "service": [inline]})).await?
            }
            _ => return Err(AgentError::Invitation("invitation has no services".into())),
        };

        let my_did = self.v1_did();
        let thid = uuid::Uuid::new_v4().to_string();
        let mut request = json!({
            "@type": format!("{protocol}/request"),
            "@id": thid,
            "~thread": {"thid": thid, "pthid": invitation_id},
            "label": label,
            "did": my_did,
        });
        if protocol == DIDEXCHANGE_1_0 {
            request["did_doc~attach"] = self.signed_attachment(self.own_v1_doc().to_string().as_bytes(), "application/json");
        }
        // Without an address of its own, this agent can only get the response back on
        // this connection.
        request["~transport"] = json!({"return_route": "all"});

        let connection = Connection {
            id: thid.clone(),
            state: ConnectionState::RequestSent,
            role: ConnectionRole::Requester,
            didcomm_version: DidcommVersion::V1,
            protocol: Some(protocol.to_string()),
            invitation_id: Some(invitation_id),
            their_label: invitation["label"].as_str().map(str::to_string),
            their_did: None,
            invitation_key: service.recipient_keys.first().cloned(),
            their_service: Some(service.clone()),
            my_did,
        };
        self.save_connection(&connection);

        if let Some(reply) = self.send_v1(&service, &request).await? {
            if reply.is_problem_report() {
                self.forget_connection(&thid);
                return Err(reply.into_problem());
            }
            self.handle_connection_message(&reply).await?;
        }
        Ok(self.connection(&thid).unwrap_or(connection))
    }

    /// Whether `received` belongs to DID Exchange (and so to
    /// [`handle_connection_message`](Self::handle_connection_message)).
    pub fn is_connection_message(received: &Received) -> bool {
        let message_type = normalize_type(received.message_type());
        [DIDEXCHANGE_1_0, DIDEXCHANGE_1_1]
            .iter()
            .any(|p| message_type.strip_prefix(p).is_some_and(|rest| rest.starts_with('/')))
    }

    /// Take a DID Exchange message one step further: answer a `request` to one of this
    /// agent's invitations (returns the `response`, to deliver with
    /// [`respond`](Self::respond)), process a `response` (sends `complete`), or record
    /// a `complete` or `problem_report`. `Ok(None)` when there's nothing to send back,
    /// including for messages that aren't DID Exchange.
    pub async fn handle_connection_message(&self, received: &Received) -> Result<Option<Value>, AgentError> {
        if !Self::is_connection_message(received) {
            return Ok(None);
        }
        let message_type = normalize_type(received.message_type());
        let (protocol, name) = message_type.rsplit_once('/').expect("a DID Exchange type has a message name");
        let message = &received.message;
        let thid = message["~thread"]["thid"].as_str().or(message["@id"].as_str()).unwrap_or_default().to_string();
        match name {
            "request" => self.answer_request(received, protocol, &thid).await,
            "response" => {
                self.process_response(received, protocol, &thid).await?;
                Ok(None)
            }
            "complete" => {
                if let Some(mut connection) = self.connection(&thid) {
                    connection.state = ConnectionState::Completed;
                    self.save_connection(&connection);
                }
                Ok(None)
            }
            "problem_report" => {
                self.forget_connection(&thid);
                Ok(None)
            }
            _ => Ok(None),
        }
    }

    async fn answer_request(&self, received: &Received, protocol: &str, thid: &str) -> Result<Option<Value>, AgentError> {
        let message = &received.message;
        let pthid = message["~thread"]["pthid"].as_str().unwrap_or_default().to_string();
        if !self.book().invitations.contains(&pthid) {
            return Ok(Some(problem(protocol, thid, &pthid, "request_not_accepted", "No such invitation")));
        }
        let their_did = message["did"].as_str().map(str::to_string);
        let doc = match (&message["did_doc~attach"], &their_did) {
            (attachment @ Value::Object(_), _) => attached_doc(attachment)?,
            (_, Some(did)) => self
                .v1_messaging()
                .resolver
                .resolve(did)
                .await
                .map_err(|e| AgentError::Resolution(e.to_string()))?,
            _ => return Ok(Some(problem(protocol, thid, &pthid, "request_not_accepted", "No DID in request"))),
        };
        let their_service = self.v1_service_of_doc(&doc).await?;

        let my_did = self.v1_did();
        let mut response = json!({
            "@type": format!("{protocol}/response"),
            "@id": uuid::Uuid::new_v4().to_string(),
            "~thread": {"thid": thid, "pthid": pthid},
            "did": my_did,
        });
        if protocol == DIDEXCHANGE_1_1 {
            response["did_rotate~attach"] = self.signed_attachment(my_did.as_bytes(), "text/string");
        } else {
            response["did_doc~attach"] = self.signed_attachment(self.own_v1_doc().to_string().as_bytes(), "application/json");
        }
        self.save_connection(&Connection {
            id: thid.to_string(),
            state: ConnectionState::ResponseSent,
            role: ConnectionRole::Responder,
            didcomm_version: DidcommVersion::V1,
            protocol: Some(protocol.to_string()),
            invitation_id: Some(pthid),
            their_label: message["label"].as_str().map(str::to_string),
            their_did: their_did.or_else(|| doc["id"].as_str().map(str::to_string)),
            their_service: Some(their_service),
            my_did,
            invitation_key: Some(self.v1_verkey()),
        });
        Ok(Some(response))
    }

    async fn process_response(&self, received: &Received, protocol: &str, thid: &str) -> Result<(), AgentError> {
        let message = &received.message;
        let mut connection = self
            .connection(thid)
            .filter(|c| c.role == ConnectionRole::Requester)
            .ok_or_else(|| AgentError::UnknownConnection(thid.to_string()))?;
        let their_did = message["did"].as_str().map(str::to_string);

        if let (Value::Object(_), Some(did)) = (&message["did_rotate~attach"], &their_did) {
            let (signed, _) = verify_attachment(&message["did_rotate~attach"], connection.invitation_key.as_deref())?;
            if signed != did.as_bytes() {
                return Err(AgentError::Attachment("did_rotate~attach doesn't sign the response's did".into()));
            }
        }
        let doc = match (&message["did_doc~attach"], &their_did) {
            (attachment @ Value::Object(_), _) => attached_doc(attachment)?,
            (_, Some(did)) => self
                .v1_messaging()
                .resolver
                .resolve(did)
                .await
                .map_err(|e| AgentError::Resolution(e.to_string()))?,
            _ => return Err(AgentError::Connection("response names no DID".into())),
        };
        let service = self.v1_service_of_doc(&doc).await?;
        connection.their_did = their_did.or_else(|| doc["id"].as_str().map(str::to_string));
        connection.their_service = Some(service.clone());
        connection.state = ConnectionState::ResponseReceived;
        self.save_connection(&connection);

        let complete = json!({
            "@type": format!("{protocol}/complete"),
            "@id": uuid::Uuid::new_v4().to_string(),
            "~thread": {"thid": thid, "pthid": connection.invitation_id},
        });
        self.send_v1(&service, &complete).await?;
        connection.state = ConnectionState::Completed;
        self.save_connection(&connection);
        Ok(())
    }

    /// This agent's v1 DID document, for `did_doc~attach`.
    fn own_v1_doc(&self) -> Value {
        let did = self.v1_did();
        didcomm_resolver_peer::peer2::resolve(&did).expect("the agent's own did:peer:2 resolves")
    }
}

/// An invitation from text that needs no network: invitation JSON (plain or base64), or
/// a URL with the invitation in an `oob`, `c_i`, `_oob` or `d_m` parameter.
pub fn parse_invitation(text: &str) -> Option<Value> {
    let text = text.trim();
    let is_invitation = |v: &Value| v["@type"].is_string() || v["type"].is_string();
    if let Ok(value) = serde_json::from_str::<Value>(text) {
        return is_invitation(&value).then_some(value);
    }
    let query = text.split_once('?').map(|(_, q)| q).unwrap_or(text);
    let query = query.split('#').next().unwrap_or(query);
    for pair in query.split('&') {
        let (name, value) = pair.split_once('=').unwrap_or(("", pair));
        if !(name.is_empty() || matches!(name, "oob" | "c_i" | "_oob" | "d_m")) {
            continue;
        }
        let value = percent_decode(value);
        let decoded = crate::v1::decode_any_base64(&value)?;
        if let Ok(invitation) = serde_json::from_slice::<Value>(&decoded) {
            if is_invitation(&invitation) {
                return Some(invitation);
            }
        }
    }
    None
}

fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).ok();
            if let Some(byte) = hex.and_then(|h| u8::from_str_radix(h, 16).ok()) {
                out.push(byte);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// A DID document from a (signed or unsigned) `did_doc~attach`.
fn attached_doc(attachment: &Value) -> Result<Value, AgentError> {
    let (bytes, _) = verify_attachment(attachment, None)?;
    serde_json::from_slice(&bytes).map_err(|e| AgentError::Attachment(format!("did_doc~attach isn't JSON: {e}")))
}

/// A DID Exchange `problem_report`.
fn problem(protocol: &str, thid: &str, pthid: &str, code: &str, explain: &str) -> Value {
    json!({
        "@type": format!("{protocol}/problem_report"),
        "@id": uuid::Uuid::new_v4().to_string(),
        "~thread": {"thid": thid, "pthid": pthid},
        "description": {"code": code, "en": explain},
        "problem-code": code,
        "explain": explain,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invitations_parse_from_json_and_urls() {
        let invitation = json!({"@type": OOB_1_1_INVITATION, "@id": "inv-1"});
        assert_eq!(parse_invitation(&invitation.to_string()), Some(invitation.clone()));

        let url = Agent::invitation_url("https://example.com/invite", &invitation);
        assert_eq!(parse_invitation(&url), Some(invitation.clone()));

        // Legacy c_i, standard (padded) base64, percent-encoded padding.
        let b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, invitation.to_string());
        let url = format!("https://example.com/?c_i={}", b64.replace('=', "%3D"));
        assert_eq!(parse_invitation(&url), Some(invitation));

        assert_eq!(parse_invitation("https://example.com/?foo=bar"), None);
    }
}
