//! DIDComm over WebSockets: a persistent connection to an agent (typically this agent's
//! mediator) through its advertised `ws://` / `wss://` service endpoint.
//!
//! Per the DIDComm Messaging spec, each frame carries exactly one packed message, and
//! trust comes from DIDComm encryption, never from the socket. Replies only flow back
//! on the socket when asked for with `return_route: "all"` -- which is what makes
//! [messagepickup/3.0]'s *live mode* work: once enabled, the mediator pushes messages
//! for this agent down the socket as they arrive, instead of queueing them.
//!
//! Built on `reqwest-websocket`, so it uses the same HTTP stack (and proxy settings) as
//! the rest of the agent.
//!
//! [messagepickup/3.0]: https://didcomm.org/messagepickup/3.0/

use std::collections::VecDeque;

use futures_util::{SinkExt, StreamExt};
use reqwest_websocket::{CloseCode, Message, Upgrade, WebSocket};
use serde_json::{json, Value};

use crate::agent::{Agent, AgentError, Received, DEFAULT_TIMEOUT, PROBLEM_REPORT};
use crate::mediation::{DELIVERY, MESSAGES_RECEIVED, STATUS};

pub const LIVE_DELIVERY_CHANGE: &str = "https://didcomm.org/messagepickup/3.0/live-delivery-change";

/// An open WebSocket to one agent. See the [module docs](self).
pub struct WsConnection<'a> {
    agent: &'a Agent,
    to: String,
    socket: WebSocket,
    /// Messages that arrived while waiting for a specific reply, in arrival order.
    pending: VecDeque<Received>,
}

impl Agent {
    /// Open a WebSocket to `to` through the first `ws://` / `wss://` URI among its
    /// DIDComm service endpoints.
    pub async fn connect_websocket(&self, to: &str) -> Result<WsConnection<'_>, AgentError> {
        let dmp = self.messaging();
        let services = dmp
            .routing
            .resolve_services(dmp.resolver.as_ref(), to)
            .await
            .map_err(didcomm_core::messaging::MessagingError::from)?;
        let uri = services
            .iter()
            .map(|s| s.uri.as_str())
            .find(|uri| uri.starts_with("ws://") || uri.starts_with("wss://"))
            .ok_or_else(|| AgentError::NoWebSocketEndpoint(to.to_string()))?
            .to_string();
        // Not the agent's own client: its whole-request timeout would also cap how
        // long the socket may stay open. Only connecting is time-limited here.
        let http = reqwest::Client::builder()
            .connect_timeout(DEFAULT_TIMEOUT)
            .build()
            .map_err(AgentError::Http)?;
        let socket = http
            .get(&uri)
            .upgrade()
            .send()
            .await
            .map_err(|e| AgentError::WebSocket(e.to_string()))?
            .into_websocket()
            .await
            .map_err(|e| AgentError::WebSocket(e.to_string()))?;
        Ok(WsConnection { agent: self, to: to.to_string(), socket, pending: VecDeque::new() })
    }
}

impl WsConnection<'_> {
    /// The DID this connection talks to.
    pub fn peer(&self) -> &str {
        &self.to
    }

    /// Pack `message` (from [`Agent::did_for`]) and send it as one frame. Asks for
    /// replies on this socket (`return_route: "all"`) unless the message says otherwise.
    pub async fn send(&mut self, message: &Value) -> Result<(), AgentError> {
        let mut message = message.clone();
        let headers = message.as_object_mut().ok_or(AgentError::NotAnObject)?;
        headers.entry("return_route").or_insert_with(|| json!("all"));
        let dmp = self.agent.messaging();
        let packed = dmp.pack_direct(&message, &self.to, Some(&self.agent.did_for(&self.to))).await?;
        let frame = match String::from_utf8(packed.message) {
            Ok(json) => Message::Text(json),
            Err(e) => Message::Binary(e.into_bytes().into()),
        };
        self.socket.send(frame).await.map_err(|e| AgentError::WebSocket(e.to_string()))
    }

    /// [`send`](Self::send), then wait for the reply on this socket's thread. Other
    /// messages arriving meanwhile are kept for [`next_message`](Self::next_message).
    /// A `problem-report` reply comes back as [`AgentError::Problem`].
    pub async fn request(&mut self, message: &Value) -> Result<Received, AgentError> {
        let mut message = message.clone();
        let id = message
            .as_object_mut()
            .ok_or(AgentError::NotAnObject)?
            .entry("id")
            .or_insert_with(|| json!(uuid::Uuid::new_v4().to_string()))
            .as_str()
            .unwrap_or_default()
            .to_string();
        let message_type = message["type"].as_str().unwrap_or_default().to_string();
        self.send(&message).await?;
        loop {
            let Some(received) = self.read().await? else {
                return Err(AgentError::NoReply { to: self.to.clone(), message_type });
            };
            let thread = received.message["thid"].as_str().or_else(|| received.message["pthid"].as_str());
            if thread != Some(id.as_str()) {
                self.pending.push_back(received);
                continue;
            }
            if received.message_type() == PROBLEM_REPORT {
                return Err(AgentError::Problem {
                    code: received.message["body"]["code"].as_str().unwrap_or_default().to_string(),
                    comment: received.message["body"]["comment"].as_str().map(str::to_string),
                    report: received.message,
                });
            }
            return Ok(received);
        }
    }

    /// Ask the mediator to push this agent's messages down this socket as they arrive
    /// (messagepickup/3.0 live mode). Returns the mediator's `status` reply. Messages
    /// already queued stay queued: collect them with [`Agent::pickup`].
    pub async fn enable_live_delivery(&mut self) -> Result<Received, AgentError> {
        let reply = self
            .request(&json!({"type": LIVE_DELIVERY_CHANGE, "body": {"live_delivery": true}}))
            .await?;
        if reply.message_type() != STATUS {
            return Err(AgentError::UnexpectedReply { expected: STATUS, got: reply.message_type().to_string() });
        }
        Ok(reply)
    }

    /// The next message from the socket (or one held back by [`request`](Self::request)),
    /// unpacked; `None` once the connection is closed. A messagepickup `delivery` is
    /// opened up: its attachments come out one by one, and are acknowledged with
    /// `messages-received`.
    pub async fn next_message(&mut self) -> Result<Option<Received>, AgentError> {
        loop {
            if let Some(received) = self.pending.pop_front() {
                return Ok(Some(received));
            }
            let Some(received) = self.read().await? else {
                return Ok(None);
            };
            if received.message_type() != DELIVERY {
                return Ok(Some(received));
            }
            let mut ids = Vec::new();
            for attachment in received.message["attachments"].as_array().into_iter().flatten() {
                if let Some(id) = attachment["id"].as_str() {
                    ids.push(id.to_string());
                }
                if let Some(packed) = crate::mediation::attachment_payload(attachment) {
                    self.pending.push_back(self.agent.receive(&packed).await?);
                }
            }
            if !ids.is_empty() {
                self.send(&json!({"type": MESSAGES_RECEIVED, "body": {"message_id_list": ids}})).await?;
            }
        }
    }

    /// Close the connection.
    pub async fn close(self) -> Result<(), AgentError> {
        self.socket.close(CloseCode::Normal, None).await.map_err(|e| AgentError::WebSocket(e.to_string()))
    }

    /// Read frames until one unpacks to a message; `None` once closed.
    async fn read(&mut self) -> Result<Option<Received>, AgentError> {
        while let Some(frame) = self.socket.next().await {
            let packed = match frame.map_err(|e| AgentError::WebSocket(e.to_string()))? {
                Message::Text(text) => text.into_bytes(),
                Message::Binary(bytes) => bytes.to_vec(),
                Message::Close { .. } => return Ok(None),
                _ => continue, // pings / pongs
            };
            return Ok(Some(self.agent.receive(&packed).await?));
        }
        Ok(None)
    }
}
