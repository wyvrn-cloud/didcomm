//! Being a mediated recipient: [coordinate-mediation/3.0] to get a routing DID and
//! register this agent's mediated DID with it, and [messagepickup/3.0] to collect
//! what peers sent to that DID.
//!
//! [coordinate-mediation/3.0]: https://didcomm.org/coordinate-mediation/3.0/
//! [messagepickup/3.0]: https://didcomm.org/messagepickup/3.0/

use didcomm_crypto_askar::AskarSecretKey;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::agent::{Agent, AgentError, DidcommVersion, Received};
use crate::v1::{decode_any_base64, normalize_type, verkey_from_key_ref};

pub const MEDIATE_REQUEST: &str = "https://didcomm.org/coordinate-mediation/3.0/mediate-request";
pub const MEDIATE_GRANT: &str = "https://didcomm.org/coordinate-mediation/3.0/mediate-grant";
pub const MEDIATE_DENY: &str = "https://didcomm.org/coordinate-mediation/3.0/mediate-deny";
pub const RECIPIENT_UPDATE: &str = "https://didcomm.org/coordinate-mediation/3.0/recipient-update";
pub const RECIPIENT_UPDATE_RESPONSE: &str = "https://didcomm.org/coordinate-mediation/3.0/recipient-update-response";
pub const DELIVERY_REQUEST: &str = "https://didcomm.org/messagepickup/3.0/delivery-request";
pub const DELIVERY: &str = "https://didcomm.org/messagepickup/3.0/delivery";
pub const STATUS: &str = "https://didcomm.org/messagepickup/3.0/status";
pub const MESSAGES_RECEIVED: &str = "https://didcomm.org/messagepickup/3.0/messages-received";

pub const MEDIATE_REQUEST_V1: &str = "https://didcomm.org/coordinate-mediation/1.0/mediate-request";
pub const MEDIATE_GRANT_V1: &str = "https://didcomm.org/coordinate-mediation/1.0/mediate-grant";
pub const MEDIATE_DENY_V1: &str = "https://didcomm.org/coordinate-mediation/1.0/mediate-deny";
pub const KEYLIST_UPDATE_V1: &str = "https://didcomm.org/coordinate-mediation/1.0/keylist-update";
pub const KEYLIST_UPDATE_RESPONSE_V1: &str = "https://didcomm.org/coordinate-mediation/1.0/keylist-update-response";
pub const DELIVERY_REQUEST_V1: &str = "https://didcomm.org/messagepickup/2.0/delivery-request";
pub const DELIVERY_V1: &str = "https://didcomm.org/messagepickup/2.0/delivery";
pub const STATUS_V1: &str = "https://didcomm.org/messagepickup/2.0/status";
pub const MESSAGES_RECEIVED_V1: &str = "https://didcomm.org/messagepickup/2.0/messages-received";

/// An established mediation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mediation {
    pub mediator_did: String,
    /// What the mediator granted: the DID peers' messages are forwarded through.
    pub routing_did: String,
    /// This agent's DID with `routing_did` as its endpoint -- the one to give peers.
    pub did: String,
}

/// An established DIDComm v1 mediation ([coordinate-mediation/1.0]), over a
/// [connection](crate::connections) with the mediator. Serializable, for keeping across
/// restarts ([`Agent::restore_v1_mediation`]).
///
/// [coordinate-mediation/1.0]: https://github.com/hyperledger/aries-rfcs/tree/main/features/0211-route-coordination
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct V1Mediation {
    /// The connection with the mediator.
    pub connection_id: String,
    /// What the mediator granted: where peers send, and the keys to forward through.
    pub endpoint: String,
    pub routing_keys: Vec<String>,
}

/// What one [`Agent::pickup`] collected.
#[derive(Debug, Default)]
pub struct Pickup {
    pub messages: Vec<Received>,
    /// Delivered messages this agent couldn't unpack, by attachment id, with why. They
    /// are acknowledged anyway: retrying can't make them decryptable, and leaving them
    /// queued would return them on every pickup.
    pub failed: Vec<(String, String)>,
}

impl Agent {
    /// Ask `mediator_did` to mediate for this agent and register this agent's mediated
    /// DID with it. Afterwards [`did`](Agent::did) is the mediated DID. Safe to repeat
    /// on every start: the mediated DID depends only on the identity and the routing DID,
    /// and re-registering an already-registered DID is a no-op.
    pub async fn mediate(&self, mediator_did: &str) -> Result<Mediation, AgentError> {
        let grant = self
            .request_as(self.base_did(), mediator_did, &json!({"type": MEDIATE_REQUEST, "body": {}}))
            .await?;
        match grant.message_type() {
            MEDIATE_GRANT => {}
            MEDIATE_DENY => return Err(AgentError::MediationDenied(mediator_did.to_string())),
            other => return Err(AgentError::UnexpectedReply { expected: MEDIATE_GRANT, got: other.to_string() }),
        }
        let routing_did = grant.message["body"]["routing_did"][0]
            .as_str()
            .ok_or_else(|| AgentError::UnexpectedReply {
                expected: "mediate-grant with body.routing_did",
                got: grant.message["body"].to_string(),
            })?
            .to_string();

        let did = self.identity().did(&routing_did)?;
        self.messaging()
            .secrets
            .add_secret(AskarSecretKey::new(format!("{did}#key-2"), self.identity().key_agreement_key().clone()));

        let update = json!({
            "type": RECIPIENT_UPDATE,
            "body": {"updates": [{"recipient_did": did, "action": "add"}]},
        });
        let response = self.request_as(self.base_did(), mediator_did, &update).await?;
        if response.message_type() != RECIPIENT_UPDATE_RESPONSE {
            return Err(AgentError::UnexpectedReply {
                expected: RECIPIENT_UPDATE_RESPONSE,
                got: response.message_type().to_string(),
            });
        }
        let result = response.message["body"]["updated"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|u| u["recipient_did"] == did.as_str())
            .and_then(|u| u["result"].as_str())
            .unwrap_or("missing from recipient-update-response")
            .to_string();
        if result != "success" && result != "no_change" {
            return Err(AgentError::RecipientUpdateFailed { did, result });
        }

        let mediation = Mediation { mediator_did: mediator_did.to_string(), routing_did, did };
        *self.mediation.write().expect("mediation lock poisoned") = Some(mediation.clone());
        Ok(mediation)
    }

    /// Collect up to `limit` queued messages from the mediator, unpack them, and
    /// acknowledge them so the mediator deletes them.
    pub async fn pickup(&self, limit: usize) -> Result<Pickup, AgentError> {
        let mediation = self.mediation().ok_or(AgentError::NotMediated)?;
        let request = json!({"type": DELIVERY_REQUEST, "body": {"limit": limit.max(1)}});
        let reply = self.request_as(self.base_did(), &mediation.mediator_did, &request).await?;
        match reply.message_type() {
            // The spec's answer to a delivery-request when the queue is empty.
            STATUS => return Ok(Pickup::default()),
            DELIVERY => {}
            other => return Err(AgentError::UnexpectedReply { expected: DELIVERY, got: other.to_string() }),
        }

        let mut pickup = Pickup::default();
        let mut ids = Vec::new();
        for attachment in reply.message["attachments"].as_array().into_iter().flatten() {
            let id = attachment["id"].as_str().unwrap_or_default().to_string();
            let outcome = match attachment_payload(attachment) {
                Some(packed) => self.receive(&packed).await.map(delivered).map_err(|e| e.to_string()),
                None => Err("attachment has neither data.json nor data.base64".to_string()),
            };
            match outcome {
                Ok(received) => pickup.messages.push(received),
                Err(error) => pickup.failed.push((id.clone(), error)),
            }
            if !id.is_empty() {
                ids.push(id);
            }
        }

        if !ids.is_empty() {
            // Asks for the reply on this connection: the mediator answers with a
            // status, which must never be queued for pickup instead.
            let ack = json!({
                "type": MESSAGES_RECEIVED,
                "body": {"message_id_list": ids},
                "return_route": "all",
            });
            self.send_as(self.base_did(), &mediation.mediator_did, &ack).await?;
        }
        Ok(pickup)
    }
}

impl Agent {
    pub fn v1_mediation(&self) -> Option<V1Mediation> {
        self.v1_mediation.read().expect("v1 mediation lock poisoned").clone()
    }

    /// Reinstate a v1 mediation kept from an earlier run (with its connection, see
    /// [`Agent::import_connections`]), instead of asking for it again.
    pub fn restore_v1_mediation(&self, mediation: Option<V1Mediation>) {
        *self.v1_mediation.write().expect("v1 mediation lock poisoned") = mediation;
    }

    /// Ask the peer on `connection` (a completed v1 connection, by id or DID) to mediate
    /// for this agent ([coordinate-mediation/1.0]) and register this agent's verkey with
    /// it. Afterwards [`v1_did`](Agent::v1_did) and [`v1_service`](Agent::v1_service)
    /// name the mediator, so peers can reach this agent without an endpoint of its
    /// own, and [`pickup_v1`](Agent::pickup_v1) collects what they sent. Connections
    /// made before keep the DID they were made with.
    ///
    /// [coordinate-mediation/1.0]: https://github.com/hyperledger/aries-rfcs/tree/main/features/0211-route-coordination
    pub async fn mediate_v1(&self, connection: &str) -> Result<V1Mediation, AgentError> {
        let connection = self
            .connection(connection)
            .filter(|c| c.didcomm_version == DidcommVersion::V1)
            .ok_or_else(|| AgentError::UnknownConnection(connection.to_string()))?;
        let grant = self.request(&connection.id, &json!({"@type": MEDIATE_REQUEST_V1})).await?;
        match normalize_type(grant.message_type()).as_str() {
            MEDIATE_GRANT_V1 => {}
            MEDIATE_DENY_V1 => return Err(AgentError::MediationDenied(connection.id.clone())),
            other => return Err(AgentError::UnexpectedReply { expected: MEDIATE_GRANT_V1, got: other.to_string() }),
        }
        let endpoint = grant.message["endpoint"]
            .as_str()
            .ok_or_else(|| AgentError::UnexpectedReply {
                expected: "mediate-grant with an endpoint",
                got: grant.message.to_string(),
            })?
            .to_string();
        let routing_keys = grant.message["routing_keys"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .map(|k| verkey_from_key_ref(k).ok_or_else(|| AgentError::Key(format!("unusable routing key {k}"))))
            .collect::<Result<Vec<_>, _>>()?;

        let my_key = self.v1_did_key();
        let update = json!({
            "@type": KEYLIST_UPDATE_V1,
            "updates": [{"recipient_key": my_key, "action": "add"}],
        });
        let response = self.request(&connection.id, &update).await?;
        if normalize_type(response.message_type()) != KEYLIST_UPDATE_RESPONSE_V1 {
            return Err(AgentError::UnexpectedReply {
                expected: KEYLIST_UPDATE_RESPONSE_V1,
                got: response.message_type().to_string(),
            });
        }
        let my_verkey = self.v1_verkey();
        let result = response.message["updated"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|u| u["recipient_key"].as_str().and_then(verkey_from_key_ref).as_deref() == Some(my_verkey.as_str()))
            .and_then(|u| u["result"].as_str())
            .unwrap_or("missing from keylist-update-response")
            .to_string();
        if result != "success" && result != "no_change" {
            return Err(AgentError::RecipientUpdateFailed { did: my_key, result });
        }

        let mediation = V1Mediation { connection_id: connection.id, endpoint, routing_keys };
        self.restore_v1_mediation(Some(mediation.clone()));
        Ok(mediation)
    }

    /// Collect up to `limit` messages the v1 mediator queued ([messagepickup/2.0]),
    /// unpack them, and acknowledge them so the mediator deletes them.
    ///
    /// [messagepickup/2.0]: https://github.com/hyperledger/aries-rfcs/tree/main/features/0685-pickup-v2
    pub async fn pickup_v1(&self, limit: usize) -> Result<Pickup, AgentError> {
        let mediation = self.v1_mediation().ok_or(AgentError::NotMediated)?;
        let request = json!({"@type": DELIVERY_REQUEST_V1, "limit": limit.max(1)});
        let reply = self.request(&mediation.connection_id, &request).await?;
        match normalize_type(reply.message_type()).as_str() {
            STATUS_V1 => return Ok(Pickup::default()),
            DELIVERY_V1 => {}
            other => return Err(AgentError::UnexpectedReply { expected: DELIVERY_V1, got: other.to_string() }),
        }

        let mut pickup = Pickup::default();
        let mut ids = Vec::new();
        for attachment in reply.message["~attach"].as_array().into_iter().flatten() {
            let id = attachment["@id"].as_str().unwrap_or_default().to_string();
            let outcome = match attachment_payload(attachment) {
                Some(packed) => self.receive(&packed).await.map(delivered).map_err(|e| e.to_string()),
                None => Err("attachment has neither data.json nor data.base64".to_string()),
            };
            match outcome {
                Ok(received) => pickup.messages.push(received),
                Err(error) => pickup.failed.push((id.clone(), error)),
            }
            if !id.is_empty() {
                ids.push(id);
            }
        }

        if !ids.is_empty() {
            // On this connection, for the same reason as `pickup`'s.
            let ack = json!({
                "@type": MESSAGES_RECEIVED_V1,
                "message_id_list": ids,
                "~transport": {"return_route": "all"},
            });
            self.send(&mediation.connection_id, &ack).await?;
        }
        Ok(pickup)
    }
}

/// A message as picked up: its return-route request is dropped, since it asked for
/// replies on the connection to the mediator, which is long gone -- so
/// [`Agent::respond`] sends replies to the sender's endpoint instead.
fn delivered(mut received: Received) -> Received {
    if let Some(headers) = received.message.as_object_mut() {
        headers.remove("return_route");
        headers.remove("~transport");
    }
    received
}

/// The packed message inside a delivery attachment: `data.json` (a JSON envelope) or
/// `data.base64` (base64url or standard, padded or not).
pub(crate) fn attachment_payload(attachment: &Value) -> Option<Vec<u8>> {
    let data = &attachment["data"];
    if data["json"].is_object() {
        return serde_json::to_vec(&data["json"]).ok();
    }
    decode_any_base64(data["base64"].as_str()?)
}
