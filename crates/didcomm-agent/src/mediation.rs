//! Being a mediated recipient: [coordinate-mediation/3.0] to get a routing DID and
//! register this agent's mediated DID with it, and [messagepickup/3.0] to collect
//! what peers sent to that DID.
//!
//! [coordinate-mediation/3.0]: https://didcomm.org/coordinate-mediation/3.0/
//! [messagepickup/3.0]: https://didcomm.org/messagepickup/3.0/

use didcomm_crypto_askar::AskarSecretKey;
use serde_json::{json, Value};

use crate::agent::{Agent, AgentError, Received};

pub const MEDIATE_REQUEST: &str = "https://didcomm.org/coordinate-mediation/3.0/mediate-request";
pub const MEDIATE_GRANT: &str = "https://didcomm.org/coordinate-mediation/3.0/mediate-grant";
pub const MEDIATE_DENY: &str = "https://didcomm.org/coordinate-mediation/3.0/mediate-deny";
pub const RECIPIENT_UPDATE: &str = "https://didcomm.org/coordinate-mediation/3.0/recipient-update";
pub const RECIPIENT_UPDATE_RESPONSE: &str = "https://didcomm.org/coordinate-mediation/3.0/recipient-update-response";
pub const DELIVERY_REQUEST: &str = "https://didcomm.org/messagepickup/3.0/delivery-request";
pub const DELIVERY: &str = "https://didcomm.org/messagepickup/3.0/delivery";
pub const STATUS: &str = "https://didcomm.org/messagepickup/3.0/status";
pub const MESSAGES_RECEIVED: &str = "https://didcomm.org/messagepickup/3.0/messages-received";

/// An established mediation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mediation {
    pub mediator_did: String,
    /// What the mediator granted: the DID peers' messages are forwarded through.
    pub routing_did: String,
    /// This agent's DID with `routing_did` as its endpoint -- the one to give peers.
    pub did: String,
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
                Some(packed) => self.receive(&packed).await.map_err(|e| e.to_string()),
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

/// The packed message inside a delivery attachment: `data.json` (a JSON envelope) or
/// `data.base64` (base64url, padded or not).
pub(crate) fn attachment_payload(attachment: &Value) -> Option<Vec<u8>> {
    let data = &attachment["data"];
    if data["json"].is_object() {
        return serde_json::to_vec(&data["json"]).ok();
    }
    let b64 = data["base64"].as_str()?.trim_end_matches('=');
    didcomm_multiformats::multibase::decode(b64).ok()
}
