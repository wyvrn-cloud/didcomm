//! Diagnoses why DIDComm messages between mediated peers don't arrive.
//!
//! Mediates a diagnostic identity of its own with a mediator, then sends probes and
//! collects whatever comes back through `messagepickup/3.0`, logging each envelope's
//! encoding (JSON JWE, COSE, or the pre-COSE "JWE in a CBOR map" layout) -- which also
//! fingerprints the library version a peer runs. See README.md for the modes and what
//! each one rules in or out.

use std::time::{Duration, Instant};

use base64::Engine;
use didcomm_agent::{Agent, Identity};
use didcomm_core::crypto::Encoding;
use serde_json::{json, Value};

const USAGE: &str = "\
usage: connect-messaging <MODE> [OPTIONS]

modes:
  selftest   send to this diagnostic identity itself (JSON and COSE) and to a DID
             nobody registered; shows the mediator round trip works, and how it
             answers for an unknown recipient
  control    register a second, JSON-first DID of this identity and send to it;
             separates \"accept order\" from \"missing registration\"
  send       send each --target a discover-features query and a profile (asking for
             theirs back), in JSON and in COSE, then poll for replies
  matrix     send each --target (plus this identity's own two DIDs) a basic message
             in every inner/forward encoding combination, its text naming which

options:
  --target NAME=DID   a DID to probe (repeatable; send/matrix)
  --wait SECONDS      how long to poll for replies (default: 120; matrix: 60)
  --identity PATH     where the diagnostic identity's keys are kept, so replies to an
                      earlier run can still be collected (default:
                      connect-messaging.identity.json -- it holds private keys)
  --mediator DID      the mediator to use (default: did:web:mediator.wyvrn.app)
  --name NAME         display name for the profile probes (default: Wyvrn diagnostic)
";

struct Options {
    mode: String,
    targets: Vec<(String, String)>,
    wait: Option<u64>,
    identity: String,
    mediator: String,
    name: String,
}

fn parse_args() -> Result<Options, String> {
    let mut args = std::env::args().skip(1);
    let mode = args.next().ok_or("missing MODE")?;
    match mode.as_str() {
        "selftest" | "control" | "send" | "matrix" => {}
        "-h" | "--help" => return Err(String::new()),
        other => return Err(format!("unknown mode {other}")),
    }
    let mut options = Options {
        mode,
        targets: Vec::new(),
        wait: None,
        identity: "connect-messaging.identity.json".into(),
        mediator: "did:web:mediator.wyvrn.app".into(),
        name: "Wyvrn diagnostic".into(),
    };
    while let Some(flag) = args.next() {
        let mut value = || args.next().ok_or(format!("{flag} needs a value"));
        match flag.as_str() {
            "--target" => {
                let target = value()?;
                let (name, did) = target.split_once('=').ok_or("--target is NAME=DID")?;
                options.targets.push((name.to_string(), did.to_string()));
            }
            "--wait" => options.wait = Some(value()?.parse().map_err(|_| "--wait takes seconds")?),
            "--identity" => options.identity = value()?,
            "--mediator" => options.mediator = value()?,
            "--name" => options.name = value()?,
            "-h" | "--help" => return Err(String::new()),
            other => return Err(format!("unknown option {other}")),
        }
    }
    if matches!(options.mode.as_str(), "send" | "matrix") && options.targets.is_empty() {
        return Err(format!("{} needs at least one --target", options.mode));
    }
    Ok(options)
}

thread_local! { static START: Instant = Instant::now(); }

macro_rules! log {
    ($($t:tt)*) => {
        println!("[{:>7.1}s] {}", START.with(|s| s.elapsed().as_secs_f64()), format!($($t)*))
    };
}

/// The DID a DID URL (`did#key-1`) belongs to.
fn did_of(kid: &str) -> &str {
    kid.split('#').next().unwrap_or(kid)
}

/// A long DID shortened for the log.
fn short(did: &str) -> String {
    if did.len() > 40 {
        format!("{}…", &did[..40])
    } else {
        did.to_string()
    }
}

fn decode_base64(text: &str) -> Option<Vec<u8>> {
    use base64::engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD};
    let trimmed = text.trim_end_matches('=');
    URL_SAFE_NO_PAD
        .decode(trimmed)
        .ok()
        .or_else(|| STANDARD_NO_PAD.decode(trimmed).ok())
}

/// Which envelope layout `packed` is -- and so, for CBOR, which library generation
/// produced it: the pre-COSE layout only ever came from versions before
/// didcomm/v2+cbor became COSE.
fn fingerprint(packed: &[u8]) -> String {
    if didcomm_core::jwe::JweEnvelope::is_legacy_cbor(packed) {
        return "legacy JWE-in-a-CBOR-map (a library from before COSE)".into();
    }
    match packed.first() {
        Some(b'{') => "JSON JWE".into(),
        Some(0xd8) | Some(0x84) => format!(
            "COSE ({})",
            didcomm_core::jwe::peek_typ(packed).unwrap_or_else(|e| e.to_string())
        ),
        Some(byte) => format!("unrecognized (first byte 0x{byte:02x})"),
        None => "empty".into(),
    }
}

struct Probe {
    agent: Agent,
    http: reqwest::Client,
    mediator: String,
    mediator_uri: String,
    /// Names for the DIDs a reply might come from, for the log.
    names: Vec<(String, String)>,
}

impl Probe {
    fn name_of(&self, did: &str) -> String {
        self.names
            .iter()
            .find(|(_, known)| known == did)
            .map(|(name, _)| name.clone())
            .unwrap_or_else(|| short(did))
    }

    async fn post(&self, uri: &str, packed: Vec<u8>) -> Result<String, String> {
        let content_type =
            didcomm_core::jwe::peek_typ(&packed).unwrap_or_else(|_| "application/didcomm-encrypted+json".into());
        let response = self
            .http
            .post(uri)
            .header("content-type", content_type.clone())
            .body(packed)
            .send()
            .await
            .map_err(|e| format!("POST failed: {e}"))?;
        let status = response.status();
        let body = response.bytes().await.unwrap_or_default();
        let detail = format!(
            "HTTP {status} from {uri} (outer envelope {content_type}){}",
            if body.is_empty() {
                String::new()
            } else {
                format!(": {}", String::from_utf8_lossy(&body))
            }
        );
        if status.is_success() {
            Ok(detail)
        } else {
            Err(detail)
        }
    }

    /// `message` to `to` with its plaintext and encryption in `encoding`; the forward
    /// to the mediator is negotiated as usual.
    async fn send(&self, to: &str, message: &Value, encoding: Encoding) -> Result<String, String> {
        let from = self.agent.did();
        let packed = self
            .agent
            .messaging()
            .pack_as(message, to, Some(&from), encoding)
            .await
            .map_err(|e| format!("pack failed: {e}"))?;
        let uri = packed.get_endpoint("http").ok_or("no HTTP endpoint")?.to_string();
        self.post(&uri, packed.message).await
    }

    /// A basic message to `to`: authcrypted in `inner`, wrapped in a routing/2.0
    /// forward anoncrypted to the mediator in `forward` -- both encodings chosen, not
    /// negotiated, so every combination can be tried.
    async fn send_matrix(&self, to: &str, text: &str, inner: Encoding, forward: Encoding) -> Result<String, String> {
        let dmp = self.agent.messaging();
        let from = self.agent.did();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or_default();
        let message = json!({
            "id": uuid::Uuid::new_v4().to_string(),
            "typ": "application/didcomm-plain+json",
            "type": "https://didcomm.org/basicmessage/2.0/message",
            "from": from,
            "to": [to],
            "created_time": now,
            "body": {"content": text},
        });
        let plaintext = didcomm_core::plaintext::encode(&message, inner).map_err(|e| e.to_string())?;
        let packed_inner = dmp
            .packaging
            .pack(
                &dmp.crypto,
                dmp.resolver.as_ref(),
                &dmp.secrets,
                &plaintext,
                &[to],
                Some(&from),
                inner,
            )
            .await
            .map_err(|e| format!("inner pack: {e}"))?;
        let (media_type, data) =
            didcomm_core::plaintext::packed_message_attachment_data(&packed_inner).map_err(|e| e.to_string())?;
        let forward_message = json!({
            "id": uuid::Uuid::new_v4().to_string(),
            "typ": "application/didcomm-plain+json",
            "type": "https://didcomm.org/routing/2.0/forward",
            "to": [self.mediator],
            "created_time": now,
            "body": {"next": to},
            "attachments": [{"id": uuid::Uuid::new_v4().to_string(), "media_type": media_type, "data": data}],
        });
        let forward_plaintext =
            didcomm_core::plaintext::encode(&forward_message, forward).map_err(|e| e.to_string())?;
        let packed = dmp
            .packaging
            .pack(
                &dmp.crypto,
                dmp.resolver.as_ref(),
                &dmp.secrets,
                &forward_plaintext,
                &[self.mediator.as_str()],
                None,
                forward,
            )
            .await
            .map_err(|e| format!("forward pack: {e}"))?;
        self.post(&self.mediator_uri, packed)
            .await
            .map(|detail| format!("{detail}, inner {}", fingerprint(&packed_inner)))
    }

    /// One `messagepickup/3.0` round: collects, unpacks and logs everything queued
    /// for this identity, then acknowledges it. Returns how many messages came.
    async fn pickup(&self) -> usize {
        let request = json!({"type": "https://didcomm.org/messagepickup/3.0/delivery-request", "body": {"limit": 50}});
        let reply = match self
            .agent
            .request_as(self.agent.base_did(), &self.mediator, &request)
            .await
        {
            Ok(reply) => reply,
            Err(error) => {
                log!("pickup failed: {error}");
                return 0;
            }
        };
        if reply.message_type().ends_with("/status") {
            return 0;
        }
        let mut ids = Vec::new();
        let mut count = 0;
        for attachment in reply.message["attachments"].as_array().into_iter().flatten() {
            let id = attachment["id"].as_str().unwrap_or_default().to_string();
            let data = &attachment["data"];
            let packed = if data["json"].is_object() {
                serde_json::to_vec(&data["json"]).ok()
            } else {
                data["base64"]
                    .as_str()
                    .or(data["binary"].as_str())
                    .and_then(decode_base64)
            };
            let Some(packed) = packed else {
                log!("delivery attachment {id} has no payload");
                continue;
            };
            count += 1;
            let envelope = fingerprint(&packed);
            match self.agent.receive(&packed).await {
                Ok(received) => {
                    let from = received
                        .sender
                        .as_deref()
                        .map(|s| self.name_of(did_of(s)))
                        .unwrap_or("nobody (anoncrypt)".into());
                    log!("<<< from {from}, envelope {envelope}");
                    log!("    {}", received.message);
                }
                Err(error) => log!("<<< UNREADABLE (envelope {envelope}): {error}"),
            }
            if !id.is_empty() {
                ids.push(id);
            }
        }
        if !ids.is_empty() {
            let ack = json!({
                "type": "https://didcomm.org/messagepickup/3.0/messages-received",
                "body": {"message_id_list": ids},
                "return_route": "all",
            });
            if let Err(error) = self.agent.send_as(self.agent.base_did(), &self.mediator, &ack).await {
                log!("acknowledging the delivery failed: {error}");
            }
        }
        count
    }

    async fn poll(&self, seconds: u64) {
        log!("polling for replies for {seconds}s...");
        let until = Instant::now() + Duration::from_secs(seconds);
        let mut total = 0;
        loop {
            total += self.pickup().await;
            if Instant::now() >= until {
                break;
            }
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
        log!("done: {total} message(s) received");
    }

    /// A second DID for this identity's keys whose service lists plain didcomm/v2
    /// first -- the order older library versions minted -- registered with the
    /// mediator under this identity.
    async fn json_first_did(&self) -> Result<String, String> {
        let identity = self.agent.identity();
        let did = didcomm_resolver_peer::peer4::generate(
            &[
                (
                    didcomm_resolver_peer::KeyPurpose::Authentication,
                    didcomm_quickstart::authentication_public_multikey(identity.verification_key()).as_str(),
                ),
                (
                    didcomm_resolver_peer::KeyPurpose::KeyAgreement,
                    didcomm_quickstart::key_agreement_public_multikey(identity.key_agreement_key()).as_str(),
                ),
            ],
            &[json!({
                "type": "DIDCommMessaging",
                "serviceEndpoint": {"uri": self.mediator, "accept": ["didcomm/v2", "didcomm/v2+cbor"], "routingKeys": []},
            })],
        )
        .map_err(|e| e.to_string())?;
        self.agent
            .messaging()
            .secrets
            .add_secret(didcomm_crypto_askar::AskarSecretKey::new(
                format!("{did}#key-2"),
                identity.key_agreement_key().clone(),
            ));
        let update = json!({
            "type": "https://didcomm.org/coordinate-mediation/3.0/recipient-update",
            "body": {"updates": [{"recipient_did": did, "action": "add"}]},
        });
        let reply = self
            .agent
            .request_as(self.agent.base_did(), &self.mediator, &update)
            .await
            .map_err(|e| e.to_string())?;
        log!("registered a JSON-first DID: {}", reply.message["body"]["updated"]);
        Ok(did)
    }
}

const ENCODINGS: [(&str, Encoding); 2] = [("JSON", Encoding::Json), ("CBOR", Encoding::Cbor)];

#[tokio::main]
async fn main() {
    let options = match parse_args() {
        Ok(options) => options,
        Err(error) => {
            if !error.is_empty() {
                eprintln!("error: {error}\n");
            }
            eprint!("{USAGE}");
            std::process::exit(2);
        }
    };

    let identity = Identity::load_or_generate(&options.identity).unwrap_or_else(|e| {
        eprintln!("error: cannot load or create {}: {e}", options.identity);
        std::process::exit(1);
    });
    let agent = Agent::new(identity).expect("an agent for the diagnostic identity");
    let mediation = agent.mediate(&options.mediator).await.unwrap_or_else(|e| {
        eprintln!("error: mediation with {} failed: {e}", options.mediator);
        std::process::exit(1);
    });
    let dmp = agent.messaging();
    let mediator_uri = dmp
        .routing
        .resolve_services(dmp.resolver.as_ref(), &options.mediator)
        .await
        .ok()
        .and_then(|services| services.first().map(|s| s.uri.clone()))
        .unwrap_or_else(|| {
            eprintln!("error: {} has no DIDCommMessaging endpoint", options.mediator);
            std::process::exit(1);
        });
    log!(
        "diagnostic identity mediated by {} ({mediator_uri}): {}",
        options.mediator,
        short(&mediation.did)
    );

    let mut names = vec![("this diagnostic".to_string(), mediation.did.clone())];
    names.extend(options.targets.iter().map(|(name, did)| (name.clone(), did.clone())));
    let mut probe = Probe {
        agent,
        http: reqwest::Client::new(),
        mediator: options.mediator.clone(),
        mediator_uri,
        names,
    };

    match options.mode.as_str() {
        "selftest" => {
            let me = probe.agent.did();
            for (label, encoding) in ENCODINGS {
                let message = json!({"type": "https://didcomm.org/basicmessage/2.0/message", "body": {"content": format!("self-test {label}")}});
                log!(">>> self [{label}]: {:?}", probe.send(&me, &message, encoding).await);
            }
            let stranger = Identity::generate()
                .expect("a fresh identity")
                .did(&options.mediator)
                .expect("its DID");
            let message = json!({"type": "https://didcomm.org/basicmessage/2.0/message", "body": {"content": "x"}});
            log!(
                ">>> a DID nobody registered: {:?}",
                probe.send(&stranger, &message, Encoding::Json).await
            );
            log!("    (a 200 here means the mediator's answer says nothing about delivery)");
            tokio::time::sleep(Duration::from_secs(3)).await;
            probe.poll(options.wait.unwrap_or(0)).await;
        }
        "control" => {
            let control = probe.json_first_did().await.unwrap_or_else(|e| {
                eprintln!("error: registering the JSON-first DID failed: {e}");
                std::process::exit(1);
            });
            probe.names.push(("JSON-first control".into(), control.clone()));
            for (label, encoding) in ENCODINGS {
                let message = json!({"type": "https://didcomm.org/basicmessage/2.0/message", "body": {"content": format!("to the JSON-first control, {label}")}});
                log!(
                    ">>> control [{label}]: {:?}",
                    probe.send(&control, &message, encoding).await
                );
            }
            tokio::time::sleep(Duration::from_secs(3)).await;
            probe.poll(options.wait.unwrap_or(0)).await;
        }
        "send" => {
            for (name, did) in &options.targets {
                log!(
                    "--- {name}: the current library would send {:?}",
                    probe.agent.messaging().negotiate_encoding(did).await
                );
                for (label, encoding) in ENCODINGS {
                    let query = json!({
                        "id": uuid::Uuid::new_v4().to_string(),
                        "type": "https://didcomm.org/discover-features/2.0/queries",
                        "body": {"queries": [{"feature-type": "protocol", "match": "*"}]},
                    });
                    match probe.send(did, &query, encoding).await {
                        Ok(detail) => log!(">>> {name} discover-features [{label}] {}: {detail}", query["id"]),
                        Err(error) => log!(">>> {name} discover-features [{label}] {}: FAILED {error}", query["id"]),
                    }
                    let profile = json!({
                        "id": uuid::Uuid::new_v4().to_string(),
                        "type": "https://didcomm.org/user-profile/1.0/profile",
                        "body": {
                            "profile": {
                                "displayName": format!("{} ({label})", options.name),
                                "description": "Test contact from a connectivity diagnostic -- safe to delete",
                            },
                            "send_back_yours": true,
                        },
                    });
                    match probe.send(did, &profile, encoding).await {
                        Ok(detail) => log!(">>> {name} profile [{label}] {}: {detail}", profile["id"]),
                        Err(error) => log!(">>> {name} profile [{label}] {}: FAILED {error}", profile["id"]),
                    }
                }
            }
            probe.poll(options.wait.unwrap_or(120)).await;
        }
        "matrix" => {
            let control = probe.json_first_did().await.unwrap_or_else(|e| {
                eprintln!("error: registering the JSON-first DID failed: {e}");
                std::process::exit(1);
            });
            probe.names.push(("JSON-first control".into(), control.clone()));
            let mut recipients = vec![
                ("this diagnostic".to_string(), probe.agent.did()),
                ("JSON-first control".to_string(), control),
            ];
            recipients.extend(options.targets.iter().cloned());
            for (name, did) in &recipients {
                for (inner_label, inner) in ENCODINGS {
                    for (forward_label, forward) in ENCODINGS {
                        let text = format!("This message was sent over ({inner_label}) ({forward_label} Forward)");
                        match probe.send_matrix(did, &text, inner, forward).await {
                            Ok(detail) => log!(">>> {name}: \"{text}\": {detail}"),
                            Err(error) => log!(">>> {name}: \"{text}\": FAILED {error}"),
                        }
                    }
                }
            }
            probe.poll(options.wait.unwrap_or(60)).await;
        }
        other => {
            eprintln!("error: unknown mode {other}\n");
            eprint!("{USAGE}");
            std::process::exit(2);
        }
    }
}
