//! A line-oriented interop peer: drives this workspace's real pack/unpack code from
//! another process, so another implementation's test harness can exchange messages with
//! it in both directions. See `fixtures/python-interop/` for the Python driver
//! (didcomm-messaging-python) that uses it.
//!
//! One JSON request per stdin line, one JSON response per stdout line:
//!
//! - `{"op":"setup","docs":{did: doc},"actors":{name:{"secrets":[{"kid","jwk"}],"signing":[{"kid","jwk"}]}}}`
//!   adds DID documents (shared by every actor, like a resolver) and actors' keys.
//! - `{"op":"pack","as":name,"message":{…},"to":did,"frm":did|null,"mode":"negotiate"|"json"|"direct"|"signed","signer":kid?}`
//!   -> `{"packed": text | null, "packed_b64": base64url, "encoding": "json"|"cbor"}`.
//! - `{"op":"unpack","as":name,"packed_b64":…}` -> the unpack result.
//! - `{"op":"v1_pack","to_verkeys":[b58…],"from_seed_hex":hex|null,"message":{…}}`,
//!   `{"op":"v1_unpack","seeds_hex":[hex…],"packed_b64":…}`: DIDComm v1 (RFC 0019).
//!
//! Errors come back as `{"ok":false,"error":"…"}`; the peer keeps running.

use std::collections::HashMap;
use std::io::{BufRead, Write};

use askar_crypto::alg::ed25519::Ed25519KeyPair;
use askar_crypto::jwk::FromJwk;
use askar_crypto::repr::{KeyPublicBytes, KeySecretBytes};
use async_trait::async_trait;
use didcomm_core::crypto::Encoding;
use didcomm_core::messaging::DIDCommMessaging;
use didcomm_core::resolver::{DIDResolver, ResolutionError};
use didcomm_core::secrets::InMemorySecretsManager;
use didcomm_crypto_askar::{AgreementKey, AskarCryptoService, AskarSecretKey, AskarSigningKey};
use didcomm_multiformats::multibase;
use didcomm_v1::packaging::{V1PackagingService, V1SecretKey};
use serde_json::{json, Value};

struct StaticResolver(HashMap<String, Value>);

#[async_trait]
impl DIDResolver for StaticResolver {
    async fn resolve(&self, did: &str) -> Result<Value, ResolutionError> {
        self.0.get(did).cloned().ok_or_else(|| ResolutionError::Resolution(format!("not found: {did}")))
    }

    async fn is_resolvable(&self, did: &str) -> bool {
        self.0.contains_key(did)
    }
}

#[derive(Default)]
struct Actor {
    secrets: Vec<(String, Value)>,
    signing: HashMap<String, Value>,
}

#[derive(Default)]
struct State {
    docs: HashMap<String, Value>,
    actors: HashMap<String, Actor>,
}

type Dmp = DIDCommMessaging<AskarCryptoService, InMemorySecretsManager<AskarSecretKey>>;

impl State {
    fn dmp(&self, actor: &str) -> Result<Dmp, String> {
        let actor = self.actors.get(actor).ok_or(format!("unknown actor {actor}"))?;
        let secrets = InMemorySecretsManager::<AskarSecretKey>::new();
        for (kid, jwk) in &actor.secrets {
            secrets.add_secret(AskarSecretKey::new(kid.clone(), AgreementKey::from_jwk(jwk).map_err(|e| e.to_string())?));
        }
        // Default header policy, as real callers use it: pack completes id/from/to/
        // created_time, and unpack checks what arrives.
        Ok(DIDCommMessaging::new(AskarCryptoService, secrets, Box::new(StaticResolver(self.docs.clone()))))
    }
}

fn str_field<'a>(req: &'a Value, key: &str) -> Result<&'a str, String> {
    req[key].as_str().ok_or(format!("missing {key}"))
}

fn packed_bytes(req: &Value) -> Result<Vec<u8>, String> {
    if let Some(text) = req["packed"].as_str() {
        return Ok(text.as_bytes().to_vec());
    }
    multibase::decode(str_field(req, "packed_b64")?).map_err(|e| e.to_string())
}

fn packed_response(bytes: &[u8]) -> Value {
    let encoding = match Encoding::detect(bytes) {
        Ok(Encoding::Json) => "json",
        Ok(Encoding::Cbor) => "cbor",
        Err(_) => "unknown",
    };
    json!({
        "packed": if encoding == "json" { String::from_utf8(bytes.to_vec()).ok() } else { None },
        "packed_b64": multibase::encode(bytes),
        "encoding": encoding,
    })
}

fn ed25519_from_seed_hex(hex: &str) -> Result<Ed25519KeyPair, String> {
    let bytes: Vec<u8> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect::<Result<_, _>>()?;
    Ed25519KeyPair::from_secret_bytes(&bytes).map_err(|e| e.to_string())
}

async fn handle(state: &mut State, req: &Value) -> Result<Value, String> {
    match str_field(req, "op")? {
        "setup" => {
            if let Some(docs) = req["docs"].as_object() {
                for (did, doc) in docs {
                    state.docs.insert(did.clone(), doc.clone());
                }
            }
            if let Some(actors) = req["actors"].as_object() {
                for (name, spec) in actors {
                    let actor = state.actors.entry(name.clone()).or_default();
                    for s in spec["secrets"].as_array().into_iter().flatten() {
                        actor.secrets.push((str_field(s, "kid")?.to_string(), s["jwk"].clone()));
                    }
                    for s in spec["signing"].as_array().into_iter().flatten() {
                        actor.signing.insert(str_field(s, "kid")?.to_string(), s["jwk"].clone());
                    }
                }
            }
            Ok(json!({}))
        }
        "pack" => {
            let actor = str_field(req, "as")?;
            let dmp = state.dmp(actor)?;
            let (message, to, frm) = (&req["message"], str_field(req, "to")?, req["frm"].as_str());
            let result = match req["mode"].as_str().unwrap_or("negotiate") {
                "negotiate" => dmp.pack(message, to, frm).await,
                "json" => dmp.pack_as(message, to, frm, Encoding::Json).await,
                "direct" => dmp.pack_direct(message, to, frm).await,
                "signed" => {
                    let kid = str_field(req, "signer")?;
                    let jwk = state.actors[actor].signing.get(kid).ok_or(format!("no signing key {kid}"))?;
                    let key = Ed25519KeyPair::from_jwk(&jwk.to_string()).map_err(|e| e.to_string())?;
                    dmp.pack_signed(message, to, &AskarSigningKey::new(kid, key)).await
                }
                other => return Err(format!("unknown mode {other}")),
            }
            .map_err(|e| e.to_string())?;
            Ok(packed_response(&result.message))
        }
        "unpack" => {
            let dmp = state.dmp(str_field(req, "as")?)?;
            let result = dmp.unpack_verified(&packed_bytes(req)?).await.map_err(|e| e.to_string())?;
            Ok(json!({
                "message": result.message().map_err(|e| e.to_string())?,
                "encrypted": result.encrypted,
                "authenticated": result.authenticated,
                "recipient_kid": result.recipient_kid,
                "sender_kid": result.sender_kid,
                "signer_kid": result.signer_kid,
                "plaintext_encoding": if result.plaintext_encoding == Encoding::Cbor { "cbor" } else { "json" },
            }))
        }
        "v1_pack" => {
            let to = req["to_verkeys"]
                .as_array()
                .ok_or("missing to_verkeys")?
                .iter()
                .map(|v| {
                    let bytes = multibase::decode_base58btc(v.as_str().unwrap_or_default()).map_err(|e| e.to_string())?;
                    Ed25519KeyPair::from_public_bytes(&bytes).map_err(|e| e.to_string())
                })
                .collect::<Result<Vec<_>, _>>()?;
            let from = req["from_seed_hex"].as_str().map(ed25519_from_seed_hex).transpose()?.map(V1SecretKey::new);
            let message = serde_json::to_vec(&req["message"]).map_err(|e| e.to_string())?;
            let packed = V1PackagingService.pack(&to, from.as_ref(), &message).map_err(|e| e.to_string())?;
            Ok(packed_response(&packed))
        }
        "v1_unpack" => {
            let secrets = InMemorySecretsManager::<V1SecretKey>::new();
            for seed in req["seeds_hex"].as_array().into_iter().flatten() {
                secrets.add_secret(V1SecretKey::new(ed25519_from_seed_hex(seed.as_str().unwrap_or_default())?));
            }
            let result = V1PackagingService.unpack(&secrets, &packed_bytes(req)?).await.map_err(|e| e.to_string())?;
            Ok(json!({
                "message": result.message().map_err(|e| e.to_string())?,
                "authenticated": result.authenticated,
                "recipient_kid": result.recipient_kid,
                "sender_kid": result.sender_kid,
            }))
        }
        other => Err(format!("unknown op {other}")),
    }
}

fn main() {

    let mut state = State::default();
    let stdout = std::io::stdout();
    for line in std::io::stdin().lock().lines() {
        let Ok(line) = line else { break };
        if line.trim().is_empty() {
            continue;
        }
        let response = match serde_json::from_str::<Value>(&line) {
            Ok(req) => match pollster::block_on(handle(&mut state, &req)) {
                Ok(Value::Object(mut body)) => {
                    body.insert("ok".into(), Value::Bool(true));
                    Value::Object(body)
                }
                Ok(other) => json!({"ok": true, "value": other}),
                Err(error) => json!({"ok": false, "error": error}),
            },
            Err(error) => json!({"ok": false, "error": format!("bad request: {error}")}),
        };
        let mut out = stdout.lock();
        writeln!(out, "{response}").unwrap();
        out.flush().unwrap();
    }
}
