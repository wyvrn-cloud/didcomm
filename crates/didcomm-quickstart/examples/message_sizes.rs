//! Wire sizes of real packed DIDComm v2 messages, JSON vs the `didcomm/v2+cbor`
//! profile, at every layer a mediated message passes through -- produced by this
//! workspace's actual pack/forward code, not estimated.
//!
//! ```text
//! cargo run -p didcomm-quickstart --example message_sizes            # tables
//! cargo run -p didcomm-quickstart --example message_sizes -- --json  # raw numbers
//! ```
//!
//! Each scenario is packed several times and the median taken (sizes only vary by a
//! few bytes, from gzip on random ciphertext). Variables:
//!
//! - **DID style**: long-form `did:peer:4` (the whole DID document inline, what wyvrn
//!   generates) vs short-form `did:peer:4` (just the hash). DIDs appear as text in
//!   kids, `apu`/`skid`, `from`/`to` and `next`, so they dominate small messages, and
//!   CBOR can't shrink text.
//! - **Payload**: a short chat message, 1 KiB of text, and a 10 KiB binary attachment
//!   (random bytes, like a compressed image, carried as `data.base64` in both encodings).
//! - **Encoding per hop**: the inner (end-to-end) message follows the recipient's
//!   `accept` list; the forward around it follows the mediator's.

use std::collections::HashMap;
use std::io::Write as _;

use askar_crypto::alg::{ed25519::Ed25519KeyPair, x25519::X25519KeyPair};
use askar_crypto::repr::KeyPublicBytes;
use async_trait::async_trait;
use didcomm_core::crypto::Encoding;
use didcomm_core::messaging::DIDCommMessaging;
use didcomm_core::plaintext;
use didcomm_core::resolver::{DIDResolver, ResolutionError};
use didcomm_core::secrets::InMemorySecretsManager;
use didcomm_crypto_askar::{AskarCryptoService, AskarSecretKey, AskarSigningKey};
use didcomm_multiformats::{multibase, multicodec};
use serde_json::{json, Value};

type Dmp = DIDCommMessaging<AskarCryptoService, InMemorySecretsManager<AskarSecretKey>>;

const RUNS: usize = 5;
const JSON_ONLY: &[&str] = &["didcomm/v2"];
const CBOR: &[&str] = &["didcomm/v2+cbor", "didcomm/v2"];

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

struct Party {
    did: String,
    agreement: X25519KeyPair,
    auth: Ed25519KeyPair,
}

impl Party {
    /// A party whose DID is a real generated `did:peer:4`, long or short form.
    fn new(long_form: bool) -> Self {
        let generated = didcomm_quickstart::generate_did_with_endpoint("https://example.com/didcomm").unwrap();
        let did = if long_form {
            generated.did.clone()
        } else {
            generated.did[..generated.did.rfind(':').unwrap()].to_string()
        };
        Self { did, agreement: generated.key_agreement_key, auth: generated.verification_key }
    }

    fn doc(&self, endpoint: &str, accept: &[&str]) -> Value {
        let multikey = |codec, bytes: Vec<u8>| format!("z{}", multibase::encode_base58btc(multicodec::wrap(codec, &bytes)));
        json!({
            "id": self.did,
            "verificationMethod": [
                {"id": "#key-1", "type": "Multikey", "controller": self.did,
                 "publicKeyMultibase": multikey(multicodec::ED25519_PUB, self.auth.with_public_bytes(<[u8]>::to_vec))},
                {"id": "#key-2", "type": "Multikey", "controller": self.did,
                 "publicKeyMultibase": multikey(multicodec::X25519_PUB, self.agreement.with_public_bytes(<[u8]>::to_vec))},
            ],
            "authentication": ["#key-1"],
            "keyAgreement": ["#key-2"],
            "service": [{"id": "#didcomm", "type": "DIDCommMessaging",
                         "serviceEndpoint": {"uri": endpoint, "accept": accept, "routingKeys": []}}],
        })
    }

    fn dmp(&self, docs: &HashMap<String, Value>) -> Dmp {
        let secrets = InMemorySecretsManager::<AskarSecretKey>::new();
        secrets.add_secret(AskarSecretKey::new(format!("{}#key-2", self.did), self.agreement.clone()));
        DIDCommMessaging::new(AskarCryptoService, secrets, Box::new(StaticResolver(docs.clone())))
    }
}

/// Bytes that look like a compressed image: no structure for gzip to find.
fn noise(len: usize) -> Vec<u8> {
    let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state as u8
        })
        .collect()
}

fn payloads() -> Vec<(&'static str, Value)> {
    let text_1k: String = "The quick brown fox jumps over the lazy dog. ".repeat(23)[..1024].to_string();
    vec![
        ("short text", json!({"type": "https://didcomm.org/basicmessage/2.0/message", "lang": "en",
                              "body": {"content": "Hello world!"}})),
        ("1 KiB text", json!({"type": "https://didcomm.org/basicmessage/2.0/message", "lang": "en",
                              "body": {"content": text_1k}})),
        ("10 KiB attachment", json!({"type": "https://didcomm.org/basicmessage/2.0/message", "lang": "en",
                              "body": {"content": "photo"},
                              "attachments": [{"id": "photo", "media_type": "image/jpeg",
                                               "data": {"base64": multibase::encode(noise(10 * 1024))}}]})),
    ]
}

fn gzip(bytes: &[u8]) -> usize {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
    encoder.write_all(bytes).unwrap();
    encoder.finish().unwrap().len()
}

fn median(mut values: Vec<usize>) -> usize {
    values.sort_unstable();
    values[values.len() / 2]
}

/// One measured message: its size, and gzipped size.
#[derive(Clone, Copy)]
struct Size {
    raw: usize,
    gz: usize,
}

fn measure(runs: impl Fn() -> Vec<u8>) -> Size {
    let samples: Vec<Vec<u8>> = (0..RUNS).map(|_| runs()).collect();
    Size {
        raw: median(samples.iter().map(Vec::len).collect()),
        gz: median(samples.iter().map(|s| gzip(s)).collect()),
    }
}

fn row(rows: &mut Vec<Value>, did_style: &str, payload: &str, case: &str, json_size: Size, cbor_size: Size) {
    rows.push(json!({
        "did_style": did_style, "payload": payload, "case": case,
        "json": json_size.raw, "json_gzip": json_size.gz,
        "cbor": cbor_size.raw, "cbor_gzip": cbor_size.gz,
    }));
}

fn main() {
    let as_json = std::env::args().any(|a| a == "--json");
    let mut rows = Vec::new();
    let mut forwards = Vec::new();

    for (did_style, long_form) in [("did:peer:4 long form", true), ("did:peer:4 short form", false)] {
        let (alice, bob, mediator) = (Party::new(long_form), Party::new(long_form), Party::new(long_form));
        // docs[(mediator accept, bob accept)]: Bob is behind the mediator.
        let docs_for = |mediator_accept: &[&str], bob_accept: &[&str]| {
            HashMap::from([
                (alice.did.clone(), alice.doc("https://alice.example.com/didcomm", bob_accept)),
                (mediator.did.clone(), mediator.doc("https://mediator.example.com/didcomm", mediator_accept)),
                (bob.did.clone(), bob.doc(&mediator.did, bob_accept)),
            ])
        };
        // Direct (no mediator): Bob reachable at a URL, accepting the given encodings.
        let direct_docs_for = |accept: &[&str]| {
            HashMap::from([
                (alice.did.clone(), alice.doc("https://alice.example.com/didcomm", accept)),
                (bob.did.clone(), bob.doc("https://bob.example.com/didcomm", accept)),
            ])
        };
        let signing_key = AskarSigningKey::new(format!("{}#key-1", alice.did), alice.auth.clone());

        for (payload_name, payload) in payloads() {
            let block = |f: &dyn Fn() -> Vec<u8>| measure(f);

            // Plaintext, with the headers pack() would add.
            let complete = alice.dmp(&direct_docs_for(JSON_ONLY)).complete_headers(&payload, &bob.did, Some(&alice.did)).unwrap().into_owned();
            let p = |enc| block(&|| plaintext::encode(&complete, enc).unwrap());
            row(&mut rows, did_style, payload_name, "plaintext", p(Encoding::Json), p(Encoding::Cbor));

            // Direct: authcrypt, anoncrypt, signed+anoncrypt.
            for (case, frm) in [("authcrypt, direct", Some(alice.did.as_str())), ("anoncrypt, direct", None)] {
                let pack = |accept: &[&str]| {
                    let dmp = alice.dmp(&direct_docs_for(accept));
                    block(&|| pollster::block_on(dmp.pack(&payload, &bob.did, frm)).unwrap().message)
                };
                row(&mut rows, did_style, payload_name, case, pack(JSON_ONLY), pack(CBOR));
            }
            let signed = |accept: &[&str]| {
                let dmp = alice.dmp(&direct_docs_for(accept));
                block(&|| pollster::block_on(dmp.pack_signed(&payload, &bob.did, &signing_key)).unwrap().message)
            };
            row(&mut rows, did_style, payload_name, "signed + anoncrypt, direct", signed(JSON_ONLY), signed(CBOR));

            // Mediated: the forward Alice sends the mediator, for every (mediator, Bob)
            // encoding combination, plus the delivery the mediator hands Bob.
            for (mediator_accept, bob_accept) in [(JSON_ONLY, JSON_ONLY), (JSON_ONLY, CBOR), (CBOR, JSON_ONLY), (CBOR, CBOR)] {
                let docs = docs_for(mediator_accept, bob_accept);
                let alice_dmp = alice.dmp(&docs);
                let mediator_dmp = mediator.dmp(&docs);
                let pack = || pollster::block_on(alice_dmp.pack(&payload, &bob.did, Some(&alice.did))).unwrap().message;
                let forward = block(&pack);
                // The inner message (what the mediator stores and later delivers).
                let inner = || {
                    let fwd = pollster::block_on(mediator_dmp.unpack(&pack())).unwrap();
                    plaintext::attachment_bytes(&fwd.message().unwrap()["attachments"][0]).unwrap()
                };
                let inner_size = block(&inner);
                // messagepickup/3.0 delivery of that one message, packed to Bob by the
                // mediator (negotiated against Bob's accept list).
                let delivery = || {
                    let (media_type, data) = plaintext::packed_message_attachment_data(&inner()).unwrap();
                    let msg = json!({"type": "https://didcomm.org/messagepickup/3.0/delivery",
                                     "body": {"recipient_did": bob.did},
                                     "attachments": [{"id": "1", "media_type": media_type, "data": data}]});
                    pollster::block_on(mediator_dmp.pack_direct(&msg, &bob.did, Some(&mediator.did))).unwrap().message
                };
                let delivery_size = block(&delivery);
                let enc = |accept: &[&str]| if accept.len() == 2 { "cbor" } else { "json" };
                forwards.push(json!({
                    "did_style": did_style, "payload": payload_name,
                    "forward_encoding": enc(mediator_accept), "inner_encoding": enc(bob_accept),
                    "inner": inner_size.raw, "forward": forward.raw, "forward_gzip": forward.gz,
                    "forward_overhead": forward.raw - inner_size.raw,
                    "delivery": delivery_size.raw, "delivery_gzip": delivery_size.gz,
                }));
            }
        }
    }

    if as_json {
        println!("{}", serde_json::to_string_pretty(&json!({"direct": rows, "mediated": forwards})).unwrap());
        return;
    }
    let pct = |json: u64, cbor: u64| format!("{:+.1}%", (cbor as f64 - json as f64) / json as f64 * 100.0);
    println!("| DIDs | payload | case | JSON | CBOR | change | JSON gz | CBOR gz |");
    println!("|---|---|---|--:|--:|--:|--:|--:|");
    for r in &rows {
        let (j, c) = (r["json"].as_u64().unwrap(), r["cbor"].as_u64().unwrap());
        println!("| {} | {} | {} | {j} | {c} | {} | {} | {} |", r["did_style"].as_str().unwrap(), r["payload"].as_str().unwrap(),
                 r["case"].as_str().unwrap(), pct(j, c), r["json_gzip"], r["cbor_gzip"]);
    }
    println!("\n| DIDs | payload | forward | inner | inner size | forward size | forward overhead | forward gz | delivery | delivery gz |");
    println!("|---|---|---|---|--:|--:|--:|--:|--:|--:|");
    for f in &forwards {
        println!("| {} | {} | {} | {} | {} | {} | {} | {} | {} | {} |", f["did_style"].as_str().unwrap(), f["payload"].as_str().unwrap(),
                 f["forward_encoding"].as_str().unwrap(), f["inner_encoding"].as_str().unwrap(), f["inner"], f["forward"],
                 f["forward_overhead"], f["forward_gzip"], f["delivery"], f["delivery_gzip"]);
    }
}
