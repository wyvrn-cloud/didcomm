//! Prints a freshly made, validly signed `did:webvh` and its log, as one line of
//! JSON: `{"did": "...", "log": "..."}`. For tests that need a real one to serve --
//! wyvrn-chat's end-to-end suite resolves it in a browser, through the wasm build,
//! to show that a genuine log is accepted there and a tampered one is not.
//!
//! Usage: `cargo run -q -p didcomm-resolver-webvh --example webvh_log -- <host>`,
//! where `<host>` is the DID's host as it appears in the DID: `example.com`, or
//! `localhost%3A8080` for one served from this machine. The document it makes names
//! an HTTP and a WebSocket `DIDCommMessaging` service at that host.

use std::sync::Arc;

use affinidi_secrets_resolver::secrets::Secret;
use didwebvh_rs::{log_entry::LogEntryMethods, DIDWebVHState};
use serde_json::json;

fn main() {
    let host = std::env::args().nth(1).expect("usage: webvh_log <host>");
    let address = host.replace("%3A", ":");

    let mut key = Secret::generate_ed25519(None, None);
    let pk = key.get_public_keymultibase().unwrap();
    key.id = format!("did:key:{pk}#{pk}");

    let did_template = format!("did:webvh:{{SCID}}:{host}");
    let document = json!({
        "id": did_template,
        "@context": ["https://www.w3.org/ns/did/v1"],
        "verificationMethod": [{
            "id": format!("{did_template}#key-0"),
            "type": "Multikey",
            "publicKeyMultibase": pk,
            "controller": did_template,
        }],
        "authentication": [format!("{did_template}#key-0")],
        "service": [
            {
                "id": format!("{did_template}#service"),
                "type": "DIDCommMessaging",
                "serviceEndpoint": {"uri": format!("http://{address}"), "accept": ["didcomm/v2"], "routingKeys": []},
            },
            {
                "id": format!("{did_template}#ws"),
                "type": "DIDCommMessaging",
                "serviceEndpoint": {"uri": format!("ws://{address}/ws"), "accept": ["didcomm/v2"], "routingKeys": []},
            },
        ],
    });
    let parameters = didwebvh_rs::parameters::Parameters {
        update_keys: Some(Arc::new(vec![didwebvh_rs::Multibase::new(pk.clone())])),
        ..Default::default()
    };

    let mut state = DIDWebVHState::default();
    pollster::block_on(state.create_log_entry(None, &document, &parameters, &key)).expect("creates a first log entry");
    let scid = state.log_entries()[0].log_entry.get_scid().expect("first entry has a SCID").to_string();
    let log = state
        .log_entries()
        .iter()
        .map(|entry| serde_json::to_string(&entry.log_entry).unwrap())
        .collect::<Vec<_>>()
        .join("\n");

    println!("{}", json!({"did": format!("did:webvh:{scid}:{host}"), "log": log}));
}
