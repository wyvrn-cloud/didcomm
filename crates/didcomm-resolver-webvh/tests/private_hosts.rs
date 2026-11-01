//! A `did:webvh` at a private host: refused unless the process says otherwise
//! (`allow_private_hosts`). In a file of its own, since that is the process's.

use std::io::{Read, Write};
use std::sync::Arc;

use affinidi_secrets_resolver::secrets::Secret;
use didcomm_core::resolver::DIDResolver;
use didcomm_resolver_webvh::{allow_private_hosts, DidWebVh};
use didwebvh_rs::log_entry::LogEntryMethods;
use didwebvh_rs::DIDWebVHState;
use serde_json::json;

/// A real, signed log for a DID at `domain`, and the DID.
async fn log_at(domain: &str) -> (String, String) {
    let mut key = Secret::generate_ed25519(None, None);
    let pk = key.get_public_keymultibase().unwrap();
    key.id = format!("did:key:{pk}#{pk}");
    let template = format!("did:webvh:{{SCID}}:{domain}");
    let document = json!({
        "id": template,
        "@context": ["https://www.w3.org/ns/did/v1"],
        "verificationMethod": [{ "id": format!("{template}#key-0"), "type": "Multikey", "publicKeyMultibase": pk, "controller": template }],
        "authentication": [format!("{template}#key-0")],
    });
    let parameters = didwebvh_rs::parameters::Parameters { update_keys: Some(Arc::new(vec![didwebvh_rs::Multibase::new(pk.clone())])), ..Default::default() };
    let mut state = DIDWebVHState::default();
    state.create_log_entry(None, &document, &parameters, &key).await.unwrap();
    let scid = state.log_entries()[0].log_entry.get_scid().unwrap().to_string();
    let log = state.log_entries().iter().map(|e| serde_json::to_string(&e.log_entry).unwrap()).collect::<Vec<_>>().join("\n");
    (format!("did:webvh:{scid}:{domain}"), log)
}

#[tokio::test(flavor = "multi_thread")]
async fn a_did_at_a_private_host_is_resolved_only_once_the_process_allows_it() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (did, log) = log_at(&format!("localhost%3A{port}")).await;
    // Whatever is asked for, the log: did.jsonl is all a resolver needs.
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut request = [0u8; 4096];
            let read = stream.read(&mut request).unwrap_or(0);
            let asked = String::from_utf8_lossy(&request[..read]);
            let (status, body) = if asked.starts_with("GET /.well-known/did.jsonl") { ("200 OK", log.clone()) } else { ("404 Not Found", String::new()) };
            let _ = write!(stream, "HTTP/1.1 {status}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}", body.len());
        }
    });

    let refused = DidWebVh.resolve(&did).await.unwrap_err().to_string();
    assert!(refused.contains("localhost"), "{refused}");
    allow_private_hosts();
    let document = DidWebVh.resolve(&did).await.unwrap();
    assert_eq!(document["id"], did);
}
