//! The native fetch path (didwebvh-rs's own), against a stand-in host: a log that
//! names a witness is taken only with its entries witnessed, and a log read again
//! must continue the one held (multi-device/1.0, "A receiver of an address"). In a
//! file of its own: `allow_private_hosts` is the process's.

use std::io::{Read, Write};
use std::sync::{Arc, Mutex};

use affinidi_secrets_resolver::secrets::Secret;
use didcomm_core::resolver::DIDResolver;
use didcomm_resolver_webvh::{allow_private_hosts, forget_kept, DidWebVh};
use didwebvh_rs::log_entry::LogEntryMethods;
use didwebvh_rs::DIDWebVHState;
use serde_json::{json, Value};

fn ed25519() -> (Secret, String) {
    let mut key = Secret::generate_ed25519(None, None);
    let pk = key.get_public_keymultibase().unwrap();
    key.id = format!("did:key:{pk}#{pk}");
    (key, pk)
}

fn document(did: &str, keys: &[&str]) -> Value {
    json!({
        "id": did,
        "@context": ["https://www.w3.org/ns/did/v1"],
        "verificationMethod": keys.iter().map(|key| json!({
            "id": format!("{did}#{key}"), "type": "Multikey", "controller": did, "publicKeyMultibase": key,
        })).collect::<Vec<_>>(),
        "keyAgreement": keys.iter().map(|key| format!("{did}#{key}")).collect::<Vec<_>>(),
    })
}

/// What the stand-in host serves: `did.jsonl`, and `did-witness.json` if any.
type Served = Arc<Mutex<(String, Option<String>)>>;

fn host() -> (u16, Served) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let served: Served = Arc::new(Mutex::new((String::new(), None)));
    let serving = served.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut request = [0u8; 4096];
            let read = stream.read(&mut request).unwrap_or(0);
            let asked = String::from_utf8_lossy(&request[..read]).to_string();
            let (log, witnesses) = serving.lock().unwrap().clone();
            let (status, body) = if asked.starts_with("GET /.well-known/did.jsonl") {
                ("200 OK", log)
            } else if asked.starts_with("GET /.well-known/did-witness.json") {
                match witnesses {
                    Some(witnesses) => ("200 OK", witnesses),
                    None => ("404 Not Found", String::new()),
                }
            } else {
                ("404 Not Found", String::new())
            };
            let _ = write!(
                stream,
                "HTTP/1.1 {status}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
        }
    });
    (port, served)
}

fn proofs(state: &DIDWebVHState) -> Option<String> {
    Some(serde_json::to_string(state.witness_proofs()).unwrap())
}

fn log_of(state: &DIDWebVHState, upto: usize) -> String {
    state.log_entries()[..upto]
        .iter()
        .map(|e| serde_json::to_string(&e.log_entry).unwrap())
        .collect::<Vec<_>>()
        .join("\n")
}

async fn witness(state: &mut DIDWebVHState, witness: &Secret) {
    let mut secrets = std::collections::HashMap::default();
    secrets.insert(
        witness.id.split('#').next().unwrap().to_string(),
        witness.clone(),
    );
    let (entries, proofs) = state.log_entries_and_witness_proofs_mut();
    let entry = entries.last().unwrap();
    didwebvh_rs::create::sign_witness_proofs(
        proofs,
        entry,
        &entry.get_active_witnesses(),
        &secrets,
    )
    .await
    .unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn only_witnessed_entries_count_and_a_log_must_continue_the_one_held() {
    allow_private_hosts();
    let (port, served) = host();
    let (signer, signer_pk) = ed25519();
    let (witness_key, witness_pk) = ed25519();
    let (a, b) = ("z6MkHttpA", "z6MkHttpB");
    let template = format!("did:webvh:{{SCID}}:localhost%3A{port}");
    let parameters = didwebvh_rs::parameters::Parameters {
        update_keys: Some(Arc::new(vec![didwebvh_rs::Multibase::new(signer_pk)])),
        witness: Some(Arc::new(
            didwebvh_rs::witness::Witnesses::builder()
                .threshold(1)
                .witness(didwebvh_rs::Multibase::new(witness_pk))
                .build()
                .unwrap(),
        )),
        ..Default::default()
    };
    let start = chrono::Utc::now().fixed_offset() - chrono::Duration::hours(1);
    let mut state = DIDWebVHState::default();
    state
        .create_log_entry(
            Some(start),
            &document(&template, &[a, b]),
            &parameters,
            &signer,
        )
        .await
        .unwrap();
    witness(&mut state, &witness_key).await;
    // As the host had it then: what it serves again below, an old copy whole.
    let first_proofs = proofs(&state);
    let did = state.log_entries()[0].log_entry.get_state()["id"]
        .as_str()
        .unwrap()
        .to_string();

    // Its proofs not served: not taken.
    *served.lock().unwrap() = (log_of(&state, 1), None);
    assert!(
        DidWebVh.resolve(&did).await.is_err(),
        "a witnessed log without its proofs"
    );
    forget_kept();
    *served.lock().unwrap() = (log_of(&state, 1), proofs(&state));
    assert_eq!(
        DidWebVh.resolve(&did).await.unwrap()["keyAgreement"]
            .as_array()
            .unwrap()
            .len(),
        2
    );

    // A second entry dropping b, served before it is witnessed: not taken.
    let last = state
        .log_entries()
        .last()
        .unwrap()
        .validated_parameters
        .clone();
    state
        .create_log_entry(
            Some(start + chrono::Duration::minutes(1)),
            &document(&did, &[a]),
            &last,
            &signer,
        )
        .await
        .unwrap();
    *served.lock().unwrap() = (log_of(&state, 2), proofs(&state));
    forget_kept();
    assert!(
        DidWebVh.resolve(&did).await.is_err(),
        "an entry served without its witness proof"
    );

    // Witnessed: taken.
    witness(&mut state, &witness_key).await;
    *served.lock().unwrap() = (log_of(&state, 2), proofs(&state));
    forget_kept();
    assert_eq!(
        DidWebVh.resolve(&did).await.unwrap()["keyAgreement"]
            .as_array()
            .unwrap()
            .len(),
        1
    );

    // The host serves the old log again (with its proofs as they were), which
    // still lists b, and verifies on its own: refused, as not continuing the one held.
    *served.lock().unwrap() = (log_of(&state, 1), first_proofs);
    forget_kept();
    let refused = DidWebVh.resolve(&did).await.unwrap_err().to_string();
    assert!(refused.contains("last read at"), "{refused}");
}
