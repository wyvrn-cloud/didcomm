//! The did:webvh Working Group's test vectors
//! (<https://github.com/decentralized-identity/didwebvh-test-suite>), run through
//! this crate's own way in: `resolve_from_log`, which is what the wasm build and
//! `wyvrn-services` resolve with.
//!
//! The suite isn't vendored. Point `DIDWEBVH_TEST_SUITE` at a checkout of it and
//! this runs every vector there; without it, the test passes having done nothing.
//!
//! ```sh
//! git clone https://github.com/decentralized-identity/didwebvh-test-suite
//! DIDWEBVH_TEST_SUITE=$PWD/didwebvh-test-suite cargo test -p didcomm-resolver-webvh --test test_suite -- --nocapture
//! ```
//!
//! What is checked, as the suite's own harnesses check it:
//!
//! - every `negative-*` log is refused, and every DID a negative script names is
//!   refused before anything is fetched;
//! - every implementation's log resolves here, at each version it has a result
//!   for: its SCID, its chain, its proofs and its witnesses all check out;
//! - the document resolved from the Rust implementation's logs is the one that
//!   implementation committed. That implementation is `didwebvh-rs`, which this
//!   crate wraps, so anything else means the wrapper changed something.
//!
//! Against the other implementations' committed documents a difference is
//! printed (`DIFF`) and doesn't fail: they disagree among themselves about what
//! a resolved document holds besides what the log says (whether the implied
//! `#files` service's address ends in a slash, what a deactivated DID resolves
//! to), and the suite records those as differences to settle, not as failures.
//! The metadata beside the document isn't something this crate hands back, and
//! isn't compared.

use std::path::{Path, PathBuf};

use didcomm_resolver_webvh::resolve_from_log;
use serde_json::Value;

fn read(path: &Path) -> Option<String> {
    std::fs::read_to_string(path).ok()
}

/// The DID a log is of: its first entry's `state.id`.
fn did_of(log: &str) -> Option<String> {
    let first: Value = serde_json::from_str(log.lines().next()?).ok()?;
    first.pointer("/state/id")?.as_str().map(str::to_owned)
}

/// The DIDs a script's `resolve-did` steps name. Read as text: a YAML parser for
/// one quoted value a line is a dependency this crate doesn't otherwise need.
fn named_dids(script: &str) -> Vec<String> {
    script
        .lines()
        .filter_map(|line| line.trim().strip_prefix("did:"))
        .map(|rest| rest.trim().trim_matches('"').trim_matches('\'').to_owned())
        .filter(|did| did.starts_with("did:"))
        .collect()
}

fn subdirs(dir: &Path) -> Vec<PathBuf> {
    let mut found: Vec<PathBuf> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.is_dir())
        .collect();
    found.sort();
    found
}

fn name(path: &Path) -> String {
    path.file_name().unwrap_or_default().to_string_lossy().into_owned()
}

#[test]
fn the_working_groups_vectors() {
    let Ok(root) = std::env::var("DIDWEBVH_TEST_SUITE") else {
        eprintln!("DIDWEBVH_TEST_SUITE isn't set: the did:webvh test suite was not run");
        return;
    };
    let vectors = Path::new(&root).join("vectors");
    assert!(vectors.is_dir(), "no vectors/ under {root}");

    let mut failures: Vec<String> = Vec::new();
    let (mut refused, mut matched, mut differed, mut skipped) = (0, 0, 0, 0);

    for scenario in subdirs(&vectors) {
        let scenario_name = name(&scenario);

        if scenario_name.starts_with("negative-") {
            // The broken logs are the TypeScript harness's: it is the one that
            // writes them (the others' folders hold their own outcome).
            let log = read(&scenario.join("ts/did.jsonl")).unwrap_or_default();
            if log.trim().is_empty() {
                let dids = named_dids(&read(&scenario.join("script.yaml")).unwrap_or_default());
                if dids.is_empty() {
                    skipped += 1;
                    println!("SKIP   {scenario_name} (no log and no DID)");
                    continue;
                }
                for did in dids {
                    // With nothing fetched there is only the DID to refuse; given
                    // a log that would otherwise do, it must still be the DID.
                    let parses = didwebvh_rs::url::WebVHURL::parse_did_url(&did).is_ok();
                    let resolves = pollster::block_on(resolve_from_log(&did, "", None)).is_ok();
                    if parses || resolves {
                        failures.push(format!("{scenario_name}: accepted {did}"));
                    } else {
                        refused += 1;
                        println!("PASS   {scenario_name} (refused {did})");
                    }
                }
                continue;
            }
            let Some(did) = did_of(&log) else {
                // A first entry with no DID in it resolves to nothing either way.
                refused += 1;
                println!("PASS   {scenario_name} (no DID in its first entry)");
                continue;
            };
            let witnesses = read(&scenario.join("ts/did-witness.json"));
            match pollster::block_on(resolve_from_log(&did, &log, witnesses.as_deref())) {
                Err(_) => {
                    refused += 1;
                    println!("PASS   {scenario_name}");
                }
                Ok(_) => failures.push(format!("{scenario_name}: resolved a log that must be refused")),
            }
            continue;
        }

        for implementation in subdirs(&scenario) {
            let implementation_name = name(&implementation);
            let Some(log) = read(&implementation.join("did.jsonl")) else {
                continue;
            };
            let Some(did) = did_of(&log) else {
                failures.push(format!("{scenario_name}/{implementation_name}: no DID in its first entry"));
                continue;
            };
            let witnesses = read(&implementation.join("did-witness.json"));
            let mut results: Vec<PathBuf> = std::fs::read_dir(&implementation)
                .into_iter()
                .flatten()
                .flatten()
                .map(|entry| entry.path())
                .filter(|path| {
                    let file = name(path);
                    file.starts_with("resolutionResult") && file.ends_with(".json")
                })
                .collect();
            results.sort();
            for result in results {
                let file = name(&result);
                let id = format!("{scenario_name}/{implementation_name}/{file}");
                let expected: Value = match read(&result).and_then(|text| serde_json::from_str(&text).ok()) {
                    Some(value) => value,
                    None => {
                        failures.push(format!("{id}: unreadable"));
                        continue;
                    }
                };
                // `resolutionResult.2.json` is the DID as of its second version.
                let asked = match file.split('.').nth(1).and_then(|n| n.parse::<u32>().ok()) {
                    Some(version) => format!("{did}?versionNumber={version}"),
                    None => did.clone(),
                };
                match pollster::block_on(resolve_from_log(&asked, &log, witnesses.as_deref())) {
                    Err(err) => failures.push(format!("{id}: {err}")),
                    Ok(document) => {
                        if Some(&document) == expected.get("didDocument") {
                            matched += 1;
                            println!("PASS   {id}");
                        } else if implementation_name != "rust" {
                            differed += 1;
                            println!("DIFF   {id} (resolved; the document isn't the one committed)");
                        } else {
                            failures.push(format!(
                                "{id}: a different document\n  expected {}\n  resolved {document}",
                                expected.get("didDocument").unwrap_or(&Value::Null)
                            ));
                        }
                    }
                }
            }
        }
    }

    println!(
        "\n{refused} refused as they must be, {matched} resolved to the committed document, {differed} resolved to a different one, {skipped} skipped, {} failed",
        failures.len()
    );
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    assert!(refused > 0 && matched > 0, "nothing was run: is {root} a checkout of the suite?");
}
