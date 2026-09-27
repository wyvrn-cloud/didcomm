//! Tauri command bindings for `wyvrn-didcomm` -- the native counterpart to
//! `didcomm-wasm`, for a Tauri app's Rust backend (`src-tauri`) rather than a browser's
//! wasm runtime. Mirrors `didcomm-wasm`'s full operation set (generation, multi-device
//! Identity DID minting, pack/unpack, `from_prior` rotation) so a consuming app's JS
//! frontend can swap between the two at build time with the same call surface, just
//! routed over `invoke()` instead of a wasm import -- see `wyvrn-chat`'s own
//! `CryptoRuntime` adapter for that swap.
//!
//! Like `didcomm-node` (and unlike `didcomm-wasm`), this is a native target -- no
//! wasm32 `Send`-future limitation, no wasm-targeting bug in `didwebvh-rs` -- so it
//! depends on `didcomm-quickstart` with its default features. `did:web` and
//! `did:webvh` both work here, a real capability advantage over the wasm build.
//!
//! Unlike `didcomm-wasm`/`didcomm-node`, a `DidcommMessaging` instance has no stable
//! object identity across the Tauri IPC boundary (everything crossing `invoke()` is
//! plain JSON, not an object reference) -- so this crate hands back an opaque `String`
//! handle from `setup_default`/`from_secrets`/`from_secrets_with_kid` instead of a
//! bindings-specific struct, and every later call (`pack`, `unpack`, ...) takes that
//! handle plus a `tauri::State<DidcommMessagingStore>` the consuming app registers via
//! `.manage(DidcommMessagingStore::default())`.
//!
//! Every command lives in the [`commands`] submodule, not here -- see that module's
//! own doc comment for why (a confirmed, currently open `tauri::command` macro bug
//! for anything declared at a crate's root). A consuming app's `src-tauri/src/main.rs`
//! wires this crate in with:
//! ```ignore
//! use didcomm_tauri::commands;
//!
//! tauri::Builder::default()
//!     .manage(commands::DidcommMessagingStore::default())
//!     .invoke_handler(tauri::generate_handler![
//!         commands::generate_did,
//!         commands::generate_did_with_endpoint,
//!         commands::generate_authentication_keypair,
//!         commands::generate_key_agreement_keypair,
//!         commands::generate_multi_device_identity_did,
//!         commands::key_agreement_public_multikey_from_secret,
//!         commands::authentication_public_multikey_from_secret,
//!         commands::setup_default,
//!         commands::from_secrets,
//!         commands::from_secrets_with_kid,
//!         commands::pack,
//!         commands::pack_as_json,
//!         commands::unpack,
//!         commands::resolve_verification_method_kid,
//!         commands::build_from_prior,
//!         commands::verify_from_prior,
//!         commands::dispose_messaging,
//!     ])
//!     .run(tauri::generate_context!())
//!     .expect("error while running tauri application");
//! ```
//! -- each referenced through the `commands::` path, *not* re-exported flat into this
//! crate's own root first (`pub use commands::*` here would work for the plain data
//! types, but passing a flattened command path to `generate_handler!` is exactly the
//! pattern the linked issues show can reintroduce the same collision at the call site,
//! so this crate deliberately doesn't re-export the command functions themselves).

pub mod commands;
