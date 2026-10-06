//! Transport-agnostic DIDComm v2 core, mirroring `didcomm_messaging`: JWE/JWS envelopes
//! and their COSE counterparts for the `didcomm/v2+cbor` profile,
//! the `DIDResolver`/`CryptoService`/`SecretsManager` traits, `PackagingService`
//! (pack/unpack by DID), `RoutingService` (mediator forwarding), and the top-level
//! `DIDCommMessaging` entry point.

pub mod cose;
pub mod crypto;
pub mod envelope;
pub mod jwe;
pub mod messaging;
pub mod packaging;
pub mod plaintext;
pub mod resolver;
pub mod rotation;
pub mod routing;
pub mod secrets;
pub mod signed;
