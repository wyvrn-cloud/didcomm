//! Transport-agnostic DIDComm v2 core, mirroring `didcomm_messaging`: JWE envelopes,
//! the `DIDResolver`/`CryptoService`/`SecretsManager` traits, `PackagingService`
//! (pack/unpack by DID), `RoutingService` (mediator forwarding), and the top-level
//! `DIDCommMessaging` entry point.

pub mod crypto;
pub mod jwe;
pub mod messaging;
pub mod packaging;
pub mod resolver;
pub mod routing;
pub mod secrets;
