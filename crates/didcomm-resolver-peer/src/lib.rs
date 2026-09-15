//! `did:peer` resolution, mirroring `didcomm_messaging.resolver.peer`: `did:peer:2`
//! (resolution and generation) and `did:peer:4` (resolution of the long form; the short
//! form is a hash-only reference that can't be resolved without already knowing the
//! long form or document from elsewhere -- see `peer4`'s module docs).

pub mod peer2;
pub mod peer4;

pub use peer2::*;
