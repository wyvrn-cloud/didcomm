//! Multibase/multicodec helpers, mirroring `didcomm_messaging.multiformats`.
//!
//! Only `base64url` exists so far (it's what `didcomm-core`'s JWE handling needs). The
//! full `multibase`/`multicodec` port (base58btc, the multicodec prefix table used for
//! `did:key`/`did:peer` verification methods, etc.) lands in a later milestone.

pub mod multibase;
