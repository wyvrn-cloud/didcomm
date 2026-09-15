//! Multibase/multicodec helpers, mirroring `didcomm_messaging.multiformats`.
//!
//! `base64url` and `base58btc` exist so far. The multicodec prefix table (used to
//! interpret the bytes *inside* a base58btc multikey -- which curve, which key type)
//! lands alongside the code that actually needs it (verification-method-to-public-key
//! conversion).

pub mod multibase;
