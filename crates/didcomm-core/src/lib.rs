//! Transport-agnostic DIDComm v2 core: JWE envelope handling today, `packaging`/
//! `routing`/`messaging` (mirroring `didcomm_messaging.{packaging,routing,messaging}`)
//! land in later milestones once a crypto backend exists to exercise them against.

pub mod jwe;
