//! A small DIDComm v2 agent runtime on top of `didcomm-core`: what an application
//! needs around `pack`/`unpack` to actually talk to other agents.
//!
//! - [`Identity`]: key material that survives restarts (a JWK file), from which the
//!   agent's DIDs are derived.
//! - [`Agent`]: [`send`](Agent::send) and [`request`](Agent::request) over HTTP(S),
//!   [`receive`](Agent::receive), and [`respond`](Agent::respond) on the same
//!   connection (`return_route`) or to the sender's endpoint.
//! - Mediation: [`Agent::mediate`] (coordinate-mediation/3.0) and [`Agent::pickup`]
//!   (messagepickup/3.0), for an agent with no public address of its own.
//! - [`Features`]: what the agent discloses to discover-features queries, and
//!   [`Agent::auto_reply`] for the standard protocols every agent should answer
//!   (discover-features 2.0, trust-ping 2.0).
//!
//! Standard headers (`id`, `from`, `to`, `created_time`) are filled in by
//! `didcomm-core`'s `pack`, so messages built here carry only `type`, `body` and
//! threading.
//!
//! ```no_run
//! # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
//! use didcomm_agent::{Agent, Identity};
//! use serde_json::json;
//!
//! let agent = Agent::new(Identity::load_or_generate("agent-identity.json")?)?;
//! agent.mediate("did:web:us-east2.public.mediator.indiciotech.io").await?;
//!
//! let pong = agent
//!     .request("did:example:bob", &json!({
//!         "type": "https://didcomm.org/trust-ping/2.0/ping",
//!         "body": {"response_requested": true},
//!     }))
//!     .await?;
//! println!("{}", pong.message);
//! # Ok(()) }
//! ```

mod agent;
pub mod features;
mod identity;
pub mod mediation;

pub use agent::{Agent, AgentError, Received, DEFAULT_TIMEOUT, NO_ENDPOINT, PROBLEM_REPORT};
pub use features::{Features, Protocol};
pub use identity::{Identity, IdentityError};
pub use mediation::{Mediation, Pickup};
