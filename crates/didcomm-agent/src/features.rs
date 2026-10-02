//! What an agent tells peers it supports ([discover-features/2.0]), and the two
//! standard protocols every agent should answer on its own: discover-features itself
//! and [trust-ping/2.0].
//!
//! [discover-features/2.0]: https://identity.foundation/didcomm-messaging/spec/v2.1/#discover-features-protocol-20
//! [trust-ping/2.0]: https://identity.foundation/didcomm-messaging/spec/v2.1/#trust-ping-protocol-20

use serde_json::{json, Value};

pub const DISCOVER_FEATURES: &str = "https://didcomm.org/discover-features/2.0";
pub const DISCOVER_FEATURES_QUERIES: &str = "https://didcomm.org/discover-features/2.0/queries";
pub const DISCOVER_FEATURES_DISCLOSE: &str = "https://didcomm.org/discover-features/2.0/disclose";
pub const TRUST_PING: &str = "https://didcomm.org/trust-ping/2.0";
pub const TRUST_PING_PING: &str = "https://didcomm.org/trust-ping/2.0/ping";
pub const TRUST_PING_RESPONSE: &str = "https://didcomm.org/trust-ping/2.0/ping-response";

/// One protocol an agent supports, and the roles it plays in it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Protocol {
    pub piuri: String,
    pub roles: Vec<String>,
}

/// The protocols an agent discloses to discover-features queries.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Features {
    protocols: Vec<Protocol>,
}

impl Features {
    /// No protocols at all -- the agent answers neither discover-features nor
    /// trust-ping on its own.
    pub fn none() -> Self {
        Self::default()
    }

    /// The two protocols [`Agent::auto_reply`](crate::Agent::auto_reply) answers:
    /// discover-features 2.0 (`responder`) and trust-ping 2.0 (`receiver`). What
    /// [`Agent::new`](crate::Agent::new) starts with.
    pub fn standard() -> Self {
        Self::none()
            .with_protocol(DISCOVER_FEATURES, &["responder"])
            .with_protocol(TRUST_PING, &["receiver"])
    }

    /// Add (or replace the roles of) a supported protocol.
    pub fn with_protocol(mut self, piuri: &str, roles: &[&str]) -> Self {
        let roles = roles.iter().map(|r| r.to_string()).collect();
        match self.protocols.iter_mut().find(|p| p.piuri == piuri) {
            Some(existing) => existing.roles = roles,
            None => self.protocols.push(Protocol { piuri: piuri.to_string(), roles }),
        }
        self
    }

    pub fn protocols(&self) -> &[Protocol] {
        &self.protocols
    }

    pub fn supports(&self, piuri: &str) -> bool {
        self.protocols.iter().any(|p| p.piuri == piuri)
    }

    /// The `disclosures` answering a `queries` message's `body`. Only the `protocol`
    /// feature type is disclosed; queries for other feature types (goal codes,
    /// headers, ...) match nothing, which the spec reads as "not disclosing", not
    /// "unsupported".
    pub fn disclose(&self, queries_body: &Value) -> Vec<Value> {
        let patterns: Vec<&str> = queries_body["queries"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|q| q["feature-type"] == "protocol")
            .filter_map(|q| q["match"].as_str())
            .collect();
        self.protocols
            .iter()
            .filter(|p| patterns.iter().any(|pattern| matches(pattern, &p.piuri)))
            .map(|p| json!({"feature-type": "protocol", "id": p.piuri, "roles": p.roles}))
            .collect()
    }
}

/// discover-features 2.0 matching: `*` matches any run of characters (including none),
/// everything else literally, so `*` alone matches everything and
/// `https://didcomm.org/tictactoe/1.*` matches every 1.x version.
pub fn matches(pattern: &str, id: &str) -> bool {
    let mut parts = pattern.split('*');
    let first = parts.next().unwrap_or_default();
    let Some(mut rest) = id.strip_prefix(first) else {
        return false;
    };
    let parts: Vec<&str> = parts.collect();
    let Some((last, middle)) = parts.split_last() else {
        return rest.is_empty(); // no `*` at all: an exact match
    };
    for part in middle {
        match rest.find(part) {
            Some(at) => rest = &rest[at + part.len()..],
            None => return false,
        }
    }
    rest.ends_with(last)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matching_follows_discover_features_wildcards() {
        let id = "https://didcomm.org/tictactoe/1.0";
        assert!(matches("*", id));
        assert!(matches(id, id));
        assert!(matches("https://didcomm.org/tictactoe/1.*", id));
        assert!(matches("https://didcomm.org/*/1.0", id));
        assert!(matches("*tictactoe*", id));
        assert!(!matches("https://didcomm.org/tictactoe/2.*", id));
        assert!(!matches("https://didcomm.org/tictactoe/1", id));
        assert!(!matches("*/2.0", id));
        // The text after the last `*` has to fit after what earlier parts consumed.
        assert!(!matches("https://didcomm.org/*.org/tictactoe/1.0", id));
    }

    #[test]
    fn discloses_only_matching_protocols() {
        let features = Features::standard().with_protocol("https://wyvrn.app/documentation/1.0", &["registry"]);
        let body = json!({"queries": [
            {"feature-type": "protocol", "match": "https://didcomm.org/*"},
            {"feature-type": "goal-code", "match": "*"},
        ]});

        let disclosed = features.disclose(&body);

        assert_eq!(disclosed, vec![
            json!({"feature-type": "protocol", "id": DISCOVER_FEATURES, "roles": ["responder"]}),
            json!({"feature-type": "protocol", "id": TRUST_PING, "roles": ["receiver"]}),
        ]);
    }

    #[test]
    fn with_protocol_replaces_roles_instead_of_duplicating() {
        let features = Features::standard().with_protocol(TRUST_PING, &["sender", "receiver"]);
        assert_eq!(features.protocols().len(), 2);
        assert_eq!(features.protocols()[1].roles, ["sender", "receiver"]);
    }
}
