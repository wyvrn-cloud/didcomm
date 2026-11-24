//! A message seen before (security review WYV-54): DIDComm's envelope proves who
//! sent a message, not that it is the first time it has arrived, so a captured
//! control message can be sent again. Whoever acts on messages that must not be
//! done twice keeps a [`SeenMessages`] and asks it of each `(sender, id)`; an
//! agent that answers every message the same however often it comes doesn't need
//! one. In memory, for a window: a message older than its window is turned away
//! by its `created_time` (or its `expires_time`) instead.

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;

/// `(sender, id)` pairs seen in the last `window_secs`, at most `most` of them.
pub struct SeenMessages {
    window_secs: u64,
    most: usize,
    held: Mutex<(
        HashMap<(String, String), u64>,
        VecDeque<(u64, (String, String))>,
    )>,
}

impl SeenMessages {
    pub fn new(window_secs: u64, most: usize) -> Self {
        Self {
            window_secs,
            most: most.max(1),
            held: Mutex::new((HashMap::new(), VecDeque::new())),
        }
    }

    /// Whether `id` from `sender` is new at `now` (seconds): noted if it is. A
    /// repeat within the window is `false`.
    pub fn first_time(&self, sender: &str, id: &str, now: u64) -> bool {
        let mut held = self
            .held
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let (seen, order) = &mut *held;
        // The oldest go: past the window, or past how many are held.
        while let Some((at, _)) = order.front() {
            if now.saturating_sub(*at) <= self.window_secs && order.len() < self.most {
                break;
            }
            let (at, key) = order.pop_front().expect("front was there");
            // (Only if it wasn't seen again since: that later sighting stands.)
            if seen.get(&key) == Some(&at) {
                seen.remove(&key);
            }
        }
        let key = (sender.to_string(), id.to_string());
        if seen
            .get(&key)
            .is_some_and(|at| now.saturating_sub(*at) <= self.window_secs)
        {
            return false;
        }
        seen.insert(key.clone(), now);
        order.push_back((now, key));
        true
    }
}

#[cfg(test)]
mod tests {
    use super::SeenMessages;

    #[test]
    fn a_message_again_within_the_window_is_a_repeat_and_after_it_is_not_remembered() {
        let seen = SeenMessages::new(600, 1000);
        assert!(seen.first_time("did:example:alice", "m1", 100));
        assert!(
            !seen.first_time("did:example:alice", "m1", 200),
            "again: a repeat"
        );
        assert!(
            seen.first_time("did:example:bob", "m1", 200),
            "another sender's id is theirs"
        );
        assert!(
            seen.first_time("did:example:alice", "m1", 800),
            "past the window"
        );
    }

    #[test]
    fn it_holds_no_more_than_it_was_told() {
        let seen = SeenMessages::new(600, 3);
        for n in 0..10 {
            assert!(seen.first_time("did:example:alice", &format!("m{n}"), 100));
        }
        assert!(seen.held.lock().unwrap().1.len() <= 3);
    }
}
