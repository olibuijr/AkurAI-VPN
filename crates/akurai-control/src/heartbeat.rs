//! Node heartbeat state (control-plane liveness).
//!
//! Tracks which nodes are currently online and their last-seen time, feeding
//! relay assignment and peer-map liveness. The table itself lives in
//! [`crate::state::AppState::heartbeats`] (keyed by node id); this module owns
//! the record shape, the online TTL, and the freshness predicate.

/// Freshness window: a node counts as online while its most recent heartbeat is
/// no older than this many seconds.
pub const HEARTBEAT_TTL_SECS: u64 = 120;

/// A node's last-seen liveness record.
#[derive(Debug, Clone)]
pub struct Heartbeat {
    /// Last reported UDP socket address (may be empty if the node reported none).
    ///
    /// Recorded now so relay assignment can consume it later; the peer-map
    /// snapshot does not yet surface it, hence `allow(dead_code)` (matching the
    /// crate's convention for not-yet-wired forward-facing fields).
    #[allow(dead_code)]
    pub endpoint: String,
    /// UNIX timestamp (seconds) of the most recent heartbeat.
    pub last_seen: u64,
}

/// Whether a node last seen at `last_seen` is online relative to `now`, using
/// the [`HEARTBEAT_TTL_SECS`] window. `saturating_sub` keeps a node with a
/// future-dated timestamp (benign clock skew) online rather than underflowing.
pub fn is_online(last_seen: u64, now: u64) -> bool {
    now.saturating_sub(last_seen) <= HEARTBEAT_TTL_SECS
}

/// One-line status of the heartbeat subsystem.
pub fn status() -> String {
    format!("heartbeat: liveness table active (in-memory, {HEARTBEAT_TTL_SECS}s online TTL)")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_heartbeat_is_online() {
        // Seen 10s ago, well inside the 120s window.
        assert!(is_online(1_000, 1_010));
    }

    #[test]
    fn heartbeat_exactly_at_ttl_is_online() {
        // The boundary is inclusive: now - last_seen == TTL is still online.
        assert!(is_online(1_000, 1_000 + HEARTBEAT_TTL_SECS));
    }

    #[test]
    fn stale_heartbeat_is_offline() {
        // One second past the window flips offline.
        assert!(!is_online(1_000, 1_001 + HEARTBEAT_TTL_SECS));
    }

    #[test]
    fn future_timestamp_clock_skew_stays_online() {
        // last_seen ahead of now must not underflow into "online forever" panic
        // nor wrongly read offline — saturating_sub yields 0, which is online.
        assert!(is_online(2_000, 1_000));
    }
}
