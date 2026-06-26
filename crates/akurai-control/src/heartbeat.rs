//! Node heartbeat state (control-plane stub).
//!
//! Tracks which nodes are currently online and their last-seen time, feeding
//! relay assignment and peer-map liveness. The heartbeat table and its expiry
//! are not implemented in 0.0.1.

/// One-line status of the heartbeat subsystem.
pub fn status() -> String {
    "heartbeat: liveness table + expiry not implemented in 0.0.1".to_string()
}
