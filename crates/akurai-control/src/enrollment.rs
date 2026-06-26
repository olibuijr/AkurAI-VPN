//! Device enrollment & pairing-code approval (control-plane stub).
//!
//! Owns the one-touch pairing flow: a node requests a short pairing code, the
//! user approves it (browser or admin CLI), and the control plane assigns an
//! overlay IP, DNS name, ACL tags, and route policy. None of this is
//! implemented in 0.0.1.

/// One-line status of the enrollment subsystem.
pub fn status() -> String {
    "enrollment: pairing-code approval flow not implemented in 0.0.1".to_string()
}
