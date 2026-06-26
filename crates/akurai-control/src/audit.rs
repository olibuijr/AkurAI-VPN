//! Audit events (control-plane stub).
//!
//! Records enrollment, approval, and policy-change events for later review.
//! Rejected gateway advertisements MUST be audited (fail-closed policy). The
//! durable event log is not implemented in 0.0.1.

/// One-line status of the audit subsystem.
pub fn status() -> String {
    "audit: durable event log not implemented in 0.0.1".to_string()
}
