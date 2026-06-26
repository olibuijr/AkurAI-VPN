//! ACL & route-approval policy (control-plane stub).
//!
//! Wraps the fail-closed [`Policy`](akurai_common::Policy) from `akurai-common`
//! and gates route/gateway advertisements behind explicit approval. Policy
//! persistence and the admin-driven approval workflow are not implemented in
//! 0.0.1; the evaluator itself already lives (and is tested) in `akurai-common`.

/// One-line status of the ACL subsystem.
pub fn status() -> String {
    "acl: fail-closed policy evaluator available in akurai-common; persistence not implemented in 0.0.1".to_string()
}
