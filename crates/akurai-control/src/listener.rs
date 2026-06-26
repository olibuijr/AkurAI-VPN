//! The control-plane HTTP listener seam (stub — DO NOT implement here).
//!
//! In production this binds `vpn.olibuijr.com` and serves the enrollment API,
//! the pairing UI, the peer-map watch stream, and the admin API. It is **not**
//! implemented in 0.0.1: `std` ships no production HTTP/TLS server, and pulling
//! a crate (`axum`, `hyper`, …) would break the zero-runtime-dependency
//! principle. TLS terminates at the nginx edge per the deployment doc, but even
//! plain HTTP needs a server implementation or a sanctioned dependency — that
//! is part of the UNRESOLVED DECISION in `docs/protocol.md`.
//!
//! [`serve`] assembles the subsystem stubs (so their shape is exercised) and
//! then refuses to start.

use std::fmt;

use crate::{acl, audit, enrollment, heartbeat, ipam, peermap};

/// Errors from the control-plane entry point.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlError {
    /// The HTTP listener / control-plane runtime is not implemented in 0.0.1.
    NotImplemented,
}

impl fmt::Display for ControlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ControlError::NotImplemented => write!(
                f,
                "control-plane HTTP listener not implemented in 0.0.1 (needs a transport decision — see docs/protocol.md)"
            ),
        }
    }
}

impl std::error::Error for ControlError {}

/// Assemble the control-plane subsystems and (would) start the listener.
///
/// In 0.0.1 this reports each subsystem's stub status, then returns
/// [`ControlError::NotImplemented`] rather than binding a socket.
pub fn serve() -> Result<(), ControlError> {
    eprintln!("akurai-control: control plane subsystems (0.0.1 stubs):");
    for line in [
        enrollment::status(),
        ipam::status(),
        peermap::status(),
        acl::status(),
        audit::status(),
        heartbeat::status(),
    ] {
        eprintln!("  - {line}");
    }
    Err(ControlError::NotImplemented)
}
