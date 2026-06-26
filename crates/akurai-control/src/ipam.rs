//! Overlay IP allocation (IPAM) — control-plane stub.
//!
//! Hands each enrolled node a stable overlay IPv4/IPv6 from the fixed ranges.
//! The allocation arithmetic itself lives in `akurai-common`; the persistent
//! index bookkeeping (who has which index, reuse on deletion) is not
//! implemented in 0.0.1.

use akurai_common::OverlayIpv4;

/// One-line status of the IP-allocation subsystem, demonstrating the overlay
/// helper that the real allocator will draw addresses from.
pub fn status() -> String {
    match OverlayIpv4::from_index(1) {
        Ok(first) => format!(
            "ipam: 100.88.0.0/16 ready, control plane would take {} (allocator not implemented in 0.0.1)",
            first.addr()
        ),
        Err(e) => format!("ipam: overlay range misconfigured: {e}"),
    }
}
