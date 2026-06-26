//! Peer-map generation (control-plane stub).
//!
//! Builds the per-node view of the network — which `NodeDescriptor`s a node may
//! see and reach, filtered by ACL — and streams updates to nodes. Generation
//! and the watch stream are not implemented in 0.0.1.

/// One-line status of the peer-map subsystem.
pub fn status() -> String {
    "peermap: ACL-filtered descriptor generation + watch stream not implemented in 0.0.1"
        .to_string()
}
