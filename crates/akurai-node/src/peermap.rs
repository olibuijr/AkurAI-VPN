//! Peer-map watch (stub — DO NOT implement here).
//!
//! Subscribes to the control plane's peer-map stream and updates local peer
//! sessions, routes, and DNS as the network changes. It needs the (undecided)
//! transport, so it is a stub in 0.0.1.

use crate::error::NodeError;
use crate::tun::TunDevice;

/// Start watching the peer map and applying updates. **Stub** — returns
/// [`NodeError::NotImplemented`].
pub fn watch(_device: &TunDevice) -> Result<(), NodeError> {
    Err(NodeError::NotImplemented("peer-map watch stream"))
}
