//! TUN device management (stub — DO NOT implement here).
//!
//! On Linux the node creates a TUN interface named `akurai0` by opening
//! `/dev/net/tun` and issuing the `TUNSETIFF` ioctl with `IFF_TUN | IFF_NO_PI`,
//! then configures the overlay address and MTU (1280) via netlink/`ip`. That
//! work needs either `unsafe` libc ioctl wrappers or a dependency — both
//! deferred in 0.0.1 — so [`open`] and [`close`] are stubs that return
//! [`NodeError::NotImplemented`] without touching the system.

use crate::error::NodeError;

/// A handle to the `akurai0` TUN interface. A unit type for now — it gains the
/// file descriptor and config state once the device is actually implemented.
#[derive(Debug, Default)]
pub struct TunDevice;

/// Open (create + configure) the TUN interface. **Stub** — returns
/// [`NodeError::NotImplemented`].
pub fn open(_name: &str) -> Result<TunDevice, NodeError> {
    Err(NodeError::NotImplemented("TUN device creation"))
}

/// Close and remove the TUN interface. **Stub** — returns
/// [`NodeError::NotImplemented`].
pub fn close(_name: &str) -> Result<(), NodeError> {
    Err(NodeError::NotImplemented("TUN device teardown"))
}
