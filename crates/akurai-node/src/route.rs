//! Route application (stub — DO NOT implement here).
//!
//! Installs the overlay routes (and any approved subnet/exit routes) on the
//! `akurai0` interface. On Linux this is netlink / `ip route` work; it is
//! deferred in 0.0.1. [`overlay_defaults`] is real — it builds the two overlay
//! prefixes from `akurai-common` — so the route set the daemon *would* install
//! is already expressible; only [`apply`] is a stub.

use std::net::IpAddr;

use akurai_common::overlay::{
    OVERLAY_IPV4_NET, OVERLAY_IPV4_PREFIX_LEN, OVERLAY_IPV6_NET, OVERLAY_IPV6_PREFIX_LEN,
};
use akurai_common::Cidr;

use crate::error::NodeError;
use crate::tun::TunDevice;

/// The default overlay routes every node installs: the IPv4 `/16` and the IPv6
/// `/48`, both via `akurai0`.
pub fn overlay_defaults() -> Vec<Cidr> {
    let mut routes = Vec::new();
    if let Ok(v4) = Cidr::new(IpAddr::V4(OVERLAY_IPV4_NET), OVERLAY_IPV4_PREFIX_LEN) {
        routes.push(v4);
    }
    if let Ok(v6) = Cidr::new(IpAddr::V6(OVERLAY_IPV6_NET), OVERLAY_IPV6_PREFIX_LEN) {
        routes.push(v6);
    }
    routes
}

/// Apply `routes` to the interface. **Stub** — returns
/// [`NodeError::NotImplemented`].
pub fn apply(_device: &TunDevice, _routes: &[Cidr]) -> Result<(), NodeError> {
    Err(NodeError::NotImplemented("route application"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overlay_defaults_cover_both_families() {
        let routes = overlay_defaults();
        assert_eq!(routes.len(), 2);
        assert_eq!(routes[0].to_string(), "100.88.0.0/16");
        assert_eq!(routes[1].prefix_len(), 48);
    }
}
