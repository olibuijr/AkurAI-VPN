//! The node descriptor — the control plane's record of one enrolled device.
//!
//! This is the shape distributed in the peer map (design doc §"Core Networking
//! Model"). It carries identity, overlay addressing, DNS name, policy, and
//! connectivity hints — but **never** private key material.

use std::net::SocketAddr;

use crate::cidr::Cidr;
use crate::ids::{MachineKey, NodeId};
use crate::overlay::{OverlayIpv4, OverlayIpv6};
use crate::policy::{GatewayMode, Tag};

/// A candidate network endpoint where a node might be reachable (direct path
/// discovery; the MVP is hub-routed and may leave this empty).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    /// A reachable transport address (UDP/QUIC candidate).
    pub addr: SocketAddr,
}

/// The control plane's record of a single enrolled node.
#[derive(Debug, Clone)]
pub struct NodeDescriptor {
    /// Stable node ID.
    pub id: NodeId,
    /// Public machine identity key (placeholder — see [`MachineKey`]).
    pub machine_key: MachineKey,
    /// Allocated overlay IPv4.
    pub overlay_v4: OverlayIpv4,
    /// Allocated overlay IPv6.
    pub overlay_v6: OverlayIpv6,
    /// Internal DNS name, e.g. `laptop.oli.akurai`.
    pub dns_name: String,
    /// Prefixes this node accepts inbound.
    pub allowed_inbound: Vec<Cidr>,
    /// Prefixes this node advertises (subnet/exit gateway).
    pub advertised_routes: Vec<Cidr>,
    /// ACL tags applied to this node.
    pub acl_tags: Vec<Tag>,
    /// Gateway capabilities this node has been approved for.
    pub gateway_modes: Vec<GatewayMode>,
    /// Direct-path endpoint candidates.
    pub endpoints: Vec<Endpoint>,
    /// Assigned relay address, if any (hub-routed fallback).
    pub relay: Option<SocketAddr>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::GatewayMode;

    #[test]
    fn descriptor_carries_the_documented_fields() {
        let desc = NodeDescriptor {
            id: NodeId::from_bytes([7; 16]),
            machine_key: MachineKey::from_public_bytes(vec![0; 32]),
            overlay_v4: OverlayIpv4::from_index(1).unwrap(),
            overlay_v6: OverlayIpv6::from_index(1),
            dns_name: "laptop.oli.akurai".to_string(),
            allowed_inbound: Vec::new(),
            advertised_routes: Vec::new(),
            acl_tags: vec![Tag("trusted".to_string())],
            gateway_modes: vec![GatewayMode::InternalMesh],
            endpoints: Vec::new(),
            relay: None,
        };
        assert_eq!(desc.dns_name, "laptop.oli.akurai");
        assert_eq!(desc.overlay_v4.addr().to_string(), "100.88.0.1");
        assert!(desc.relay.is_none());
    }
}
