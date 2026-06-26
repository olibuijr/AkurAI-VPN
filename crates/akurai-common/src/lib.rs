//! AkurAI VPN common types — pure `std`, zero dependencies.
//!
//! This crate is the shared vocabulary of the overlay: stable node identities,
//! overlay IPv4/IPv6 addressing, CIDR route prefixes, the ACL/route policy
//! model, and the node descriptor that the control plane distributes. Every
//! type here is a value type with no I/O and no cryptography.
//!
//! **No cryptography lives in this crate.** [`MachineKey`] is an opaque
//! placeholder and [`transport`] is a deliberate stub. The choice of transport
//! and handshake — and whether a vetted crypto crate may be linked despite the
//! zero-dependency principle — is an UNRESOLVED DECISION documented in
//! `docs/protocol.md`.

#![forbid(unsafe_code)]

pub mod cidr;
pub mod ids;
pub mod node;
pub mod overlay;
pub mod policy;
pub mod transport;

pub use cidr::Cidr;
pub use ids::{MachineKey, NodeId};
pub use node::{Endpoint, NodeDescriptor};
pub use overlay::{
    OverlayIpv4, OverlayIpv6, OVERLAY_IPV4_NET, OVERLAY_IPV4_PREFIX_LEN, OVERLAY_IPV6_NET,
    OVERLAY_IPV6_PREFIX_LEN, OVERLAY_MTU, TUN_INTERFACE,
};
pub use policy::{AclRule, Decision, GatewayMode, Policy, Principal, Route, Tag};
pub use transport::{Session, TransportError};
