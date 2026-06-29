//! AkurAI VPN common types — pure `std`, zero dependencies.
//!
//! This crate is the shared vocabulary of the overlay: stable node identities,
//! overlay IPv4/IPv6 addressing, CIDR route prefixes, the ACL/route policy
//! model, and the node descriptor that the control plane distributes. Every
//! type here is a value type with no I/O and no cryptography.
//!
//! **No cryptography lives in this crate.** The data-plane secure channel is
//! implemented in the sibling `akurai-transport` crate (Noise_IK over the
//! `akurai-crypto` primitives) — the zero-dependency-custom-crypto decision is
//! resolved. This crate carries only the value vocabulary: identities,
//! addressing, the policy model, the node descriptor, and the relay [`frame`]
//! envelope codec.

#![forbid(unsafe_code)]

pub mod b64;
pub mod cidr;
pub mod frame;
pub mod ids;
pub mod node;
pub mod overlay;
pub mod policy;

pub use cidr::Cidr;
pub use frame::{Frame, FrameKind};
pub use ids::{MachineKey, NodeId};
pub use node::{Endpoint, NodeDescriptor};
pub use overlay::{
    OverlayIpv4, OverlayIpv6, OVERLAY_IPV4_NET, OVERLAY_IPV4_PREFIX_LEN, OVERLAY_IPV6_NET,
    OVERLAY_IPV6_PREFIX_LEN, OVERLAY_MTU, TUN_INTERFACE,
};
pub use policy::{AclRule, Decision, GatewayMode, Policy, Principal, Route, Tag};
