//! Overlay addressing — the fixed network parameters and IP allocation helpers.
//!
//! AkurAI VPN is an L3 overlay reached through a TUN interface. The address
//! plan is fixed by the design doc:
//!
//! - IPv4 overlay: `100.88.0.0/16`
//! - IPv6 overlay: `fd88:akurai::/48` (mnemonic — see [`OVERLAY_IPV6_NET`])
//! - Initial MTU:  `1280`
//! - TUN iface:    `akurai0`
//!
//! Everything here is pure arithmetic over `std::net` address types.

use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

/// TUN interface name created on every node.
pub const TUN_INTERFACE: &str = "akurai0";

/// Initial overlay MTU, in bytes. Deliberately conservative (1280, the IPv6
/// minimum) to leave headroom for the transport + crypto envelope without
/// path-MTU discovery in the MVP.
pub const OVERLAY_MTU: u16 = 1280;

/// IPv4 overlay network base address: `100.88.0.0` (a `100.64.0.0/10` CGNAT
/// address, intentionally outside normal RFC 1918 LAN ranges).
pub const OVERLAY_IPV4_NET: Ipv4Addr = Ipv4Addr::new(100, 88, 0, 0);

/// IPv4 overlay prefix length: `/16`.
pub const OVERLAY_IPV4_PREFIX_LEN: u8 = 16;

/// IPv6 overlay prefix length: `/48`.
pub const OVERLAY_IPV6_PREFIX_LEN: u8 = 48;

/// IPv6 overlay prefix base address.
///
/// The design doc writes this as `fd88:akurai::/48`, but `akurai` is a
/// non-hexadecimal mnemonic, not a valid IPv6 group — so the real Unique-Local
/// (RFC 4193, `fd00::/8`) prefix used by the code is `fd88::/48`. The mnemonic
/// spelling is kept in prose only.
pub const OVERLAY_IPV6_NET: Ipv6Addr = Ipv6Addr::new(0xfd88, 0, 0, 0, 0, 0, 0, 0);

/// Errors from overlay address allocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OverlayError {
    /// A host index fell outside the addressable space of the overlay prefix.
    IndexOutOfRange { index: u32, max: u32 },
}

impl fmt::Display for OverlayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OverlayError::IndexOutOfRange { index, max } => {
                write!(f, "overlay host index {index} out of range (max {max})")
            }
        }
    }
}

impl std::error::Error for OverlayError {}

/// An allocated overlay IPv4 address inside `100.88.0.0/16`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OverlayIpv4(Ipv4Addr);

impl OverlayIpv4 {
    /// Highest host index in the `/16` (65535, 0-based).
    pub const MAX_INDEX: u32 = (1u32 << (32 - OVERLAY_IPV4_PREFIX_LEN as u32)) - 1;

    /// Allocate the `index`-th address in the overlay `/16`, 0-based.
    ///
    /// Index `0` is the network address `100.88.0.0` and should be reserved by
    /// the caller (the control plane typically gives index `1` to itself).
    pub fn from_index(index: u32) -> Result<Self, OverlayError> {
        if index > Self::MAX_INDEX {
            return Err(OverlayError::IndexOutOfRange {
                index,
                max: Self::MAX_INDEX,
            });
        }
        let base = u32::from(OVERLAY_IPV4_NET);
        Ok(Self(Ipv4Addr::from(base + index)))
    }

    /// The underlying [`Ipv4Addr`].
    pub fn addr(&self) -> Ipv4Addr {
        self.0
    }

    /// Whether an arbitrary address is inside the overlay `100.88.0.0/16`.
    pub fn contains(addr: Ipv4Addr) -> bool {
        let o = addr.octets();
        o[0] == 100 && o[1] == 88
    }
}

impl fmt::Display for OverlayIpv4 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// An allocated overlay IPv6 address inside `fd88::/48`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OverlayIpv6(Ipv6Addr);

impl OverlayIpv6 {
    /// Allocate an overlay IPv6 address by placing `index` in the low bits of
    /// the `fd88::/48` prefix. The `/48` leaves 80 host bits, so any `u64`
    /// index fits without colliding with the prefix.
    pub fn from_index(index: u64) -> Self {
        let base = u128::from(OVERLAY_IPV6_NET);
        Self(Ipv6Addr::from(base | u128::from(index)))
    }

    /// The underlying [`Ipv6Addr`].
    pub fn addr(&self) -> Ipv6Addr {
        self.0
    }

    /// Whether an arbitrary address is inside the overlay `fd88::/48`.
    pub fn contains(addr: Ipv6Addr) -> bool {
        let s = addr.segments();
        s[0] == 0xfd88 && s[1] == 0 && s[2] == 0
    }
}

impl fmt::Display for OverlayIpv6 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constants_match_the_plan() {
        assert_eq!(TUN_INTERFACE, "akurai0");
        assert_eq!(OVERLAY_MTU, 1280);
        assert_eq!(OVERLAY_IPV4_NET, Ipv4Addr::new(100, 88, 0, 0));
        assert_eq!(OVERLAY_IPV4_PREFIX_LEN, 16);
        assert_eq!(OVERLAY_IPV6_PREFIX_LEN, 48);
    }

    #[test]
    fn ipv4_allocation_from_index() {
        assert_eq!(
            OverlayIpv4::from_index(0).unwrap().addr(),
            Ipv4Addr::new(100, 88, 0, 0)
        );
        assert_eq!(
            OverlayIpv4::from_index(1).unwrap().addr(),
            Ipv4Addr::new(100, 88, 0, 1)
        );
        assert_eq!(
            OverlayIpv4::from_index(256).unwrap().addr(),
            Ipv4Addr::new(100, 88, 1, 0)
        );
        assert_eq!(
            OverlayIpv4::from_index(OverlayIpv4::MAX_INDEX)
                .unwrap()
                .addr(),
            Ipv4Addr::new(100, 88, 255, 255)
        );
    }

    #[test]
    fn ipv4_allocation_rejects_out_of_range() {
        let err = OverlayIpv4::from_index(OverlayIpv4::MAX_INDEX + 1).unwrap_err();
        assert_eq!(
            err,
            OverlayError::IndexOutOfRange {
                index: 65536,
                max: 65535,
            }
        );
    }

    #[test]
    fn ipv4_membership() {
        assert!(OverlayIpv4::contains(Ipv4Addr::new(100, 88, 7, 3)));
        assert!(!OverlayIpv4::contains(Ipv4Addr::new(100, 89, 0, 1)));
        assert!(!OverlayIpv4::contains(Ipv4Addr::new(192, 168, 1, 1)));
    }

    #[test]
    fn ipv6_allocation_and_membership() {
        let ip = OverlayIpv6::from_index(0x42);
        assert_eq!(ip.addr().segments()[0], 0xfd88);
        assert_eq!(ip.addr().segments()[7], 0x42);
        assert!(OverlayIpv6::contains(ip.addr()));
        assert!(!OverlayIpv6::contains(Ipv6Addr::new(
            0xfd99, 0, 0, 0, 0, 0, 0, 1
        )));
    }
}
