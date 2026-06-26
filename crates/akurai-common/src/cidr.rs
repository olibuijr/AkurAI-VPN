//! CIDR prefixes — route blocks and membership tests.
//!
//! Routes (advertised subnets, exit defaults, allowed-inbound ranges) are all
//! CIDR blocks. [`Cidr`] is a tiny, pure-`std` value type with a correct
//! prefix-mask membership test for both IPv4 and IPv6.

use std::fmt;
use std::net::IpAddr;

/// Errors constructing a [`Cidr`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CidrError {
    /// The prefix length exceeds the address family's bit width.
    PrefixTooLong { prefix_len: u8, max: u8 },
}

impl fmt::Display for CidrError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CidrError::PrefixTooLong { prefix_len, max } => {
                write!(f, "prefix length /{prefix_len} exceeds maximum /{max}")
            }
        }
    }
}

impl std::error::Error for CidrError {}

/// A CIDR block: a base address plus a prefix length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    addr: IpAddr,
    prefix_len: u8,
}

impl Cidr {
    /// Construct a CIDR, validating the prefix length against the family width
    /// (`/32` max for IPv4, `/128` max for IPv6).
    pub fn new(addr: IpAddr, prefix_len: u8) -> Result<Self, CidrError> {
        let max = match addr {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        if prefix_len > max {
            return Err(CidrError::PrefixTooLong { prefix_len, max });
        }
        Ok(Self { addr, prefix_len })
    }

    /// The base address of the block.
    pub fn addr(&self) -> IpAddr {
        self.addr
    }

    /// The prefix length.
    pub fn prefix_len(&self) -> u8 {
        self.prefix_len
    }

    /// Whether `ip` falls inside this block. Mixed-family comparisons are
    /// always `false`.
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(test)) => {
                let mask = v4_mask(self.prefix_len);
                (u32::from(net) & mask) == (u32::from(test) & mask)
            }
            (IpAddr::V6(net), IpAddr::V6(test)) => {
                let mask = v6_mask(self.prefix_len);
                (u128::from(net) & mask) == (u128::from(test) & mask)
            }
            _ => false,
        }
    }
}

impl fmt::Display for Cidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix_len)
    }
}

fn v4_mask(prefix_len: u8) -> u32 {
    if prefix_len == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(prefix_len))
    }
}

fn v6_mask(prefix_len: u8) -> u128 {
    if prefix_len == 0 {
        0
    } else {
        u128::MAX << (128 - u32::from(prefix_len))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    #[test]
    fn ipv4_membership() {
        let net = Cidr::new(v4(192, 168, 1, 0), 24).unwrap();
        assert!(net.contains(v4(192, 168, 1, 5)));
        assert!(net.contains(v4(192, 168, 1, 255)));
        assert!(!net.contains(v4(192, 168, 2, 5)));
    }

    #[test]
    fn default_route_contains_everything() {
        let default = Cidr::new(v4(0, 0, 0, 0), 0).unwrap();
        assert!(default.contains(v4(8, 8, 8, 8)));
        assert!(default.contains(v4(192, 168, 1, 1)));
    }

    #[test]
    fn mixed_family_never_matches() {
        let net = Cidr::new(v4(10, 0, 0, 0), 8).unwrap();
        assert!(!net.contains(IpAddr::V6(Ipv6Addr::LOCALHOST)));
    }

    #[test]
    fn rejects_overlong_prefix() {
        let err = Cidr::new(v4(10, 0, 0, 0), 33).unwrap_err();
        assert_eq!(
            err,
            CidrError::PrefixTooLong {
                prefix_len: 33,
                max: 32,
            }
        );
    }

    #[test]
    fn ipv6_membership() {
        let net = Cidr::new(IpAddr::V6(Ipv6Addr::new(0xfd88, 0, 0, 0, 0, 0, 0, 0)), 48).unwrap();
        assert!(net.contains(IpAddr::V6(Ipv6Addr::new(0xfd88, 0, 0, 1, 2, 3, 4, 5))));
        assert!(!net.contains(IpAddr::V6(Ipv6Addr::new(0xfd99, 0, 0, 0, 0, 0, 0, 1))));
    }
}
