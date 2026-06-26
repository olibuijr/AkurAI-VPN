//! The MagicDNS resolver (stub — DO NOT implement here).
//!
//! Maps overlay names in the [`ZONE`] zone to overlay IPs from the control
//! plane's peer map. The UDP/53 server and the name→IP table are not
//! implemented in 0.0.1; [`resolve`] always returns `None` and [`serve`]
//! returns [`DnsError::NotImplemented`].

use std::fmt;
use std::net::IpAddr;

/// The internal DNS zone for overlay names.
pub const ZONE: &str = "*.oli.akurai";

/// Errors from the DNS service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsError {
    /// The DNS server is not implemented in 0.0.1.
    NotImplemented,
}

impl fmt::Display for DnsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DnsError::NotImplemented => {
                write!(f, "DNS server not implemented in 0.0.1")
            }
        }
    }
}

impl std::error::Error for DnsError {}

/// Resolve an overlay name to its overlay IP. **Stub** — always `None` until
/// the peer-map-backed zone table exists.
pub fn resolve(_name: &str) -> Option<IpAddr> {
    None
}

/// Start the DNS server. **Stub** — returns [`DnsError::NotImplemented`].
pub fn serve() -> Result<(), DnsError> {
    Err(DnsError::NotImplemented)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_is_a_stub_in_0_0_1() {
        assert_eq!(resolve("laptop.oli.akurai"), None);
    }
}
