//! Peer-map handling.
//!
//! Initial host-only mode does not subscribe to subnet, exit, or gateway route
//! updates. The peer map will only contain AkurAI-VPN nodes once enrollment is
//! implemented.

pub fn host_only_notice() {
    eprintln!("akurai-node: host-only peer map; subnet and exit routes disabled");
}
