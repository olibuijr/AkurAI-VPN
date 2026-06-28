//! TUN device management.
//!
//! The first AkurAI-VPN node release is host-only. It intentionally does not
//! create a TUN interface or install routes; only machines with the node
//! software installed should be reachable.

pub fn host_only_notice(interface: &str) {
    eprintln!("akurai-node: host-only mode; not creating {interface} or installing routes");
}
