//! Binary glue between the CLI and the [`akurai_dns`] library: load a hosts file
//! and either serve MagicDNS or resolve a single name from it.

use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;

/// Default flat zone for overlay names (`<label>.akurai`).
pub const DEFAULT_ZONE: &str = "akurai";
/// Default UDP bind address. Loopback so an unprivileged dev run never fights
/// the system resolver; production binds the overlay address explicitly.
pub const DEFAULT_BIND: &str = "127.0.0.1:53";

/// Load a hosts file (`<overlay_ip> <name>` per line) into a name table.
pub fn load_hosts(path: &Path) -> std::io::Result<Vec<(String, Ipv4Addr)>> {
    let content = std::fs::read_to_string(path)?;
    Ok(akurai_dns::parse_hosts(&content))
}

/// Serve MagicDNS for `zone` on `bind`, answering from the static `hosts` table.
pub fn serve(
    bind: SocketAddr,
    zone: String,
    hosts: Vec<(String, Ipv4Addr)>,
) -> std::io::Result<()> {
    akurai_dns::serve(bind, &zone, move |label| {
        akurai_dns::resolve_from_hosts(label, &hosts)
    })
}

/// Resolve a single (possibly zone-qualified) name against the `hosts` table.
pub fn resolve(name: &str, zone: &str, hosts: &[(String, Ipv4Addr)]) -> Option<Ipv4Addr> {
    let label = akurai_dns::strip_zone(name, zone);
    akurai_dns::resolve_from_hosts(label, hosts)
}
