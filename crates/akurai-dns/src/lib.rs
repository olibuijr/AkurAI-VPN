//! `akurai-dns` — the AkurAI VPN internal MagicDNS service (library).
//!
//! Resolves overlay names under a single flat zone (default `akurai`) to a
//! peer's overlay IPv4, so a user can `ping nodeb.akurai` (or the bare label
//! `nodeb`) instead of memorising `100.88.0.3`. The peer/name → IP mapping is
//! supplied by the caller as a closure, so this crate stays free of any
//! control-plane or peer-table dependency.
//!
//! Pure `std`, zero dependencies, no `unsafe`. The DNS wire format lives in
//! [`wire`]; this module is the UDP server and the host-table helpers.

#![forbid(unsafe_code)]

pub mod wire;

pub use wire::{
    build_query, build_response, parse_query, Query, CLASS_IN, RCODE_NOERROR, RCODE_NXDOMAIN,
    TYPE_A, TYPE_AAAA,
};

use std::net::{Ipv4Addr, SocketAddr, UdpSocket};

/// Default answer TTL, in seconds. Overlay names are stable but cheap to
/// re-resolve, so a short TTL keeps clients honest after a peer changes IP.
pub const DEFAULT_TTL: u32 = 60;

/// Maximum size of a (non-EDNS) DNS message over UDP (RFC 1035 §4.2.1).
const MAX_UDP_MSG: usize = 512;

/// Resolve `name` against an in-memory host table, matching case-insensitively.
pub fn resolve_from_hosts(name: &str, hosts: &[(String, Ipv4Addr)]) -> Option<Ipv4Addr> {
    hosts
        .iter()
        .find(|(host, _)| host.eq_ignore_ascii_case(name))
        .map(|(_, ip)| *ip)
}

/// Parse a hosts file: one `<overlay_ip> <name>` per line. Blank lines and `#`
/// comments are ignored; unparseable lines are skipped (fail-open on the file,
/// fail-closed on each record — mirrors the node's peer-file parser).
pub fn parse_hosts(content: &str) -> Vec<(String, Ipv4Addr)> {
    let mut hosts = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.split_whitespace();
        let (Some(ip_s), Some(name)) = (parts.next(), parts.next()) else {
            continue;
        };
        if let Ok(ip) = ip_s.parse::<Ipv4Addr>() {
            hosts.push((name.to_string(), ip));
        }
    }
    hosts
}

/// Strip the trailing `.<zone>` (case-insensitively) and any trailing dot from a
/// queried name, yielding the bare label to look up. Leading/trailing dots in
/// `zone` are ignored, so `akurai`, `.akurai`, and `akurai.` all behave the same.
///
/// - `nodeb.akurai` (zone `akurai`) → `nodeb`
/// - `nodeb.akurai.` → `nodeb`
/// - `nodeb` → `nodeb` (already bare)
/// - `other.example` → `other.example` (left untouched)
pub fn strip_zone<'a>(name: &'a str, zone: &str) -> &'a str {
    let trimmed = name.strip_suffix('.').unwrap_or(name);
    let zone = zone.trim_matches('.');
    if zone.is_empty() {
        return trimmed;
    }
    // `to_ascii_lowercase` only rewrites ASCII A–Z and preserves every byte
    // boundary, so the stripped length is a valid index back into `trimmed`.
    let lower = trimmed.to_ascii_lowercase();
    let suffix = format!(".{}", zone.to_ascii_lowercase());
    match lower.strip_suffix(&suffix) {
        Some(head) if !head.is_empty() => &trimmed[..head.len()],
        _ => trimmed,
    }
}

/// Bind a UDP socket at `bind` and serve MagicDNS for `zone` forever.
///
/// The loop blocks on `recv_from` (no busy-wait), parses each datagram as a
/// query, strips the zone suffix, calls `resolve(label)`, and replies. Malformed
/// datagrams are dropped and serving continues; only a hard socket error stops
/// the loop. This call blocks and normally never returns.
pub fn serve(
    bind: SocketAddr,
    zone: &str,
    resolve: impl Fn(&str) -> Option<Ipv4Addr> + Send + Sync + 'static,
) -> std::io::Result<()> {
    let socket = UdpSocket::bind(bind)?;
    let zone = zone.to_string();
    let mut buf = [0u8; MAX_UDP_MSG];
    loop {
        let (n, src) = match socket.recv_from(&mut buf) {
            Ok(pair) => pair,
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        let Some(query) = wire::parse_query(&buf[..n]) else {
            continue; // survive malformed datagrams
        };
        let label = strip_zone(&query.name, &zone);
        let resolved = resolve(label);
        let response = wire::build_response(&query, resolved, DEFAULT_TTL);
        let _ = socket.send_to(&response, src);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_from_hosts_is_case_insensitive() {
        let hosts = vec![("nodeb".to_string(), Ipv4Addr::new(100, 88, 0, 3))];
        assert_eq!(
            resolve_from_hosts("nodeb", &hosts),
            Some(Ipv4Addr::new(100, 88, 0, 3))
        );
        assert_eq!(
            resolve_from_hosts("NodeB", &hosts),
            Some(Ipv4Addr::new(100, 88, 0, 3))
        );
        assert_eq!(resolve_from_hosts("nodec", &hosts), None);
    }

    #[test]
    fn strip_zone_handles_suffix_and_bare_label() {
        assert_eq!(strip_zone("nodeb.akurai", "akurai"), "nodeb");
        assert_eq!(strip_zone("nodeb.akurai.", "akurai"), "nodeb"); // trailing dot
        assert_eq!(strip_zone("NODEB.AKURAI", "akurai"), "NODEB"); // case-insensitive
        assert_eq!(strip_zone("nodeb", "akurai"), "nodeb"); // already bare
        assert_eq!(strip_zone("nodeb.akurai", ".akurai."), "nodeb"); // zone dots ignored
        assert_eq!(strip_zone("other.example", "akurai"), "other.example");
        assert_eq!(strip_zone("anything", ""), "anything"); // empty zone is a no-op
    }

    #[test]
    fn parse_hosts_reads_ip_name_lines() {
        let content = "# overlay hosts\n100.88.0.3 nodeb\n100.88.0.4   nodec\n\nbroken line\nnot-an-ip nodee\n";
        let hosts = parse_hosts(content);
        assert_eq!(hosts.len(), 2);
        assert_eq!(
            hosts[0],
            ("nodeb".to_string(), Ipv4Addr::new(100, 88, 0, 3))
        );
        assert_eq!(
            hosts[1],
            ("nodec".to_string(), Ipv4Addr::new(100, 88, 0, 4))
        );
    }

    #[test]
    fn end_to_end_resolve_via_hosts() {
        let hosts = parse_hosts("100.88.0.3 nodeb\n");
        let label = strip_zone("nodeb.akurai", "akurai");
        assert_eq!(
            resolve_from_hosts(label, &hosts),
            Some(Ipv4Addr::new(100, 88, 0, 3))
        );
    }
}
