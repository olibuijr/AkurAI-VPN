//! The peer table — who this node may reach over the overlay.
//!
//! A peer is an overlay IPv4 plus the X25519 public key needed to open a
//! Noise_IK session to it. The table is loaded from one of two sources:
//!
//! - a static `config/peers` file (`<overlay_ip> <pubkey_b64> <name>` per line) —
//!   used for tests and offline bring-up, and
//! - the control plane's `GET /api/peermap`, fetched via `curl` (pure-std has no
//!   TLS client; the node already shells to `ip`, so `curl` is consistent).
//!
//! Fail-closed: a line/peer that does not parse is skipped, and a packet to a
//! destination not in the table is dropped by the data plane.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;
use std::process::Command;

use akurai_common::b64;
use akurai_common::{Cidr, Principal, Tag};

/// One reachable overlay peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Peer {
    pub overlay_ip: Ipv4Addr,
    pub public_key: [u8; 32],
    pub name: String,
    /// Subnets this peer is an approved gateway for (MVP2 subnet routing). A
    /// packet whose destination falls in one of these is tunnelled to this peer,
    /// which forwards it to the real subnet behind it.
    pub advertised: Vec<Cidr>,
    /// ACL tags this peer carries (MVP4 fine-grained ACLs). These are the
    /// destination principals the policy evaluator matches a `tag:X -> tag:Y`
    /// rule against. Empty ⇒ the peer matches only `tag:*` wildcard rules.
    pub tags: Vec<Tag>,
}

/// Overlay-IP-indexed peer table.
#[derive(Debug, Clone, Default)]
pub struct PeerTable {
    by_ip: HashMap<Ipv4Addr, Peer>,
}

impl PeerTable {
    pub fn from_peers(peers: Vec<Peer>) -> Self {
        let mut by_ip = HashMap::new();
        for p in peers {
            by_ip.insert(p.overlay_ip, p);
        }
        Self { by_ip }
    }

    pub fn get(&self, ip: &Ipv4Addr) -> Option<&Peer> {
        self.by_ip.get(ip)
    }

    /// The destination principals a peer presents to the ACL evaluator: its
    /// tags as [`Principal::Tag`]. The `from` side of an evaluation is THIS
    /// node's own principals (see `acl::Acl`).
    pub fn peer_principals(peer: &Peer) -> Vec<Principal> {
        peer.tags.iter().cloned().map(Principal::Tag).collect()
    }

    /// Resolve a destination IPv4 to the peer that should carry it: an exact
    /// overlay-IP match first, otherwise the peer advertising a subnet that
    /// contains it (MVP2 subnet routing). `None` ⇒ fail-closed drop.
    pub fn route_to(&self, dest: &Ipv4Addr) -> Option<&Peer> {
        if let Some(p) = self.by_ip.get(dest) {
            return Some(p);
        }
        self.by_ip
            .values()
            .find(|p| p.advertised.iter().any(|c| c.contains(IpAddr::V4(*dest))))
    }

    /// Resolve any destination IP (v4 or v6) to the carrying peer. The IPv6
    /// overlay address of a peer is derived from its overlay-IPv4 host index
    /// (so `100.88.0.2` ↔ `fd88::2`) — sessions stay keyed by the IPv4 overlay IP.
    pub fn route_to_ip(&self, dest: IpAddr) -> Option<&Peer> {
        match dest {
            IpAddr::V4(v4) => self.route_to(&v4),
            IpAddr::V6(v6) => self.by_ip.values().find(|p| {
                let idx = u32::from(p.overlay_ip)
                    .wrapping_sub(u32::from(akurai_common::OVERLAY_IPV4_NET));
                akurai_common::OverlayIpv6::from_index(idx as u64).addr() == v6
            }),
        }
    }

    /// Resolve a peer NAME (case-insensitive) to its overlay IP — MagicDNS.
    pub fn resolve_name(&self, name: &str) -> Option<Ipv4Addr> {
        let want = name.trim().to_ascii_lowercase();
        if want.is_empty() {
            return None;
        }
        self.by_ip
            .values()
            .find(|p| p.name.to_ascii_lowercase() == want)
            .map(|p| p.overlay_ip)
    }

    /// Every (subnet, gateway-peer-overlay-IP) pair, for installing routes that
    /// point advertised subnets at the overlay interface.
    pub fn advertised_routes(&self) -> Vec<(Cidr, Ipv4Addr)> {
        self.by_ip
            .values()
            .flat_map(|p| p.advertised.iter().map(|c| (*c, p.overlay_ip)))
            .collect()
    }

    pub fn len(&self) -> usize {
        self.by_ip.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_ip.is_empty()
    }

    /// Load from a static `peers` file. Missing file ⇒ empty table (not an error).
    pub fn load_file(path: &Path) -> Self {
        let content = std::fs::read_to_string(path).unwrap_or_default();
        Self::from_peers(parse_peers_file(&content))
    }

    /// Fetch from the control plane's `/api/peermap` via `curl` with the saved
    /// session cookie jar. Returns an empty table on any curl/parse failure (the
    /// caller decides whether to fall back to the static file).
    pub fn fetch(control_url: &str, cookie_jar: &Path) -> Self {
        let out = Command::new("curl")
            .args([
                "-fsSL",
                "-b",
                &cookie_jar.to_string_lossy(),
                &format!("{}/api/peermap", control_url.trim_end_matches('/')),
            ])
            .output();
        match out {
            Ok(o) if o.status.success() => {
                Self::from_peers(parse_peermap_json(&String::from_utf8_lossy(&o.stdout)))
            }
            _ => Self::default(),
        }
    }

    /// Fetch from the control plane's `/api/peermap` via `curl` with a durable
    /// node bearer token. Preferred over [`PeerTable::fetch`] when a token is
    /// available — the request does not depend on an unexpired session cookie.
    /// Returns an empty table on any curl/parse failure.
    pub fn fetch_with_token(control_url: &str, token: &str) -> Self {
        let out = Command::new("curl")
            .args([
                "-fsSL",
                "-H",
                &format!("Authorization: Bearer {token}"),
                &format!("{}/api/peermap", control_url.trim_end_matches('/')),
            ])
            .output();
        match out {
            Ok(o) if o.status.success() => {
                Self::from_peers(parse_peermap_json(&String::from_utf8_lossy(&o.stdout)))
            }
            _ => Self::default(),
        }
    }
}

/// Parse a static peers file: one
/// `<overlay_ip> <pubkey_b64> [name] [advertised] [tags]` per line, e.g.
/// `100.88.0.3 <pubkey> nodeb 192.168.50.0/24 tag:server,tag:trusted`.
/// The 4th field is comma-separated advertised CIDRs (`-` or any non-CIDR
/// token ⇒ none, which lets a tagged peer with no subnets keep the 5th field
/// positional). The 5th field is comma-separated ACL tags (`tag:` prefix
/// optional). Blank lines and `#` comments are ignored; unparseable lines are
/// skipped.
pub fn parse_peers_file(content: &str) -> Vec<Peer> {
    let mut peers = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.split_whitespace();
        let (Some(ip_s), Some(pk_s)) = (parts.next(), parts.next()) else {
            continue;
        };
        let name = parts.next().unwrap_or("").to_string();
        // Optional 4th field: comma-separated advertised subnets (gateway peer).
        let advertised = parts
            .next()
            .map(|s| s.split(',').filter_map(parse_cidr).collect())
            .unwrap_or_default();
        // Optional 5th field: comma-separated ACL tags.
        let tags = parts.next().map(parse_tags).unwrap_or_default();
        if let (Ok(ip), Some(pk)) = (ip_s.parse::<Ipv4Addr>(), b64::decode_array::<32>(pk_s)) {
            peers.push(Peer {
                overlay_ip: ip,
                public_key: pk,
                name,
                advertised,
                tags,
            });
        }
    }
    peers
}

/// Parse a comma-separated ACL tag list (`tag:server,tag:trusted`, or bare
/// `server,trusted`) into [`Tag`]s, stripping an optional `tag:` prefix and
/// dropping empty entries.
pub fn parse_tags(s: &str) -> Vec<Tag> {
    s.split(',')
        .filter_map(|t| {
            let name = t.trim().strip_prefix("tag:").unwrap_or(t.trim()).trim();
            (!name.is_empty()).then(|| Tag(name.to_string()))
        })
        .collect()
}

/// Parse a CIDR like `192.168.50.0/24` into an [`akurai_common::Cidr`].
pub fn parse_cidr(s: &str) -> Option<Cidr> {
    let s = s.trim();
    let (addr_s, prefix_s) = s.split_once('/')?;
    let addr: IpAddr = addr_s.parse().ok()?;
    let prefix: u8 = prefix_s.parse().ok()?;
    Cidr::new(addr, prefix).ok()
}

/// Parse the control plane's peer-map JSON array
/// (`[{"overlay_ipv4":"..","public_key":"..","name":"..","online":..}]`).
/// Hand-rolled, dependency-free; skips malformed objects.
pub fn parse_peermap_json(json: &str) -> Vec<Peer> {
    let mut peers = Vec::new();
    // Each object is delimited by braces; split conservatively on '}'.
    for obj in json.split('}') {
        let (Some(ip_s), Some(pk_s)) = (
            json_str_field(obj, "overlay_ipv4"),
            json_str_field(obj, "public_key"),
        ) else {
            continue;
        };
        let name = json_str_field(obj, "name").unwrap_or_default();
        // The control plane's peer map may carry comma-separated advertised
        // subnets in an "advertised" field; absent in MVP1 → empty.
        let advertised = json_str_field(obj, "advertised")
            .map(|s| s.split(',').filter_map(parse_cidr).collect())
            .unwrap_or_default();
        // Likewise an optional comma-separated "tags" field for fine-grained
        // ACLs; absent → untagged.
        let tags = json_str_field(obj, "tags")
            .map(|s| parse_tags(&s))
            .unwrap_or_default();
        if let (Ok(ip), Some(pk)) = (ip_s.parse::<Ipv4Addr>(), b64::decode_array::<32>(&pk_s)) {
            peers.push(Peer {
                overlay_ip: ip,
                public_key: pk,
                name,
                advertised,
                tags,
            });
        }
    }
    peers
}

/// Extract a `"key":"value"` string field from a JSON fragment (no escapes in
/// our values — overlay IPs, Base64, and names are escape-free).
fn json_str_field(fragment: &str, key: &str) -> Option<String> {
    let needle = format!("\"{key}\"");
    let pos = fragment.find(&needle)? + needle.len();
    let rest = fragment[pos..].trim_start();
    let rest = rest.strip_prefix(':')?.trim_start();
    let rest = rest.strip_prefix('"')?;
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pk(seed: u8) -> [u8; 32] {
        [seed; 32]
    }

    #[test]
    fn parses_static_peers_file() {
        let pk_b64 = b64::encode(&pk(7));
        let content =
            format!("# a comment\n100.88.0.3 {pk_b64} laptop\n\n100.88.0.4 {pk_b64}\nbogus line\n");
        let peers = parse_peers_file(&content);
        assert_eq!(peers.len(), 2);
        assert_eq!(peers[0].overlay_ip, Ipv4Addr::new(100, 88, 0, 3));
        assert_eq!(peers[0].public_key, pk(7));
        assert_eq!(peers[0].name, "laptop");
        assert_eq!(peers[1].name, ""); // name optional
    }

    #[test]
    fn skips_unparseable_lines() {
        let peers = parse_peers_file("not-an-ip badkey\n999.999.999.999 x\n");
        assert!(peers.is_empty());
    }

    #[test]
    fn parses_control_peermap_json() {
        let pk_b64 = b64::encode(&pk(9));
        let json = format!(
            "[{{\"overlay_ipv4\":\"100.88.0.5\",\"public_key\":\"{pk_b64}\",\"name\":\"phone\",\"online\":true}}]"
        );
        let peers = parse_peermap_json(&json);
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].overlay_ip, Ipv4Addr::new(100, 88, 0, 5));
        assert_eq!(peers[0].public_key, pk(9));
        assert_eq!(peers[0].name, "phone");
    }

    #[test]
    fn table_lookup_by_ip() {
        let t = PeerTable::from_peers(vec![Peer {
            overlay_ip: Ipv4Addr::new(100, 88, 0, 3),
            public_key: pk(1),
            name: "b".into(),
            advertised: vec![],
            tags: vec![],
        }]);
        assert!(t.get(&Ipv4Addr::new(100, 88, 0, 3)).is_some());
        assert!(t.get(&Ipv4Addr::new(100, 88, 0, 9)).is_none());
    }

    #[test]
    fn parses_advertised_subnets() {
        let pk_b64 = b64::encode(&pk(3));
        let peers = parse_peers_file(&format!(
            "100.88.0.3 {pk_b64} gw 192.168.50.0/24,10.20.0.0/16\n"
        ));
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].advertised.len(), 2);
    }

    #[test]
    fn route_to_prefers_exact_then_subnet() {
        let t = PeerTable::from_peers(vec![Peer {
            overlay_ip: Ipv4Addr::new(100, 88, 0, 3),
            public_key: pk(1),
            name: "gw".into(),
            advertised: vec![parse_cidr("192.168.50.0/24").unwrap()],
            tags: vec![],
        }]);
        // Exact overlay IP.
        assert_eq!(
            t.route_to(&Ipv4Addr::new(100, 88, 0, 3)).unwrap().name,
            "gw"
        );
        // A subnet IP routes via the advertising gateway.
        assert_eq!(
            t.route_to(&Ipv4Addr::new(192, 168, 50, 7)).unwrap().name,
            "gw"
        );
        // Outside any subnet / overlay → fail-closed.
        assert!(t.route_to(&Ipv4Addr::new(8, 8, 8, 8)).is_none());
        assert_eq!(t.advertised_routes().len(), 1);
    }

    #[test]
    fn parses_peer_tags() {
        let pk_b64 = b64::encode(&pk(4));
        // 5th field tags, alongside an advertised subnet in the 4th.
        let with_subnet = parse_peers_file(&format!(
            "100.88.0.3 {pk_b64} srv 192.168.50.0/24 tag:server,tag:trusted\n"
        ));
        assert_eq!(with_subnet[0].advertised.len(), 1);
        assert_eq!(
            with_subnet[0].tags,
            vec![Tag("server".into()), Tag("trusted".into())]
        );
        // Tags with no advertised subnets: `-` placeholder keeps the field positional.
        let no_subnet = parse_peers_file(&format!("100.88.0.4 {pk_b64} ws - tag:workstation\n"));
        assert!(no_subnet[0].advertised.is_empty());
        assert_eq!(no_subnet[0].tags, vec![Tag("workstation".into())]);
        // No 5th field → untagged.
        let bare = parse_peers_file(&format!("100.88.0.5 {pk_b64} bare\n"));
        assert!(bare[0].tags.is_empty());
    }

    #[test]
    fn peer_principals_are_tag_principals() {
        let p = Peer {
            overlay_ip: Ipv4Addr::new(100, 88, 0, 3),
            public_key: pk(1),
            name: "x".into(),
            advertised: vec![],
            tags: vec![Tag("server".into()), Tag("trusted".into())],
        };
        assert_eq!(
            PeerTable::peer_principals(&p),
            vec![
                Principal::Tag(Tag("server".into())),
                Principal::Tag(Tag("trusted".into())),
            ]
        );
    }
}
