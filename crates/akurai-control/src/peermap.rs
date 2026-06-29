//! Peer-map generation (control-plane).
//!
//! Builds the per-node view of the network — for a given user, the set of their
//! own [`VpnEndpoint`]s a node may reach, minus the requesting node itself, each
//! tagged with its overlay IPv4 and current liveness. The data-plane node polls
//! this to learn its peers. The ACL-filtered watch stream is not implemented in
//! 0.0.1; this is the snapshot endpoint that backs it.

use std::collections::HashMap;

use crate::heartbeat::{self, Heartbeat};
use crate::ipam;
use crate::vpn_endpoint::VpnEndpoint;

/// Build the JSON array of peers visible to `user_email`.
///
/// Scope rules:
/// * only endpoints with `added_by == user_email` are included (per-user tenancy);
/// * the caller's own node, named by `self_id`, is excluded — when `self_id` is
///   `None`, nothing is excluded on that basis.
///
/// Each element is `{"overlay_ipv4","public_key","name","online"}`. `online` is
/// `true` when a fresh heartbeat exists for that node id (see
/// [`heartbeat::is_online`]). Hand-rolled JSON — no serde.
pub fn build_peermap_json(
    endpoints: &[VpnEndpoint],
    heartbeats: &HashMap<String, Heartbeat>,
    user_email: &str,
    self_id: Option<&str>,
    now: u64,
) -> String {
    let peers = endpoints
        .iter()
        .filter(|e| e.added_by == user_email)
        .filter(|e| self_id != Some(e.id.as_str()))
        .map(|e| peer_json(e, heartbeats, now))
        .collect::<Vec<_>>()
        .join(",");
    format!("[{peers}]\n")
}

/// Serialize one peer to a JSON object string.
fn peer_json(e: &VpnEndpoint, heartbeats: &HashMap<String, Heartbeat>, now: u64) -> String {
    let overlay = ipam::overlay_addr_string(&e.allowed_ips).unwrap_or_default();
    let online = heartbeats
        .get(&e.id)
        .map(|hb| heartbeat::is_online(hb.last_seen, now))
        .unwrap_or(false);
    format!(
        "{{\"overlay_ipv4\":\"{}\",\"public_key\":\"{}\",\"name\":\"{}\",\"online\":{}}}",
        json_esc(&overlay),
        json_esc(&e.public_key),
        json_esc(&e.name),
        online,
    )
}

fn json_esc(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
}

/// One-line status of the peer-map subsystem.
pub fn status() -> String {
    "peermap: per-user peer view active (overlay IP + liveness); watch stream not implemented"
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ep(id: &str, added_by: &str, allowed: &[&str]) -> VpnEndpoint {
        VpnEndpoint {
            id: id.to_string(),
            name: format!("name-{id}"),
            public_key: format!("pk-{id}"),
            endpoint_addr: String::new(),
            allowed_ips: allowed.iter().map(|s| s.to_string()).collect(),
            added_by: added_by.to_string(),
            added_at: 1,
        }
    }

    fn fresh(now: u64) -> Heartbeat {
        Heartbeat {
            endpoint: "203.0.113.1:51820".to_string(),
            last_seen: now,
        }
    }

    #[test]
    fn peermap_is_scoped_to_the_user() {
        let endpoints = vec![
            ep("mine", "user@example.com", &["100.88.0.2/32"]),
            ep("theirs", "other@example.com", &["100.88.0.3/32"]),
        ];
        let hbs = HashMap::new();
        let json = build_peermap_json(&endpoints, &hbs, "user@example.com", None, 1_000);
        assert!(json.contains("name-mine"));
        // Another user's node never appears in the caller's peer map.
        assert!(!json.contains("name-theirs"));
        assert!(!json.contains("100.88.0.3"));
    }

    #[test]
    fn peermap_excludes_the_self_node() {
        let endpoints = vec![
            ep("self", "user@example.com", &["100.88.0.2/32"]),
            ep("peer", "user@example.com", &["100.88.0.3/32"]),
        ];
        let hbs = HashMap::new();
        let json = build_peermap_json(&endpoints, &hbs, "user@example.com", Some("self"), 1_000);
        assert!(!json.contains("name-self"));
        assert!(!json.contains("100.88.0.2"));
        assert!(json.contains("name-peer"));
        assert!(json.contains("100.88.0.3"));
    }

    #[test]
    fn peermap_no_self_param_excludes_nothing() {
        let endpoints = vec![ep("a", "user@example.com", &["100.88.0.2/32"])];
        let hbs = HashMap::new();
        let json = build_peermap_json(&endpoints, &hbs, "user@example.com", None, 1_000);
        assert!(json.contains("name-a"));
    }

    #[test]
    fn online_is_false_without_a_heartbeat() {
        let endpoints = vec![ep("a", "user@example.com", &["100.88.0.2/32"])];
        let hbs = HashMap::new();
        let json = build_peermap_json(&endpoints, &hbs, "user@example.com", None, 1_000);
        assert!(json.contains("\"online\":false"));
    }

    #[test]
    fn online_is_true_with_a_fresh_heartbeat() {
        let endpoints = vec![ep("a", "user@example.com", &["100.88.0.2/32"])];
        let now = 1_000;
        let mut hbs = HashMap::new();
        hbs.insert("a".to_string(), fresh(now));
        let json = build_peermap_json(&endpoints, &hbs, "user@example.com", None, now);
        assert!(json.contains("\"online\":true"));
    }

    #[test]
    fn online_flips_false_when_heartbeat_is_older_than_ttl() {
        let endpoints = vec![ep("a", "user@example.com", &["100.88.0.2/32"])];
        let last_seen = 1_000;
        let mut hbs = HashMap::new();
        hbs.insert(
            "a".to_string(),
            Heartbeat {
                endpoint: String::new(),
                last_seen,
            },
        );
        // One second past the TTL window -> offline.
        let now = last_seen + heartbeat::HEARTBEAT_TTL_SECS + 1;
        let json = build_peermap_json(&endpoints, &hbs, "user@example.com", None, now);
        assert!(json.contains("\"online\":false"));
    }

    #[test]
    fn peer_json_carries_overlay_ipv4_and_public_key() {
        let endpoints = vec![ep("a", "user@example.com", &["100.88.0.7/32"])];
        let hbs = HashMap::new();
        let json = build_peermap_json(&endpoints, &hbs, "user@example.com", None, 1_000);
        assert!(json.contains("\"overlay_ipv4\":\"100.88.0.7\""));
        assert!(json.contains("\"public_key\":\"pk-a\""));
    }

    #[test]
    fn overlay_ipv4_is_empty_string_when_node_has_no_overlay_address() {
        let endpoints = vec![ep("a", "user@example.com", &["0.0.0.0/0"])];
        let hbs = HashMap::new();
        let json = build_peermap_json(&endpoints, &hbs, "user@example.com", None, 1_000);
        assert!(json.contains("\"overlay_ipv4\":\"\""));
    }
}
