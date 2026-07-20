//! Peer-map generation (control-plane).
//!
//! Builds the per-node view of the network — for a given user, the set of their
//! own [`VpnEndpoint`]s a node may reach, minus the requesting node itself, each
//! tagged with its overlay IPv4, current liveness, and best direct UDP endpoint
//! candidate. The data-plane node polls this to learn its peers. The ACL-filtered
//! watch stream is not implemented in 0.0.1; this is the snapshot endpoint that
//! backs it.

use std::collections::HashMap;

use crate::heartbeat::{self, Heartbeat};
use crate::ipam;
use crate::vpn_endpoint::VpnEndpoint;

/// Build the JSON array of peers visible to one organization/workspace.
///
/// Only active devices in the exact tenant boundary are included. The caller's
/// own node, named by `self_id`, is excluded.
pub fn build_peermap_json(
    endpoints: &[VpnEndpoint],
    heartbeats: &HashMap<String, Heartbeat>,
    organization_id: &str,
    workspace_id: &str,
    self_id: Option<&str>,
    now: u64,
) -> String {
    let peers = endpoints
        .iter()
        .filter(|e| e.is_active() && e.belongs_to(organization_id, workspace_id))
        .filter(|e| self_id != Some(e.id.as_str()))
        .map(|e| peer_json(e, heartbeats, now))
        .collect::<Vec<_>>()
        .join(",");
    format!("[{peers}]\n")
}

/// Serialize one peer to a JSON object string.
fn peer_json(e: &VpnEndpoint, heartbeats: &HashMap<String, Heartbeat>, now: u64) -> String {
    let overlay = ipam::overlay_addr_string(&e.allowed_ips).unwrap_or_default();
    let hb = heartbeats.get(&e.id);
    let online = hb
        .map(|hb| heartbeat::is_online(hb.last_seen, now))
        .unwrap_or(false);
    let endpoint = if online {
        hb.map(|h| h.endpoint.trim()).filter(|s| !s.is_empty())
    } else {
        None
    }
    .or_else(|| {
        let saved = e.endpoint_addr.trim();
        (!saved.is_empty()).then_some(saved)
    })
    .unwrap_or("");
    format!(
        "{{\"overlay_ipv4\":\"{}\",\"public_key\":\"{}\",\"name\":\"{}\",\"online\":{},\"endpoint\":\"{}\"}}",
        json_esc(&overlay),
        json_esc(&e.public_key),
        json_esc(&e.name),
        online,
        json_esc(endpoint),
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

    fn ep(id: &str, org_id: &str, ws_id: &str, allowed: &[&str]) -> VpnEndpoint {
        VpnEndpoint {
            id: id.to_string(),
            name: format!("name-{id}"),
            public_key: format!("pk-{id}"),
            allowed_ips: allowed.iter().map(|s| s.to_string()).collect(),
            added_by: format!("{org_id}@example.com"),
            added_at: 1,
            organization_id: org_id.to_string(),
            workspace_id: ws_id.to_string(),
            ..Default::default()
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
            ep("mine", "org-1", "ws-1", &["100.88.0.2/32"]),
            ep("theirs", "org-2", "ws-2", &["100.88.0.3/32"]),
        ];
        let hbs = HashMap::new();
        let json = build_peermap_json(&endpoints, &hbs, "org-1", "ws-1", None, 1_000);
        assert!(json.contains("name-mine"));
        // Another tenant's node never appears in the caller's peer map.
        assert!(!json.contains("name-theirs"));
        assert!(!json.contains("100.88.0.3"));
    }

    #[test]
    fn peermap_excludes_the_self_node() {
        let endpoints = vec![
            ep("self", "org-1", "ws-1", &["100.88.0.2/32"]),
            ep("peer", "org-1", "ws-1", &["100.88.0.3/32"]),
        ];
        let hbs = HashMap::new();
        let json = build_peermap_json(&endpoints, &hbs, "org-1", "ws-1", Some("self"), 1_000);
        assert!(!json.contains("name-self"));
        assert!(!json.contains("100.88.0.2"));
        assert!(json.contains("name-peer"));
        assert!(json.contains("100.88.0.3"));
    }

    #[test]
    fn peermap_no_self_param_excludes_nothing() {
        let endpoints = vec![ep("a", "org-1", "ws-1", &["100.88.0.2/32"])];
        let hbs = HashMap::new();
        let json = build_peermap_json(&endpoints, &hbs, "org-1", "ws-1", None, 1_000);
        assert!(json.contains("name-a"));
    }

    #[test]
    fn online_is_false_without_a_heartbeat() {
        let endpoints = vec![ep("a", "org-1", "ws-1", &["100.88.0.2/32"])];
        let hbs = HashMap::new();
        let json = build_peermap_json(&endpoints, &hbs, "org-1", "ws-1", None, 1_000);
        assert!(json.contains("\"online\":false"));
    }

    #[test]
    fn online_is_true_with_a_fresh_heartbeat() {
        let endpoints = vec![ep("a", "org-1", "ws-1", &["100.88.0.2/32"])];
        let now = 1_000;
        let mut hbs = HashMap::new();
        hbs.insert("a".to_string(), fresh(now));
        let json = build_peermap_json(&endpoints, &hbs, "org-1", "ws-1", None, now);
        assert!(json.contains("\"online\":true"));
    }

    #[test]
    fn fresh_heartbeat_endpoint_is_included() {
        let endpoints = vec![ep("a", "org-1", "ws-1", &["100.88.0.2/32"])];
        let now = 1_000;
        let mut hbs = HashMap::new();
        hbs.insert(
            "a".to_string(),
            Heartbeat {
                endpoint: "192.168.1.44:51399".to_string(),
                last_seen: now,
            },
        );
        let json = build_peermap_json(&endpoints, &hbs, "org-1", "ws-1", None, now);
        assert!(json.contains("\"endpoint\":\"192.168.1.44:51399\""));
    }

    #[test]
    fn stale_heartbeat_endpoint_is_not_included() {
        let endpoints = vec![ep("a", "org-1", "ws-1", &["100.88.0.2/32"])];
        let mut hbs = HashMap::new();
        hbs.insert(
            "a".to_string(),
            Heartbeat {
                endpoint: "192.168.1.44:51399".to_string(),
                last_seen: 1_000,
            },
        );
        let json = build_peermap_json(
            &endpoints,
            &hbs,
            "org-1",
            "ws-1",
            None,
            1_001 + heartbeat::HEARTBEAT_TTL_SECS,
        );
        assert!(json.contains("\"endpoint\":\"\""));
    }

    #[test]
    fn online_flips_false_when_heartbeat_is_older_than_ttl() {
        let endpoints = vec![ep("a", "org-1", "ws-1", &["100.88.0.2/32"])];
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
        let json = build_peermap_json(&endpoints, &hbs, "org-1", "ws-1", None, now);
        assert!(json.contains("\"online\":false"));
    }

    #[test]
    fn peer_json_carries_overlay_ipv4_and_public_key() {
        let endpoints = vec![ep("a", "org-1", "ws-1", &["100.88.0.7/32"])];
        let hbs = HashMap::new();
        let json = build_peermap_json(&endpoints, &hbs, "org-1", "ws-1", None, 1_000);
        assert!(json.contains("\"overlay_ipv4\":\"100.88.0.7\""));
        assert!(json.contains("\"public_key\":\"pk-a\""));
    }

    #[test]
    fn overlay_ipv4_is_empty_string_when_node_has_no_overlay_address() {
        let endpoints = vec![ep("a", "org-1", "ws-1", &["0.0.0.0/0"])];
        let hbs = HashMap::new();
        let json = build_peermap_json(&endpoints, &hbs, "org-1", "ws-1", None, 1_000);
        assert!(json.contains("\"overlay_ipv4\":\"\""));
    }
}
