//! Node liveness heartbeat to the control plane.
//!
//! While the tunnel is up, the node periodically POSTs `/api/heartbeat` so the
//! control plane marks it ONLINE and peers see it as connected (the green dot in
//! the clients). Two auth paths:
//!
//! - **Token path** (preferred): uses a durable `Authorization: Bearer` node
//!   token. No CSRF fetch, no session expiry. Used when a `node.token` file
//!   exists (written at first boot or bootstrapped from the OIDC cookie).
//! - **Cookie path** (fallback): fetches a fresh CSRF token from the dashboard
//!   HTML, then POSTs the heartbeat with the session cookie + CSRF header.
//!   Active until a node token is acquired.
//!
//! Both paths use `curl` — pure-std has no TLS client.

use std::net::{SocketAddr, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;
use std::time::Duration;

/// How often to report liveness (well within the control plane's 120s TTL).
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(30);

/// Resolve this node's control-plane id by matching our public key in the
/// authenticated `/api/endpoints` list.
pub fn fetch_node_id(control_url: &str, cookie_jar: &Path, pubkey_b64: &str) -> Option<String> {
    let base = control_url.trim_end_matches('/');
    let out = Command::new("curl")
        .args([
            "-fsSL",
            "-b",
            &cookie_jar.to_string_lossy(),
            &format!("{base}/api/endpoints"),
        ])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let json = String::from_utf8_lossy(&out.stdout);
    json.split('}')
        .find(|obj| obj.contains(pubkey_b64))
        .and_then(|obj| json_field(obj, "id"))
}

/// POST a single heartbeat: fetch a fresh dashboard `csrf_token`, then submit our id.
fn beat(control_url: &str, cookie_jar: &Path, node_id: &str, endpoint: &str) -> bool {
    let base = control_url.trim_end_matches('/');
    let jar = cookie_jar.to_string_lossy().into_owned();
    let dash = Command::new("curl")
        .args(["-fsSL", "-b", &jar, &format!("{base}/dashboard")])
        .output();
    let csrf = match dash {
        Ok(o) if o.status.success() => csrf_token(&String::from_utf8_lossy(&o.stdout)),
        _ => None,
    };
    let Some(csrf) = csrf else {
        return false;
    };
    // The control plane expects a JSON body + the CSRF token in the X-CSRF-Token
    // header (not a form field).
    Command::new("curl")
        .args([
            "-fsS",
            "-o",
            "/dev/null",
            "-b",
            &jar,
            "-H",
            &format!("X-CSRF-Token: {csrf}"),
            "-H",
            "Content-Type: application/json",
            "--data",
            &heartbeat_body(node_id, endpoint),
            &format!("{base}/api/heartbeat"),
        ])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Resolve this node's control-plane id using a durable node bearer token.
/// Preferred over [`fetch_node_id`] when a token is available.
pub fn fetch_node_id_with_token(
    control_url: &str,
    token: &str,
    pubkey_b64: &str,
) -> Option<String> {
    let base = control_url.trim_end_matches('/');
    let out = Command::new("curl")
        .args([
            "-fsSL",
            "-H",
            &format!("Authorization: Bearer {token}"),
            &format!("{base}/api/endpoints"),
        ])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let json = String::from_utf8_lossy(&out.stdout);
    json.split('}')
        .find(|obj| obj.contains(pubkey_b64))
        .and_then(|obj| json_field(obj, "id"))
}

/// POST a single heartbeat using a bearer token — no CSRF fetch required.
fn beat_with_token(control_url: &str, token: &str, node_id: &str, endpoint: &str) -> bool {
    let base = control_url.trim_end_matches('/');
    Command::new("curl")
        .args([
            "-fsS",
            "-o",
            "/dev/null",
            "-H",
            &format!("Authorization: Bearer {token}"),
            "-H",
            "Content-Type: application/json",
            "--data",
            &heartbeat_body(node_id, endpoint),
            &format!("{base}/api/heartbeat"),
        ])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Spawn the background heartbeat loop.
///
/// When `node_token` is `Some`, uses bearer-token auth (no CSRF overhead,
/// survives session-cookie expiry). When `None`, falls back to the cookie +
/// CSRF dance. No-op (with a notice) if the node id cannot be resolved.
pub fn spawn(
    control_url: String,
    cookie_jar: PathBuf,
    pubkey_b64: String,
    node_token: Option<String>,
    relay: SocketAddr,
    tunnel_port: u16,
) {
    thread::spawn(move || {
        let resolved = if let Some(ref tok) = node_token {
            fetch_node_id_with_token(&control_url, tok, &pubkey_b64)
        } else {
            fetch_node_id(&control_url, &cookie_jar, &pubkey_b64)
        };
        // With a token, the control plane backfills the id from the token's own
        // endpoint when we send an empty one — so a failed id lookup is NOT fatal
        // in token mode; we heartbeat with an empty id and let the server fill it.
        let id = match (resolved, node_token.is_some()) {
            (Some(id), _) => id,
            (None, true) => String::new(),
            (None, false) => {
                eprintln!("akurai-node: heartbeat disabled — could not resolve this node's id");
                return;
            }
        };
        eprintln!("akurai-node: heartbeat to {control_url} as node {id}");
        loop {
            let endpoint = advertised_endpoint(relay, tunnel_port).unwrap_or_default();
            if let Some(ref tok) = node_token {
                let _ = beat_with_token(&control_url, tok, &id, &endpoint);
            } else {
                let _ = beat(&control_url, &cookie_jar, &id, &endpoint);
            }
            thread::sleep(HEARTBEAT_INTERVAL);
        }
    });
}

/// Resolve the local underlay address that would reach the relay, then replace
/// its random probe port with the tunnel socket's actual listening port.
fn advertised_endpoint(relay: SocketAddr, tunnel_port: u16) -> Option<String> {
    let bind = match relay {
        SocketAddr::V4(_) => "0.0.0.0:0",
        SocketAddr::V6(_) => "[::]:0",
    };
    let sock = UdpSocket::bind(bind).ok()?;
    sock.connect(relay).ok()?;
    let local = sock.local_addr().ok()?;
    match local {
        SocketAddr::V4(v4) if !v4.ip().is_unspecified() => {
            Some(SocketAddr::from((*v4.ip(), tunnel_port)).to_string())
        }
        SocketAddr::V6(v6) if !v6.ip().is_unspecified() => {
            Some(SocketAddr::from((*v6.ip(), tunnel_port)).to_string())
        }
        _ => None,
    }
}

fn heartbeat_body(node_id: &str, endpoint: &str) -> String {
    format!(
        "{{\"id\":\"{}\",\"endpoint\":\"{}\"}}",
        json_esc(node_id),
        json_esc(endpoint)
    )
}

fn json_esc(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
}

/// Extract a `"key":"value"` or `"key":<number>` JSON field (hand-rolled).
fn json_field(obj: &str, key: &str) -> Option<String> {
    let needle = format!("\"{key}\"");
    let rest = obj[obj.find(&needle)? + needle.len()..].trim_start();
    let rest = rest.strip_prefix(':')?.trim_start();
    if let Some(rest) = rest.strip_prefix('"') {
        let end = rest.find('"')?;
        Some(rest[..end].to_string())
    } else {
        let v: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
        (!v.is_empty()).then_some(v)
    }
}

/// Parse `name="csrf_token" value="..."` out of the dashboard HTML.
fn csrf_token(html: &str) -> Option<String> {
    let needle = "name=\"csrf_token\" value=\"";
    let rest = &html[html.find(needle)? + needle.len()..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_string_and_numeric_ids() {
        assert_eq!(
            json_field("{\"id\":\"abc123\",\"x\":1}", "id").as_deref(),
            Some("abc123")
        );
        assert_eq!(
            json_field("{\"id\":42,\"x\":1}", "id").as_deref(),
            Some("42")
        );
        assert_eq!(json_field("{\"y\":1}", "id"), None);
    }

    #[test]
    fn parses_csrf_token() {
        let html = r#"<input name="csrf_token" value="tok-9f8e" type="hidden">"#;
        assert_eq!(csrf_token(html).as_deref(), Some("tok-9f8e"));
    }

    #[test]
    fn heartbeat_body_includes_endpoint() {
        assert_eq!(
            heartbeat_body("node-a", "192.168.1.44:51399"),
            r#"{"id":"node-a","endpoint":"192.168.1.44:51399"}"#
        );
    }

    #[test]
    fn heartbeat_body_escapes_json_values() {
        assert_eq!(
            heartbeat_body("node\"a", "192.168.1.44:51399"),
            r#"{"id":"node\"a","endpoint":"192.168.1.44:51399"}"#
        );
    }
}
