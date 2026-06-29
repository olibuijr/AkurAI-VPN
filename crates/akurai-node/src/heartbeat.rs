//! Node liveness heartbeat to the control plane.
//!
//! While the tunnel is up, the node periodically POSTs `/api/heartbeat` so the
//! control plane marks it ONLINE and peers see it as connected (the green dot in
//! the clients). Uses `curl` with the saved session cookie — pure-std has no TLS
//! client, and the node already shells to `curl` for the peer map.

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
fn beat(control_url: &str, cookie_jar: &Path, node_id: &str) -> bool {
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
    Command::new("curl")
        .args([
            "-fsS",
            "-o",
            "/dev/null",
            "-b",
            &jar,
            "--data-urlencode",
            &format!("csrf_token={csrf}"),
            "--data-urlencode",
            &format!("id={node_id}"),
            "--data-urlencode",
            "endpoint=",
            &format!("{base}/api/heartbeat"),
        ])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Spawn the background heartbeat loop. No-op (with a notice) if the node id
/// can't be resolved (e.g. no `--control`/cookie configured).
pub fn spawn(control_url: String, cookie_jar: PathBuf, pubkey_b64: String) {
    thread::spawn(move || {
        let Some(id) = fetch_node_id(&control_url, &cookie_jar, &pubkey_b64) else {
            eprintln!("akurai-node: heartbeat disabled — could not resolve this node's id");
            return;
        };
        eprintln!("akurai-node: heartbeat to {control_url} as node {id}");
        loop {
            let _ = beat(&control_url, &cookie_jar, &id);
            thread::sleep(HEARTBEAT_INTERVAL);
        }
    });
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
}
