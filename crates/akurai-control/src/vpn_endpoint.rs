//! VPN endpoint registry — persisted as JSON in `AKURAI_DATA_DIR`.
//!
//! Each record describes a network peer (WireGuard-compatible fields).
//! The file is read at startup and rewritten atomically (rename) on every
//! mutation.
//!
//! **Data file**: `$AKURAI_DATA_DIR/vpn-endpoints.json`
//! (falls back to `./data/vpn-endpoints.json` when the env var is unset).

use std::io::{Read, Write};
use std::time::{SystemTime, UNIX_EPOCH};

/// A registered VPN endpoint.
#[derive(Debug, Clone)]
pub struct VpnEndpoint {
    pub id: String,
    pub name: String,
    pub public_key: String,
    pub endpoint_addr: String,
    pub allowed_ips: Vec<String>,
    pub added_by: String,
    pub added_at: u64,
    /// Durable node authentication token (prefix `aknk_` + 64 hex chars).
    /// Generated at registration time and persisted alongside the endpoint
    /// record. Nodes present this in `Authorization: Bearer` or `X-Node-Token`
    /// to authenticate API calls without an active OIDC session cookie.
    /// The empty string means "not yet assigned" (pre-backfill records).
    pub node_token: String,
}

impl VpnEndpoint {
    /// Serialize to a JSON object string (no serde dependency).
    pub fn to_json(&self) -> String {
        let ips = self
            .allowed_ips
            .iter()
            .map(|ip| format!("\"{}\"", json_esc(ip)))
            .collect::<Vec<_>>()
            .join(",");
        let overlay_ipv4 = crate::ipam::overlay_addr_string(&self.allowed_ips).unwrap_or_default();
        format!(
            "{{\"id\":\"{}\",\"name\":\"{}\",\"public_key\":\"{}\",\
             \"endpoint\":\"{}\",\"overlay_ipv4\":\"{}\",\"allowed_ips\":[{}],\
             \"added_by\":\"{}\",\"added_at\":{},\"node_token\":\"{}\"}}",
            json_esc(&self.id),
            json_esc(&self.name),
            json_esc(&self.public_key),
            json_esc(&self.endpoint_addr),
            json_esc(&overlay_ipv4),
            ips,
            json_esc(&self.added_by),
            self.added_at,
            json_esc(&self.node_token),
        )
    }
}

fn json_esc(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
}

// ---------------------------------------------------------------------------
// Path
// ---------------------------------------------------------------------------

/// Resolved path to the endpoint data file.
pub fn data_path() -> std::path::PathBuf {
    let dir = std::env::var("AKURAI_DATA_DIR").unwrap_or_else(|_| "./data".to_string());
    std::path::Path::new(&dir).join("vpn-endpoints.json")
}

// ---------------------------------------------------------------------------
// I/O
// ---------------------------------------------------------------------------

/// Load endpoints from disk; returns an empty list on missing file or errors.
pub fn load() -> Vec<VpnEndpoint> {
    let mut content = String::new();
    if let Ok(mut f) = std::fs::File::open(data_path()) {
        let _ = f.read_to_string(&mut content);
    }
    parse_array(&content)
}

/// Persist the full endpoint list atomically via a temp-file rename.
pub fn save(endpoints: &[VpnEndpoint]) -> std::io::Result<()> {
    let path = data_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let json = format!(
        "[\n{}\n]\n",
        endpoints
            .iter()
            .map(VpnEndpoint::to_json)
            .collect::<Vec<_>>()
            .join(",\n")
    );
    let tmp = path.with_extension("json.tmp");
    {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(json.as_bytes())?;
        f.flush()?;
    }
    std::fs::rename(tmp, path)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

/// Generate a random 16-character hex endpoint ID from `/dev/urandom`.
pub fn random_id() -> String {
    use std::io::Read as IoRead;
    let mut buf = [0u8; 8];
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        let _ = f.read_exact(&mut buf);
    }
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

/// Generate a durable node authentication token: the prefix `"aknk_"` followed
/// by 64 lowercase hex characters (32 bytes / 128 bits of `/dev/urandom` entropy).
///
/// Example: `aknk_3f2a1b8c…` (total length 69 characters).
pub fn generate_node_token() -> String {
    use std::io::Read as IoRead;
    let mut buf = [0u8; 32];
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        let _ = f.read_exact(&mut buf);
    }
    let hex: String = buf.iter().map(|b| format!("{b:02x}")).collect();
    format!("aknk_{hex}")
}

/// Current UNIX timestamp in seconds.
pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ---------------------------------------------------------------------------
// Minimal JSON parser (no serde)
// ---------------------------------------------------------------------------

fn parse_array(json: &str) -> Vec<VpnEndpoint> {
    split_objects(json.trim())
        .into_iter()
        .filter_map(|obj| parse_object(&obj))
        .collect()
}

fn split_objects(s: &str) -> Vec<String> {
    let mut objects = Vec::new();
    let mut depth: i32 = 0;
    let mut start: Option<usize> = None;
    for (i, ch) in s.char_indices() {
        match ch {
            '{' => {
                if depth == 0 {
                    start = Some(i);
                }
                depth += 1;
            }
            '}' => {
                depth -= 1;
                if depth == 0 {
                    if let Some(s_pos) = start.take() {
                        objects.push(s[s_pos..=i].to_string());
                    }
                }
            }
            _ => {}
        }
    }
    objects
}

fn parse_object(obj: &str) -> Option<VpnEndpoint> {
    let id = crate::auth::extract_json_str(obj, "id").unwrap_or_default();
    if id.is_empty() {
        return None;
    }
    Some(VpnEndpoint {
        id,
        name: crate::auth::extract_json_str(obj, "name").unwrap_or_default(),
        public_key: crate::auth::extract_json_str(obj, "public_key").unwrap_or_default(),
        endpoint_addr: crate::auth::extract_json_str(obj, "endpoint").unwrap_or_default(),
        allowed_ips: crate::auth::extract_json_str_array(obj, "allowed_ips"),
        added_by: crate::auth::extract_json_str(obj, "added_by").unwrap_or_default(),
        added_at: obj_u64(obj, "added_at"),
        // Default to "" for records written before node tokens existed —
        // AppState::new() backfills a fresh token and re-saves at startup.
        node_token: crate::auth::extract_json_str(obj, "node_token").unwrap_or_default(),
    })
}

fn obj_u64(obj: &str, key: &str) -> u64 {
    let needle = format!("\"{key}\"");
    let Some(pos) = obj.find(&needle) else {
        return 0;
    };
    let rest = obj[pos + needle.len()..].trim_start();
    let Some(rest) = rest.strip_prefix(':') else {
        return 0;
    };
    rest.trim_start()
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect::<String>()
        .parse()
        .unwrap_or(0)
}
