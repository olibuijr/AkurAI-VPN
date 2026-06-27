//! OIDC Authorization Code Flow helpers — std-only, zero external crates.
//!
//! JWT verification is delegated to the IDP's `/introspect` endpoint (called
//! via `curl`). The IDP verifies the EdDSA signature, expiry, and returns
//! claim data. We additionally validate issuer and audience client-side.
//!
//! **Required env vars** (server logs a warning and disables login if any
//! are absent):
//!   `OIDC_CLIENT_ID`     — client ID registered in the AkurAI IDP
//!   `OIDC_CLIENT_SECRET` — client secret for the token endpoint
//!   `OIDC_REDIRECT_URI`  — callback URL, e.g. `https://vpn.olibuijr.com/auth/callback`
//!   `OIDC_ISSUER_URL`    — IDP base URL (default: `https://auth.olibuijr.com`)

use std::collections::HashMap;
use std::io::Read;

// ---------------------------------------------------------------------------
// AuthUser & session store
// ---------------------------------------------------------------------------

/// Authenticated principal decoded from the OIDC id_token payload.
#[derive(Debug, Clone)]
pub struct AuthUser {
    /// OIDC subject identifier (opaque, stable per user).
    pub sub: String,
    pub email: String,
    /// Display name from the `name` or `preferred_username` claim.
    pub name: String,
}

/// In-memory session store.
#[derive(Debug, Default)]
pub struct SessionStore {
    sessions: HashMap<String, AuthUser>,
}

impl SessionStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, token: String, user: AuthUser) {
        self.sessions.insert(token, user);
    }

    pub fn get(&self, token: &str) -> Option<&AuthUser> {
        self.sessions.get(token)
    }

    pub fn remove(&mut self, token: &str) {
        self.sessions.remove(token);
    }
}

// ---------------------------------------------------------------------------
// OIDC config
// ---------------------------------------------------------------------------

/// Configuration loaded from environment variables.
pub struct OidcConfig {
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
    pub issuer_url: String,
}

impl OidcConfig {
    /// Returns `None` if any required env var is missing.
    pub fn from_env() -> Option<Self> {
        Some(Self {
            client_id: std::env::var("OIDC_CLIENT_ID").ok()?,
            client_secret: std::env::var("OIDC_CLIENT_SECRET").ok()?,
            redirect_uri: std::env::var("OIDC_REDIRECT_URI").ok()?,
            issuer_url: std::env::var("OIDC_ISSUER_URL")
                .unwrap_or_else(|_| "https://auth.olibuijr.com".to_string()),
        })
    }
}

// ---------------------------------------------------------------------------
// OIDC flow helpers
// ---------------------------------------------------------------------------

/// Build the redirect URL for the OIDC authorization endpoint.
pub fn build_authorize_url(config: &OidcConfig, state: &str) -> String {
    format!(
        "{}/authorize?response_type=code&client_id={}&redirect_uri={}&scope=openid+email+profile&state={}",
        config.issuer_url,
        url_encode(&config.client_id),
        url_encode(&config.redirect_uri),
        url_encode(state),
    )
}

/// Exchange an authorization code for tokens by spawning `curl`.
///
/// **Runtime requirement**: `curl` must be on PATH. The IDP token endpoint is
/// HTTPS; a std-only TLS client is not possible without a crypto crate (see
/// the UNRESOLVED DECISION in `Cargo.toml`). `curl` on the server host is the
/// pragmatic workaround for the MVP.
pub fn exchange_code(config: &OidcConfig, code: &str) -> Result<String, String> {
    let token_url = format!("{}/token", config.issuer_url);
    let body = format!(
        "grant_type=authorization_code&code={code}&redirect_uri={redirect}&client_id={id}&client_secret={secret}",
        code = url_encode(code),
        redirect = url_encode(&config.redirect_uri),
        id = url_encode(&config.client_id),
        secret = url_encode(&config.client_secret),
    );
    let output = std::process::Command::new("curl")
        .args([
            "-s",
            "--max-time",
            "10",
            "-X",
            "POST",
            "-H",
            "Content-Type: application/x-www-form-urlencoded",
            "-d",
            &body,
            &token_url,
        ])
        .output()
        .map_err(|e| format!("curl exec failed: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "curl exited {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    String::from_utf8(output.stdout).map_err(|e| format!("curl output not UTF-8: {e}"))
}

/// Extract the `id_token` string from a token endpoint JSON response body.
pub fn extract_id_token(json: &str) -> Option<String> {
    extract_json_str(json, "id_token")
}

/// Verify an id_token by calling the IDP's `/introspect` endpoint.
///
/// The IDP performs full EdDSA signature verification and expiry checking.
/// This function additionally validates issuer and audience locally.
///
/// Returns `Ok(AuthUser)` on success or `Err(reason)` if the token is invalid,
/// expired, has the wrong audience, or cannot be reached.
pub fn verify_id_token(config: &OidcConfig, id_token: &str) -> Result<AuthUser, String> {
    let introspect_url = format!("{}/introspect", config.issuer_url);
    let body = format!(
        "token={token}&token_type_hint=access_token&client_id={cid}",
        token = url_encode(id_token),
        cid = url_encode(&config.client_id),
    );
    let output = std::process::Command::new("curl")
        .args([
            "-s",
            "--max-time",
            "10",
            "-X",
            "POST",
            "-H",
            "Content-Type: application/x-www-form-urlencoded",
            "-d",
            &body,
            &introspect_url,
        ])
        .output()
        .map_err(|e| format!("curl exec failed: {e}"))?;

    if !output.status.success() {
        return Err(format!(
            "curl exited {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    let json =
        String::from_utf8(output.stdout).map_err(|e| format!("curl output not UTF-8: {e}"))?;
    verify_introspect_response(&json, &config.client_id, &config.issuer_url)
}

/// Validate an introspect JSON response and extract the authenticated user.
/// Separated from the curl call so it can be unit-tested.
pub fn verify_introspect_response(
    json: &str,
    expected_client_id: &str,
    expected_issuer: &str,
) -> Result<AuthUser, String> {
    let active = extract_json_bool(json, "active").unwrap_or(false);
    if !active {
        return Err("token rejected by IDP (expired, invalid signature, or revoked)".to_string());
    }

    let iss = extract_json_str(json, "iss").unwrap_or_default();
    if !iss.is_empty() && iss != expected_issuer {
        return Err(format!(
            "issuer mismatch: got '{iss}', expected '{expected_issuer}'"
        ));
    }

    let aud = extract_json_str(json, "aud").unwrap_or_default();
    if !aud.is_empty() && aud != expected_client_id {
        return Err(format!(
            "audience mismatch: got '{aud}', expected '{expected_client_id}'"
        ));
    }

    Ok(AuthUser {
        sub: extract_json_str(json, "sub").unwrap_or_default(),
        email: extract_json_str(json, "email").unwrap_or_default(),
        name: extract_json_str(json, "name")
            .or_else(|| extract_json_str(json, "preferred_username"))
            .unwrap_or_default(),
    })
}

/// Decode the JWT payload and return user identity fields (no signature check).
///
/// Used as a fallback when the introspect endpoint is unreachable. Prefer
/// `verify_id_token` for production code paths.
#[allow(dead_code)]
pub fn decode_jwt_claims(id_token: &str) -> Option<AuthUser> {
    let payload_b64 = id_token.split('.').nth(1)?;
    let bytes = base64url_decode(payload_b64)?;
    let payload = String::from_utf8(bytes).ok()?;
    Some(AuthUser {
        sub: extract_json_str(&payload, "sub").unwrap_or_default(),
        email: extract_json_str(&payload, "email").unwrap_or_default(),
        name: extract_json_str(&payload, "name")
            .or_else(|| extract_json_str(&payload, "preferred_username"))
            .unwrap_or_default(),
    })
}

// ---------------------------------------------------------------------------
// Session / cookie helpers
// ---------------------------------------------------------------------------

/// Generate a random 64-hex-char session token from `/dev/urandom`.
pub fn random_token() -> String {
    let mut buf = [0u8; 32];
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        let _ = f.read_exact(&mut buf);
    }
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

/// Extract the `akurai_session` value from a raw Cookie header string.
pub fn parse_session_cookie(cookie_header: &str) -> Option<String> {
    for part in cookie_header.split(';') {
        if let Some(val) = part.trim().strip_prefix("akurai_session=") {
            return Some(val.trim().to_string());
        }
    }
    None
}

// ---------------------------------------------------------------------------
// URL encode / decode
// ---------------------------------------------------------------------------

/// Percent-encode a string for inclusion in a URL query parameter value.
pub fn url_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Percent-decode a query value or form field.
pub fn url_decode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            out.push(char::from(
                from_hex(bytes[i + 1]) << 4 | from_hex(bytes[i + 2]),
            ));
            i += 3;
        } else if bytes[i] == b'+' {
            out.push(' ');
            i += 1;
        } else {
            out.push(bytes[i] as char);
            i += 1;
        }
    }
    out
}

fn from_hex(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        b'A'..=b'F' => b - b'A' + 10,
        _ => 0,
    }
}

/// Parse an `application/x-www-form-urlencoded` body.
pub fn parse_form(body: &str) -> HashMap<String, String> {
    body.split('&')
        .filter_map(|pair| pair.split_once('='))
        .map(|(k, v)| (url_decode(k), url_decode(v)))
        .collect()
}

// ---------------------------------------------------------------------------
// Minimal JSON extraction (no serde — zero crate dep)
// ---------------------------------------------------------------------------

/// Extract a JSON boolean value by key from a flat JSON object.
pub fn extract_json_bool(json: &str, key: &str) -> Option<bool> {
    let needle = format!("\"{key}\"");
    let start = json.find(&needle)?;
    let rest = json[start + needle.len()..].trim_start();
    let rest = rest.strip_prefix(':')?.trim_start();
    if rest.starts_with("true") {
        Some(true)
    } else if rest.starts_with("false") {
        Some(false)
    } else {
        None
    }
}

/// Extract a JSON string value by key from a flat JSON object.
///
/// Handles simple cases only: does not parse deep nesting, but correctly
/// handles `\"` escapes inside values.
pub fn extract_json_str(json: &str, key: &str) -> Option<String> {
    let needle = format!("\"{key}\"");
    let start = json.find(&needle)?;
    let rest = json[start + needle.len()..].trim_start();
    let rest = rest.strip_prefix(':')?.trim_start();
    let inner = rest.strip_prefix('"')?;
    let end = json_str_end(inner)?;
    Some(inner[..end].replace("\\\"", "\"").replace("\\\\", "\\"))
}

fn json_str_end(s: &str) -> Option<usize> {
    let mut chars = s.char_indices();
    while let Some((i, c)) = chars.next() {
        if c == '\\' {
            chars.next();
        } else if c == '"' {
            return Some(i);
        }
    }
    None
}

/// Extract a JSON string array by key from a flat JSON object.
///
/// Items must not contain commas (fine for IP prefixes, keys, names).
pub fn extract_json_str_array(json: &str, key: &str) -> Vec<String> {
    let needle = format!("\"{key}\"");
    let Some(start) = json.find(&needle) else {
        return Vec::new();
    };
    let rest = json[start + needle.len()..].trim_start();
    let Some(rest) = rest.strip_prefix(':') else {
        return Vec::new();
    };
    let rest = rest.trim_start();
    if !rest.starts_with('[') {
        return Vec::new();
    }
    let end = rest.find(']').unwrap_or(rest.len());
    rest[1..end]
        .split(',')
        .map(str::trim)
        .filter_map(|s| s.strip_prefix('"').and_then(|s| s.strip_suffix('"')))
        .map(str::to_string)
        .collect()
}

// ---------------------------------------------------------------------------
// Base64url decode (for JWT payload — no external crate)
// ---------------------------------------------------------------------------

#[allow(dead_code)]
fn base64url_decode(s: &str) -> Option<Vec<u8>> {
    let standard = s.replace('-', "+").replace('_', "/");
    let rem = standard.len() % 4;
    let padded = if rem == 0 {
        standard
    } else {
        format!("{standard}{}", "=".repeat(4 - rem))
    };
    base64_decode(&padded)
}

#[allow(dead_code)]
const B64_TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

#[allow(dead_code)]
fn base64_decode(s: &str) -> Option<Vec<u8>> {
    let chars: Vec<u8> = s
        .bytes()
        .filter(|&b| b != b'=')
        .map(|b| B64_TABLE.iter().position(|&c| c == b).map(|p| p as u8))
        .collect::<Option<Vec<_>>>()?;

    let mut out = Vec::with_capacity(chars.len() * 3 / 4);
    for chunk in chars.chunks(4) {
        match *chunk {
            [a, b, c, d] => {
                out.push((a << 2) | (b >> 4));
                out.push((b << 4) | (c >> 2));
                out.push((c << 6) | d);
            }
            [a, b, c] => {
                out.push((a << 2) | (b >> 4));
                out.push((b << 4) | (c >> 2));
            }
            [a, b] => {
                out.push((a << 2) | (b >> 4));
            }
            _ => {}
        }
    }
    Some(out)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- verify_introspect_response --

    #[test]
    fn introspect_active_good_claims() {
        let json = r#"{"active":true,"iss":"https://auth.olibuijr.com","aud":"client-abc","sub":"user-1","email":"user@example.com","name":"Test User"}"#;
        let user =
            verify_introspect_response(json, "client-abc", "https://auth.olibuijr.com").unwrap();
        assert_eq!(user.sub, "user-1");
        assert_eq!(user.email, "user@example.com");
        assert_eq!(user.name, "Test User");
    }

    #[test]
    fn introspect_inactive_rejected() {
        let json = r#"{"active":false}"#;
        let err = verify_introspect_response(json, "client-abc", "https://auth.olibuijr.com")
            .unwrap_err();
        assert!(err.contains("rejected by IDP"), "got: {err}");
    }

    #[test]
    fn introspect_wrong_audience() {
        let json = r#"{"active":true,"iss":"https://auth.olibuijr.com","aud":"other-client","sub":"u","email":"u@x.com"}"#;
        let err = verify_introspect_response(json, "client-abc", "https://auth.olibuijr.com")
            .unwrap_err();
        assert!(err.contains("audience mismatch"), "got: {err}");
    }

    #[test]
    fn introspect_wrong_issuer() {
        let json = r#"{"active":true,"iss":"https://evil.example.com","aud":"client-abc","sub":"u","email":"u@x.com"}"#;
        let err = verify_introspect_response(json, "client-abc", "https://auth.olibuijr.com")
            .unwrap_err();
        assert!(err.contains("issuer mismatch"), "got: {err}");
    }

    #[test]
    fn introspect_missing_iss_aud_still_accepted() {
        // IDP may omit iss/aud if token is valid; we accept it (defensive)
        let json = r#"{"active":true,"sub":"u","email":"u@x.com"}"#;
        let user =
            verify_introspect_response(json, "client-abc", "https://auth.olibuijr.com").unwrap();
        assert_eq!(user.sub, "u");
    }

    // -- extract_json_bool --

    #[test]
    fn json_bool_true() {
        assert_eq!(
            extract_json_bool(r#"{"active":true}"#, "active"),
            Some(true)
        );
    }

    #[test]
    fn json_bool_false() {
        assert_eq!(
            extract_json_bool(r#"{"active":false}"#, "active"),
            Some(false)
        );
    }

    #[test]
    fn json_bool_missing() {
        assert_eq!(extract_json_bool(r#"{"foo":"bar"}"#, "active"), None);
    }

    // -- extract_json_str (regression) --

    #[test]
    fn json_str_basic() {
        assert_eq!(
            extract_json_str(r#"{"email":"user@example.com"}"#, "email"),
            Some("user@example.com".to_string())
        );
    }

    // -- url_encode / url_decode roundtrip --

    #[test]
    fn url_encode_decode_roundtrip() {
        let original = "https://vpn.olibuijr.com/auth/callback?foo=bar&baz=qux";
        assert_eq!(url_decode(&url_encode(original)), original);
    }

    // -- parse_session_cookie --

    #[test]
    fn session_cookie_found() {
        let cookie = "other=val; akurai_session=abc123; another=x";
        assert_eq!(parse_session_cookie(cookie), Some("abc123".to_string()));
    }

    #[test]
    fn session_cookie_missing() {
        assert_eq!(parse_session_cookie("foo=bar"), None);
    }
}
