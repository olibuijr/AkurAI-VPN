//! Control-plane HTTP listener — OIDC login and VPN endpoint management.
//!
//! Routes:
//!
//! | Method | Path                          | Auth? | Description                          |
//! |--------|-------------------------------|-------|--------------------------------------|
//! | GET    | /                             | No    | JSON status                          |
//! | GET    | /health, /healthz             | No    | JSON health check                    |
//! | GET    | /login                        | No    | Redirect to AkurAI IDP               |
//! | GET    | /auth/callback                | No    | Receive OIDC code, set session cookie|
//! | GET    | /auth/logout                  | No    | Clear session, redirect to /         |
//! | GET    | /dashboard                    | Yes   | HTML endpoint management UI          |
//! | GET    | /api/endpoints                | Yes   | JSON list of registered endpoints    |
//! | POST   | /api/endpoints                | Yes   | Add endpoint (JSON body)             |
//! | POST   | /api/endpoints/add            | Yes   | Add endpoint (HTML form POST)        |
//! | POST   | /api/endpoints/:id/delete     | Yes   | Delete endpoint (HTML form)          |
//! | DELETE | /api/endpoints/:id            | Yes   | Delete endpoint (REST)               |
//! | GET    | /api/peermap                  | Yes   | JSON peer view (`?self=<id>` excl.)  |
//! | POST   | /api/heartbeat                | Yes   | Record node liveness (JSON body)     |
//!
//! **Auth**: protected routes require a valid `akurai_session` cookie.
//! Missing or unknown tokens redirect to `/login`.
//!
//! **OIDC required env vars** (`/login` returns an error page if absent):
//!   `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`, `OIDC_REDIRECT_URI`, `OIDC_ISSUER_URL`

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::Arc;
use std::thread;

use crate::auth::{self, AuthUser, OidcConfig};
use crate::state::SharedState;
use crate::{acl, audit, enrollment, heartbeat, ipam, peermap};

const DEFAULT_PORT: u16 = 8104;
const NAME: &str = env!("CARGO_PKG_NAME");
const VERSION: &str = env!("CARGO_PKG_VERSION");
/// Maximum accepted request body size (64 KiB).
const MAX_BODY: usize = 65_536;
/// Maximum pending OIDC state nonces before the set is rotated.
const MAX_PENDING_STATES: usize = 512;

// ---------------------------------------------------------------------------
// Request
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Method {
    Get,
    Post,
    Delete,
}

struct Request {
    method: Method,
    path: String,
    query: String,
    headers: HashMap<String, String>,
    body: String,
}

#[derive(Debug, Clone)]
struct AuthSession {
    user: AuthUser,
    csrf_token: String,
}

// ---------------------------------------------------------------------------
// Response
// ---------------------------------------------------------------------------

struct Response {
    status: &'static str,
    content_type: &'static str,
    /// Additional raw header lines (e.g. `Location: ...`, `Set-Cookie: ...`).
    extra: Vec<String>,
    body: String,
}

impl Response {
    fn ok_json(body: String) -> Self {
        Self {
            status: "200 OK",
            content_type: "application/json",
            extra: vec![],
            body,
        }
    }
    fn ok_html(body: String) -> Self {
        Self {
            status: "200 OK",
            content_type: "text/html; charset=utf-8",
            extra: vec![],
            body,
        }
    }
    fn redirect(location: impl Into<String>) -> Self {
        Self {
            status: "302 Found",
            content_type: "text/plain",
            extra: vec![format!("Location: {}", location.into())],
            body: String::new(),
        }
    }
    fn redirect_cookie(location: impl Into<String>, set_cookie: String) -> Self {
        Self {
            status: "302 Found",
            content_type: "text/plain",
            extra: vec![format!("Location: {}", location.into()), set_cookie],
            body: String::new(),
        }
    }
    fn not_found() -> Self {
        Self {
            status: "404 Not Found",
            content_type: "application/json",
            extra: vec![],
            body: r#"{"error":"not found"}"#.to_string(),
        }
    }
    fn bad_request(msg: &str) -> Self {
        Self {
            status: "400 Bad Request",
            content_type: "application/json",
            extra: vec![],
            body: format!("{{\"error\":\"{}\"}}", html_esc(msg)),
        }
    }
    fn error_html(msg: &str) -> Self {
        Self {
            status: "500 Internal Server Error",
            content_type: "text/html; charset=utf-8",
            extra: vec![],
            body: error_page(msg),
        }
    }

    fn to_bytes(&self) -> Vec<u8> {
        let body_bytes = self.body.as_bytes();
        let mut head = format!(
            "HTTP/1.1 {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n",
            self.status,
            self.content_type,
            body_bytes.len(),
        );
        for h in &self.extra {
            head.push_str(h);
            head.push_str("\r\n");
        }
        head.push_str("\r\n");
        let mut out = head.into_bytes();
        out.extend_from_slice(body_bytes);
        out
    }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

pub fn serve() -> Result<(), String> {
    let state = crate::state::new_shared();

    eprintln!("{NAME} {VERSION}: control-plane subsystems:");
    for line in [
        enrollment::status(),
        peermap::status(),
        acl::status(),
        audit::status(),
        heartbeat::status(),
    ] {
        eprintln!("  - {line}");
    }
    if OidcConfig::from_env().is_some() {
        eprintln!("  - auth: OIDC configured (AkurAI IDP)");
    } else {
        eprintln!(
            "  - auth: OIDC NOT configured — set OIDC_CLIENT_ID, OIDC_CLIENT_SECRET, OIDC_REDIRECT_URI"
        );
    }
    {
        let st = state.lock().map_err(|e| e.to_string())?;
        eprintln!("  - endpoints: {} loaded from disk", st.endpoints.len());
        eprintln!("  - {}", ipam::status(&st.endpoints));
    }

    let port: u16 = std::env::var("CONTROL_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_PORT);
    let addr = format!("127.0.0.1:{port}");
    let listener = TcpListener::bind(&addr).map_err(|e| format!("failed to bind {addr}: {e}"))?;
    eprintln!("{NAME} {VERSION}: HTTP listener ready on http://{addr}");

    for stream in listener.incoming() {
        match stream {
            Ok(s) => {
                let st = Arc::clone(&state);
                thread::spawn(move || handle(s, st));
            }
            Err(e) => eprintln!("{NAME}: accept error: {e}"),
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Connection handler
// ---------------------------------------------------------------------------

fn handle(stream: std::net::TcpStream, state: SharedState) {
    if let Some(req) = read_request(&stream) {
        let resp = route(&req, &state);
        log_request(&req, &resp);
        let _ = (&stream).write_all(&resp.to_bytes());
    }
}

/// Log method, path, and status to stderr (captured by journald).
///
/// Logs only request metadata — no body, headers, or VPN key material.
fn log_request(req: &Request, resp: &Response) {
    let method = match req.method {
        Method::Get => "GET",
        Method::Post => "POST",
        Method::Delete => "DELETE",
    };
    let code = resp.status.split(' ').next().unwrap_or("???");
    eprintln!("{method} {} -> {code}", req.path);
}

fn read_request(stream: &std::net::TcpStream) -> Option<Request> {
    let mut reader = BufReader::new(stream.try_clone().ok()?);

    // Request line
    let mut first = String::new();
    reader.read_line(&mut first).ok()?;
    let first = first.trim();

    let mut parts = first.splitn(3, ' ');
    let method = match parts.next().unwrap_or("") {
        "POST" => Method::Post,
        "DELETE" => Method::Delete,
        _ => Method::Get,
    };
    let raw_path = parts.next().unwrap_or("/");
    let (path, query) = raw_path
        .split_once('?')
        .map(|(p, q)| (p.to_string(), q.to_string()))
        .unwrap_or_else(|| (raw_path.to_string(), String::new()));

    // Headers
    let mut headers: HashMap<String, String> = HashMap::new();
    loop {
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) | Err(_) => break,
            Ok(_) if line.trim().is_empty() => break,
            Ok(_) => {
                if let Some(colon) = line.find(':') {
                    let key = line[..colon].trim().to_lowercase();
                    let val = line[colon + 1..].trim().to_string();
                    headers.insert(key, val);
                }
            }
        }
    }

    // Body (bounded by Content-Length, capped at MAX_BODY)
    let body_len = headers
        .get("content-length")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(0)
        .min(MAX_BODY);
    let body = if body_len > 0 {
        let mut buf = vec![0u8; body_len];
        reader.read_exact(&mut buf).ok();
        String::from_utf8_lossy(&buf).into_owned()
    } else {
        String::new()
    };

    Some(Request {
        method,
        path,
        query,
        headers,
        body,
    })
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

fn route(req: &Request, state: &SharedState) -> Response {
    let path = req.path.as_str();

    // Un-authenticated routes
    match (req.method, path) {
        (Method::Get, "/" | "/health" | "/healthz" | "/api/health") => return handle_status(state),
        (Method::Get, "/login") => return handle_login(state),
        (Method::Get, "/auth/callback") => return handle_callback(req, state),
        (Method::Get, "/auth/logout") => return handle_logout(req, state),
        (Method::Get, "/dashboard") => return handle_dashboard(req, state),
        _ => {}
    }

    // Authenticated REST / form routes
    match (req.method, path) {
        (Method::Get, "/api/endpoints") => {
            if let Some(session) = require_auth(req, state) {
                handle_list_endpoints(&session, state)
            } else if let Some((user, _ep_id)) = auth_node(req, state) {
                // Token-auth: a node lists its owner's endpoints (used to resolve
                // its own id + bootstrap). csrf_token unused for a GET.
                let session = AuthSession {
                    user,
                    csrf_token: String::new(),
                };
                handle_list_endpoints(&session, state)
            } else {
                Response::redirect("/login")
            }
        }
        (Method::Get, "/api/peermap") => {
            if let Some(session) = require_auth(req, state) {
                handle_peermap(req, &session, state, None)
            } else if let Some((user, ep_id)) = auth_node(req, state) {
                // Token-auth: build a synthetic AuthSession (csrf_token unused for peermap).
                let session = AuthSession {
                    user,
                    csrf_token: String::new(),
                };
                handle_peermap(req, &session, state, Some(&ep_id))
            } else {
                Response {
                    status: "401 Unauthorized",
                    content_type: "application/json",
                    extra: vec![],
                    body: r#"{"error":"unauthorized"}"#.to_string(),
                }
            }
        }
        (Method::Post, "/api/heartbeat") => {
            if let Some(session) = require_auth(req, state) {
                // Cookie-auth path: CSRF enforced inside handle_heartbeat.
                handle_heartbeat(req, &session, state)
            } else if let Some((user, ep_id)) = auth_node(req, state) {
                // Token-auth path: CSRF skipped; id may be backfilled from token.
                handle_heartbeat_token(req, &user, &ep_id, state)
            } else {
                Response {
                    status: "401 Unauthorized",
                    content_type: "application/json",
                    extra: vec![],
                    body: r#"{"error":"unauthorized"}"#.to_string(),
                }
            }
        }
        (Method::Post, "/api/endpoints") => {
            let Some(user) = require_auth(req, state) else {
                return Response::redirect("/login");
            };
            add_endpoint_json(req, &user, state)
        }
        (Method::Post, "/api/endpoints/add") => {
            let Some(user) = require_auth(req, state) else {
                return Response::redirect("/login");
            };
            add_endpoint_form(req, &user, state)
        }
        (Method::Post, p) if p.starts_with("/api/endpoints/") && p.ends_with("/delete") => {
            let Some(user) = require_auth(req, state) else {
                return Response::redirect("/login");
            };
            let id = p
                .trim_start_matches("/api/endpoints/")
                .trim_end_matches("/delete");
            delete_endpoint(id, &user, req, state)
        }
        (Method::Post, p) if p.starts_with("/api/endpoints/") && p.ends_with("/rotate-token") => {
            let Some(user) = require_auth(req, state) else {
                return Response::redirect("/login");
            };
            let id = p
                .trim_start_matches("/api/endpoints/")
                .trim_end_matches("/rotate-token");
            rotate_token(id, &user, req, state)
        }
        (Method::Delete, p) if p.starts_with("/api/endpoints/") => {
            let Some(user) = require_auth(req, state) else {
                return Response::redirect("/login");
            };
            let id = p.trim_start_matches("/api/endpoints/");
            delete_endpoint(id, &user, req, state)
        }
        _ => Response::not_found(),
    }
}

// ---------------------------------------------------------------------------
// Route handlers
// ---------------------------------------------------------------------------

fn handle_status(state: &SharedState) -> Response {
    let count = state.lock().ok().map(|s| s.endpoints.len()).unwrap_or(0);
    Response::ok_json(format!(
        "{{\"app\":\"{NAME}\",\"status\":\"ok\",\"version\":\"{VERSION}\",\"endpoints\":{count}}}\n"
    ))
}

fn handle_login(state: &SharedState) -> Response {
    let Some(config) = OidcConfig::from_env() else {
        return Response::error_html(
            "OIDC not configured — set OIDC_CLIENT_ID, OIDC_CLIENT_SECRET, OIDC_REDIRECT_URI",
        );
    };
    let nonce = auth::random_token();
    if let Ok(mut st) = state.lock() {
        if st.pending_states.len() >= MAX_PENDING_STATES {
            st.pending_states.clear();
        }
        st.pending_states.insert(nonce.clone());
    }
    Response::redirect(auth::build_authorize_url(&config, &nonce))
}

fn handle_callback(req: &Request, state: &SharedState) -> Response {
    let params = parse_query(&req.query);

    let code = match params.get("code") {
        Some(c) if !c.is_empty() => c.clone(),
        _ => return Response::error_html("Missing authorization code from IDP"),
    };
    let returned_state = params.get("state").cloned().unwrap_or_default();

    // CSRF: validate the state nonce
    match state.lock() {
        Err(_) => return Response::error_html("Internal state lock error"),
        Ok(mut st) => {
            if !st.pending_states.remove(&returned_state) {
                return Response::error_html("Invalid or expired OIDC state parameter");
            }
        }
    }

    // Exchange code for tokens via curl
    let Some(config) = OidcConfig::from_env() else {
        return Response::error_html("OIDC config missing — cannot exchange code");
    };
    let token_json = match auth::exchange_code(&config, &code) {
        Ok(j) => j,
        Err(e) => return Response::error_html(&format!("Token exchange failed: {e}")),
    };

    // Surface IDP-level errors
    if let Some(err) = auth::extract_json_str(&token_json, "error") {
        let desc = auth::extract_json_str(&token_json, "error_description").unwrap_or_default();
        return Response::error_html(&format!("IDP error: {err} — {desc}"));
    }

    let id_token = match auth::extract_id_token(&token_json) {
        Some(t) => t,
        None => return Response::error_html("No id_token in IDP response"),
    };
    let user = match auth::verify_id_token(&config, &id_token) {
        Ok(u) => u,
        Err(e) => return Response::error_html(&format!("Token verification failed: {e}")),
    };

    // Create session
    let session_token = auth::random_token();
    eprintln!(
        "{NAME}: session created for {} (sub={})",
        user.email, user.sub
    );
    if let Ok(mut st) = state.lock() {
        st.sessions
            .insert(session_token.clone(), user, auth::random_token(), 86400);
    }

    let set_cookie = format!(
        "Set-Cookie: akurai_session={session_token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=86400"
    );
    Response::redirect_cookie("/dashboard", set_cookie)
}

fn handle_logout(req: &Request, state: &SharedState) -> Response {
    if let Some(cookie) = req.headers.get("cookie") {
        if let Some(token) = auth::parse_session_cookie(cookie) {
            if let Ok(mut st) = state.lock() {
                st.sessions.remove(&token);
            }
        }
    }
    let clear = "Set-Cookie: akurai_session=; Path=/; HttpOnly; Secure; Max-Age=0".to_string();
    Response {
        status: "302 Found",
        content_type: "text/plain",
        extra: vec!["Location: /".to_string(), clear],
        body: String::new(),
    }
}

fn handle_dashboard(req: &Request, state: &SharedState) -> Response {
    let Some(user) = require_auth(req, state) else {
        return Response::redirect("/login");
    };
    let endpoints = state
        .lock()
        .ok()
        .map(|s| {
            s.endpoints
                .iter()
                .filter(|e| e.added_by == user.user.email)
                .cloned()
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    Response::ok_html(render_dashboard(&user.user, &user.csrf_token, &endpoints))
}

fn handle_list_endpoints(session: &AuthSession, state: &SharedState) -> Response {
    let json = state
        .lock()
        .ok()
        .map(|s| {
            s.endpoints
                .iter()
                .filter(|e| e.added_by == session.user.email)
                .map(|e| e.to_json())
                .collect::<Vec<_>>()
                .join(",")
        })
        .unwrap_or_default();
    Response::ok_json(format!("[{json}]\n"))
}

/// `GET /api/peermap` — the caller's peers (their own nodes minus the requesting
/// node, identified by an optional `?self=<node_id>`), each with overlay IPv4,
/// public key, name, and liveness. Generation is delegated to [`peermap`] so the
/// pure mapping logic stays unit-testable without an HTTP request.
fn handle_peermap(
    req: &Request,
    session: &AuthSession,
    state: &SharedState,
    default_self_id: Option<&str>,
) -> Response {
    let params = parse_query(&req.query);
    let self_id = params.get("self").map(String::as_str).or(default_self_id);
    let st = match state.lock() {
        Ok(s) => s,
        Err(_) => return Response::error_html("Internal state lock error"),
    };
    let now = crate::vpn_endpoint::now_secs();
    let json = peermap::build_peermap_json(
        &st.endpoints,
        &st.heartbeats,
        &session.user.email,
        self_id,
        now,
    );
    Response::ok_json(json)
}

/// `POST /api/heartbeat` — record liveness for one of the caller's own nodes.
///
/// Body carries the node `id` and an optional reported `endpoint` (UDP socket
/// addr). The heartbeat is accepted only when `id` names an endpoint owned by
/// the authenticated user; an unknown or foreign id returns 404 so a caller
/// cannot probe for, or forge liveness on, other tenants' nodes.
fn handle_heartbeat(req: &Request, session: &AuthSession, state: &SharedState) -> Response {
    if !csrf_valid(req, session) {
        return Response::bad_request("invalid csrf token");
    }
    let id = auth::extract_json_str(&req.body, "id").unwrap_or_default();
    if id.is_empty() {
        return Response::bad_request("id is required");
    }
    let endpoint = auth::extract_json_str(&req.body, "endpoint").unwrap_or_default();

    let mut st = match state.lock() {
        Ok(s) => s,
        Err(_) => return Response::error_html("Internal state lock error"),
    };
    let owned = st
        .endpoints
        .iter()
        .any(|e| e.id == id && e.added_by == session.user.email);
    if !owned {
        return Response::not_found();
    }
    let last_seen = crate::vpn_endpoint::now_secs();
    st.heartbeats.insert(
        id,
        heartbeat::Heartbeat {
            endpoint,
            last_seen,
        },
    );
    Response::ok_json("{\"ok\":true}\n".to_string())
}

fn add_endpoint_json(req: &Request, session: &AuthSession, state: &SharedState) -> Response {
    if !csrf_valid(req, session) {
        return Response::bad_request("invalid csrf token");
    }
    let name = auth::extract_json_str(&req.body, "name").unwrap_or_default();
    let public_key = auth::extract_json_str(&req.body, "public_key").unwrap_or_default();
    let endpoint_addr = auth::extract_json_str(&req.body, "endpoint").unwrap_or_default();
    let allowed_ips = auth::extract_json_str_array(&req.body, "allowed_ips");

    if name.is_empty() || public_key.is_empty() {
        return Response::bad_request("name and public_key are required");
    }
    do_add_endpoint(
        name,
        public_key,
        endpoint_addr,
        allowed_ips,
        &session.user,
        state,
    )
}

fn add_endpoint_form(req: &Request, session: &AuthSession, state: &SharedState) -> Response {
    if !csrf_valid(req, session) {
        return Response::error_html("Invalid CSRF token");
    }
    let params = auth::parse_form(&req.body);
    let name = params.get("name").cloned().unwrap_or_default();
    let public_key = params.get("public_key").cloned().unwrap_or_default();
    let endpoint_addr = params.get("endpoint").cloned().unwrap_or_default();
    let allowed_ips: Vec<String> = params
        .get("allowed_ips")
        .map(|s| s.as_str())
        .unwrap_or("")
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect();

    if name.is_empty() || public_key.is_empty() {
        return Response::error_html("name and public_key are required");
    }
    let result = do_add_endpoint(
        name,
        public_key,
        endpoint_addr,
        allowed_ips,
        &session.user,
        state,
    );
    if result.status.starts_with("2") || result.status.starts_with("3") {
        Response::redirect("/dashboard")
    } else {
        result
    }
}

fn do_add_endpoint(
    name: String,
    public_key: String,
    endpoint_addr: String,
    mut allowed_ips: Vec<String>,
    user: &AuthUser,
    state: &SharedState,
) -> Response {
    use crate::vpn_endpoint::{now_secs, random_id, save, VpnEndpoint};

    let mut st = match state.lock() {
        Ok(s) => s,
        Err(_) => return Response::error_html("Internal state lock error"),
    };

    // Assign a stable, unique overlay IPv4 from 100.88.0.0/16. Done under the
    // state lock so concurrent enrollments cannot race onto the same index.
    // Normalize to exactly ONE overlay address per node: strip every overlay
    // entry the caller supplied (so no stray index can be smuggled in), then
    // re-insert a single canonical /32 — the supplied index if it is a valid,
    // free node index, else the lowest free address. Non-overlay CIDRs are
    // preserved. Pure bookkeeping — no route, TUN device, or host-network change.
    let used = crate::ipam::used_indices(&st.endpoints);
    let supplied = crate::ipam::overlay_index_of(&allowed_ips);
    allowed_ips.retain(|e| crate::ipam::overlay_index_of(std::slice::from_ref(e)).is_none());
    match crate::ipam::choose_for_enrollment(supplied, &used) {
        Some(ip) => allowed_ips.insert(0, crate::ipam::overlay_cidr(ip)),
        None => {
            // The /16 is exhausted. The node can still join host-only without an
            // overlay address, but make the condition loud — silent exhaustion
            // would otherwise surface only as a dashboard "—".
            eprintln!(
                "{NAME}: overlay pool 100.88.0.0/16 exhausted — registering node without an overlay IP"
            );
        }
    }

    let ep = VpnEndpoint {
        id: random_id(),
        name,
        public_key,
        endpoint_addr,
        allowed_ips,
        added_by: user.email.clone(),
        added_at: now_secs(),
        node_token: crate::vpn_endpoint::generate_node_token(),
    };
    let id = ep.id.clone();
    let overlay_ipv4 = crate::ipam::overlay_addr_string(&ep.allowed_ips).unwrap_or_default();

    // Persist BEFORE acknowledging success. If the data dir is unwritable, the
    // node must learn enrollment did not durably land rather than be told ok and
    // silently vanish on the next restart — so roll the in-memory push back and
    // return an error that keeps memory consistent with disk.
    st.endpoints.push(ep);
    if let Err(e) = save(&st.endpoints) {
        st.endpoints.pop();
        eprintln!("{NAME}: failed to persist endpoint {id}: {e}");
        return Response {
            status: "500 Internal Server Error",
            content_type: "application/json",
            extra: vec![],
            body: "{\"ok\":false,\"error\":\"failed to persist endpoint\"}\n".to_string(),
        };
    }
    Response::ok_json(format!(
        "{{\"ok\":true,\"id\":\"{id}\",\"overlay_ipv4\":\"{overlay_ipv4}\"}}\n"
    ))
}

fn delete_endpoint(
    id: &str,
    session: &AuthSession,
    req: &Request,
    state: &SharedState,
) -> Response {
    if !csrf_valid(req, session) {
        return Response::bad_request("invalid csrf token");
    }
    let mut st = match state.lock() {
        Ok(s) => s,
        Err(_) => return Response::error_html("Internal state lock error"),
    };
    let before = st.endpoints.len();
    st.endpoints
        .retain(|e| !(e.id == id && e.added_by == session.user.email));
    if st.endpoints.len() == before {
        return Response::not_found();
    }
    if let Err(e) = crate::vpn_endpoint::save(&st.endpoints) {
        eprintln!("{NAME}: failed to persist endpoints after delete: {e}");
    }
    Response::redirect("/dashboard")
}

/// Rotate (revoke + reissue) the durable node token for one of the caller's own
/// endpoints. The old token stops authenticating immediately; the node must be
/// re-seeded with the new one. Owner-scoped + CSRF-protected like delete.
fn rotate_token(id: &str, session: &AuthSession, req: &Request, state: &SharedState) -> Response {
    if !csrf_valid(req, session) {
        return Response::bad_request("invalid csrf token");
    }
    let mut st = match state.lock() {
        Ok(s) => s,
        Err(_) => return Response::error_html("Internal state lock error"),
    };
    let Some(ep) = st
        .endpoints
        .iter_mut()
        .find(|e| e.id == id && e.added_by == session.user.email)
    else {
        return Response::not_found();
    };
    ep.node_token = crate::vpn_endpoint::generate_node_token();
    if let Err(e) = crate::vpn_endpoint::save(&st.endpoints) {
        eprintln!("{NAME}: failed to persist endpoints after token rotation: {e}");
    }
    Response::redirect("/dashboard")
}

// ---------------------------------------------------------------------------
// Auth helper
// ---------------------------------------------------------------------------

fn require_auth(req: &Request, state: &SharedState) -> Option<AuthSession> {
    let cookie = req.headers.get("cookie")?;
    let token = auth::parse_session_cookie(cookie)?;
    let st = state.lock().ok()?;
    let user = st.sessions.get(&token).cloned()?;
    let csrf_token = st.sessions.csrf(&token)?.to_string();
    Some(AuthSession { user, csrf_token })
}

fn csrf_valid(req: &Request, session: &AuthSession) -> bool {
    csrf_from_request(req).as_deref() == Some(session.csrf_token.as_str())
}

fn csrf_from_request(req: &Request) -> Option<String> {
    req.headers
        .get("x-csrf-token")
        .cloned()
        .or_else(|| auth::parse_form(&req.body).get("csrf_token").cloned())
}

// ---------------------------------------------------------------------------
// Node-token auth helpers
// ---------------------------------------------------------------------------

/// Extract the bearer token from an `Authorization: Bearer <t>` header or a
/// `X-Node-Token: <t>` header. Returns `None` when neither is present.
fn node_token_from_req(req: &Request) -> Option<String> {
    if let Some(auth_hdr) = req.headers.get("authorization") {
        if let Some(rest) = auth_hdr.strip_prefix("Bearer ") {
            let t = rest.trim().to_string();
            if !t.is_empty() {
                return Some(t);
            }
        }
    }
    if let Some(t) = req.headers.get("x-node-token") {
        let t = t.trim().to_string();
        if !t.is_empty() {
            return Some(t);
        }
    }
    None
}

/// Authenticate a request via a durable node token.
///
/// Returns `(AuthUser, endpoint_id)` when the presented token matches a
/// registered endpoint. A non-empty token that matches no endpoint returns
/// `None`. An empty `node_token` field never matches (pre-backfill records
/// that haven't been upgraded yet).
fn auth_node(req: &Request, state: &SharedState) -> Option<(AuthUser, String)> {
    let token = node_token_from_req(req)?;
    let st = state.lock().ok()?;
    let ep = st
        .endpoints
        .iter()
        .find(|e| !e.node_token.is_empty() && e.node_token == token)?;
    let user = auth::AuthUser {
        sub: ep.added_by.clone(),
        email: ep.added_by.clone(),
        name: String::new(),
    };
    Some((user, ep.id.clone()))
}

/// `POST /api/heartbeat` — node-token auth variant.
///
/// CSRF is skipped because the bearer token IS the long-term credential.
/// If the JSON body carries an empty `"id"` field, the token's own endpoint id
/// is used — so always-on daemons need not know their own id at startup.
/// The ownership invariant is preserved: the resolved user must own the
/// heartbeated node.
fn handle_heartbeat_token(
    req: &Request,
    user: &auth::AuthUser,
    token_ep_id: &str,
    state: &SharedState,
) -> Response {
    // Back-fill id from the token's own endpoint when the caller omits it.
    let id = {
        let body_id = auth::extract_json_str(&req.body, "id").unwrap_or_default();
        if body_id.is_empty() {
            token_ep_id.to_string()
        } else {
            body_id
        }
    };
    if id.is_empty() {
        return Response::bad_request("id is required");
    }
    let endpoint = auth::extract_json_str(&req.body, "endpoint").unwrap_or_default();

    let mut st = match state.lock() {
        Ok(s) => s,
        Err(_) => return Response::error_html("Internal state lock error"),
    };
    // Ownership check: the resolved email must own the heartbeated node.
    let owned = st
        .endpoints
        .iter()
        .any(|e| e.id == id && e.added_by == user.email);
    if !owned {
        return Response::not_found();
    }
    let last_seen = crate::vpn_endpoint::now_secs();
    st.heartbeats.insert(
        id,
        heartbeat::Heartbeat {
            endpoint,
            last_seen,
        },
    );
    Response::ok_json("{\"ok\":true}\n".to_string())
}

// ---------------------------------------------------------------------------
// URL / form helpers
// ---------------------------------------------------------------------------

fn parse_query(query: &str) -> HashMap<String, String> {
    query
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .map(|(k, v)| (auth::url_decode(k), auth::url_decode(v)))
        .collect()
}

// ---------------------------------------------------------------------------
// HTML templates
// ---------------------------------------------------------------------------

fn render_dashboard(
    user: &AuthUser,
    csrf_token: &str,
    endpoints: &[crate::vpn_endpoint::VpnEndpoint],
) -> String {
    let table = if endpoints.is_empty() {
        r#"<p class="empty">No VPN endpoints registered yet. Add one below.</p>"#.to_string()
    } else {
        let rows: String = endpoints
            .iter()
            .map(|e| {
                let pk_short = if e.public_key.len() > 24 {
                    format!("{}…", &e.public_key[..24])
                } else {
                    e.public_key.clone()
                };
                let token_short = if e.node_token.len() > 14 {
                    format!("{}…", &e.node_token[..14])
                } else if e.node_token.is_empty() {
                    "—".to_string()
                } else {
                    e.node_token.clone()
                };
                let ips = e.allowed_ips.join(", ");
                let ep_disp = if e.endpoint_addr.is_empty() {
                    "—".to_string()
                } else {
                    e.endpoint_addr.clone()
                };
                let overlay = crate::ipam::overlay_addr_string(&e.allowed_ips)
                    .unwrap_or_else(|| "—".to_string());
                format!(
                    "<tr>\
                     <td>{name}</td>\
                     <td class=\"code\" title=\"{pk_full}\">{pk_short}</td>\
                     <td>{ep}</td>\
                     <td class=\"code\">Overlay IP: {overlay}</td>\
                     <td>{ips}</td>\
                     <td>{by}</td>\
                     <td class=\"code\" title=\"{token_full}\">{token_short}</td>\
                     <td>\
                       <form method=\"POST\" action=\"/api/endpoints/{id}/rotate-token\" style=\"margin:0 0 4px 0\">\
                         <input type=\"hidden\" name=\"csrf_token\" value=\"{csrf}\">\
                         <button type=\"submit\" class=\"btn\">Rotate token</button>\
                       </form>\
                       <form method=\"POST\" action=\"/api/endpoints/{id}/delete\" style=\"margin:0\">\
                         <input type=\"hidden\" name=\"csrf_token\" value=\"{csrf}\">\
                         <button type=\"submit\" class=\"btn btn-danger\">Delete</button>\
                       </form>\
                     </td>\
                     </tr>",
                    name = html_esc(&e.name),
                    pk_full = html_esc(&e.public_key),
                    pk_short = html_esc(&pk_short),
                    ep = html_esc(&ep_disp),
                    overlay = html_esc(&overlay),
                    ips = html_esc(&ips),
                    by = html_esc(&e.added_by),
                    token_full = html_esc(&e.node_token),
                    token_short = html_esc(&token_short),
                    id = html_esc(&e.id),
                    csrf = html_esc(csrf_token),
                )
            })
            .collect();
        format!(
            "<table>\
             <thead><tr>\
               <th>Name</th><th>Public Key</th><th>Endpoint</th>\
               <th>Overlay IP</th><th>Allowed IPs</th><th>Added By</th><th>Node Token</th><th></th>\
             </tr></thead>\
             <tbody>{rows}</tbody>\
             </table>"
        )
    };

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>AkurAI VPN — Dashboard</title>
<style>
*{{box-sizing:border-box}}
body{{font-family:system-ui,sans-serif;max-width:960px;margin:0 auto;padding:2rem;background:#0f172a;color:#e2e8f0;line-height:1.5}}
h2{{color:#60a5fa;margin-top:2rem;font-size:1.1rem}}
.bar{{display:flex;justify-content:space-between;align-items:center;background:#1e293b;padding:.875rem 1.25rem;border-radius:8px;margin-bottom:2rem;font-size:.9rem}}
.bar strong{{color:#e2e8f0}}
table{{width:100%;border-collapse:collapse}}
th,td{{text-align:left;padding:.5rem .75rem;border-bottom:1px solid #1e293b;font-size:.85rem}}
th{{background:#1e293b;color:#94a3b8;font-weight:500}}
tr:hover td{{background:#1e293b55}}
.btn{{display:inline-block;padding:.375rem .875rem;border:none;border-radius:5px;cursor:pointer;font-size:.8125rem;text-decoration:none;font-family:inherit}}
.btn-primary{{background:#3b82f6;color:#fff}}
.btn-primary:hover{{background:#2563eb}}
.btn-danger{{background:#ef4444;color:#fff}}
.btn-danger:hover{{background:#dc2626}}
.btn-ghost{{background:#334155;color:#e2e8f0}}
.btn-ghost:hover{{background:#475569}}
form.add-form{{background:#1e293b;padding:1.5rem;border-radius:8px;margin-top:1rem}}
.field{{margin-bottom:1rem}}
label{{display:block;color:#94a3b8;font-size:.8125rem;margin-bottom:.3rem}}
input{{width:100%;padding:.5rem .75rem;background:#0f172a;border:1px solid #334155;border-radius:4px;color:#e2e8f0;font-size:.875rem}}
input:focus{{outline:none;border-color:#3b82f6}}
.code{{font-family:monospace;font-size:.75rem;word-break:break-all}}
.empty{{color:#64748b;padding:2rem 0;font-size:.9rem}}
</style>
</head>
<body>
<div class="bar">
  <span><strong>AkurAI VPN</strong> &mdash; Control Dashboard</span>
  <span>Signed in as <strong>{display}</strong>&nbsp;
    <a href="/auth/logout" class="btn btn-ghost">Sign out</a>
  </span>
</div>

<h2>VPN Endpoints</h2>
{table}

<h2>Add Endpoint</h2>
<form method="POST" action="/api/endpoints/add" class="add-form">
  <input type="hidden" name="csrf_token" value="{csrf_token}">
  <div class="field">
    <label for="f-name">Name</label>
    <input id="f-name" name="name" type="text" placeholder="home-server" required>
  </div>
  <div class="field">
    <label for="f-pk">Public Key (WireGuard base64)</label>
    <input id="f-pk" name="public_key" type="text" placeholder="base64-encoded 32-byte public key" required>
  </div>
  <div class="field">
    <label for="f-ep">Endpoint Address <small style="color:#64748b">(optional)</small></label>
    <input id="f-ep" name="endpoint" type="text" placeholder="203.0.113.1:51820">
  </div>
  <div class="field">
    <label for="f-ips">Allowed IPs <small style="color:#64748b">(comma-separated)</small></label>
    <input id="f-ips" name="allowed_ips" type="text" placeholder="100.88.0.2/32, 0.0.0.0/0">
  </div>
  <button type="submit" class="btn btn-primary">Add Endpoint</button>
</form>
</body>
</html>"#,
        display = {
            let n = html_esc(&user.name);
            let e = html_esc(&user.email);
            if n.is_empty() {
                e
            } else {
                format!("{n} &lt;{e}&gt;")
            }
        },
        table = table,
        csrf_token = html_esc(csrf_token),
    )
}

fn error_page(msg: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>AkurAI VPN — Error</title>
<style>
body{{font-family:system-ui;max-width:600px;margin:4rem auto;padding:2rem;background:#0f172a;color:#e2e8f0}}
h1{{color:#ef4444;font-size:1.25rem}}p{{color:#94a3b8}}a{{color:#60a5fa}}
</style>
</head>
<body>
<h1>Error</h1>
<p>{msg}</p>
<p><a href="/">← Back to status</a> &nbsp; <a href="/login">Log in</a></p>
</body>
</html>"#,
        msg = html_esc(msg),
    )
}

fn html_esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(headers: &[(&str, &str)], body: &str) -> Request {
        Request {
            method: Method::Post,
            path: "/api/endpoints/add".to_string(),
            query: String::new(),
            headers: headers
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            body: body.to_string(),
        }
    }

    #[test]
    fn csrf_token_can_come_from_header() {
        let req = request(&[("x-csrf-token", "abc123")], "");
        assert_eq!(csrf_from_request(&req).as_deref(), Some("abc123"));
    }

    #[test]
    fn csrf_token_can_come_from_form_body() {
        let req = request(&[], "name=node&csrf_token=form-token");
        assert_eq!(csrf_from_request(&req).as_deref(), Some("form-token"));
    }

    #[test]
    fn dashboard_forms_include_csrf_token() {
        let user = AuthUser {
            sub: "sub".to_string(),
            email: "user@example.com".to_string(),
            name: "User".to_string(),
        };
        let html = render_dashboard(&user, "csrf-value", &[]);
        assert!(html.contains(r#"name="csrf_token" value="csrf-value""#));
    }

    #[test]
    fn dashboard_surfaces_overlay_ip() {
        let user = AuthUser {
            sub: "sub".to_string(),
            email: "user@example.com".to_string(),
            name: "User".to_string(),
        };
        let ep = crate::vpn_endpoint::VpnEndpoint {
            id: "n1".to_string(),
            name: "midget".to_string(),
            public_key: "pk".to_string(),
            endpoint_addr: String::new(),
            allowed_ips: vec!["100.88.0.2/32".to_string()],
            added_by: "user@example.com".to_string(),
            added_at: 1,
            node_token: String::new(),
        };
        let html = render_dashboard(&user, "csrf", std::slice::from_ref(&ep));
        assert!(html.contains("Overlay IP: 100.88.0.2"));
        assert!(html.contains("<th>Overlay IP</th>"));
    }

    #[test]
    fn endpoint_list_is_scoped_to_authenticated_user() {
        let state = crate::state::new_test_shared();
        {
            let mut st = state.lock().unwrap();
            st.endpoints.push(crate::vpn_endpoint::VpnEndpoint {
                id: "mine".to_string(),
                name: "midget".to_string(),
                public_key: "pk1".to_string(),
                endpoint_addr: String::new(),
                allowed_ips: Vec::new(),
                added_by: "user@example.com".to_string(),
                added_at: 1,
                node_token: String::new(),
            });
            st.endpoints.push(crate::vpn_endpoint::VpnEndpoint {
                id: "other".to_string(),
                name: "other-host".to_string(),
                public_key: "pk2".to_string(),
                endpoint_addr: String::new(),
                allowed_ips: Vec::new(),
                added_by: "other@example.com".to_string(),
                added_at: 1,
                node_token: String::new(),
            });
        }
        let session = AuthSession {
            user: AuthUser {
                sub: "sub".to_string(),
                email: "user@example.com".to_string(),
                name: "User".to_string(),
            },
            csrf_token: "csrf".to_string(),
        };
        let response = handle_list_endpoints(&session, &state);
        assert!(response.body.contains("mine"));
        assert!(!response.body.contains("other"));
    }

    #[test]
    fn delete_endpoint_cannot_remove_another_users_node() {
        let state = crate::state::new_test_shared();
        {
            let mut st = state.lock().unwrap();
            st.endpoints.push(crate::vpn_endpoint::VpnEndpoint {
                id: "other".to_string(),
                name: "other-host".to_string(),
                public_key: "pk2".to_string(),
                endpoint_addr: String::new(),
                allowed_ips: Vec::new(),
                added_by: "other@example.com".to_string(),
                added_at: 1,
                node_token: String::new(),
            });
        }
        let session = AuthSession {
            user: AuthUser {
                sub: "sub".to_string(),
                email: "user@example.com".to_string(),
                name: "User".to_string(),
            },
            csrf_token: "csrf".to_string(),
        };
        let req = request(&[], "csrf_token=csrf");
        let response = delete_endpoint("other", &session, &req, &state);
        assert_eq!(response.status, "404 Not Found");
        assert_eq!(state.lock().unwrap().endpoints.len(), 1);
    }

    #[test]
    fn rotate_token_reissues_for_owned_node_and_rejects_others() {
        let state = crate::state::new_test_shared();
        {
            let mut st = state.lock().unwrap();
            let mut mine = ep("mine", "user@example.com", &["100.88.0.2/32"]);
            mine.node_token = "aknk_old".to_string();
            st.endpoints.push(mine);
            st.endpoints
                .push(ep("other", "other@example.com", &["100.88.0.3/32"]));
        }
        let session = session_for("user@example.com");
        let req = request(&[], "csrf_token=csrf");

        // Owner can rotate: token changes to a fresh aknk_ value.
        let resp = rotate_token("mine", &session, &req, &state);
        assert_eq!(resp.status, "302 Found");
        let new_tok = state
            .lock()
            .unwrap()
            .endpoints
            .iter()
            .find(|e| e.id == "mine")
            .unwrap()
            .node_token
            .clone();
        assert_ne!(new_tok, "aknk_old");
        assert!(new_tok.starts_with("aknk_"));

        // Cannot rotate another user's node.
        let resp = rotate_token("other", &session, &req, &state);
        assert_eq!(resp.status, "404 Not Found");
    }

    // -- peer map + heartbeat ------------------------------------------------

    fn session_for(email: &str) -> AuthSession {
        AuthSession {
            user: AuthUser {
                sub: "sub".to_string(),
                email: email.to_string(),
                name: "User".to_string(),
            },
            csrf_token: "csrf".to_string(),
        }
    }

    fn ep(id: &str, added_by: &str, allowed: &[&str]) -> crate::vpn_endpoint::VpnEndpoint {
        crate::vpn_endpoint::VpnEndpoint {
            id: id.to_string(),
            name: format!("name-{id}"),
            public_key: format!("pk-{id}"),
            endpoint_addr: String::new(),
            allowed_ips: allowed.iter().map(|s| s.to_string()).collect(),
            added_by: added_by.to_string(),
            added_at: 1,
            node_token: String::new(),
        }
    }

    #[test]
    fn heartbeat_records_endpoint_and_timestamp_for_owned_node() {
        let state = crate::state::new_test_shared();
        {
            let mut st = state.lock().unwrap();
            st.endpoints
                .push(ep("mine", "user@example.com", &["100.88.0.2/32"]));
        }
        let session = session_for("user@example.com");
        let req = request(
            &[("x-csrf-token", "csrf")],
            r#"{"id":"mine","endpoint":"203.0.113.9:51820"}"#,
        );
        let resp = handle_heartbeat(&req, &session, &state);
        assert_eq!(resp.status, "200 OK");
        assert!(resp.body.contains("\"ok\":true"));

        let st = state.lock().unwrap();
        let hb = st.heartbeats.get("mine").expect("heartbeat recorded");
        assert_eq!(hb.endpoint, "203.0.113.9:51820");
        assert!(hb.last_seen > 0, "timestamp stamped on record");
    }

    #[test]
    fn heartbeat_rejects_node_not_owned_by_user() {
        let state = crate::state::new_test_shared();
        {
            let mut st = state.lock().unwrap();
            st.endpoints
                .push(ep("other", "other@example.com", &["100.88.0.2/32"]));
        }
        let session = session_for("user@example.com");
        let req = request(
            &[("x-csrf-token", "csrf")],
            r#"{"id":"other","endpoint":"203.0.113.9:51820"}"#,
        );
        let resp = handle_heartbeat(&req, &session, &state);
        assert_eq!(resp.status, "404 Not Found");
        // No liveness was forged for a node the caller does not own.
        assert!(state.lock().unwrap().heartbeats.is_empty());
    }

    #[test]
    fn peermap_handler_excludes_self_query_param() {
        let state = crate::state::new_test_shared();
        {
            let mut st = state.lock().unwrap();
            st.endpoints
                .push(ep("self-node", "user@example.com", &["100.88.0.2/32"]));
            st.endpoints
                .push(ep("peer-node", "user@example.com", &["100.88.0.3/32"]));
        }
        let session = session_for("user@example.com");
        let req = Request {
            method: Method::Get,
            path: "/api/peermap".to_string(),
            query: "self=self-node".to_string(),
            headers: std::collections::HashMap::new(),
            body: String::new(),
        };
        let resp = handle_peermap(&req, &session, &state, None);
        assert_eq!(resp.status, "200 OK");
        // The node named by ?self= is excluded; the peer is present.
        assert!(!resp.body.contains("name-self-node"));
        assert!(!resp.body.contains("100.88.0.2"));
        assert!(resp.body.contains("name-peer-node"));
        assert!(resp.body.contains("\"overlay_ipv4\":\"100.88.0.3\""));
        assert!(resp.body.contains("\"public_key\":\"pk-peer-node\""));
    }

    #[test]
    fn peermap_handler_is_scoped_to_user_and_reports_liveness() {
        let state = crate::state::new_test_shared();
        let now = crate::vpn_endpoint::now_secs();
        {
            let mut st = state.lock().unwrap();
            st.endpoints
                .push(ep("mine", "user@example.com", &["100.88.0.2/32"]));
            st.endpoints
                .push(ep("theirs", "other@example.com", &["100.88.0.3/32"]));
            // Fresh heartbeat for the owned node -> online true.
            st.heartbeats.insert(
                "mine".to_string(),
                heartbeat::Heartbeat {
                    endpoint: "203.0.113.9:51820".to_string(),
                    last_seen: now,
                },
            );
        }
        let session = session_for("user@example.com");
        let req = Request {
            method: Method::Get,
            path: "/api/peermap".to_string(),
            query: String::new(),
            headers: std::collections::HashMap::new(),
            body: String::new(),
        };
        let resp = handle_peermap(&req, &session, &state, None);
        assert!(resp.body.contains("name-mine"));
        assert!(resp.body.contains("\"online\":true"));
        // Another tenant's node is never disclosed.
        assert!(!resp.body.contains("name-theirs"));
        assert!(!resp.body.contains("100.88.0.3"));
    }

    // -- node token auth -------------------------------------------------------

    /// Tokens must start with `aknk_` and carry exactly 64 lowercase hex chars.
    #[test]
    fn generate_node_token_has_correct_format() {
        let t = crate::vpn_endpoint::generate_node_token();
        assert!(t.starts_with("aknk_"), "prefix wrong: {t}");
        assert_eq!(
            t.len(),
            5 + 64,
            "expected 'aknk_' + 64 hex chars (len {}), got: {t}",
            5 + 64
        );
        assert!(
            t[5..]
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase()),
            "non-lowercase-hex in token: {t}"
        );
    }

    /// `auth_node` resolves a bearer token to its owning `AuthUser` and endpoint id.
    #[test]
    fn auth_node_resolves_token_to_owner() {
        let state = crate::state::new_test_shared();
        let tok = "aknk_".to_string() + &"ab".repeat(32); // 5 + 64 chars
        {
            let mut st = state.lock().unwrap();
            let mut my_ep = ep("mine", "user@example.com", &["100.88.0.2/32"]);
            my_ep.node_token = tok.clone();
            st.endpoints.push(my_ep);
        }
        let req = Request {
            method: Method::Get,
            path: "/api/peermap".to_string(),
            query: String::new(),
            headers: [("authorization".to_string(), format!("Bearer {tok}"))]
                .into_iter()
                .collect(),
            body: String::new(),
        };
        let result = auth_node(&req, &state);
        assert!(result.is_some(), "expected auth_node to succeed");
        let (user, ep_id) = result.unwrap();
        assert_eq!(user.email, "user@example.com");
        assert_eq!(ep_id, "mine");
    }

    /// A token that matches no endpoint returns `None`.
    #[test]
    fn auth_node_bogus_token_returns_none() {
        let state = crate::state::new_test_shared();
        {
            let mut st = state.lock().unwrap();
            let mut my_ep = ep("mine", "user@example.com", &["100.88.0.2/32"]);
            my_ep.node_token = "aknk_goodtoken".to_string();
            st.endpoints.push(my_ep);
        }
        let req = Request {
            method: Method::Get,
            path: "/api/peermap".to_string(),
            query: String::new(),
            headers: [("authorization".to_string(), "Bearer aknk_bogus".to_string())]
                .into_iter()
                .collect(),
            body: String::new(),
        };
        assert!(auth_node(&req, &state).is_none());
    }

    /// `GET /api/peermap` with a valid bearer token returns the user's other peers.
    #[test]
    fn peermap_via_token_header_returns_user_peers() {
        let state = crate::state::new_test_shared();
        let tok = "aknk_".to_string() + &"cc".repeat(32);
        {
            let mut st = state.lock().unwrap();
            let mut my_ep = ep("mine", "user@example.com", &["100.88.0.2/32"]);
            my_ep.node_token = tok.clone();
            st.endpoints.push(my_ep);
            st.endpoints
                .push(ep("peer", "user@example.com", &["100.88.0.4/32"]));
            // Another tenant's endpoint — must not appear.
            st.endpoints
                .push(ep("theirs", "other@example.com", &["100.88.0.3/32"]));
        }
        let req = Request {
            method: Method::Get,
            path: "/api/peermap".to_string(),
            query: String::new(),
            headers: [("authorization".to_string(), format!("Bearer {tok}"))]
                .into_iter()
                .collect(),
            body: String::new(),
        };
        let resp = route(&req, &state);
        assert_eq!(resp.status, "200 OK");
        assert!(
            !resp.body.contains("name-mine"),
            "token-auth peermap should exclude the requesting node"
        );
        assert!(
            resp.body.contains("name-peer"),
            "same-tenant peer should be present"
        );
        assert!(
            !resp.body.contains("name-theirs"),
            "other tenant must not appear"
        );
    }

    /// `POST /api/heartbeat` with a bearer token succeeds without a CSRF token
    /// and records the node's liveness.
    #[test]
    fn heartbeat_via_token_no_csrf_marks_liveness() {
        let state = crate::state::new_test_shared();
        let tok = "aknk_".to_string() + &"dd".repeat(32);
        {
            let mut st = state.lock().unwrap();
            let mut my_ep = ep("mine", "user@example.com", &["100.88.0.2/32"]);
            my_ep.node_token = tok.clone();
            st.endpoints.push(my_ep);
        }
        // No cookie, no CSRF header, no CSRF body field — only the bearer token.
        let req = Request {
            method: Method::Post,
            path: "/api/heartbeat".to_string(),
            query: String::new(),
            headers: [("authorization".to_string(), format!("Bearer {tok}"))]
                .into_iter()
                .collect(),
            body: r#"{"id":"mine","endpoint":"203.0.113.9:51820"}"#.to_string(),
        };
        let resp = route(&req, &state);
        assert_eq!(resp.status, "200 OK");
        assert!(resp.body.contains("\"ok\":true"));
        let st = state.lock().unwrap();
        let hb = st.heartbeats.get("mine").expect("heartbeat was recorded");
        assert_eq!(hb.endpoint, "203.0.113.9:51820");
        assert!(hb.last_seen > 0, "timestamp must be set");
    }

    /// When the JSON body carries an empty `"id"`, the token's own endpoint id
    /// is used as the heartbeat target.
    #[test]
    fn heartbeat_via_token_backfills_id_when_empty() {
        let state = crate::state::new_test_shared();
        let tok = "aknk_".to_string() + &"ee".repeat(32);
        {
            let mut st = state.lock().unwrap();
            let mut my_ep = ep("mine", "user@example.com", &["100.88.0.2/32"]);
            my_ep.node_token = tok.clone();
            st.endpoints.push(my_ep);
        }
        let req = Request {
            method: Method::Post,
            path: "/api/heartbeat".to_string(),
            query: String::new(),
            headers: [("authorization".to_string(), format!("Bearer {tok}"))]
                .into_iter()
                .collect(),
            // Empty id — should be backfilled from the token's endpoint.
            body: r#"{"id":"","endpoint":""}"#.to_string(),
        };
        let resp = route(&req, &state);
        assert_eq!(resp.status, "200 OK");
        assert!(
            state.lock().unwrap().heartbeats.contains_key("mine"),
            "id was backfilled from the token's endpoint"
        );
    }
}
