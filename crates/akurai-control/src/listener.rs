//! Control-plane HTTP listener — minimal `std`-only HTTP/1.1 server.
//!
//! Binds on `127.0.0.1:CONTROL_PORT` (default 8104; override via env) and
//! handles `GET /` and `GET /health` for the deploy-binary health gate. TLS
//! terminates at nginx. No secrets or privileged access required for startup.
//!
//! Full control-plane routes (enrollment, peer-map, ACL, relay assignment) are
//! not implemented in 0.0.1 — see the UNRESOLVED crypto decision in
//! `docs/protocol.md`. This listener unblocks deploy health-checks while that
//! decision is pending.

use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::thread;

use crate::{acl, audit, enrollment, heartbeat, ipam, peermap};

const DEFAULT_PORT: u16 = 8104;
const NAME: &str = env!("CARGO_PKG_NAME");
const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Errors from the control-plane HTTP listener.
#[derive(Debug, Clone)]
pub enum ControlError {
    Bind(String),
}

impl std::fmt::Display for ControlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ControlError::Bind(msg) => write!(f, "failed to bind listener: {msg}"),
        }
    }
}

impl std::error::Error for ControlError {}

/// Start the control-plane HTTP listener.
///
/// Logs subsystem stub status, then binds and enters the accept loop.
/// Reads `CONTROL_PORT` from the environment; falls back to `8104`.
pub fn serve() -> Result<(), ControlError> {
    eprintln!("{NAME} {VERSION}: control-plane subsystems (0.0.1 stubs):");
    for line in [
        enrollment::status(),
        ipam::status(),
        peermap::status(),
        acl::status(),
        audit::status(),
        heartbeat::status(),
    ] {
        eprintln!("  - {line}");
    }

    let port: u16 = std::env::var("CONTROL_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_PORT);

    let addr = format!("127.0.0.1:{port}");
    let listener =
        TcpListener::bind(&addr).map_err(|e| ControlError::Bind(format!("{addr}: {e}")))?;

    eprintln!("{NAME} {VERSION}: HTTP listener ready on http://{addr}");

    for stream in listener.incoming() {
        match stream {
            Ok(s) => {
                thread::spawn(move || handle(s));
            }
            Err(e) => eprintln!("{NAME}: accept error: {e}"),
        }
    }
    Ok(())
}

fn handle(stream: std::net::TcpStream) {
    // Clone the stream so the BufReader owns one fd and we write to the other.
    let reader_fd = match stream.try_clone() {
        Ok(s) => s,
        Err(_) => return,
    };
    let mut reader = BufReader::new(reader_fd);

    // Read the request line (e.g. "GET / HTTP/1.1").
    let mut request_line = String::new();
    if reader.read_line(&mut request_line).is_err() {
        return;
    }

    // Drain the remaining headers so the client won't get a TCP RST.
    let mut header = String::new();
    loop {
        header.clear();
        match reader.read_line(&mut header) {
            Ok(0) | Err(_) => break,
            Ok(_) if header.trim().is_empty() => break,
            _ => {}
        }
    }
    drop(reader);

    let (status, body) = route(request_line.trim());
    let response = format!(
        "HTTP/1.1 {status}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {len}\r\n\
         Connection: close\r\n\
         \r\n\
         {body}",
        len = body.len(),
    );
    let _ = (&stream).write_all(response.as_bytes());
}

fn route(request_line: &str) -> (&'static str, String) {
    // Extract path, stripping any query string.
    let path = request_line
        .split(' ')
        .nth(1)
        .unwrap_or("/")
        .split('?')
        .next()
        .unwrap_or("/");

    match path {
        "/" | "/health" | "/healthz" => (
            "200 OK",
            format!("{{\"status\":\"ok\",\"service\":\"{NAME}\",\"version\":\"{VERSION}\"}}\n"),
        ),
        _ => (
            "404 Not Found",
            format!("{{\"error\":\"not found\",\"path\":\"{path}\"}}\n"),
        ),
    }
}
