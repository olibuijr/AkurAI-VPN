//! The ingress TCP proxy.
//!
//! For each [`Map`] we bind a public listener on `0.0.0.0:<listen_port>` and, for
//! every accepted connection, open a fresh TCP connection to the internal overlay
//! target and splice bytes in both directions — one worker thread per direction,
//! `std::io::copy`. The host is on the overlay (akurai0 up), so the overlay target
//! IP routes over the mesh. The proxy is payload-agnostic: it forwards opaque
//! bytes and holds no buffer beyond `io::copy`'s fixed 8 KiB stack copy.

use std::io;
use std::net::{Shutdown, TcpListener, TcpStream};
use std::thread;

use crate::config::Map;

/// Bind every map's public listener, then serve accepted connections forever.
///
/// All listeners are bound up front so a failure (e.g. the port is already in
/// use) surfaces immediately as a startup error instead of after a partial start.
pub fn serve(maps: Vec<Map>) -> io::Result<()> {
    if maps.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "no maps configured",
        ));
    }
    let mut workers = Vec::with_capacity(maps.len());
    for map in maps {
        let listener = TcpListener::bind(("0.0.0.0", map.listen_port)).map_err(|e| {
            io::Error::new(e.kind(), format!("bind 0.0.0.0:{}: {e}", map.listen_port))
        })?;
        eprintln!("akurai-ingress: listening {map}");
        workers.push(thread::spawn(move || accept_loop(&listener, &map)));
    }
    // The accept loops run forever; joining keeps the process alive and lets a
    // panicking listener surface rather than the process silently exiting.
    for w in workers {
        let _ = w.join();
    }
    Ok(())
}

/// Accept connections on one listener, dispatching each to its own thread so
/// many connections proxy concurrently.
fn accept_loop(listener: &TcpListener, map: &Map) {
    for conn in listener.incoming() {
        match conn {
            Ok(client) => {
                let host = map.target_host.clone();
                let port = map.target_port;
                thread::spawn(move || handle_connection(client, host, port));
            }
            Err(e) => eprintln!(
                "akurai-ingress: accept on 0.0.0.0:{} failed: {e}",
                map.listen_port
            ),
        }
    }
}

/// Proxy one accepted client to `target_host:target_port` over the overlay,
/// splicing both directions until either side closes. On any error the sockets
/// drop and close — no thread or descriptor is leaked.
pub(crate) fn handle_connection(client: TcpStream, target_host: String, target_port: u16) {
    let upstream = match TcpStream::connect((target_host.as_str(), target_port)) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("akurai-ingress: connect {target_host}:{target_port} failed: {e}");
            return; // `client` drops here → its socket is closed cleanly
        }
    };

    // Each socket needs an independent handle for its read and write halves:
    // `client_rd`/`upstream_wr` drive the client→upstream direction; the owned
    // `upstream`/`client` drive upstream→client.
    let (client_rd, upstream_wr) = match dual(&client, &upstream) {
        Some(pair) => pair,
        None => return, // sockets drop here → both closed cleanly
    };

    // client → upstream on a worker; upstream → client on this thread. We join
    // the worker before returning so no detached thread outlives the connection.
    let worker = thread::spawn(move || splice(client_rd, upstream_wr));
    splice(upstream, client);
    let _ = worker.join();
}

/// Clone a read-half handle of `a` and a write-half handle of `b`, returning
/// `None` (after logging) if the kernel cannot duplicate the descriptors.
fn dual(a: &TcpStream, b: &TcpStream) -> Option<(TcpStream, TcpStream)> {
    match (a.try_clone(), b.try_clone()) {
        (Ok(a2), Ok(b2)) => Some((a2, b2)),
        _ => {
            eprintln!("akurai-ingress: could not duplicate socket; dropping connection");
            None
        }
    }
}

/// Copy `from` → `to` until EOF, then half-close both ends so the peer's opposite
/// copy also unblocks and the connection tears down cleanly. `io::copy` uses a
/// bounded 8 KiB stack buffer, so per-connection memory stays fixed.
fn splice(mut from: TcpStream, mut to: TcpStream) {
    let _ = io::copy(&mut from, &mut to);
    let _ = to.shutdown(Shutdown::Write);
    let _ = from.shutdown(Shutdown::Read);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;

    /// End-to-end loopback proof: client → ingress front → upstream echo, and the
    /// echoed bytes flow back. Exercises both splice directions and clean
    /// half-close teardown without any network namespace.
    #[test]
    fn proxies_bytes_bidirectionally_to_upstream() {
        // Upstream "service": an echo server on an ephemeral loopback port.
        let upstream = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let up_addr = upstream.local_addr().unwrap();
        let echo = thread::spawn(move || {
            if let Ok((mut s, _)) = upstream.accept() {
                let mut buf = [0u8; 256];
                loop {
                    match s.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if s.write_all(&buf[..n]).is_err() {
                                break;
                            }
                        }
                    }
                }
            }
        });

        // Ingress front: an ephemeral listener; one accepted connection is handed
        // to the real `handle_connection`, pointed at the echo upstream.
        let front = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let front_addr = front.local_addr().unwrap();
        let host = up_addr.ip().to_string();
        let port = up_addr.port();
        let front_thread = thread::spawn(move || {
            let (client, _) = front.accept().unwrap();
            handle_connection(client, host, port);
        });

        // Public client: connect to the front, send, half-close, read the echo.
        let mut c = TcpStream::connect(front_addr).unwrap();
        c.write_all(b"marcus").unwrap();
        c.shutdown(Shutdown::Write).unwrap();
        let mut got = Vec::new();
        c.read_to_end(&mut got).unwrap();
        assert_eq!(&got, b"marcus");

        front_thread.join().unwrap();
        echo.join().unwrap();
    }

    /// An empty map set is rejected rather than binding nothing and hanging.
    #[test]
    fn serve_rejects_empty_maps() {
        let err = serve(Vec::new()).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }
}
