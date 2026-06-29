//! The relay forward loop — a ciphertext-only hub.
//!
//! **Invariant: the relay never decrypts anything.** It reads only the outer
//! [`akurai_common::Frame`] envelope (magic, type, source/destination overlay
//! IP) and copies the datagram to the destination's last-known UDP endpoint. It
//! holds no payload keys and links no crypto crate.
//!
//! Endpoint learning: every frame teaches the relay that its `src` overlay IP is
//! currently reachable at the UDP address it arrived from (so a roaming node's
//! mapping updates on its next keepalive). A `Data`/handshake frame for a
//! destination the relay has not yet learned is dropped — there is nowhere to
//! send it and the relay never buffers unbounded state.

use std::collections::HashMap;
use std::io;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicU64, Ordering};

use akurai_common::frame::{Frame, FrameKind};

/// Default relay UDP port (overridable via `RELAY_PORT`).
const DEFAULT_PORT: u16 = 51820;

/// Forwarding counters, for operational visibility (and the e2e test's proof
/// that traffic actually traversed the hub).
#[derive(Default)]
pub struct Stats {
    pub learned: AtomicU64,
    pub forwarded: AtomicU64,
    pub dropped_unknown: AtomicU64,
    pub malformed: AtomicU64,
}

/// Run the relay forward loop on `RELAY_PORT` (default 51820), forever.
pub fn run() -> io::Result<()> {
    let port: u16 = std::env::var("RELAY_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_PORT);
    let sock = UdpSocket::bind(("0.0.0.0", port))?;
    eprintln!("akurai-relay: ciphertext-only hub on 0.0.0.0:{port}");
    let mut table: HashMap<Ipv4Addr, SocketAddr> = HashMap::new();
    let stats = Stats::default();
    let mut buf = [0u8; 4096];
    loop {
        let (n, from) = match sock.recv_from(&mut buf) {
            Ok(v) => v,
            Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        forward_one(&sock, &mut table, &stats, &buf[..n], from);
    }
}

/// Process a single received datagram: learn the source endpoint, then forward
/// to the destination (or drop). Factored out so it is unit-testable without a
/// live socket loop. Returns the action taken.
fn forward_one(
    sock: &UdpSocket,
    table: &mut HashMap<Ipv4Addr, SocketAddr>,
    stats: &Stats,
    datagram: &[u8],
    from: SocketAddr,
) -> Action {
    let Some(frame) = Frame::decode(datagram) else {
        stats.malformed.fetch_add(1, Ordering::Relaxed);
        return Action::Malformed;
    };
    // Learn: this source overlay IP is reachable at `from` (roaming updates here).
    if !frame.src.is_unspecified() && table.insert(frame.src, from) != Some(from) {
        stats.learned.fetch_add(1, Ordering::Relaxed);
    }
    // Keepalives only teach the relay; they are not forwarded.
    if frame.kind == FrameKind::Keepalive {
        return Action::Learned(frame.src);
    }
    // Forward to the destination's last-known endpoint, if known.
    match table.get(&frame.dest).copied() {
        Some(dest_addr) => {
            let _ = sock.send_to(datagram, dest_addr);
            stats.forwarded.fetch_add(1, Ordering::Relaxed);
            Action::Forwarded {
                dest: frame.dest,
                to: dest_addr,
            }
        }
        None => {
            stats.dropped_unknown.fetch_add(1, Ordering::Relaxed);
            Action::DroppedUnknown(frame.dest)
        }
    }
}

/// What `forward_one` did with a datagram (for tests + tracing).
#[derive(Debug, PartialEq, Eq)]
enum Action {
    Malformed,
    Learned(Ipv4Addr),
    Forwarded { dest: Ipv4Addr, to: SocketAddr },
    DroppedUnknown(Ipv4Addr),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(d: u8) -> Ipv4Addr {
        Ipv4Addr::new(100, 88, 0, d)
    }
    fn addr(p: u16) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], p))
    }

    // A throwaway bound socket; send_to to a dropped port is harmless for tests.
    fn sock() -> UdpSocket {
        UdpSocket::bind(("127.0.0.1", 0)).unwrap()
    }

    #[test]
    fn learns_endpoint_from_keepalive_and_does_not_forward_it() {
        let s = sock();
        let mut t = HashMap::new();
        let st = Stats::default();
        let ka = Frame::new(FrameKind::Keepalive, ip(2), Ipv4Addr::UNSPECIFIED, vec![])
            .unwrap()
            .encode();
        let action = forward_one(&s, &mut t, &st, &ka, addr(5000));
        assert_eq!(action, Action::Learned(ip(2)));
        assert_eq!(t.get(&ip(2)), Some(&addr(5000)));
        assert_eq!(st.learned.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn forwards_data_to_a_learned_destination() {
        let s = sock();
        let mut t = HashMap::new();
        let st = Stats::default();
        // B (100.88.0.3) is known at port 6000.
        t.insert(ip(3), addr(6000));
        // A→B data frame arriving from A's socket.
        let data = Frame::new(FrameKind::Data, ip(2), ip(3), vec![0xAB; 16])
            .unwrap()
            .encode();
        let action = forward_one(&s, &mut t, &st, &data, addr(5000));
        assert_eq!(
            action,
            Action::Forwarded {
                dest: ip(3),
                to: addr(6000)
            }
        );
        // Forwarding also learned A's endpoint.
        assert_eq!(t.get(&ip(2)), Some(&addr(5000)));
        assert_eq!(st.forwarded.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn drops_data_for_an_unknown_destination() {
        let s = sock();
        let mut t = HashMap::new();
        let st = Stats::default();
        let data = Frame::new(FrameKind::Data, ip(2), ip(9), vec![0; 8])
            .unwrap()
            .encode();
        assert_eq!(
            forward_one(&s, &mut t, &st, &data, addr(5000)),
            Action::DroppedUnknown(ip(9))
        );
        assert_eq!(st.dropped_unknown.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn roaming_updates_the_endpoint() {
        let s = sock();
        let mut t = HashMap::new();
        let st = Stats::default();
        let ka1 = Frame::new(FrameKind::Keepalive, ip(2), Ipv4Addr::UNSPECIFIED, vec![])
            .unwrap()
            .encode();
        forward_one(&s, &mut t, &st, &ka1, addr(5000));
        forward_one(&s, &mut t, &st, &ka1, addr(7777)); // same node, new address
        assert_eq!(t.get(&ip(2)), Some(&addr(7777)));
    }

    #[test]
    fn rejects_malformed_datagram() {
        let s = sock();
        let mut t = HashMap::new();
        let st = Stats::default();
        assert_eq!(
            forward_one(&s, &mut t, &st, b"not a frame", addr(5000)),
            Action::Malformed
        );
        assert_eq!(st.malformed.load(Ordering::Relaxed), 1);
    }
}
