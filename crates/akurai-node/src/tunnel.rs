//! The data plane — a hub-routed encrypted overlay pump.
//!
//! `run` opens the `akurai0` TUN, assigns the node's overlay IP and a
//! `100.88.0.0/16`-ONLY route (never a default route — the host's internet path
//! is inviolable), connects a UDP socket to the relay, and runs two blocking
//! pumps that share a per-peer session table:
//!
//! - **TUN → UDP**: read an IPv4 packet, look up the destination peer, encrypt
//!   with its Noise session (initiating a handshake if none exists), and send a
//!   `Data` frame to the relay, which forwards it to the peer.
//! - **UDP → TUN**: receive a relay frame; complete handshakes (`HandshakeInit`
//!   / `HandshakeResp`) or decrypt a `Data` frame and write the inner packet to
//!   the TUN.
//!
//! End-to-end: the relay only ever forwards ciphertext. Fail-closed: a packet to
//! an unknown destination, or from an unverified peer, is dropped.

use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::fs::File;
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use akurai_common::frame::{Frame, FrameKind};
use akurai_transport::noise::{self, Initiator};
use akurai_transport::session::Session;
use akurai_transport::Keypair;

use crate::peers::PeerTable;

/// Runtime configuration for the data-plane daemon.
pub struct TunnelConfig {
    pub iface: String,
    pub overlay_ip: Ipv4Addr,
    pub overlay_cidr: String,
    pub mtu: u16,
    pub relay: SocketAddr,
    pub keypair: Keypair,
    pub peers: PeerTable,
    /// Subnets THIS node is a gateway for (MVP2). When non-empty, the node
    /// enables IP forwarding so it can relay overlay traffic to the real subnet.
    pub advertise: Vec<akurai_common::Cidr>,
}

/// Per-peer Noise session state, shared between the two pump threads.
#[derive(Default)]
struct SessionTable {
    /// Completed sessions keyed by the peer's overlay IP.
    established: HashMap<Ipv4Addr, Session>,
    /// Handshakes we initiated and are awaiting a response for.
    pending: HashMap<Ipv4Addr, Initiator>,
}

/// 32 bytes of OS entropy for an ephemeral handshake secret.
fn rand32() -> io::Result<[u8; 32]> {
    let mut b = [0u8; 32];
    File::open("/dev/urandom")?.read_exact(&mut b)?;
    Ok(b)
}

/// Bring up the overlay interface with the node's address and the overlay-only
/// route. Uses `ip` (safe `std::process::Command`); adds NO default route.
fn setup_interface(cfg: &TunnelConfig) -> io::Result<()> {
    let ip = |args: &[&str]| -> io::Result<()> {
        let status = Command::new("ip").args(args).status()?;
        if !status.success() {
            return Err(io::Error::other(format!("`ip {}` failed", args.join(" "))));
        }
        Ok(())
    };
    let addr = format!("{}/32", cfg.overlay_ip);
    let mtu = cfg.mtu.to_string();
    ip(&["addr", "add", &addr, "dev", &cfg.iface])?;
    ip(&["link", "set", &cfg.iface, "mtu", &mtu])?;
    ip(&["link", "set", &cfg.iface, "up"])?;
    // Overlay-scoped route ONLY. Never 0.0.0.0/0.
    ip(&["route", "add", &cfg.overlay_cidr, "dev", &cfg.iface])?;
    // Subnet routes: point each peer-advertised subnet at the overlay so packets
    // for it are tunnelled to the advertising gateway. Still NEVER 0.0.0.0/0.
    for (subnet, _gw) in cfg.peers.advertised_routes() {
        let cidr = subnet.to_string();
        // Best-effort: a subnet may already be routed; ignore an add failure.
        let _ = Command::new("ip")
            .args(["route", "add", &cidr, "dev", &cfg.iface])
            .status();
    }
    // If THIS node is a subnet gateway, enable IP forwarding so it can relay
    // overlay traffic onward to the real subnet behind it.
    if !cfg.advertise.is_empty() {
        let _ = Command::new("sysctl")
            .args(["-qw", "net.ipv4.ip_forward=1"])
            .status();
    }
    Ok(())
}

/// Run the data plane. Opens the TUN, brings up the interface, connects to the
/// relay, and blocks running the two pumps until the process is killed.
pub fn run(cfg: TunnelConfig) -> io::Result<()> {
    let tun = Arc::new(akurai_sys::create_tun(&cfg.iface)?);
    setup_interface(&cfg)?;

    let sock = Arc::new(UdpSocket::bind(("0.0.0.0", 0))?);
    sock.connect(cfg.relay)?;

    let sessions = Arc::new(Mutex::new(SessionTable::default()));
    let peers = Arc::new(cfg.peers);
    let kp = Arc::new(cfg.keypair);
    let my_ip = cfg.overlay_ip;

    // MagicDNS: resolve `<peer-name>.akurai` (and bare `<peer-name>`) to a peer's
    // overlay IP, served on the node's own overlay IP:53. Point the system
    // resolver at this address (e.g. `nameserver <overlay_ip>`) to `ping nodeb`.
    {
        let dns_peers = Arc::clone(&peers);
        let bind = SocketAddr::from((my_ip, 53));
        thread::spawn(move || {
            let _ = akurai_dns::serve(bind, "akurai", move |label| dns_peers.resolve_name(label));
        });
    }

    // Teach the relay our endpoint, and keep it (and any NAT mapping) fresh.
    let keepalive_sock = Arc::clone(&sock);
    let _keepalive = thread::spawn(move || loop {
        if let Some(f) = Frame::new(
            FrameKind::Keepalive,
            my_ip,
            Ipv4Addr::UNSPECIFIED,
            Vec::new(),
        ) {
            let _ = keepalive_sock.send(&f.encode());
        }
        thread::sleep(Duration::from_secs(20));
    });

    // UDP → TUN pump (handshakes + decrypt).
    let udp = {
        let tun = Arc::clone(&tun);
        let sock = Arc::clone(&sock);
        let sessions = Arc::clone(&sessions);
        let peers = Arc::clone(&peers);
        let kp = Arc::clone(&kp);
        thread::spawn(move || udp_pump(tun, sock, sessions, peers, kp, my_ip))
    };

    // TUN → UDP pump (encrypt + initiate). Runs on this thread; blocks forever.
    tun_pump(tun, sock, sessions, peers, kp, my_ip)?;
    let _ = udp.join();
    Ok(())
}

/// Read packets from the TUN, encrypt to the destination peer (initiating a
/// handshake on first contact), and send `Data` frames to the relay.
fn tun_pump(
    tun: Arc<File>,
    sock: Arc<UdpSocket>,
    sessions: Arc<Mutex<SessionTable>>,
    peers: Arc<PeerTable>,
    kp: Arc<Keypair>,
    my_ip: Ipv4Addr,
) -> io::Result<()> {
    let mut buf = [0u8; 2048];
    loop {
        let mut tunref: &File = &tun;
        let n = match tunref.read(&mut buf) {
            Ok(0) => return Ok(()),
            Ok(n) => n,
            Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        let pkt = &buf[..n];
        // IPv4 only (version nibble 4, ≥20-byte header).
        if n < 20 || (pkt[0] >> 4) != 4 {
            continue;
        }
        let dest = Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);
        // Route to the carrying peer: an exact overlay peer, or the gateway peer
        // advertising the subnet `dest` falls in. The Noise session is keyed by
        // the PEER's overlay IP (not the inner destination), so subnet traffic
        // rides the gateway peer's session; the gateway forwards the inner packet.
        let Some(peer) = peers.route_to(&dest) else {
            continue; // fail-closed: no peer/route for this destination
        };
        let peer_ip = peer.overlay_ip;
        let peer_pub = peer.public_key;

        // Decide what to emit while holding the lock; send after releasing it.
        let mut to_send: Option<Vec<u8>> = None;
        {
            let mut tbl = sessions.lock().unwrap();
            if let Some(sess) = tbl.established.get_mut(&peer_ip) {
                let ct = sess.encrypt(pkt);
                to_send = Frame::new(FrameKind::Data, my_ip, peer_ip, ct).map(|f| f.encode());
            } else if let Entry::Vacant(slot) = tbl.pending.entry(peer_ip) {
                // First contact: initiate a handshake and drop this packet (the
                // upper layer — ICMP/TCP — retransmits once we have a session).
                if let Ok(eph) = rand32() {
                    let (state, msg1) = noise::initiate(&kp, &peer_pub, &eph);
                    slot.insert(state);
                    to_send = Frame::new(FrameKind::HandshakeInit, my_ip, peer_ip, msg1)
                        .map(|f| f.encode());
                }
            }
        }
        if let Some(bytes) = to_send {
            let _ = sock.send(&bytes);
        }
    }
}

/// Receive relay frames: complete handshakes, or decrypt `Data` and write the
/// inner packet to the TUN. Survives malformed datagrams (logs nothing, continues).
fn udp_pump(
    tun: Arc<File>,
    sock: Arc<UdpSocket>,
    sessions: Arc<Mutex<SessionTable>>,
    peers: Arc<PeerTable>,
    kp: Arc<Keypair>,
    my_ip: Ipv4Addr,
) {
    let mut buf = [0u8; 4096];
    loop {
        let n = match sock.recv(&mut buf) {
            Ok(n) => n,
            Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => return,
        };
        let Some(frame) = Frame::decode(&buf[..n]) else {
            continue; // malformed datagram dropped
        };
        match frame.kind {
            FrameKind::HandshakeInit => {
                // A peer wants to reach us. Respond only if we can authenticate
                // the initiator's static key against our peer table (fail-closed).
                let Ok(eph) = rand32() else { continue };
                if let Some((keys, msg2, init_pub)) = noise::respond(&kp, &eph, &frame.payload) {
                    match peers.get(&frame.src) {
                        Some(p) if p.public_key == init_pub => {
                            sessions
                                .lock()
                                .unwrap()
                                .established
                                .insert(frame.src, Session::new(keys));
                            if let Some(reply) =
                                Frame::new(FrameKind::HandshakeResp, my_ip, frame.src, msg2)
                            {
                                let _ = sock.send(&reply.encode());
                            }
                        }
                        _ => {} // unknown / mismatched peer: drop
                    }
                }
            }
            FrameKind::HandshakeResp => {
                let mut tbl = sessions.lock().unwrap();
                if let Some(state) = tbl.pending.remove(&frame.src) {
                    if let Some(keys) = noise::finalize(state, &frame.payload) {
                        tbl.established.insert(frame.src, Session::new(keys));
                    }
                }
            }
            FrameKind::Data => {
                let mut tbl = sessions.lock().unwrap();
                if let Some(sess) = tbl.established.get_mut(&frame.src) {
                    if let Some(pt) = sess.decrypt(&frame.payload) {
                        drop(tbl);
                        let mut tunref: &File = &tun;
                        let _ = tunref.write_all(&pt);
                    }
                }
            }
            FrameKind::Keepalive => {} // nodes ignore; only the relay learns from these
        }
    }
}
