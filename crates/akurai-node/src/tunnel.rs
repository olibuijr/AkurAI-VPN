//! The data plane — an encrypted overlay pump with relay fallback and direct paths.
//!
//! `run` opens the `akurai0` TUN, assigns the node's overlay IP and a
//! `100.88.0.0/16`-ONLY route (never a default route — the host's internet path
//! is inviolable), binds a UDP socket, and runs two blocking pumps over a shared
//! per-peer state table:
//!
//! - **TUN → UDP**: read an IPv4 packet, route it to the carrying peer, encrypt
//!   with that peer's Noise session, and send a `Data` frame on the peer's
//!   current path — a **direct** UDP address once one is confirmed, otherwise the
//!   relay (which forwards by destination overlay IP).
//! - **UDP → TUN**: receive a frame; complete handshakes, learn/confirm direct
//!   paths from `PeerAddr` hints, or decrypt a `Data` frame and write the inner
//!   packet to the TUN.
//!
//! Direct paths (MVP3): handshakes go via the relay, which sends each end a
//! `PeerAddr` hint with the other's observed UDP address. Both nodes probe that
//! address (opening any NAT hole); a frame received straight from a peer confirms
//! the direct path and traffic leaves the hub. If no direct path forms, the relay
//! carries everything. End-to-end: the relay only ever sees ciphertext.
//! Fail-closed: a packet to an unknown destination, or from an unverified peer, is dropped.

use std::collections::{HashMap, HashSet};
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

use crate::acl::Acl;
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
    /// Use this peer as a full-tunnel EXIT node (route 0.0.0.0/0 over the overlay
    /// to it). Explicit opt-in only — `None` means normal split-tunnel.
    pub exit_node: Option<Ipv4Addr>,
    /// Fine-grained ACL (MVP4). `Some` ⇒ enforce a fail-closed tag policy on
    /// every outbound flow (`this-node → routing-peer`); `None` ⇒ no ACL file,
    /// so any peer in the map is reachable (network-membership-only).
    pub acl: Option<Acl>,
}

/// Per-peer session + path state, shared between the pump threads.
#[derive(Default)]
struct PeerState {
    /// Completed Noise session (None until the handshake finishes).
    session: Option<Session>,
    /// In-flight handshake we initiated.
    pending: Option<Initiator>,
    /// A confirmed direct UDP path — outbound frames go here instead of the relay.
    direct: Option<SocketAddr>,
    /// A direct address learned from a relay `PeerAddr` hint, being probed but
    /// not yet confirmed.
    candidate: Option<SocketAddr>,
}

type Table = HashMap<Ipv4Addr, PeerState>;

/// The handles both pump loops share: the TUN, the UDP socket, the per-peer
/// state table, the peer/routing table, this node's keypair, its overlay IP,
/// and the relay address. Bundled (and cheaply `Clone`, since the heavy members
/// are `Arc`s) so each pump takes a single context argument.
#[derive(Clone)]
struct Pump {
    tun: Arc<File>,
    sock: Arc<UdpSocket>,
    table: Arc<Mutex<Table>>,
    peers: Arc<PeerTable>,
    kp: Arc<Keypair>,
    my_ip: Ipv4Addr,
    relay: SocketAddr,
}

/// 32 bytes of OS entropy for an ephemeral handshake secret.
fn rand32() -> io::Result<[u8; 32]> {
    let mut b = [0u8; 32];
    File::open("/dev/urandom")?.read_exact(&mut b)?;
    Ok(b)
}

/// Decode a 6-byte `PeerAddr` payload (4 octets + BE port) into a socket address.
fn parse_addr(payload: &[u8]) -> Option<SocketAddr> {
    if payload.len() != 6 {
        return None;
    }
    let ip = Ipv4Addr::new(payload[0], payload[1], payload[2], payload[3]);
    let port = u16::from_be_bytes([payload[4], payload[5]]);
    Some(SocketAddr::from((ip, port)))
}

/// Bring up the overlay interface: address, MTU, the overlay-only route, any
/// peer-advertised subnet routes, and IP forwarding if this node is a gateway.
/// Uses `ip`/`sysctl` (safe `std::process::Command`); adds NO default route.
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
    // Subnet routes: point each peer-advertised subnet at the overlay. A
    // 0.0.0.0/0 advertisement is SKIPPED here — a peer can never silently capture
    // all traffic; full-tunnel happens only via the explicit `--exit-node` opt-in.
    for (subnet, _gw) in cfg.peers.advertised_routes() {
        if subnet.prefix_len() == 0 {
            continue; // never auto-install a default route
        }
        let cidr = subnet.to_string();
        let _ = Command::new("ip")
            .args(["route", "add", &cidr, "dev", &cfg.iface])
            .status();
    }
    // Exit node (full-tunnel), EXPLICIT opt-in only: route everything via the
    // overlay using two /1 routes that out-specific the real default WITHOUT
    // deleting it — so when the tunnel/TUN closes, normal routing is restored
    // automatically. The chosen exit peer must advertise 0.0.0.0/0.
    if let Some(exit) = cfg.exit_node {
        eprintln!(
            "{}: full-tunnel — routing 0.0.0.0/0 via exit node {exit}",
            cfg.iface
        );
        let _ = Command::new("ip")
            .args(["route", "add", "0.0.0.0/1", "dev", &cfg.iface])
            .status();
        let _ = Command::new("ip")
            .args(["route", "add", "128.0.0.0/1", "dev", &cfg.iface])
            .status();
    }
    // If THIS node is a gateway, enable IP forwarding. An exit gateway (advertising
    // 0.0.0.0/0) also masquerades overlay traffic out its real interface.
    if !cfg.advertise.is_empty() {
        let _ = Command::new("sysctl")
            .args(["-qw", "net.ipv4.ip_forward=1"])
            .status();
        if cfg.advertise.iter().any(|c| c.prefix_len() == 0) {
            let _ = Command::new("sh")
                .args([
                    "-c",
                    "iptables -t nat -C POSTROUTING -s 100.88.0.0/16 ! -o akurai0 -j MASQUERADE 2>/dev/null \
                     || iptables -t nat -A POSTROUTING -s 100.88.0.0/16 ! -o akurai0 -j MASQUERADE",
                ])
                .status();
        }
    }
    Ok(())
}

/// Run the data plane. Opens the TUN, brings up the interface, binds the socket,
/// and blocks running the pumps until the process is killed.
pub fn run(cfg: TunnelConfig) -> io::Result<()> {
    let tun = Arc::new(akurai_sys::create_tun(&cfg.iface)?);
    setup_interface(&cfg)?;

    let sock = Arc::new(UdpSocket::bind(("0.0.0.0", 0))?);
    let relay = cfg.relay;
    let table: Arc<Mutex<Table>> = Arc::new(Mutex::new(HashMap::new()));
    let peers = Arc::new(cfg.peers);
    let kp = Arc::new(cfg.keypair);
    let my_ip = cfg.overlay_ip;
    // ACL is consulted only on the outbound (TUN→UDP) path, which runs on this
    // thread, so it need not be shared with the UDP pump.
    let acl = cfg.acl;

    // MagicDNS: resolve `<peer-name>.akurai` (and bare `<peer-name>`) to a peer's
    // overlay IP, served on the node's own overlay IP:53.
    {
        let dns_peers = Arc::clone(&peers);
        let bind = SocketAddr::from((my_ip, 53));
        thread::spawn(move || {
            let _ = akurai_dns::serve(bind, "akurai", move |label| dns_peers.resolve_name(label));
        });
    }

    // Keepalive to the relay (stay known) + probe direct candidates/paths to keep
    // any NAT hole open.
    {
        let sock = Arc::clone(&sock);
        let table = Arc::clone(&table);
        thread::spawn(move || loop {
            if let Some(f) = Frame::new(
                FrameKind::Keepalive,
                my_ip,
                Ipv4Addr::UNSPECIFIED,
                Vec::new(),
            ) {
                let bytes = f.encode();
                let _ = sock.send_to(&bytes, relay);
                if let Ok(t) = table.lock() {
                    for st in t.values() {
                        if let Some(a) = st.direct.or(st.candidate) {
                            let _ = sock.send_to(&bytes, a);
                        }
                    }
                }
            }
            thread::sleep(Duration::from_secs(15));
        });
    }

    let pump = Pump {
        tun,
        sock,
        table,
        peers,
        kp,
        my_ip,
        relay,
    };
    let udp = {
        let pump = pump.clone();
        thread::spawn(move || udp_pump(pump))
    };

    tun_pump(pump, acl)?;
    let _ = udp.join();
    Ok(())
}

/// Read packets from the TUN, encrypt to the routing peer (initiating a handshake
/// via the relay on first contact), and send `Data` frames on the peer's current
/// path (direct if confirmed, else the relay).
fn tun_pump(pump: Pump, acl: Option<Acl>) -> io::Result<()> {
    let Pump {
        tun,
        sock,
        table,
        peers,
        kp,
        my_ip,
        relay,
    } = pump;
    let mut buf = [0u8; 2048];
    // Peers already logged as ACL-denied, so the drop notice prints once each.
    let mut acl_denied_logged: HashSet<Ipv4Addr> = HashSet::new();
    loop {
        let mut tunref: &File = &tun;
        let n = match tunref.read(&mut buf) {
            Ok(0) => return Ok(()),
            Ok(n) => n,
            Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        let pkt = &buf[..n];
        if n < 20 || (pkt[0] >> 4) != 4 {
            continue; // IPv4 only
        }
        let dest = Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);
        // Route to the carrying peer: an exact overlay peer, or the gateway peer
        // advertising the subnet `dest` falls in. The session is keyed by the
        // PEER overlay IP, so subnet traffic rides the gateway peer's session.
        let Some(peer) = peers.route_to(&dest) else {
            continue; // fail-closed: no peer/route for this destination
        };
        // Fine-grained ACL gate (fail-closed): if enforcement is on and this
        // node is not permitted to reach the routing peer, DROP the packet —
        // no handshake, no send, no per-peer state. A one-time notice per
        // denied peer keeps the data path silent but observable.
        if let Some(acl) = acl.as_ref() {
            if !acl.permits(peer) {
                if acl_denied_logged.insert(peer.overlay_ip) {
                    let label = if peer.name.is_empty() {
                        peer.overlay_ip.to_string()
                    } else {
                        peer.name.clone()
                    };
                    eprintln!("acl: denied {label}");
                }
                continue;
            }
        }
        let peer_ip = peer.overlay_ip;
        let peer_pub = peer.public_key;

        let mut out: Option<(Vec<u8>, SocketAddr)> = None;
        {
            let mut t = table.lock().unwrap();
            let st = t.entry(peer_ip).or_default();
            if let Some(sess) = st.session.as_mut() {
                let ct = sess.encrypt(pkt);
                let addr = st.direct.unwrap_or(relay);
                out = Frame::new(FrameKind::Data, my_ip, peer_ip, ct).map(|f| (f.encode(), addr));
            } else if st.pending.is_none() {
                // First contact: initiate via the relay and drop this packet (the
                // upper layer retransmits once a session exists).
                if let Ok(eph) = rand32() {
                    let (state, msg1) = noise::initiate(&kp, &peer_pub, &eph);
                    st.pending = Some(state);
                    out = Frame::new(FrameKind::HandshakeInit, my_ip, peer_ip, msg1)
                        .map(|f| (f.encode(), relay));
                }
            }
        }
        if let Some((bytes, addr)) = out {
            let _ = sock.send_to(&bytes, addr);
        }
    }
}

/// Receive frames: confirm direct paths, complete handshakes, act on `PeerAddr`
/// hints, or decrypt `Data` and write the inner packet to the TUN. Survives
/// malformed datagrams (continues).
fn udp_pump(pump: Pump) {
    let Pump {
        tun,
        sock,
        table,
        peers,
        kp,
        my_ip,
        relay,
    } = pump;
    let mut buf = [0u8; 4096];
    loop {
        let (n, from) = match sock.recv_from(&mut buf) {
            Ok(v) => v,
            Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => return,
        };
        let Some(frame) = Frame::decode(&buf[..n]) else {
            continue;
        };

        // A frame arriving straight from a known peer (not the relay) proves a
        // working direct path — switch this peer's outbound path to it.
        if from != relay && frame.kind != FrameKind::PeerAddr && peers.get(&frame.src).is_some() {
            if let Ok(mut t) = table.lock() {
                let st = t.entry(frame.src).or_default();
                if st.direct.is_none() {
                    eprintln!("akurai-node: direct path to {} via {from}", frame.src);
                }
                st.direct = Some(from);
            }
        }

        match frame.kind {
            FrameKind::PeerAddr => {
                // The relay hints that peer `frame.src` is reachable at the payload
                // address. Remember it and probe to open any NAT hole.
                if let (Some(addr), true) =
                    (parse_addr(&frame.payload), peers.get(&frame.src).is_some())
                {
                    {
                        let mut t = table.lock().unwrap();
                        let st = t.entry(frame.src).or_default();
                        if st.direct.is_none() {
                            st.candidate = Some(addr);
                        }
                    }
                    if let Some(f) = Frame::new(
                        FrameKind::Keepalive,
                        my_ip,
                        Ipv4Addr::UNSPECIFIED,
                        Vec::new(),
                    ) {
                        let _ = sock.send_to(&f.encode(), addr);
                    }
                }
            }
            FrameKind::HandshakeInit => {
                let Ok(eph) = rand32() else { continue };
                if let Some((keys, msg2, init_pub)) = noise::respond(&kp, &eph, &frame.payload) {
                    match peers.get(&frame.src) {
                        Some(p) if p.public_key == init_pub => {
                            table.lock().unwrap().entry(frame.src).or_default().session =
                                Some(Session::new(keys));
                            if let Some(reply) =
                                Frame::new(FrameKind::HandshakeResp, my_ip, frame.src, msg2)
                            {
                                let _ = sock.send_to(&reply.encode(), from); // reply on arrival path
                            }
                        }
                        _ => {} // unknown / mismatched peer: drop
                    }
                }
            }
            FrameKind::HandshakeResp => {
                let mut t = table.lock().unwrap();
                let st = t.entry(frame.src).or_default();
                if let Some(state) = st.pending.take() {
                    if let Some(keys) = noise::finalize(state, &frame.payload) {
                        st.session = Some(Session::new(keys));
                    }
                }
            }
            FrameKind::Data => {
                let mut t = table.lock().unwrap();
                if let Some(st) = t.get_mut(&frame.src) {
                    if let Some(sess) = st.session.as_mut() {
                        if let Some(pt) = sess.decrypt(&frame.payload) {
                            drop(t);
                            let mut tunref: &File = &tun;
                            let _ = tunref.write_all(&pt);
                        }
                    }
                }
            }
            FrameKind::Keepalive => {} // direct-path confirmation handled above
        }
    }
}
