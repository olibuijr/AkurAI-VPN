//! `akurai-node` — the AkurAI VPN node daemon, installed on every device.
//!
//! Initial scope is deliberately host-only: a node can install local state and
//! mark itself up for AkurAI-VPN host-to-host membership, but it does not install
//! subnet routes, exit routes, or gateway advertisements. Command dispatch is
//! parsed from `std::env::args` by hand to keep the zero-dependency promise.

mod acl;
mod error;
mod heartbeat;
mod identity;
mod peermap;
mod peers;
mod rng;
mod tun;
mod tunnel;

use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::net::{Ipv4Addr, SocketAddr, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use error::NodeError;

const NAME: &str = "akurai-node";
const VERSION: &str = env!("CARGO_PKG_VERSION");

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::FAILURE
        }
    }
}

fn run(args: &[String]) -> Result<(), NodeError> {
    match args.first().map(String::as_str) {
        Some("version" | "--version" | "-V") => {
            println!("{NAME} {VERSION}");
            Ok(())
        }
        Some("install") => install(&args[1..]),
        Some("up") => up(&args[1..]),
        Some("tunnel") => tunnel_cmd(&args[1..]),
        Some("selftest") => selftest_cmd(&args[1..]),
        Some("echo-peer") => echo_peer_cmd(&args[1..]),
        Some("service-install") => service_install(&args[1..]),
        Some("down") => down(),
        Some("status") => status(&args[1..]),
        Some("path") => {
            println!("{}", node_home(&args[1..])?.display());
            Ok(())
        }
        Some("help" | "--help" | "-h") | None => {
            print_usage();
            Ok(())
        }
        Some(other) => {
            eprintln!("unknown command: {other}\n");
            print_usage();
            Err(NodeError::Usage("unknown command".to_string()))
        }
    }
}

/// Install the node into the local per-user AkurAI-VPN home.
fn install(args: &[String]) -> Result<(), NodeError> {
    let home = node_home(args)?;
    let dirs = NodeDirs::new(home);
    dirs.create()?;

    let current_exe = std::env::current_exe()?;
    let installed_exe = dirs.bin.join(NAME);
    if current_exe.canonicalize().ok() != installed_exe.canonicalize().ok() {
        fs::copy(&current_exe, &installed_exe)?;
    }

    if !dirs.config_file.exists() {
        let hostname = std::env::var("HOSTNAME")
            .ok()
            .or_else(|| fs::read_to_string("/etc/hostname").ok())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "unknown-host".to_string());
        write_file(
            &dirs.config_file,
            &format!("version={VERSION}\nmode=host-only\nhostname={hostname}\nrouting=disabled\n"),
        )?;
    }
    write_state(&dirs, "installed")?;

    // Generate (or keep) this node's X25519 identity. The public key is what the
    // control plane records and peers use to open a session to us.
    let id = identity::Identity::load_or_create(
        &dirs.config.join("identity.key"),
        &dirs.config.join("identity.pub"),
    )?;
    let pubkey_b64 = id.public_b64();

    println!("installed {NAME} {VERSION}");
    println!("  home : {}", dirs.home.display());
    println!("  bin  : {}", installed_exe.display());
    println!("  mode : host-only (routing disabled)");
    println!("  id   : {pubkey_b64}");
    Ok(())
}

/// Bring host-only membership up without installing subnet or exit routes.
fn up(args: &[String]) -> Result<(), NodeError> {
    let home = node_home(args)?;
    let dirs = NodeDirs::new(home);
    dirs.create()?;
    if let Some(key) = auth_key(args) {
        write_file(&dirs.auth_key_file, key)?;
    }
    if let Some(ip) = arg_value(args, "--overlay-ip") {
        write_file(&dirs.overlay_file, ip)?;
    }
    tun::host_only_notice(akurai_common::TUN_INTERFACE);
    peermap::host_only_notice();
    write_state(&dirs, "up")?;
    println!("{NAME}: host-only membership is up");
    println!("  home    : {}", dirs.home.display());
    println!("  overlay : {}", read_overlay(&dirs));
    println!("  routing : disabled");
    Ok(())
}

/// Run the data-plane daemon: bring up `akurai0`, connect to the relay, and pump
/// encrypted overlay traffic until killed. Blocks. Requires CAP_NET_ADMIN.
///
/// Flags: `--overlay-ip <ip>` (required), `--relay <host:port>` (required),
/// `--peers <file>` (default `<home>/config/peers`), `--iface <name>`
/// (default `akurai0`), `--mtu <n>` (default overlay MTU),
/// `--acl <file>` (default `<home>/config/acl`; enforced only if it exists),
/// `--my-tags tag:a,tag:b` (this node's ACL principals; also `my_tags` in
/// `network.conf`).
fn tunnel_cmd(args: &[String]) -> Result<(), NodeError> {
    let dirs = NodeDirs::new(node_home(args)?);
    dirs.create()?;
    let id = identity::Identity::load_or_create(
        &dirs.config.join("identity.key"),
        &dirs.config.join("identity.pub"),
    )?;
    let pubkey_b64 = id.public_b64();

    // network.conf (written by the installer) supplies overlay_ip/relay/control;
    // explicit flags override it. This lets the systemd unit run a bare
    // `tunnel --home <home>` with no arguments.
    let conf = read_conf(&dirs.config.join("network.conf"));
    let from = |flag: &str, key: &str| -> Option<String> {
        arg_value(args, flag)
            .map(str::to_string)
            .or_else(|| conf.get(key).cloned())
    };

    let iface = arg_value(args, "--iface").unwrap_or("akurai0").to_string();
    let overlay_ip: Ipv4Addr = from("--overlay-ip", "overlay_ip")
        .ok_or_else(|| NodeError::Usage("tunnel needs --overlay-ip <ip> (or network.conf)".into()))?
        .parse()
        .map_err(|_| NodeError::Usage("invalid overlay ip".to_string()))?;
    let relay_s = from("--relay", "relay").ok_or_else(|| {
        NodeError::Usage("tunnel needs --relay <host:port> (or network.conf)".into())
    })?;
    // Resolve `host:port` via DNS — supports `vpn.olibuijr.com:51820`, not only IPs.
    let relay: SocketAddr = relay_s
        .to_socket_addrs()
        .map_err(|e| NodeError::Usage(format!("cannot resolve relay '{relay_s}': {e}")))?
        .next()
        .ok_or_else(|| NodeError::Usage(format!("relay '{relay_s}' resolved to no address")))?;
    let mtu: u16 = arg_value(args, "--mtu")
        .and_then(|s| s.parse().ok())
        .unwrap_or(akurai_common::OVERLAY_MTU);
    let peers_path = arg_value(args, "--peers")
        .map(PathBuf::from)
        .unwrap_or_else(|| dirs.config.join("peers"));
    let control_url = from("--control", "control");
    let cookie_path = dirs.config.join("cookies.txt");
    // Self-bootstrap: load the durable node token from disk, or acquire it from
    // the control plane via the saved OIDC session cookie and write it to disk
    // so future restarts survive cookie expiry.  Falls back to None when no
    // control URL is configured or the cookie jar is absent.
    let node_token: Option<String> = control_url.as_ref().and_then(|url| {
        load_or_bootstrap_token(
            &dirs.config.join("node.token"),
            url,
            &cookie_path,
            &pubkey_b64,
        )
    });

    // Source the peer map from the control plane (`--control <url>`) when
    // available.  Prefer the bearer token so the fetch survives cookie expiry;
    // fall back to the cookie jar when no token is available yet.
    let peers = match control_url.as_ref() {
        Some(url) => {
            let fetched = if let Some(ref tok) = node_token {
                peers::PeerTable::fetch_with_token(url, tok)
            } else {
                peers::PeerTable::fetch(url, &cookie_path)
            };
            if fetched.is_empty() {
                peers::PeerTable::load_file(&peers_path)
            } else {
                fetched
            }
        }
        None => peers::PeerTable::load_file(&peers_path),
    };
    if peers.is_empty() {
        eprintln!("{NAME}: warning — no peers loaded; the tunnel reaches nothing until a peer map is available");
    }

    // Subnets this node advertises as a gateway (MVP2): `--advertise a/24,b/16`.
    let advertise: Vec<akurai_common::Cidr> = arg_value(args, "--advertise")
        .map(|s| s.split(',').filter_map(peers::parse_cidr).collect())
        .unwrap_or_default();
    // Full-tunnel exit node opt-in (MVP2): `--exit-node <peer-overlay-ip>`.
    let exit_node: Option<Ipv4Addr> = from("--exit-node", "exit_node").and_then(|s| s.parse().ok());

    // Fine-grained ACL (MVP4). Default file `<home>/config/acl`. If it exists,
    // enforce it (fail-closed `this-node → peer`); if not, preserve today's
    // network-membership-only behavior (every peer in the map is reachable).
    let acl_path = arg_value(args, "--acl")
        .map(PathBuf::from)
        .unwrap_or_else(|| dirs.config.join("acl"));
    let my_principals = from("--my-tags", "my_tags")
        .map(|s| acl::parse_my_principals(&s))
        .unwrap_or_default();
    let acl = if acl_path.exists() {
        eprintln!(
            "{NAME}: ACL enforcement ON — {} ({} principal(s) for this node)",
            acl_path.display(),
            my_principals.len()
        );
        Some(acl::Acl::load(&acl_path, my_principals))
    } else {
        None
    };

    let overlay_cidr = format!(
        "{}/{}",
        akurai_common::OVERLAY_IPV4_NET,
        akurai_common::OVERLAY_IPV4_PREFIX_LEN
    );
    eprintln!(
        "{NAME}: tunnel up — overlay {overlay_ip} on {iface}, relay {relay}, {} peer(s), id {}",
        peers.len(),
        pubkey_b64
    );
    let cfg = tunnel::TunnelConfig {
        iface,
        overlay_ip,
        overlay_cidr,
        mtu,
        relay,
        keypair: id.keypair,
        peers,
        advertise,
        exit_node,
        acl,
        control_url: control_url.clone(),
        cookie_jar: Some(cookie_path.clone()),
        node_token: node_token.clone(),
        heartbeat: control_url
            .clone()
            .map(|control_url| tunnel::HeartbeatConfig {
                control_url,
                cookie_jar: cookie_path.clone(),
                pubkey_b64,
                node_token: node_token.clone(),
            }),
    };
    tunnel::run(cfg)?;
    Ok(())
}

/// Diagnostic: bring up the TUN and echo ICMP for a few seconds, so a `ping` to
/// any overlay IP proves the platform recv/send packet path works at runtime.
/// `--overlay-ip <ip>` (default 100.88.0.3), `--secs <n>` (default 10),
/// `--iface <name>` (default akurai0). Requires CAP_NET_ADMIN / root.
fn selftest_cmd(args: &[String]) -> Result<(), NodeError> {
    let dirs = NodeDirs::new(node_home(args)?);
    dirs.create()?;
    let id = identity::Identity::load_or_create(
        &dirs.config.join("identity.key"),
        &dirs.config.join("identity.pub"),
    )?;
    let iface = arg_value(args, "--iface").unwrap_or("akurai0").to_string();
    let overlay_ip: Ipv4Addr = arg_value(args, "--overlay-ip")
        .unwrap_or("100.88.0.3")
        .parse()
        .map_err(|_| NodeError::Usage("invalid overlay ip".to_string()))?;
    let secs: u64 = arg_value(args, "--secs")
        .and_then(|s| s.parse().ok())
        .unwrap_or(10);
    let overlay_cidr = format!(
        "{}/{}",
        akurai_common::OVERLAY_IPV4_NET,
        akurai_common::OVERLAY_IPV4_PREFIX_LEN
    );
    let cfg = tunnel::TunnelConfig {
        iface,
        overlay_ip,
        overlay_cidr,
        mtu: akurai_common::OVERLAY_MTU,
        relay: "127.0.0.1:51820"
            .parse()
            .expect("static loopback addr parses"),
        keypair: id.keypair,
        peers: peers::PeerTable::from_peers(Vec::new()),
        advertise: Vec::new(),
        exit_node: None,
        acl: None,
        control_url: None,
        cookie_jar: None,
        node_token: None,
        heartbeat: None,
    };
    tunnel::selftest(cfg, secs)?;
    Ok(())
}

/// Transport-level echo peer: bind a UDP socket, connect to the relay, complete
/// Noise handshakes with configured peers, and echo ICMP echo-requests back as
/// encrypted replies.  No TUN is opened — use this to E2E-test the encrypted
/// overlay path (relay + node A + echo-peer as node B) on a single host.
///
/// Required: `--overlay-ip <ip>`, `--relay <host:port>`.
/// Optional: `--peers <file>` (default `<home>/config/peers`),
///           `--secs <n>` (default 30), `--home <path>`.
fn echo_peer_cmd(args: &[String]) -> Result<(), NodeError> {
    let dirs = NodeDirs::new(node_home(args)?);
    dirs.create()?;
    let id = identity::Identity::load_or_create(
        &dirs.config.join("identity.key"),
        &dirs.config.join("identity.pub"),
    )?;

    let overlay_ip: Ipv4Addr = arg_value(args, "--overlay-ip")
        .ok_or_else(|| NodeError::Usage("echo-peer needs --overlay-ip <ip>".into()))?
        .parse()
        .map_err(|_| NodeError::Usage("invalid overlay ip".to_string()))?;
    let relay_s = arg_value(args, "--relay")
        .ok_or_else(|| NodeError::Usage("echo-peer needs --relay <host:port>".into()))?
        .to_string();
    let relay: SocketAddr = relay_s
        .to_socket_addrs()
        .map_err(|e| NodeError::Usage(format!("cannot resolve relay '{relay_s}': {e}")))?
        .next()
        .ok_or_else(|| NodeError::Usage(format!("relay '{relay_s}' resolved to no address")))?;
    let secs: u64 = arg_value(args, "--secs")
        .and_then(|s| s.parse().ok())
        .unwrap_or(30);
    let peers_path = arg_value(args, "--peers")
        .map(PathBuf::from)
        .unwrap_or_else(|| dirs.config.join("peers"));
    let peers = peers::PeerTable::load_file(&peers_path);

    let cfg = tunnel::EchoPeerConfig {
        overlay_ip,
        relay,
        keypair: id.keypair,
        peers,
    };
    tunnel::echo_peer(cfg, secs)?;
    Ok(())
}

/// Render the systemd unit that runs the tunnel daemon at boot. The daemon reads
/// `network.conf` for its parameters, so the unit needs no arguments beyond `--home`.
fn render_tunnel_unit(bin: &Path, home: &Path) -> String {
    format!(
        "[Unit]\n\
         Description=AkurAI VPN node tunnel (encrypted overlay mesh)\n\
         After=network-online.target\n\
         Wants=network-online.target\n\n\
         [Service]\n\
         Type=simple\n\
         ExecStart={bin} tunnel --home {home}\n\
         Restart=on-failure\n\
         RestartSec=3\n\
         AmbientCapabilities=CAP_NET_ADMIN\n\
         CapabilityBoundingSet=CAP_NET_ADMIN\n\
         NoNewPrivileges=yes\n\n\
         [Install]\n\
         WantedBy=multi-user.target\n",
        bin = bin.display(),
        home = home.display(),
    )
}

/// Install (and start) the systemd service that runs the tunnel at boot — the
/// one-touch daemon. Requires root. `--dry-run` prints the unit instead of
/// writing it (safe to run anywhere). The daemon reads `network.conf` written by
/// the installer for its overlay IP / relay / control URL.
fn service_install(args: &[String]) -> Result<(), NodeError> {
    let dirs = NodeDirs::new(node_home(args)?);
    let bin = dirs.bin.join(NAME);
    let unit = render_tunnel_unit(&bin, &dirs.home);
    let unit_path = Path::new("/etc/systemd/system/akurai-node-tunnel.service");

    if args.iter().any(|a| a == "--dry-run") {
        println!("# would write {}\n{unit}", unit_path.display());
        return Ok(());
    }
    write_file(unit_path, &unit)?;
    for sc in [
        vec!["daemon-reload"],
        vec!["enable", "--now", "akurai-node-tunnel.service"],
    ] {
        let status = std::process::Command::new("systemctl").args(&sc).status()?;
        if !status.success() {
            return Err(NodeError::Usage(format!(
                "systemctl {} failed",
                sc.join(" ")
            )));
        }
    }
    println!("{NAME}: tunnel service installed and started (akurai-node-tunnel.service)");
    Ok(())
}

/// Read a simple `key=value` config file (e.g. `network.conf`). Missing file ⇒
/// empty map. Blank lines and `#` comments ignored.
fn read_conf(path: &Path) -> HashMap<String, String> {
    let mut map = HashMap::new();
    if let Ok(content) = fs::read_to_string(path) {
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some((k, v)) = line.split_once('=') {
                map.insert(k.trim().to_string(), v.trim().to_string());
            }
        }
    }
    map
}

/// Tear host-only membership down.
fn down() -> Result<(), NodeError> {
    let dirs = NodeDirs::new(node_home(&[])?);
    dirs.create()?;
    write_state(&dirs, "down")?;
    println!("{NAME}: host-only membership is down");
    println!("  home    : {}", dirs.home.display());
    println!("  routing : disabled");
    Ok(())
}

/// Print local overlay status.
fn status(args: &[String]) -> Result<(), NodeError> {
    let home = node_home(args)?;
    let dirs = NodeDirs::new(home);
    let state = fs::read_to_string(&dirs.state_file)
        .unwrap_or_else(|_| "state=not-installed\n".to_string());
    println!("{NAME} {VERSION}");
    println!("  home    : {}", dirs.home.display());
    println!("  mode    : host-only");
    println!("  overlay : {}", read_overlay(&dirs));
    println!("  routing : disabled");
    print!("{state}");
    Ok(())
}

/// Read the locally-recorded overlay IP, or a placeholder when unassigned.
fn read_overlay(dirs: &NodeDirs) -> String {
    fs::read_to_string(&dirs.overlay_file)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unassigned".to_string())
}

/// Extract `--auth-key <value>` from the argument list, if present.
fn auth_key(args: &[String]) -> Option<&str> {
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if a == "--auth-key" {
            return it.next().map(String::as_str);
        }
    }
    None
}

fn print_usage() {
    println!("{NAME} {VERSION} — AkurAI VPN node daemon");
    println!();
    println!("USAGE:");
    println!("    {NAME} <command> [--home <path>]");
    println!();
    println!("COMMANDS:");
    println!("    install                 Install into ~/.akurai-vpn by default");
    println!("    up [--auth-key <key>] [--overlay-ip <ip>]");
    println!("                            Enable host-only membership (no routing)");
    println!("    tunnel [--home <p>]     Run the encrypted mesh daemon (reads network.conf)");
    println!("           [--acl <file>] [--my-tags tag:a,tag:b]");
    println!("                            Enforce a fail-closed tag ACL when the file exists");
    println!("    selftest [--overlay-ip <ip>] [--secs <n>]");
    println!("                            Echo ICMP on the TUN without a peer (root)");
    println!("    echo-peer --overlay-ip <ip> --relay <host:port>");
    println!("              [--peers <file>] [--secs <n>]");
    println!("                            Encrypted overlay echo peer (no TUN, no root)");
    println!("    service-install         Install + start the systemd tunnel service (root)");
    println!("    down                    Disable host-only membership");
    println!("    status                  Show local node status");
    println!("    path                    Print the resolved AkurAI-VPN home");
    println!("    version                 Print version and exit");
    println!("    help                    Show this help");
    println!();
    println!("OPTIONS:");
    println!("    --home <path>           Override the default ~/.akurai-vpn path");
}

fn node_home(args: &[String]) -> Result<PathBuf, NodeError> {
    if let Some(path) = arg_value(args, "--home") {
        return Ok(PathBuf::from(path));
    }
    if let Ok(path) = std::env::var("AKURAI_VPN_HOME") {
        if !path.is_empty() {
            return Ok(PathBuf::from(path));
        }
    }
    let home = std::env::var("HOME").map_err(|_| {
        NodeError::Usage("HOME is not set; pass --home <path> or set AKURAI_VPN_HOME".to_string())
    })?;
    Ok(Path::new(&home).join(".akurai-vpn"))
}

fn arg_value<'a>(args: &'a [String], key: &str) -> Option<&'a str> {
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if a == key {
            return it.next().map(String::as_str);
        }
    }
    None
}

struct NodeDirs {
    home: PathBuf,
    bin: PathBuf,
    state: PathBuf,
    config: PathBuf,
    config_file: PathBuf,
    state_file: PathBuf,
    auth_key_file: PathBuf,
    overlay_file: PathBuf,
}

impl NodeDirs {
    fn new(home: PathBuf) -> Self {
        let bin = home.join("bin");
        let state = home.join("state");
        let config = home.join("config");
        let config_file = config.join("node.conf");
        let state_file = state.join("node.state");
        let auth_key_file = config.join("auth.key");
        let overlay_file = state.join("overlay.ip");
        Self {
            home,
            bin,
            state,
            config,
            config_file,
            state_file,
            auth_key_file,
            overlay_file,
        }
    }

    fn create(&self) -> Result<(), NodeError> {
        fs::create_dir_all(&self.bin)?;
        fs::create_dir_all(&self.state)?;
        fs::create_dir_all(&self.config)?;
        Ok(())
    }
}

fn write_state(dirs: &NodeDirs, state: &str) -> Result<(), NodeError> {
    write_file(
        &dirs.state_file,
        &format!("state={state}\nmode=host-only\nrouting=disabled\n"),
    )
}

fn write_file(path: &Path, content: &str) -> Result<(), NodeError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("tmp");
    {
        let mut f = fs::File::create(&tmp)?;
        f.write_all(content.as_bytes())?;
        f.flush()?;
    }
    fs::rename(tmp, path)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Node token self-bootstrap
// ---------------------------------------------------------------------------

/// Extract a `"key":"value"` string field from a JSON fragment (hand-rolled,
/// no escapes in the values we care about — hex tokens, IDs, pubkeys).
fn extract_json_str_field(obj: &str, key: &str) -> Option<String> {
    let needle = format!("\"{key}\"");
    let pos = obj.find(&needle)? + needle.len();
    let rest = obj[pos..].trim_start();
    let rest = rest.strip_prefix(':')?.trim_start();
    let rest = rest.strip_prefix('"')?;
    let end = rest.find('"')?;
    let v = rest[..end].to_string();
    if v.is_empty() {
        None
    } else {
        Some(v)
    }
}

/// Load the durable node token from `token_path`, or bootstrap it by calling
/// the control plane's `/api/endpoints` with the saved session cookie, finding
/// the endpoint whose `public_key` matches this node, and writing its
/// `node_token` to `token_path` with 0600 permissions.
///
/// Returns `None` when neither source is available (first run without OIDC
/// login, or control URL not configured).
fn load_or_bootstrap_token(
    token_path: &Path,
    control_url: &str,
    cookie_jar: &Path,
    pubkey_b64: &str,
) -> Option<String> {
    // Fast path: token already on disk.
    if let Ok(existing) = fs::read_to_string(token_path) {
        let t = existing.trim().to_string();
        if !t.is_empty() {
            return Some(t);
        }
    }
    // Bootstrap via the session cookie: fetch /api/endpoints, locate our
    // endpoint by public key, extract node_token.
    if !cookie_jar.exists() {
        return None;
    }
    let base = control_url.trim_end_matches('/');
    let out = std::process::Command::new("curl")
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
    // Each JSON object is separated by `}`; find the one that contains our pubkey.
    let token = json
        .split('}')
        .find(|obj| obj.contains(pubkey_b64))
        .and_then(|obj| extract_json_str_field(obj, "node_token"))?;
    // Persist with 0600 permissions so future restarts skip the cookie round-trip.
    {
        use std::io::Write as IoWrite;
        #[cfg(unix)]
        use std::os::unix::fs::OpenOptionsExt;
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        // 0600 on Unix; on Windows the file inherits the user-profile ACL.
        #[cfg(unix)]
        opts.mode(0o600);
        if let Ok(mut f) = opts.open(token_path) {
            let _ = f.write_all(token.as_bytes());
            let _ = f.write_all(b"\n");
        }
    }
    eprintln!(
        "{NAME}: node token bootstrapped and written to {}",
        token_path.display()
    );
    Some(token)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_home_overrides_default() {
        let args = vec!["--home".to_string(), "/tmp/akurai-vpn-test".to_string()];
        assert_eq!(
            node_home(&args).unwrap(),
            PathBuf::from("/tmp/akurai-vpn-test")
        );
    }

    #[test]
    fn auth_key_is_parsed_independently_of_home() {
        let args = vec![
            "--home".to_string(),
            "/tmp/akurai-vpn-test".to_string(),
            "--auth-key".to_string(),
            "secret".to_string(),
        ];
        assert_eq!(auth_key(&args), Some("secret"));
    }

    #[test]
    fn overlay_ip_is_parsed_independently_of_other_flags() {
        let args = vec![
            "--home".to_string(),
            "/tmp/akurai-vpn-test".to_string(),
            "--auth-key".to_string(),
            "secret".to_string(),
            "--overlay-ip".to_string(),
            "100.88.0.2".to_string(),
        ];
        assert_eq!(arg_value(&args, "--overlay-ip"), Some("100.88.0.2"));
        // Order-independence: overlay flag does not disturb auth-key parsing.
        assert_eq!(auth_key(&args), Some("secret"));
    }

    #[test]
    fn overlay_file_lives_under_state() {
        let dirs = NodeDirs::new(PathBuf::from("/tmp/akurai-vpn-test"));
        assert_eq!(
            dirs.overlay_file,
            PathBuf::from("/tmp/akurai-vpn-test/state/overlay.ip")
        );
    }

    /// echo_peer_cmd must return a Usage error that mentions `overlay-ip` when
    /// `--overlay-ip` is absent.  The identity is generated in a throw-away temp
    /// dir (cleaned up after the test).
    #[test]
    fn echo_peer_cmd_requires_overlay_ip() {
        let dir = format!("/tmp/akurai-ep-test-{}", std::process::id());
        let args = vec![
            "--home".to_string(),
            dir.clone(),
            "--relay".to_string(),
            "127.0.0.1:51820".to_string(),
        ];
        match echo_peer_cmd(&args) {
            Err(NodeError::Usage(msg)) => {
                assert!(
                    msg.contains("overlay-ip"),
                    "expected overlay-ip in error, got: {msg}"
                )
            }
            result => panic!("expected Usage(overlay-ip) error, got {result:?}"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// echo_peer_cmd must return a Usage error that mentions `relay` when
    /// `--relay` is absent.
    #[test]
    fn echo_peer_cmd_requires_relay() {
        let dir = format!("/tmp/akurai-ep-relay-test-{}", std::process::id());
        let args = vec![
            "--home".to_string(),
            dir.clone(),
            "--overlay-ip".to_string(),
            "100.88.0.9".to_string(),
        ];
        match echo_peer_cmd(&args) {
            Err(NodeError::Usage(msg)) => {
                assert!(msg.contains("relay"), "expected relay in error, got: {msg}")
            }
            result => panic!("expected Usage(relay) error, got {result:?}"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
