//! `akurai-node` — the AkurAI VPN node daemon, installed on every device.
//!
//! Initial scope is deliberately host-only: a node can install local state and
//! mark itself up for AkurAI-VPN host-to-host membership, but it does not install
//! subnet routes, exit routes, or gateway advertisements. Command dispatch is
//! parsed from `std::env::args` by hand to keep the zero-dependency promise.

mod error;
mod peermap;
mod tun;

use std::fs;
use std::io::Write;
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

    println!("installed {NAME} {VERSION}");
    println!("  home : {}", dirs.home.display());
    println!("  bin  : {}", installed_exe.display());
    println!("  mode : host-only (routing disabled)");
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
}
