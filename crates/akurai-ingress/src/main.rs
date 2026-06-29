//! `akurai-ingress` — public ingress for the AkurAI VPN.
//!
//! Forwards a public TCP port on this host to an internal overlay service — the
//! pure-Rust, std-only equivalent of Tailscale Funnel/Serve. The host runs an
//! AkurAI node (akurai0 up), so it sits on the overlay at some `100.88.0.x`; an
//! ingress maps `0.0.0.0:<listen_port>` to `<overlay_ip>:<target_port>`, and a
//! public client hitting the port transparently reaches the internal service.
//!
//! Argument parsing is hand-rolled to keep the zero-dependency promise.

#![forbid(unsafe_code)]

mod config;
mod proxy;

use std::process::ExitCode;

use config::Map;

const NAME: &str = "akurai-ingress";
const VERSION: &str = env!("CARGO_PKG_VERSION");

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(msg) => {
            eprintln!("error: {msg}");
            ExitCode::FAILURE
        }
    }
}

fn run(args: &[String]) -> Result<(), String> {
    match args.first().map(String::as_str) {
        Some("version" | "--version" | "-V") => {
            println!("{NAME} {VERSION}");
            Ok(())
        }
        Some("serve") => serve(&args[1..]),
        Some("help" | "--help" | "-h") | None => {
            print_usage();
            Ok(())
        }
        Some(other) => {
            eprintln!("unknown command: {other}\n");
            print_usage();
            Err("unknown command".to_string())
        }
    }
}

/// Parse `serve` arguments into maps and run the proxy. `--map` flags and a
/// `--config <file>` may be combined; at least one map must result.
fn serve(args: &[String]) -> Result<(), String> {
    let mut maps: Vec<Map> = Vec::new();
    let mut config_path: Option<&str> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--map" => {
                let spec = args.get(i + 1).ok_or_else(|| {
                    "--map requires <listen_port>:<overlay_ip>:<target_port>".to_string()
                })?;
                maps.push(Map::parse_spec(spec).map_err(|e| format!("--map {e}"))?);
                i += 2;
            }
            "--config" => {
                config_path = Some(
                    args.get(i + 1)
                        .ok_or_else(|| "--config requires <file>".to_string())?
                        .as_str(),
                );
                i += 2;
            }
            other => return Err(format!("unknown serve argument: {other}")),
        }
    }

    if let Some(path) = config_path {
        let text = std::fs::read_to_string(path).map_err(|e| format!("read {path}: {e}"))?;
        maps.append(&mut config::parse_config(&text).map_err(|e| format!("{path}: {e}"))?);
    }

    if maps.is_empty() {
        return Err(
            "no maps — use --map <listen_port>:<overlay_ip>:<target_port> or --config <file>"
                .to_string(),
        );
    }

    proxy::serve(maps).map_err(|e| e.to_string())
}

fn print_usage() {
    println!("{NAME} {VERSION} — AkurAI VPN public ingress (TCP -> overlay service)");
    println!();
    println!("USAGE:");
    println!("    {NAME} serve --map <listen_port>:<overlay_ip>:<target_port> [--map ...]");
    println!("    {NAME} serve --config <file>");
    println!("    {NAME} version");
    println!("    {NAME} help");
    println!();
    println!("FORWARDS a public TCP port to an internal overlay service. This host must");
    println!("be on the overlay (akurai0 up) so <overlay_ip> is reachable over the mesh.");
    println!();
    println!("EXAMPLES:");
    println!("    {NAME} serve --map 8443:100.88.0.3:80");
    println!("    {NAME} serve --map 8443:100.88.0.3:80 --map 2222:nas.oli.akurai:22");
    println!("    {NAME} serve --config /etc/akurai-vpn/ingress.conf");
    println!();
    println!("CONFIG FILE (one map per line; '#' comments and blank lines ignored):");
    println!("    8443:100.88.0.3:80");
    println!("    listen=8080 overlay=nas.oli.akurai target=80");
}
