//! `akurai-control` — the AkurAI VPN control plane.
//!
//! Owns device enrollment, overlay IP allocation, the peer map, ACL policy,
//! audit, heartbeat state, and relay assignment for the network hosted at
//! `vpn.olibuijr.com`. This is a 0.0.1 skeleton: the modules below name each
//! responsibility and the HTTP listener seam, but none of the control-plane
//! logic is implemented yet. Argument parsing is hand-rolled to keep the
//! zero-dependency promise.

mod acl;
mod audit;
mod enrollment;
mod heartbeat;
mod ipam;
mod listener;
mod peermap;

use std::process::ExitCode;

const NAME: &str = "akurai-control";
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
        Some("serve") => listener::serve().map_err(|e| e.to_string()),
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

fn print_usage() {
    use akurai_common::overlay;
    println!("{NAME} {VERSION} — AkurAI VPN control plane");
    println!();
    println!("USAGE:");
    println!("    {NAME} <command>");
    println!();
    println!("COMMANDS:");
    println!("    serve      Start the control-plane HTTP listener on CONTROL_PORT (default 8104)");
    println!("    version    Print version and exit");
    println!("    help       Show this help");
    println!();
    println!(
        "Overlay: IPv4 {}/{}, IPv6 fd88::/{}, MTU {}",
        overlay::OVERLAY_IPV4_NET,
        overlay::OVERLAY_IPV4_PREFIX_LEN,
        overlay::OVERLAY_IPV6_PREFIX_LEN,
        overlay::OVERLAY_MTU
    );
}
