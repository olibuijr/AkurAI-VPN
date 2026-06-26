//! `akurai-node` — the AkurAI VPN node daemon, installed on every device.
//!
//! Creates the `akurai0` TUN interface, applies routes pushed by the control
//! plane, watches the peer map, and (when approved) acts as a subnet/exit
//! gateway. This is a 0.0.1 skeleton: the device, routing, and transport are
//! stubs that return explicit "not implemented" errors rather than touching the
//! system. Command dispatch (`up`/`down`/`status`/`gateway`) is parsed from
//! `std::env::args` by hand to keep the zero-dependency promise.

mod error;
mod gateway;
mod peermap;
mod route;
mod tun;

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
        Some("up") => up(&args[1..]),
        Some("down") => down(),
        Some("status") => {
            status();
            Ok(())
        }
        Some("gateway") => gateway::dispatch(&args[1..]),
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

/// Bring the overlay up: open `akurai0`, apply routes, start the peer-map watch.
fn up(args: &[String]) -> Result<(), NodeError> {
    if let Some(key) = auth_key(args) {
        eprintln!("akurai-node: would enroll with auth key {key} (not implemented in 0.0.1)");
    }
    let device = tun::open(akurai_common::TUN_INTERFACE)?;
    route::apply(&device, &route::overlay_defaults())?;
    peermap::watch(&device)?;
    Ok(())
}

/// Tear the overlay down: stop the watch and close `akurai0`.
fn down() -> Result<(), NodeError> {
    tun::close(akurai_common::TUN_INTERFACE)
}

/// Print local overlay status.
fn status() {
    use akurai_common::overlay;
    println!("{NAME} {VERSION}");
    println!("  interface : {}", overlay::TUN_INTERFACE);
    println!(
        "  overlay   : 100.88.0.0/{} , fd88::/{} , MTU {}",
        overlay::OVERLAY_IPV4_PREFIX_LEN,
        overlay::OVERLAY_IPV6_PREFIX_LEN,
        overlay::OVERLAY_MTU
    );
    println!("  state     : down (data plane not implemented in 0.0.1)");
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
    println!("    {NAME} <command>");
    println!();
    println!("COMMANDS:");
    println!("    up [--auth-key <key>]   Bring the overlay up (not implemented in 0.0.1)");
    println!("    down                    Tear the overlay down (not implemented in 0.0.1)");
    println!("    status                  Show local overlay status");
    println!("    gateway <subcommand>    Manage gateway modes (subnet/exit)");
    println!("    version                 Print version and exit");
    println!("    help                    Show this help");
}
