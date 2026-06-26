//! `akurai-admin` — the AkurAI VPN admin CLI.
//!
//! Drives the control plane: pre-auth keys, route approval, public ingress,
//! device management, and ACL edits. This is a 0.0.1 skeleton: every
//! subcommand parses its surface and prints usage, then reports that the action
//! is not yet implemented. Argument parsing is hand-rolled to keep the
//! zero-dependency promise.

mod acl;
mod devices;
mod error;
mod ingress;
mod preauth;
mod routes;

use std::process::ExitCode;

use error::AdminError;

const NAME: &str = "akurai-admin";
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

fn run(args: &[String]) -> Result<(), AdminError> {
    match args.first().map(String::as_str) {
        Some("version" | "--version" | "-V") => {
            println!("{NAME} {VERSION}");
            Ok(())
        }
        Some("preauth") => preauth::run(&args[1..]),
        Some("routes") => routes::run(&args[1..]),
        Some("ingress") => ingress::run(&args[1..]),
        Some("devices") => devices::run(&args[1..]),
        Some("acl") => acl::run(&args[1..]),
        Some("help" | "--help" | "-h") | None => {
            print_usage();
            Ok(())
        }
        Some(other) => {
            eprintln!("unknown command: {other}\n");
            print_usage();
            Err(AdminError::Usage("unknown command".to_string()))
        }
    }
}

fn print_usage() {
    println!("{NAME} {VERSION} — AkurAI VPN admin CLI");
    println!();
    println!("USAGE:");
    println!("    {NAME} <subcommand> [args]");
    println!();
    println!("SUBCOMMANDS:");
    println!("    preauth    Manage pre-auth enrollment keys");
    println!("    routes     Approve / list advertised routes");
    println!("    ingress    Manage public ingress mappings");
    println!("    devices    List / remove enrolled devices");
    println!("    acl        Edit access-control policy");
    println!("    version    Print version and exit");
    println!("    help       Show this help");
}
