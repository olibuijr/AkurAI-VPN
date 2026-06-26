//! Gateway-mode commands (stub).
//!
//! A node may, with admin approval, advertise a subnet (`--subnet <cidr>`) or
//! become an exit gateway (`--exit`). Advertisement and approval are not
//! implemented in 0.0.1; this only parses the command surface and reports the
//! intent. A node must NEVER become a gateway without explicit admin approval
//! at the control plane — enforced there, not here.

use crate::error::NodeError;

/// Dispatch a `gateway` subcommand.
pub fn dispatch(args: &[String]) -> Result<(), NodeError> {
    match args.first().map(String::as_str) {
        Some("enable") => enable(&args[1..]),
        Some("disable") => Err(NodeError::NotImplemented("gateway disable")),
        Some("help" | "--help" | "-h") | None => {
            print_usage();
            Ok(())
        }
        Some(other) => {
            eprintln!("unknown gateway subcommand: {other}\n");
            print_usage();
            Err(NodeError::Usage("unknown gateway subcommand".to_string()))
        }
    }
}

fn enable(args: &[String]) -> Result<(), NodeError> {
    match args.first().map(String::as_str) {
        Some("--subnet") => {
            let cidr = args.get(1).ok_or_else(|| {
                NodeError::Usage("usage: gateway enable --subnet <cidr>".to_string())
            })?;
            eprintln!(
                "akurai-node: would request subnet gateway for {cidr} (needs admin approval)"
            );
            Err(NodeError::NotImplemented("subnet gateway advertisement"))
        }
        Some("--exit") => {
            eprintln!("akurai-node: would request exit gateway (needs admin approval)");
            Err(NodeError::NotImplemented("exit gateway advertisement"))
        }
        _ => {
            print_usage();
            Err(NodeError::Usage(
                "usage: gateway enable [--subnet <cidr> | --exit]".to_string(),
            ))
        }
    }
}

fn print_usage() {
    println!("USAGE:");
    println!("    akurai-node gateway enable --subnet <cidr>");
    println!("    akurai-node gateway enable --exit");
    println!("    akurai-node gateway disable");
}
