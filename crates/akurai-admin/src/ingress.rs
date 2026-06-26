//! `ingress` — public ingress mappings (stub).
//!
//! Mirrors the documented UX:
//! `akurai-admin ingress create dashboard.vpn.olibuijr.com --to nas.oli.akurai:8080 --tls auto`.
//! Public ingress is an MVP4 feature; it is not implemented in 0.0.1.

use crate::error::AdminError;

/// Dispatch an `ingress` subcommand.
pub fn run(args: &[String]) -> Result<(), AdminError> {
    match args.first().map(String::as_str) {
        Some("create") => {
            eprintln!("akurai-admin: would create a public ingress mapping (MVP4)");
            Err(AdminError::NotImplemented("ingress create"))
        }
        Some("list") => Err(AdminError::NotImplemented("ingress list")),
        Some("delete") => Err(AdminError::NotImplemented("ingress delete")),
        Some("help" | "--help" | "-h") | None => {
            print_usage();
            Ok(())
        }
        Some(other) => {
            eprintln!("unknown ingress subcommand: {other}\n");
            print_usage();
            Err(AdminError::Usage("unknown ingress subcommand".to_string()))
        }
    }
}

fn print_usage() {
    println!("USAGE:");
    println!("    akurai-admin ingress create <public-host> --to <node:port> [--tls auto]");
    println!("    akurai-admin ingress list");
    println!("    akurai-admin ingress delete <public-host>");
}
