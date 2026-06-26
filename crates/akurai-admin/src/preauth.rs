//! `preauth` — pre-auth enrollment keys (stub).
//!
//! Mirrors the documented UX:
//! `akurai-admin preauth create --user oli --ttl 1h`. Key minting and storage
//! are not implemented in 0.0.1.

use crate::error::AdminError;

/// Dispatch a `preauth` subcommand.
pub fn run(args: &[String]) -> Result<(), AdminError> {
    match args.first().map(String::as_str) {
        Some("create") => {
            eprintln!("akurai-admin: would mint a pre-auth key (use --user <name> --ttl <dur>)");
            Err(AdminError::NotImplemented("preauth create"))
        }
        Some("list") => Err(AdminError::NotImplemented("preauth list")),
        Some("revoke") => Err(AdminError::NotImplemented("preauth revoke")),
        Some("help" | "--help" | "-h") | None => {
            print_usage();
            Ok(())
        }
        Some(other) => {
            eprintln!("unknown preauth subcommand: {other}\n");
            print_usage();
            Err(AdminError::Usage("unknown preauth subcommand".to_string()))
        }
    }
}

fn print_usage() {
    println!("USAGE:");
    println!("    akurai-admin preauth create --user <name> --ttl <dur>");
    println!("    akurai-admin preauth list");
    println!("    akurai-admin preauth revoke <key>");
}
