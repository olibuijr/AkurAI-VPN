//! `devices` — enrolled-device management (stub).
//!
//! List and remove enrolled nodes. Not implemented in 0.0.1.

use crate::error::AdminError;

/// Dispatch a `devices` subcommand.
pub fn run(args: &[String]) -> Result<(), AdminError> {
    match args.first().map(String::as_str) {
        Some("list") => Err(AdminError::NotImplemented("device listing")),
        Some("remove") => {
            let node = args
                .get(1)
                .ok_or_else(|| AdminError::Usage("usage: devices remove <node>".to_string()))?;
            eprintln!("akurai-admin: would remove device {node}");
            Err(AdminError::NotImplemented("device removal"))
        }
        Some("help" | "--help" | "-h") | None => {
            print_usage();
            Ok(())
        }
        Some(other) => {
            eprintln!("unknown devices subcommand: {other}\n");
            print_usage();
            Err(AdminError::Usage("unknown devices subcommand".to_string()))
        }
    }
}

fn print_usage() {
    println!("USAGE:");
    println!("    akurai-admin devices list");
    println!("    akurai-admin devices remove <node>");
}
