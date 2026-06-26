//! `acl` — access-control policy edits (stub).
//!
//! Edits the fail-closed policy evaluated in `akurai-common`. Persistence and
//! the edit workflow are not implemented in 0.0.1.

use crate::error::AdminError;

/// Dispatch an `acl` subcommand.
pub fn run(args: &[String]) -> Result<(), AdminError> {
    match args.first().map(String::as_str) {
        Some("show") => Err(AdminError::NotImplemented("acl show")),
        Some("allow") => {
            eprintln!("akurai-admin: would add an allow rule (from -> to)");
            Err(AdminError::NotImplemented("acl allow"))
        }
        Some("deny") => Err(AdminError::NotImplemented("acl deny")),
        Some("help" | "--help" | "-h") | None => {
            print_usage();
            Ok(())
        }
        Some(other) => {
            eprintln!("unknown acl subcommand: {other}\n");
            print_usage();
            Err(AdminError::Usage("unknown acl subcommand".to_string()))
        }
    }
}

fn print_usage() {
    println!("USAGE:");
    println!("    akurai-admin acl show");
    println!("    akurai-admin acl allow <from> <to>");
    println!("    akurai-admin acl deny <from> <to>");
}
