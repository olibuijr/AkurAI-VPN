//! `routes` — advertised-route approval (stub).
//!
//! Mirrors the documented UX:
//! `akurai-admin routes approve home-router 192.168.1.0/24`. Approval is
//! fail-closed and not implemented in 0.0.1, but the CIDR argument is parsed
//! and validated here with `akurai-common` so malformed input is rejected
//! early.

use std::net::IpAddr;

use akurai_common::Cidr;

use crate::error::AdminError;

/// Dispatch a `routes` subcommand.
pub fn run(args: &[String]) -> Result<(), AdminError> {
    match args.first().map(String::as_str) {
        Some("approve") => {
            let node = args.get(1).ok_or_else(|| {
                AdminError::Usage("usage: routes approve <node> <cidr>".to_string())
            })?;
            let cidr_str = args.get(2).ok_or_else(|| {
                AdminError::Usage("usage: routes approve <node> <cidr>".to_string())
            })?;
            let cidr = parse_cidr(cidr_str)?;
            eprintln!("akurai-admin: would approve {cidr} advertised by {node}");
            Err(AdminError::NotImplemented("route approval"))
        }
        Some("list") => Err(AdminError::NotImplemented("route listing")),
        Some("help" | "--help" | "-h") | None => {
            print_usage();
            Ok(())
        }
        Some(other) => {
            eprintln!("unknown routes subcommand: {other}\n");
            print_usage();
            Err(AdminError::Usage("unknown routes subcommand".to_string()))
        }
    }
}

/// Parse `addr/prefix` into a validated [`Cidr`] using std + `akurai-common`.
fn parse_cidr(s: &str) -> Result<Cidr, AdminError> {
    let (addr_str, prefix_str) = s
        .split_once('/')
        .ok_or_else(|| AdminError::Usage(format!("invalid CIDR '{s}' (expected addr/prefix)")))?;
    let addr: IpAddr = addr_str
        .parse()
        .map_err(|_| AdminError::Usage(format!("invalid IP address '{addr_str}'")))?;
    let prefix: u8 = prefix_str
        .parse()
        .map_err(|_| AdminError::Usage(format!("invalid prefix length '{prefix_str}'")))?;
    Cidr::new(addr, prefix).map_err(|e| AdminError::Usage(e.to_string()))
}

fn print_usage() {
    println!("USAGE:");
    println!("    akurai-admin routes approve <node> <cidr>");
    println!("    akurai-admin routes list");
}
