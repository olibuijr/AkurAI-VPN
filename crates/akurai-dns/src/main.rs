//! `akurai-dns` — the AkurAI VPN internal MagicDNS service.
//!
//! Resolves overlay names under the `*.oli.akurai` zone (e.g.
//! `laptop.oli.akurai`) to the device's overlay IP. It can be folded into the
//! control plane at first. This is a 0.0.1 skeleton: the resolver and UDP/53
//! server are stubs. Argument parsing is hand-rolled to keep the zero-dependency
//! promise.

mod resolver;

use std::process::ExitCode;

const NAME: &str = "akurai-dns";
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
        Some("serve") => resolver::serve().map_err(|e| e.to_string()),
        Some("resolve") => {
            let name = args.get(1).ok_or("usage: akurai-dns resolve <name>")?;
            match resolver::resolve(name) {
                Some(ip) => {
                    println!("{name} -> {ip}");
                    Ok(())
                }
                None => Err(format!(
                    "no record for '{name}' (zone resolution not implemented in 0.0.1)"
                )),
            }
        }
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
    println!(
        "{NAME} {VERSION} — AkurAI VPN internal MagicDNS ({})",
        resolver::ZONE
    );
    println!();
    println!("USAGE:");
    println!("    {NAME} <command>");
    println!();
    println!("COMMANDS:");
    println!("    serve              Start the DNS server (not implemented in 0.0.1)");
    println!(
        "    resolve <name>     Resolve a {} name (stub)",
        resolver::ZONE
    );
    println!("    version            Print version and exit");
    println!("    help               Show this help");
}
