//! `akurai-relay` — the AkurAI VPN relay fallback.
//!
//! When two nodes cannot establish a direct path, their traffic is relayed
//! through `vpn.olibuijr.com`. **The relay sees only ciphertext** — it forwards
//! opaque, end-to-end-encrypted packets between peers and never possesses
//! payload keys. In 0.0.1 the forward loop is a stub. Argument parsing is
//! hand-rolled to keep the zero-dependency promise.

mod forward;

use std::process::ExitCode;

const NAME: &str = "akurai-relay";
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
        Some("serve") => forward::run().map_err(|e| e.to_string()),
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
    println!("{NAME} {VERSION} — AkurAI VPN relay (ciphertext-only fallback)");
    println!();
    println!("USAGE:");
    println!("    {NAME} <command>");
    println!();
    println!("COMMANDS:");
    println!("    serve      Start the relay forward loop (not implemented in 0.0.1)");
    println!("    version    Print version and exit");
    println!("    help       Show this help");
}
