//! `akurai-dns` — the AkurAI VPN internal MagicDNS service (binary).
//!
//! Resolves overlay names under a flat zone (default `akurai`) to a peer's
//! overlay IPv4, so users can `ping nodeb.akurai` instead of `ping 100.88.0.3`.
//! Argument parsing is hand-rolled to keep the zero-dependency promise. The DNS
//! wire codec and UDP server live in the `akurai_dns` library crate.

mod resolver;

use std::net::SocketAddr;
use std::path::Path;
use std::process::ExitCode;

use resolver::{DEFAULT_BIND, DEFAULT_ZONE};

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
        Some("serve") => cmd_serve(&args[1..]),
        Some("resolve") => cmd_resolve(&args[1..]),
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

fn cmd_serve(args: &[String]) -> Result<(), String> {
    let mut zone = DEFAULT_ZONE.to_string();
    let mut bind_s = DEFAULT_BIND.to_string();
    let mut hosts_path: Option<String> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--zone" => zone = take_value(args, &mut i, "--zone")?,
            "--bind" => bind_s = take_value(args, &mut i, "--bind")?,
            "--hosts" => hosts_path = Some(take_value(args, &mut i, "--hosts")?),
            other => return Err(format!("unknown serve option: {other}")),
        }
    }

    let bind: SocketAddr = bind_s
        .parse()
        .map_err(|_| format!("invalid --bind address: {bind_s}"))?;
    let hosts = load_hosts(hosts_path.as_deref())?;

    eprintln!(
        "{NAME}: serving zone '.{zone}' on {bind} ({} host record(s))",
        hosts.len()
    );
    resolver::serve(bind, zone, hosts).map_err(|e| e.to_string())
}

fn cmd_resolve(args: &[String]) -> Result<(), String> {
    let mut zone = DEFAULT_ZONE.to_string();
    let mut hosts_path: Option<String> = None;
    let mut name: Option<String> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--zone" => zone = take_value(args, &mut i, "--zone")?,
            "--hosts" => hosts_path = Some(take_value(args, &mut i, "--hosts")?),
            other if other.starts_with("--") => {
                return Err(format!("unknown resolve option: {other}"))
            }
            _ => {
                name = Some(args[i].clone());
                i += 1;
            }
        }
    }

    let name = name.ok_or("usage: akurai-dns resolve <name> [--zone <zone>] [--hosts <file>]")?;
    let hosts = load_hosts(hosts_path.as_deref())?;

    match resolver::resolve(&name, &zone, &hosts) {
        Some(ip) => {
            println!("{ip}");
            Ok(())
        }
        None => Err(format!("no record for '{name}' in zone '.{zone}'")),
    }
}

/// Load the optional hosts file, or an empty table when none was given.
fn load_hosts(path: Option<&str>) -> Result<Vec<(String, std::net::Ipv4Addr)>, String> {
    match path {
        Some(p) => resolver::load_hosts(Path::new(p))
            .map_err(|e| format!("cannot read hosts file {p}: {e}")),
        None => Ok(Vec::new()),
    }
}

/// Consume the value that follows a flag, advancing the cursor past both.
fn take_value(args: &[String], i: &mut usize, flag: &str) -> Result<String, String> {
    *i += 1;
    let value = args
        .get(*i)
        .ok_or_else(|| format!("{flag} requires a value"))?
        .clone();
    *i += 1;
    Ok(value)
}

fn print_usage() {
    println!("{NAME} {VERSION} — AkurAI VPN internal MagicDNS");
    println!();
    println!("USAGE:");
    println!("    {NAME} <command> [options]");
    println!();
    println!("COMMANDS:");
    println!("    serve [--zone <zone>] [--hosts <file>] [--bind <addr>]");
    println!("                       Serve MagicDNS over UDP (default zone");
    println!("                       '{DEFAULT_ZONE}', bind {DEFAULT_BIND})");
    println!("    resolve <name> [--zone <zone>] [--hosts <file>]");
    println!("                       Resolve a single overlay name and print its IP");
    println!("    version            Print version and exit");
    println!("    help               Show this help");
    println!();
    println!("HOSTS FILE:");
    println!("    One '<overlay_ip> <name>' per line; '#' comments and blanks ignored.");
}
