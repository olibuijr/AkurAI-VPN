//! `akurai-sys` — the zero-dependency Linux system seam for the AkurAI VPN node.
//!
//! AkurAI VPN ships with **no external runtime crates**. The one capability
//! `std` cannot provide is creating a TUN interface, which needs an `ioctl`.
//! This crate supplies exactly that, isolating the only `unsafe` in the whole
//! data plane to [`raw`]. Above it, packet I/O is plain [`std::fs::File`] reads
//! and writes, interface/route setup is `ip` via [`std::process::Command`], and
//! the transport is [`std::net::UdpSocket`] — all safe.
//!
//! Layering: this crate = OS seam → `akurai-transport` = secure channel →
//! `akurai-node` / `akurai-relay` = sockets + TUN + pump.

pub mod raw;
pub mod tun;

pub use tun::create as create_tun;
