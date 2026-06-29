//! `akurai-sys` — the zero-dependency system seam for the AkurAI VPN node.
//!
//! AkurAI VPN ships with **no external runtime crates**. The one capability
//! `std` cannot provide is creating a TUN interface; this crate supplies exactly
//! that behind one small cross-platform handle, [`TunDevice`]:
//!
//! - **Linux** — open `/dev/net/tun` + one `ioctl(TUNSETIFF)`. The only `unsafe`
//!   in the whole data plane is the raw syscall in `raw`; `recv`/`send` are plain
//!   [`std::fs::File`] reads and writes of bare packets (`IFF_NO_PI`).
//! - **macOS** — a real `utun` interface via raw `extern "C"` libSystem calls
//!   (always linked — never a crate dependency); the 4-byte utun AF header is
//!   added/stripped internally so callers still see bare packets.
//! - **Windows** — a real Wintun interface via `wintun.dll`, loaded at runtime
//!   with `LoadLibraryW`/`GetProcAddress` (no crate dependency); Wintun frames are
//!   already bare IP, so packets pass straight through (see [`tun`]).
//!
//! Above this crate, packet I/O is [`TunDevice::recv`]/[`TunDevice::send`],
//! interface/route setup is the OS CLI via [`std::process::Command`], and the
//! transport is [`std::net::UdpSocket`] — all safe.
//!
//! Layering: this crate = OS seam → `akurai-transport` = secure channel →
//! `akurai-node` / `akurai-relay` = sockets + TUN + pump.

// The raw syscall seam is Linux-specific (Linux ioctl numbers + asm `syscall`).
#[cfg(target_os = "linux")]
pub mod raw;
pub mod tun;

pub use tun::{create as create_tun, TunDevice};
