//! Cross-platform TUN device — layer-3 packet I/O behind one small handle.
//!
//! [`TunDevice`] hides every OS difference behind three calls: [`TunDevice::recv`]
//! returns exactly one **bare IPv4/IPv6 packet** (no platform framing) and
//! [`TunDevice::send`] writes exactly one. `recv`/`send` take `&self`, so a single
//! device wrapped in an `Arc` can be read by one thread and written by another at
//! the same time — the kernel serializes the underlying read/write per fd.
//!
//! - **Linux** — open `/dev/net/tun`, bind it with one `ioctl(TUNSETIFF)` using
//!   `IFF_TUN | IFF_NO_PI` (so frames have NO header). `recv`/`send` are plain
//!   `File` read/write. The only `unsafe` is the raw syscall in [`crate::raw`].
//! - **macOS** — a REAL `utun` interface created with raw `extern "C"` calls into
//!   libSystem (always linked, never a crate dependency). utun frames carry a
//!   4-byte big-endian address-family header, which this module adds on `send` and
//!   strips on `recv`, so callers still see bare packets.
//! - **Windows** — a clearly-bounded stub that COMPILES but fails loudly at
//!   runtime until the Wintun driver is wired (see the `windows` module below).
//!
//! The kernel-assigned name (`utunN` on macOS) is exposed via [`TunDevice::name`]
//! so the caller can configure the right interface.

use std::io;

// ---------------------------------------------------------------------------
// Linux — the original /dev/net/tun seam, now wrapped in TunDevice.
// ---------------------------------------------------------------------------
#[cfg(target_os = "linux")]
mod platform {
    use std::fs::{File, OpenOptions};
    use std::io::{self, Read, Write};
    use std::os::unix::io::AsRawFd;

    /// Path to the TUN/TAP clone device.
    const TUN_CLONE: &str = "/dev/net/tun";

    /// A Linux layer-3 TUN interface (`IFF_TUN | IFF_NO_PI`): bare IPv4/IPv6
    /// packets, no packet-info header.
    pub struct TunDevice {
        file: File,
        name: String,
    }

    impl TunDevice {
        /// Create a layer-3 TUN named `name`. The interface starts **down** with no
        /// address; the caller brings it up (safe `ip` commands). Requires
        /// `CAP_NET_ADMIN`.
        ///
        /// # Errors
        /// Surfaces the OS error if `/dev/net/tun` cannot be opened (missing module,
        /// `EPERM`) or the `ioctl` fails (name in use/invalid). Never panics.
        pub fn create(name: &str) -> io::Result<TunDevice> {
            let file = OpenOptions::new().read(true).write(true).open(TUN_CLONE)?;
            crate::raw::tunsetiff(file.as_raw_fd(), name)?;
            Ok(TunDevice {
                file,
                name: name.to_string(),
            })
        }

        /// Read one bare packet. `&self`-safe to call concurrently with [`send`].
        ///
        /// [`send`]: TunDevice::send
        pub fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
            // `Read for &File` lets us read through a shared reference; the fd's
            // read/write are independently safe to call from two threads.
            let mut f: &File = &self.file;
            f.read(buf)
        }

        /// Write one bare packet. `&self`-safe to call concurrently with [`recv`].
        ///
        /// [`recv`]: TunDevice::recv
        pub fn send(&self, pkt: &[u8]) -> io::Result<usize> {
            let mut f: &File = &self.file;
            f.write(pkt)
        }

        /// The interface name (the requested name on Linux — the kernel honors it).
        pub fn name(&self) -> &str {
            &self.name
        }
    }
}

// ---------------------------------------------------------------------------
// macOS — a real utun interface via raw libSystem FFI (no crate dependency).
// ---------------------------------------------------------------------------
#[cfg(target_os = "macos")]
mod platform {
    //! macOS `utun` data plane.
    //!
    //! A utun interface is a `PF_SYSTEM` kernel-control socket: resolve the utun
    //! control id by name, `connect` to it (the kernel allocates `utunN`), then
    //! `read`/`write` frames. Each frame is prefixed with a 4-byte big-endian
    //! address-family word, which we add on send and strip on recv.

    use std::io;
    use std::os::raw::{c_char, c_int, c_uint, c_ulong, c_void};

    /// `socklen_t` on macOS (LP64): a 32-bit unsigned int.
    type Socklen = c_uint;

    // Kernel-control / utun constants (from <sys/sys_domain.h>, <net/if_utun.h>).
    const PF_SYSTEM: c_int = 32;
    const SOCK_DGRAM: c_int = 2;
    const SYSPROTO_CONTROL: c_int = 2;
    const AF_SYSTEM: u8 = 32;
    const AF_SYS_CONTROL: u16 = 2;
    /// `CTLIOCGINFO` = `_IOWR('N', 3, struct ctl_info)` (ctl_info is 100 bytes).
    const CTLIOCGINFO: c_ulong = 0xc064_4e03;
    /// `getsockopt` name for the kernel-assigned interface name (`utunN`).
    const UTUN_OPT_IFNAME: c_int = 2;
    /// The well-known utun kernel-control name.
    const UTUN_CONTROL_NAME: &[u8] = b"com.apple.net.utun_control";

    /// `struct ctl_info { u_int32_t ctl_id; char ctl_name[MAX_KCTL_NAME=96]; }`.
    #[repr(C)]
    struct CtlInfo {
        ctl_id: u32,
        ctl_name: [c_char; 96],
    }

    /// `struct sockaddr_ctl` — 32 bytes total.
    #[repr(C)]
    struct SockaddrCtl {
        sc_len: u8,
        sc_family: u8,
        ss_sysaddr: u16,
        sc_id: u32,
        sc_unit: u32,
        sc_reserved: [u32; 5],
    }

    extern "C" {
        fn socket(domain: c_int, ty: c_int, protocol: c_int) -> c_int;
        // ioctl is variadic in C; we always pass exactly one pointer argument.
        fn ioctl(fd: c_int, request: c_ulong, ...) -> c_int;
        fn connect(fd: c_int, addr: *const c_void, len: Socklen) -> c_int;
        fn getsockopt(
            fd: c_int,
            level: c_int,
            optname: c_int,
            optval: *mut c_void,
            optlen: *mut Socklen,
        ) -> c_int;
        fn read(fd: c_int, buf: *mut c_void, count: usize) -> isize;
        fn write(fd: c_int, buf: *const c_void, count: usize) -> isize;
        fn close(fd: c_int) -> c_int;
    }

    /// Closes a raw fd on drop unless disarmed via [`FdGuard::take`]. Guarantees the
    /// socket is released if any step of `create` fails after the `socket` call.
    struct FdGuard(c_int);

    impl Drop for FdGuard {
        fn drop(&mut self) {
            if self.0 >= 0 {
                // SAFETY: `self.0` is an fd we opened and still own; closed once.
                unsafe { close(self.0) };
            }
        }
    }

    impl FdGuard {
        /// Take ownership of the fd, disarming the guard so it won't close it.
        fn take(mut self) -> c_int {
            let fd = self.0;
            self.0 = -1;
            fd
        }
    }

    /// A macOS `utun` layer-3 interface. Owns one fd (closed on drop) plus the
    /// kernel-assigned name (`utunN`). The fd is a plain `i32`, so the handle is
    /// `Send + Sync`; concurrent `recv`/`send` map to independent `read`/`write`
    /// syscalls the kernel serializes per fd.
    pub struct TunDevice {
        fd: c_int,
        name: String,
    }

    impl TunDevice {
        /// Create a real `utun` interface. `name` is ignored — the kernel assigns
        /// `utunN`; the chosen name is available via [`TunDevice::name`].
        ///
        /// # Errors
        /// Surfaces the OS error from `socket`/`ioctl`/`connect` (e.g. `EPERM`
        /// without root). Never panics.
        pub fn create(_name: &str) -> io::Result<TunDevice> {
            // 1. Open a kernel-control socket.
            // SAFETY: a plain syscall with constant args; returns < 0 on error.
            let fd = unsafe { socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL) };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            let guard = FdGuard(fd);

            // 2. Resolve the utun control id by name into ctl_info.ctl_id.
            let mut info = CtlInfo {
                ctl_id: 0,
                ctl_name: [0; 96],
            };
            for (slot, &b) in info.ctl_name.iter_mut().zip(UTUN_CONTROL_NAME) {
                *slot = b as c_char;
            }
            // SAFETY: `info` is a valid, correctly-sized ctl_info that outlives the
            // call; the kernel reads ctl_name and writes ctl_id, both in-bounds.
            let rc = unsafe { ioctl(fd, CTLIOCGINFO, &mut info as *mut CtlInfo) };
            if rc < 0 {
                return Err(io::Error::last_os_error());
            }

            // 3. Connect to the control; sc_unit = 0 => kernel picks utunN.
            let addr = SockaddrCtl {
                sc_len: core::mem::size_of::<SockaddrCtl>() as u8,
                sc_family: AF_SYSTEM,
                ss_sysaddr: AF_SYS_CONTROL,
                sc_id: info.ctl_id,
                sc_unit: 0,
                sc_reserved: [0; 5],
            };
            // SAFETY: `addr` is a valid sockaddr_ctl of exactly `sc_len` bytes.
            let rc = unsafe {
                connect(
                    fd,
                    &addr as *const SockaddrCtl as *const c_void,
                    core::mem::size_of::<SockaddrCtl>() as Socklen,
                )
            };
            if rc < 0 {
                return Err(io::Error::last_os_error());
            }

            // 4. Learn the kernel-assigned interface name (utunN).
            let name = ifname(fd).unwrap_or_default();

            Ok(TunDevice {
                fd: guard.take(),
                name,
            })
        }

        /// Read one bare IP packet, stripping the 4-byte utun AF header.
        /// `&self`-safe to call concurrently with [`send`](TunDevice::send).
        pub fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
            // utun delivers one whole frame per read: a 4-byte big-endian AF header
            // followed by the IP packet. Read into a temp, then hand back [4..].
            let mut frame = [0u8; 4 + 4096];
            let want = core::cmp::min(buf.len() + 4, frame.len());
            // SAFETY: writing at most `want` bytes into `frame`, which is `want`-big.
            let n = unsafe { read(self.fd, frame.as_mut_ptr() as *mut c_void, want) };
            if n < 0 {
                return Err(io::Error::last_os_error());
            }
            let n = n as usize;
            if n == 0 {
                return Ok(0); // EOF — device closed.
            }
            if n < 4 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "utun frame shorter than its 4-byte header",
                ));
            }
            let payload = n - 4;
            buf[..payload].copy_from_slice(&frame[4..n]);
            Ok(payload)
        }

        /// Write one bare IP packet, prepending the 4-byte utun AF header and
        /// writing the whole frame in ONE `write`. `&self`-safe to call
        /// concurrently with [`recv`](TunDevice::recv).
        pub fn send(&self, pkt: &[u8]) -> io::Result<usize> {
            // Big-endian address family: AF_INET (2) for IPv4, AF_INET6 (30) for v6,
            // chosen from the IP version nibble. Header bytes [0..3] stay zero.
            const AF_INET: u8 = 2;
            const AF_INET6: u8 = 30;
            let mut frame = [0u8; 4 + 4096];
            if pkt.len() > frame.len() - 4 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "packet larger than the utun frame buffer",
                ));
            }
            frame[3] = if !pkt.is_empty() && (pkt[0] >> 4) == 6 {
                AF_INET6
            } else {
                AF_INET
            };
            frame[4..4 + pkt.len()].copy_from_slice(pkt);
            let total = 4 + pkt.len();
            // SAFETY: writing exactly `total` bytes from `frame`, which is `total`-big.
            let n = unsafe { write(self.fd, frame.as_ptr() as *const c_void, total) };
            if n < 0 {
                return Err(io::Error::last_os_error());
            }
            // The kernel counts the 4-byte header; report inner-packet bytes only.
            Ok((n as usize).saturating_sub(4))
        }

        /// The kernel-assigned interface name, e.g. `utun4`.
        pub fn name(&self) -> &str {
            &self.name
        }
    }

    impl Drop for TunDevice {
        fn drop(&mut self) {
            if self.fd >= 0 {
                // SAFETY: we own this fd and close it exactly once.
                unsafe { close(self.fd) };
            }
        }
    }

    /// Fetch the kernel-assigned interface name (e.g. `utun4`) for a utun fd via
    /// `getsockopt(SYSPROTO_CONTROL, UTUN_OPT_IFNAME)`.
    fn ifname(fd: c_int) -> Option<String> {
        let mut buf = [0u8; 64];
        let mut len: Socklen = buf.len() as Socklen;
        // SAFETY: getsockopt writes up to `len` bytes into `buf` and updates `len`.
        let rc = unsafe {
            getsockopt(
                fd,
                SYSPROTO_CONTROL,
                UTUN_OPT_IFNAME,
                buf.as_mut_ptr() as *mut c_void,
                &mut len,
            )
        };
        if rc < 0 {
            return None;
        }
        let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
        Some(String::from_utf8_lossy(&buf[..end]).into_owned())
    }
}

// ---------------------------------------------------------------------------
// Windows — compiling stub. Fails loudly until the Wintun driver is wired.
// ---------------------------------------------------------------------------
#[cfg(target_os = "windows")]
mod platform {
    //! Windows TUN — NOT yet wired.
    //!
    //! A real implementation rides the Wintun driver (`wintun.dll`), loaded at
    //! runtime with no crate dependency:
    //!
    //! 1. `LoadLibraryW(L"wintun.dll")` then `GetProcAddress` for the exports.
    //! 2. `WintunCreateAdapter(name, "AkurAI", &guid)` to make the adapter.
    //! 3. `WintunStartSession(adapter, capacity)` to get a ring-buffer session.
    //! 4. `recv` -> `WintunReceivePacket` (+ `WintunReleaseReceivePacket`);
    //!    `send` -> `WintunAllocateSendPacket` + memcpy + `WintunSendPacket`.
    //!    Wintun packets are already bare IP — no 4-byte AF header (unlike utun).
    //! 5. Drop -> `WintunEndSession` + `WintunCloseAdapter`.
    //!
    //! Until then, every call returns `ErrorKind::Unsupported` so the boundary is
    //! explicit and the daemon fails fast rather than silently misbehaving.

    use std::io;

    /// Placeholder handle. Never constructed (`create` always errors) — present so
    /// the node compiles on Windows with the platform gap made explicit.
    pub struct TunDevice {
        _private: (),
    }

    /// The single error every stubbed entry point returns.
    fn unsupported() -> io::Error {
        io::Error::new(
            io::ErrorKind::Unsupported,
            "Windows TUN requires the Wintun driver — not yet wired",
        )
    }

    impl TunDevice {
        pub fn create(_name: &str) -> io::Result<TunDevice> {
            Err(unsupported())
        }

        pub fn recv(&self, _buf: &mut [u8]) -> io::Result<usize> {
            Err(unsupported())
        }

        pub fn send(&self, _pkt: &[u8]) -> io::Result<usize> {
            Err(unsupported())
        }

        pub fn name(&self) -> &str {
            ""
        }
    }
}

pub use platform::TunDevice;

/// Create a layer-3 TUN interface named `name` and return a cross-platform handle.
///
/// On Linux the kernel honors `name`; on macOS it assigns `utunN` (read it back via
/// [`TunDevice::name`]); on Windows this currently returns `ErrorKind::Unsupported`.
///
/// # Errors
/// Surfaces the underlying OS error. Never panics.
pub fn create(name: &str) -> io::Result<TunDevice> {
    TunDevice::create(name)
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::fs::OpenOptions;
    use std::io;

    #[test]
    fn rejects_empty_and_overlong_names() {
        // The ioctl seam validates the name before touching the kernel; an empty or
        // >15-byte name is an InvalidInput error, never a panic.
        assert_eq!(
            crate::raw::tunsetiff(-1, "").unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(
            crate::raw::tunsetiff(-1, "a_very_long_iface_name")
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn missing_device_is_an_error_not_a_panic() {
        // Opening a non-existent clone device must surface as an io::Error.
        let r = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/net/tun-does-not-exist");
        assert!(r.is_err());
    }
}
