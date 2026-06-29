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
//! - **Windows** — a REAL Wintun interface: `wintun.dll` is loaded at runtime via
//!   `LoadLibraryW`/`GetProcAddress` (no crate dependency), an adapter + ring
//!   session are created, and `recv`/`send` shuttle packets through the ring.
//!   Wintun frames are already bare IP (no AF header, unlike utun).
//!
//! The interface name is exposed via [`TunDevice::name`] so the caller can
//! configure the right interface — the requested name on Linux and Windows, the
//! kernel-assigned `utunN` on macOS.

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
// Windows — a real Wintun interface via runtime-loaded `wintun.dll` (no crate).
// ---------------------------------------------------------------------------
#[cfg(target_os = "windows")]
mod platform {
    //! Windows `utun`-equivalent data plane on the Wintun driver.
    //!
    //! IMPLEMENTED. `wintun.dll` is loaded at runtime — no crate dependency, no
    //! import-time link to wintun — preserving the zero-dependency promise:
    //!
    //! 1. `LoadLibraryW(L"wintun.dll")` then `GetProcAddress` for every export.
    //! 2. `WintunCreateAdapter(name, "AkurAI", NULL)` to make the adapter.
    //! 3. `WintunStartSession(adapter, 4 MiB)` to get a ring-buffer session.
    //! 4. `recv` -> `WintunReceivePacket` (+ `WintunReleaseReceivePacket`),
    //!    blocking on `WintunGetReadWaitEvent` via `WaitForSingleObject` when the
    //!    ring is empty; `send` -> `WintunAllocateSendPacket` + memcpy +
    //!    `WintunSendPacket`. Wintun packets are already bare IP — no 4-byte AF
    //!    header (unlike utun), so packets pass straight through.
    //! 5. Drop -> `WintunEndSession` + `WintunCloseAdapter`.
    //!
    //! Only `kernel32` (`LoadLibraryW`/`GetProcAddress`/`GetLastError`/
    //! `WaitForSingleObject`) is statically imported — that is the bootstrap that
    //! cannot itself be dynamically loaded. Everything Wintun is resolved by name.

    use core::ffi::c_void;
    use std::io;

    /// Wintun ring capacity: 4 MiB (must be a power of two between 128 KiB and 64
    /// MiB per the Wintun API).
    const WINTUN_RING_CAPACITY: u32 = 0x0040_0000;
    /// `WaitForSingleObject` — wait with no timeout.
    const INFINITE: u32 = 0xFFFF_FFFF;
    /// `GetLastError`: the receive ring is currently empty (block on the event).
    const ERROR_NO_MORE_ITEMS: u32 = 259;
    /// `GetLastError`: the send ring is full (back-pressure → `WouldBlock`).
    const ERROR_BUFFER_OVERFLOW: u32 = 111;

    // --- Wintun exported function-pointer types (all `__stdcall` = extern system).
    /// Opaque `WINTUN_ADAPTER_HANDLE` / `WINTUN_SESSION_HANDLE` / `HANDLE`.
    type Handle = *mut c_void;
    /// `WINTUN_ADAPTER_HANDLE WintunCreateAdapter(LPCWSTR, LPCWSTR, const GUID*)`.
    type WintunCreateAdapterFn =
        unsafe extern "system" fn(*const u16, *const u16, *const c_void) -> Handle;
    /// `void WintunCloseAdapter(WINTUN_ADAPTER_HANDLE)`.
    type WintunCloseAdapterFn = unsafe extern "system" fn(Handle);
    /// `WINTUN_SESSION_HANDLE WintunStartSession(WINTUN_ADAPTER_HANDLE, DWORD)`.
    type WintunStartSessionFn = unsafe extern "system" fn(Handle, u32) -> Handle;
    /// `void WintunEndSession(WINTUN_SESSION_HANDLE)`.
    type WintunEndSessionFn = unsafe extern "system" fn(Handle);
    /// `BYTE* WintunAllocateSendPacket(WINTUN_SESSION_HANDLE, DWORD)`.
    type WintunAllocateSendPacketFn = unsafe extern "system" fn(Handle, u32) -> *mut u8;
    /// `void WintunSendPacket(WINTUN_SESSION_HANDLE, const BYTE*)`.
    type WintunSendPacketFn = unsafe extern "system" fn(Handle, *const u8);
    /// `BYTE* WintunReceivePacket(WINTUN_SESSION_HANDLE, DWORD* PacketSize)`.
    type WintunReceivePacketFn = unsafe extern "system" fn(Handle, *mut u32) -> *mut u8;
    /// `void WintunReleaseReceivePacket(WINTUN_SESSION_HANDLE, const BYTE*)`.
    type WintunReleaseReceivePacketFn = unsafe extern "system" fn(Handle, *const u8);
    /// `HANDLE WintunGetReadWaitEvent(WINTUN_SESSION_HANDLE)`.
    type WintunGetReadWaitEventFn = unsafe extern "system" fn(Handle) -> Handle;

    // kernel32 — the irreducible static imports. `LoadLibraryW`/`GetProcAddress`
    // cannot themselves be dynamically loaded (chicken-and-egg), so they, plus the
    // error/wait helpers, are linked directly. Everything Wintun goes through them.
    #[link(name = "kernel32")]
    extern "system" {
        fn LoadLibraryW(lp_lib_file_name: *const u16) -> *mut c_void;
        fn GetProcAddress(h_module: *mut c_void, lp_proc_name: *const u8) -> *mut c_void;
        fn GetLastError() -> u32;
        fn WaitForSingleObject(h_handle: *mut c_void, dw_milliseconds: u32) -> u32;
    }

    /// The resolved Wintun entry points for one loaded `wintun.dll`.
    struct Wintun {
        create_adapter: WintunCreateAdapterFn,
        close_adapter: WintunCloseAdapterFn,
        start_session: WintunStartSessionFn,
        end_session: WintunEndSessionFn,
        allocate_send_packet: WintunAllocateSendPacketFn,
        send_packet: WintunSendPacketFn,
        receive_packet: WintunReceivePacketFn,
        release_receive_packet: WintunReleaseReceivePacketFn,
        get_read_wait_event: WintunGetReadWaitEventFn,
    }

    /// Resolve one Wintun export by name and transmute it to its typed fn pointer,
    /// returning `Unsupported` from the enclosing function if the export is absent
    /// (an old or incomplete `wintun.dll`). Must be expanded inside an `unsafe`
    /// block — `GetProcAddress` and `transmute` are unsafe.
    macro_rules! load_sym {
        ($module:expr, $name:literal, $ty:ty) => {{
            let sym = GetProcAddress($module, concat!($name, "\0").as_ptr());
            if sym.is_null() {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    concat!("wintun.dll is missing export ", $name),
                ));
            }
            core::mem::transmute::<*mut c_void, $ty>(sym)
        }};
    }

    /// A Windows layer-3 interface backed by a Wintun ring session. Holds the raw
    /// adapter + session handles, the read-ready event, the requested name, and the
    /// resolved Wintun entry points.
    pub struct TunDevice {
        adapter: Handle,
        session: Handle,
        read_wait: Handle,
        name: String,
        api: Wintun,
    }

    // SAFETY: a Wintun session is documented as thread-safe for concurrent
    // `WintunSendPacket` and `WintunReceivePacket` from different threads, so
    // sharing one `TunDevice` across the send and receive pump threads (via `Arc`)
    // is sound. The stored handles are process-stable pointers with no thread
    // affinity, and the resolved fn pointers are immutable after `create`.
    unsafe impl Send for TunDevice {}
    unsafe impl Sync for TunDevice {}

    /// UTF-16, NUL-terminated — the form `LoadLibraryW`/`WintunCreateAdapter` want.
    fn to_wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(core::iter::once(0)).collect()
    }

    impl TunDevice {
        /// Create a real Wintun adapter named `name` (with tunnel type `AkurAI`) and
        /// start a 4 MiB ring session. Unlike macOS, Wintun honors the requested
        /// name, so [`TunDevice::name`] returns `name` and the caller configures
        /// that interface.
        ///
        /// # Errors
        /// Returns `ErrorKind::Unsupported` if `wintun.dll` cannot be loaded (driver
        /// not installed) or is missing an export; otherwise surfaces the Win32
        /// error from `WintunCreateAdapter`/`WintunStartSession`. Never panics.
        pub fn create(name: &str) -> io::Result<TunDevice> {
            let name_w = to_wide(name);
            let tunnel_w = to_wide("AkurAI");
            let dll_w = to_wide("wintun.dll");

            // SAFETY: every call below is FFI into kernel32 / wintun.dll matching the
            // documented signatures. The wide-string buffers outlive their calls,
            // and every returned handle is null-checked before use.
            unsafe {
                let module = LoadLibraryW(dll_w.as_ptr());
                if module.is_null() {
                    return Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        "wintun.dll not found — install the Wintun driver",
                    ));
                }
                let api = Wintun {
                    create_adapter: load_sym!(module, "WintunCreateAdapter", WintunCreateAdapterFn),
                    close_adapter: load_sym!(module, "WintunCloseAdapter", WintunCloseAdapterFn),
                    start_session: load_sym!(module, "WintunStartSession", WintunStartSessionFn),
                    end_session: load_sym!(module, "WintunEndSession", WintunEndSessionFn),
                    allocate_send_packet: load_sym!(
                        module,
                        "WintunAllocateSendPacket",
                        WintunAllocateSendPacketFn
                    ),
                    send_packet: load_sym!(module, "WintunSendPacket", WintunSendPacketFn),
                    receive_packet: load_sym!(module, "WintunReceivePacket", WintunReceivePacketFn),
                    release_receive_packet: load_sym!(
                        module,
                        "WintunReleaseReceivePacket",
                        WintunReleaseReceivePacketFn
                    ),
                    get_read_wait_event: load_sym!(
                        module,
                        "WintunGetReadWaitEvent",
                        WintunGetReadWaitEventFn
                    ),
                };

                // NULL requested GUID ⇒ Wintun derives a stable GUID from the name.
                let adapter =
                    (api.create_adapter)(name_w.as_ptr(), tunnel_w.as_ptr(), core::ptr::null());
                if adapter.is_null() {
                    return Err(io::Error::last_os_error());
                }
                let session = (api.start_session)(adapter, WINTUN_RING_CAPACITY);
                if session.is_null() {
                    let err = io::Error::last_os_error();
                    (api.close_adapter)(adapter);
                    return Err(err);
                }
                let read_wait = (api.get_read_wait_event)(session);

                Ok(TunDevice {
                    adapter,
                    session,
                    read_wait,
                    name: name.to_string(),
                    api,
                })
            }
        }

        /// Read one bare IP packet from the ring. Blocks on the read-ready event
        /// when the ring is empty, so this never busy-spins. `&self`-safe to call
        /// concurrently with [`send`](TunDevice::send).
        pub fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
            loop {
                let mut size: u32 = 0;
                // SAFETY: `self.session` is a live Wintun session. `receive_packet`
                // returns either a pointer to `size` readable bytes (released below)
                // or NULL with a reason in `GetLastError`.
                let pkt = unsafe { (self.api.receive_packet)(self.session, &mut size) };
                if !pkt.is_null() {
                    let n = (size as usize).min(buf.len());
                    // SAFETY: `pkt` is valid for `size` bytes until we release it; we
                    // copy `n <= size` into the caller's buffer (no overlap), then
                    // hand the ring slot straight back.
                    unsafe {
                        core::ptr::copy_nonoverlapping(pkt, buf.as_mut_ptr(), n);
                        (self.api.release_receive_packet)(self.session, pkt);
                    }
                    return Ok(n);
                }
                // SAFETY: kernel32 call, no pointer arguments.
                let err = unsafe { GetLastError() };
                if err == ERROR_NO_MORE_ITEMS {
                    // SAFETY: `read_wait` is this session's read-ready event handle.
                    unsafe { WaitForSingleObject(self.read_wait, INFINITE) };
                    continue;
                }
                return Err(io::Error::from_raw_os_error(err as i32));
            }
        }

        /// Write one bare IP packet into the send ring. Returns `WouldBlock` if the
        /// ring is full. `&self`-safe to call concurrently with
        /// [`recv`](TunDevice::recv).
        pub fn send(&self, pkt: &[u8]) -> io::Result<usize> {
            if pkt.is_empty() {
                return Ok(0);
            }
            // SAFETY: `self.session` is live; `allocate_send_packet` returns a
            // writable buffer of exactly `pkt.len()` bytes, or NULL with a reason in
            // `GetLastError`.
            let slot = unsafe { (self.api.allocate_send_packet)(self.session, pkt.len() as u32) };
            if slot.is_null() {
                // SAFETY: kernel32 call, no pointer arguments.
                let err = unsafe { GetLastError() };
                if err == ERROR_BUFFER_OVERFLOW {
                    return Err(io::Error::new(
                        io::ErrorKind::WouldBlock,
                        "wintun send ring full",
                    ));
                }
                return Err(io::Error::from_raw_os_error(err as i32));
            }
            // SAFETY: `slot` is `pkt.len()` writable bytes we own until handed to the
            // ring by `send_packet`; source and destination do not overlap.
            unsafe {
                core::ptr::copy_nonoverlapping(pkt.as_ptr(), slot, pkt.len());
                (self.api.send_packet)(self.session, slot);
            }
            Ok(pkt.len())
        }

        /// The interface name — the requested name (Wintun honors it).
        pub fn name(&self) -> &str {
            &self.name
        }
    }

    impl Drop for TunDevice {
        fn drop(&mut self) {
            // SAFETY: `session`/`adapter` came from `WintunStartSession`/
            // `WintunCreateAdapter` and are still owned here; each is ended/closed
            // exactly once, session before adapter (Wintun's required order).
            unsafe {
                if !self.session.is_null() {
                    (self.api.end_session)(self.session);
                }
                if !self.adapter.is_null() {
                    (self.api.close_adapter)(self.adapter);
                }
            }
        }
    }
}

pub use platform::TunDevice;

/// Create a layer-3 TUN interface named `name` and return a cross-platform handle.
///
/// On Linux and Windows the requested `name` is honored; on macOS the kernel
/// assigns `utunN` (read it back via [`TunDevice::name`]). On Windows a missing
/// `wintun.dll` surfaces as `ErrorKind::Unsupported`.
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
