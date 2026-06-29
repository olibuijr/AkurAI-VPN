//! Raw Linux syscall seam — the **only** unsafe code in the AkurAI VPN data plane.
//!
//! Creating a TUN interface requires `ioctl(TUNSETIFF)`, which `std` does not
//! expose. Rather than pull in `libc` (and break the zero-dependency promise),
//! this module issues the one needed `ioctl` through a direct `syscall`
//! instruction. The unsafe surface is exactly two functions; everything that
//! builds on top — packet read/write, address/route setup — is safe `std`.

use std::io;
use std::os::unix::io::RawFd;

/// Linux x86_64 syscall number for `ioctl`.
#[cfg(target_arch = "x86_64")]
const SYS_IOCTL: usize = 16;
/// Linux aarch64 syscall number for `ioctl` (for a future Android/ARM node).
#[cfg(target_arch = "aarch64")]
const SYS_IOCTL: usize = 29;

/// `TUNSETIFF` request code (set the TUN/TAP interface flags + name).
const TUNSETIFF: usize = 0x4004_54ca;
/// `IFF_TUN`: layer-3 packet (no Ethernet header).
const IFF_TUN: u16 = 0x0001;
/// `IFF_NO_PI`: no 4-byte packet-info prefix on each frame.
const IFF_NO_PI: u16 = 0x1000;

/// Issue a 3-argument syscall. The single unsafe primitive.
///
/// Returns the kernel's raw return value: `>= 0` on success, or `-errno` on
/// failure (the C ABI convention for the raw syscall instruction).
#[cfg(target_arch = "x86_64")]
unsafe fn syscall3(n: usize, a1: usize, a2: usize, a3: usize) -> isize {
    let ret: isize;
    core::arch::asm!(
        "syscall",
        inlateout("rax") n as isize => ret,
        in("rdi") a1,
        in("rsi") a2,
        in("rdx") a3,
        lateout("rcx") _,
        lateout("r11") _,
        options(nostack, preserves_flags),
    );
    ret
}

/// Issue a 3-argument syscall on aarch64 (svc #0; args in x0-x2, nr in x8).
#[cfg(target_arch = "aarch64")]
unsafe fn syscall3(n: usize, a1: usize, a2: usize, a3: usize) -> isize {
    let ret: isize;
    core::arch::asm!(
        "svc #0",
        in("x8") n,
        inlateout("x0") a1 => ret,
        in("x1") a2,
        in("x2") a3,
        options(nostack, preserves_flags),
    );
    ret
}

/// Bind an opened `/dev/net/tun` file descriptor to a named layer-3 TUN
/// interface (`IFF_TUN | IFF_NO_PI`).
///
/// `name` must be < 16 bytes (Linux `IFNAMSIZ`). On success the interface
/// exists in the current network namespace; the caller still has to bring it
/// up and assign addresses (done in safe code via `ip`).
pub fn tunsetiff(fd: RawFd, name: &str) -> io::Result<()> {
    let bytes = name.as_bytes();
    if bytes.is_empty() || bytes.len() >= 16 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "TUN interface name must be 1..=15 bytes",
        ));
    }
    // struct ifreq is 40 bytes: char ifr_name[16] then a 24-byte union whose
    // first field here is the u16 ifr_flags.
    let mut ifr = [0u8; 40];
    ifr[..bytes.len()].copy_from_slice(bytes);
    let flags = (IFF_TUN | IFF_NO_PI).to_ne_bytes();
    ifr[16] = flags[0];
    ifr[17] = flags[1];

    // SAFETY: `ifr` is a correctly-sized, initialized ifreq buffer that outlives
    // the call; `fd` is a valid descriptor for an open `/dev/net/tun`. The
    // kernel reads the 40-byte struct and may write the resolved name back into
    // it — both within `ifr`'s bounds.
    let ret = unsafe { syscall3(SYS_IOCTL, fd as usize, TUNSETIFF, ifr.as_mut_ptr() as usize) };
    if ret < 0 {
        return Err(io::Error::from_raw_os_error(-ret as i32));
    }
    Ok(())
}
