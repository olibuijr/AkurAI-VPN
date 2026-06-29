//! Cross-platform OS entropy seam for the node runtime.
//!
//! The node draws cryptographically-strong randomness at runtime in two places:
//! generating its persistent X25519 identity secret ([`crate::identity`]) and the
//! per-handshake ephemeral secret ([`crate::tunnel`]). On Unix that is a read from
//! `/dev/urandom`; Windows has no such file, so we call `BCryptGenRandom` from
//! `bcrypt.dll` through a tiny `extern "system"` seam — no crate dependency, in
//! keeping with the zero-dependency promise. Either way [`fill_random`] fills the
//! whole buffer with OS entropy or returns an [`io::Error`].

use std::io;

/// Fill `buf` with cryptographically-strong OS entropy (Unix: `/dev/urandom`).
///
/// # Errors
/// Surfaces the OS error if the entropy source cannot be read.
#[cfg(unix)]
pub fn fill_random(buf: &mut [u8]) -> io::Result<()> {
    use std::fs::File;
    use std::io::Read;
    File::open("/dev/urandom")?.read_exact(buf)
}

/// Fill `buf` with cryptographically-strong OS entropy via `BCryptGenRandom`
/// (`BCRYPT_USE_SYSTEM_PREFERRED_RNG`), so no algorithm handle is needed.
///
/// # Errors
/// Returns an error carrying the `NTSTATUS` if `BCryptGenRandom` fails.
#[cfg(windows)]
pub fn fill_random(buf: &mut [u8]) -> io::Result<()> {
    use core::ffi::c_void;

    /// `BCRYPT_USE_SYSTEM_PREFERRED_RNG` — draw from the system-preferred RNG with
    /// a NULL algorithm handle.
    const BCRYPT_USE_SYSTEM_PREFERRED_RNG: u32 = 0x0000_0002;

    #[link(name = "bcrypt")]
    extern "system" {
        // `NTSTATUS BCryptGenRandom(BCRYPT_ALG_HANDLE, PUCHAR, ULONG, ULONG)`.
        fn BCryptGenRandom(
            h_algorithm: *mut c_void,
            pb_buffer: *mut u8,
            cb_buffer: u32,
            dw_flags: u32,
        ) -> i32;
    }

    // `cbBuffer` is a ULONG; chunk so the (practically impossible) >4 GiB request
    // still fills completely instead of truncating.
    for chunk in buf.chunks_mut(u32::MAX as usize) {
        // SAFETY: `chunk.as_mut_ptr()` is valid for `chunk.len()` writable bytes,
        // and `chunk.len()` fits a `u32` by construction. A NULL algorithm handle
        // is valid with `BCRYPT_USE_SYSTEM_PREFERRED_RNG`; the call only writes
        // within that range.
        let status = unsafe {
            BCryptGenRandom(
                core::ptr::null_mut(),
                chunk.as_mut_ptr(),
                chunk.len() as u32,
                BCRYPT_USE_SYSTEM_PREFERRED_RNG,
            )
        };
        // STATUS_SUCCESS is exactly 0 for BCryptGenRandom; anything else is failure.
        if status != 0 {
            return Err(io::Error::other(format!(
                "BCryptGenRandom failed: NTSTATUS 0x{:08x}",
                status as u32
            )));
        }
    }
    Ok(())
}
