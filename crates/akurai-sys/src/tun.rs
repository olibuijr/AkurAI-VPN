//! TUN device creation and packet I/O.
//!
//! A TUN device is just a file descriptor: open `/dev/net/tun`, bind it to a
//! named interface with one `ioctl`, then `read`/`write` raw IPv4 packets. All
//! of that is safe `std` except the single `ioctl`, which lives in [`crate::raw`].

use std::fs::{File, OpenOptions};
use std::io;
use std::os::unix::io::AsRawFd;

/// Path to the TUN/TAP clone device.
const TUN_CLONE: &str = "/dev/net/tun";

/// Create a layer-3 TUN interface named `name` and return its file handle.
///
/// The returned [`File`] reads and writes bare IPv4 packets (no packet-info
/// header — `IFF_NO_PI`). The interface starts **down** with no address; bring
/// it up and assign the overlay IP in the caller (safe `ip` commands). Requires
/// `CAP_NET_ADMIN` (root or a network namespace).
///
/// # Errors
/// Returns the underlying OS error if `/dev/net/tun` cannot be opened (missing
/// module, `EPERM`) or if the `ioctl` fails (name in use, bad name). Never panics.
pub fn create(name: &str) -> io::Result<File> {
    let file = OpenOptions::new().read(true).write(true).open(TUN_CLONE)?;
    crate::raw::tunsetiff(file.as_raw_fd(), name)?;
    Ok(file)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_empty_and_overlong_names() {
        // The ioctl seam validates the name before touching the kernel; an
        // empty or >15-byte name is an InvalidInput error, never a panic.
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
