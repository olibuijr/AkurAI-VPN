//! The relay forward loop (stub — DO NOT implement here).
//!
//! Invariant: **the relay only ever sees ciphertext.** It pairs two peers by an
//! opaque session token and copies encrypted datagrams between them; it holds
//! no payload keys and can decrypt nothing. The loop needs the (undecided)
//! transport, so it is a stub in 0.0.1.

use std::fmt;

/// Errors from the relay forward loop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayError {
    /// The forward loop is not implemented in 0.0.1.
    NotImplemented,
}

impl fmt::Display for RelayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RelayError::NotImplemented => write!(
                f,
                "relay forward loop not implemented in 0.0.1 (needs a transport decision — see docs/protocol.md)"
            ),
        }
    }
}

impl std::error::Error for RelayError {}

/// Run the ciphertext forward loop. **Stub** — returns
/// [`RelayError::NotImplemented`].
pub fn run() -> Result<(), RelayError> {
    Err(RelayError::NotImplemented)
}
