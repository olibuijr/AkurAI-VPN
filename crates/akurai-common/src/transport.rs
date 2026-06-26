//! Transport & session **stubs** — intentionally cryptography-free.
//!
//! AkurAI VPN carries application traffic inside an authenticated, encrypted
//! session between nodes (and as ciphertext-only through the relay). **None of
//! that is implemented here, and no cryptographic primitive is implemented
//! anywhere in this crate.**
//!
//! The choice of transport and handshake is an UNRESOLVED DECISION documented
//! at length in `docs/protocol.md`:
//!
//! - QUIC + TLS identity (e.g. `quinn` + `rustls`), or
//! - Noise-over-UDP (e.g. `snow`),
//!
//! both of which mandate a vetted third-party crypto crate — in direct tension
//! with this project's zero-runtime-dependency principle. That trade-off is for
//! Ólafur to resolve. Until then these are typed placeholders that return
//! [`TransportError::NotImplemented`] rather than pretending to secure anything.

use std::fmt;

use crate::ids::NodeId;

/// Errors from the (unimplemented) transport layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportError {
    /// The session/transport layer is not implemented in 0.0.1. No transport
    /// or cryptography may be added until the protocol decision is made.
    NotImplemented,
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TransportError::NotImplemented => write!(
                f,
                "transport/crypto not implemented in 0.0.1 (UNRESOLVED DECISION — see docs/protocol.md)"
            ),
        }
    }
}

impl std::error::Error for TransportError {}

/// A peer session placeholder. Holds **no** keys and performs **no**
/// cryptography — it exists only so callers can name the seam.
#[derive(Debug, Default)]
pub struct Session;

impl Session {
    /// Establish a session to a peer. **Stub** — always returns
    /// [`TransportError::NotImplemented`].
    pub fn establish(_peer: &NodeId) -> Result<Self, TransportError> {
        Err(TransportError::NotImplemented)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn establishing_a_session_is_not_implemented() {
        let peer = NodeId::from_bytes([0; 16]);
        assert_eq!(
            Session::establish(&peer).unwrap_err(),
            TransportError::NotImplemented
        );
    }
}
