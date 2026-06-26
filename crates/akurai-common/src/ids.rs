//! Stable identities — node IDs and the (placeholder) machine identity key.
//!
//! These are opaque value types. **No cryptography lives here.** [`MachineKey`]
//! is a transparent placeholder for the *public* half of a node's long-term
//! identity key; the real key type, signature scheme, and generation routine
//! are an UNRESOLVED DECISION (see `docs/protocol.md`). Until that is settled,
//! this module only models the *shape* of an identity, never its security.

use std::fmt;

/// A stable, globally-unique node identifier.
///
/// 16 bytes, rendered as lowercase hex. The value is assigned by the control
/// plane at enrollment and never changes for the lifetime of the device.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct NodeId([u8; NodeId::LEN]);

impl NodeId {
    /// Length of a node ID in bytes.
    pub const LEN: usize = 16;

    /// Wrap raw identifier bytes assigned by the control plane.
    pub fn from_bytes(bytes: [u8; NodeId::LEN]) -> Self {
        Self(bytes)
    }

    /// Borrow the raw identifier bytes.
    pub fn as_bytes(&self) -> &[u8; NodeId::LEN] {
        &self.0
    }

    /// Lowercase hex rendering (32 hex chars).
    pub fn to_hex(&self) -> String {
        self.to_string()
    }
}

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in &self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NodeId({self})")
    }
}

/// Placeholder for the *public* half of a node's long-term identity key.
///
/// **This is not a real key and performs no cryptography.** It only carries
/// opaque bytes so the rest of the system can model "a node has an identity".
/// The real type — Ed25519? X25519? a `ring` key? a `snow` static key? — is an
/// UNRESOLVED DECISION (see `docs/protocol.md`). The private half is never
/// represented in this crate.
#[derive(Clone, PartialEq, Eq)]
pub struct MachineKey(Vec<u8>);

impl MachineKey {
    /// Wrap already-existing public-key bytes. Does **not** generate anything
    /// and does **not** validate the bytes as a key.
    pub fn from_public_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Borrow the opaque public-key bytes.
    pub fn public_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for MachineKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never print key material, even a placeholder's, into logs.
        write!(f, "MachineKey([{} bytes])", self.0.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_id_hex_round_trips() {
        let bytes = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];
        let id = NodeId::from_bytes(bytes);
        assert_eq!(id.to_hex(), "00112233445566778899aabbccddeeff");
        assert_eq!(id.as_bytes(), &bytes);
    }

    #[test]
    fn node_id_equality_is_by_value() {
        let a = NodeId::from_bytes([1; 16]);
        let b = NodeId::from_bytes([1; 16]);
        let c = NodeId::from_bytes([2; 16]);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn machine_key_debug_redacts_bytes() {
        let key = MachineKey::from_public_bytes(vec![0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(format!("{key:?}"), "MachineKey([4 bytes])");
        assert_eq!(key.public_bytes(), &[0xde, 0xad, 0xbe, 0xef]);
    }
}
