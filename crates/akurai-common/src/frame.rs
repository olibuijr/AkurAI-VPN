//! The relay wire frame — the outer envelope every datagram travels in.
//!
//! AkurAI VPN is hub-routed in MVP1: nodes send all traffic to `akurai-relay`,
//! which forwards each frame to the destination overlay IP's last-known UDP
//! endpoint. The relay reads only this envelope (magic, type, src/dest overlay
//! IP) — never the payload, which for `Data` frames is end-to-end ciphertext the
//! relay cannot decrypt.
//!
//! Layout (big-endian, 14-byte header):
//!
//! ```text
//! 0      2   3      4        8        12     14
//! +------+---+------+--------+--------+------+----------+
//! | AC01 | v | type | dst v4 | src v4 | len  | payload  |
//! +------+---+------+--------+--------+------+----------+
//! ```
//!
//! No cryptography lives here — this is a pure value codec.

use std::net::Ipv4Addr;

/// Frame magic: `0xAC 0x01` ("AkurAI v1").
pub const MAGIC: [u8; 2] = [0xAC, 0x01];
/// Wire version. Bumped only on an incompatible envelope change.
pub const VERSION: u8 = 1;
/// Fixed header length in bytes.
pub const HEADER_LEN: usize = 14;
/// Maximum payload a single frame may carry (keeps the codec bounded against a
/// hostile `len`). Comfortably above the overlay MTU + crypto envelope.
pub const MAX_PAYLOAD: usize = 2048;

/// What a frame carries, demultiplexed by the relay-transparent type byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameKind {
    /// Node→relay liveness; teaches the relay this src overlay IP's UDP endpoint.
    Keepalive,
    /// Noise_IK handshake message 1 (initiator → responder), payload-opaque.
    HandshakeInit,
    /// Noise_IK handshake message 2 (responder → initiator), payload-opaque.
    HandshakeResp,
    /// An end-to-end-encrypted inner IP packet (ciphertext to the relay).
    Data,
}

impl FrameKind {
    fn to_byte(self) -> u8 {
        match self {
            FrameKind::Keepalive => 1,
            FrameKind::HandshakeInit => 2,
            FrameKind::HandshakeResp => 3,
            FrameKind::Data => 4,
        }
    }

    fn from_byte(b: u8) -> Option<Self> {
        match b {
            1 => Some(FrameKind::Keepalive),
            2 => Some(FrameKind::HandshakeInit),
            3 => Some(FrameKind::HandshakeResp),
            4 => Some(FrameKind::Data),
            _ => None,
        }
    }
}

/// A decoded relay frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub kind: FrameKind,
    /// Destination node overlay IPv4 (`0.0.0.0` addresses the relay itself).
    pub dest: Ipv4Addr,
    /// Source node overlay IPv4 — what the relay learns the sender's endpoint as.
    pub src: Ipv4Addr,
    pub payload: Vec<u8>,
}

impl Frame {
    /// Build a frame; the payload must fit [`MAX_PAYLOAD`].
    pub fn new(kind: FrameKind, src: Ipv4Addr, dest: Ipv4Addr, payload: Vec<u8>) -> Option<Self> {
        if payload.len() > MAX_PAYLOAD {
            return None;
        }
        Some(Self {
            kind,
            dest,
            src,
            payload,
        })
    }

    /// Serialize to the wire envelope.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_LEN + self.payload.len());
        out.extend_from_slice(&MAGIC);
        out.push(VERSION);
        out.push(self.kind.to_byte());
        out.extend_from_slice(&self.dest.octets());
        out.extend_from_slice(&self.src.octets());
        out.extend_from_slice(&(self.payload.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.payload);
        out
    }

    /// Parse a wire envelope. Returns `None` on any malformed input — wrong
    /// magic/version, unknown type, truncated header, a `len` that overflows
    /// [`MAX_PAYLOAD`], or a `len` that disagrees with the bytes present. Never panics.
    pub fn decode(buf: &[u8]) -> Option<Self> {
        if buf.len() < HEADER_LEN {
            return None;
        }
        if buf[0..2] != MAGIC || buf[2] != VERSION {
            return None;
        }
        let kind = FrameKind::from_byte(buf[3])?;
        let dest = Ipv4Addr::new(buf[4], buf[5], buf[6], buf[7]);
        let src = Ipv4Addr::new(buf[8], buf[9], buf[10], buf[11]);
        let len = u16::from_be_bytes([buf[12], buf[13]]) as usize;
        if len > MAX_PAYLOAD || buf.len() < HEADER_LEN + len {
            return None;
        }
        let payload = buf[HEADER_LEN..HEADER_LEN + len].to_vec();
        Some(Self {
            kind,
            dest,
            src,
            payload,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(a: u8, b: u8, c: u8, d: u8) -> Ipv4Addr {
        Ipv4Addr::new(a, b, c, d)
    }

    #[test]
    fn round_trip_preserves_all_fields() {
        let f = Frame::new(
            FrameKind::Data,
            ip(100, 88, 0, 2),
            ip(100, 88, 0, 3),
            b"ciphertext-bytes".to_vec(),
        )
        .unwrap();
        let wire = f.encode();
        assert_eq!(wire.len(), HEADER_LEN + 16);
        assert_eq!(Frame::decode(&wire), Some(f));
    }

    #[test]
    fn every_kind_round_trips() {
        for kind in [
            FrameKind::Keepalive,
            FrameKind::HandshakeInit,
            FrameKind::HandshakeResp,
            FrameKind::Data,
        ] {
            let f = Frame::new(kind, ip(100, 88, 0, 9), ip(0, 0, 0, 0), vec![1, 2, 3]).unwrap();
            assert_eq!(Frame::decode(&f.encode()).unwrap().kind, kind);
        }
    }

    #[test]
    fn rejects_bad_magic_version_and_type() {
        let mut wire = Frame::new(FrameKind::Data, ip(1, 1, 1, 1), ip(2, 2, 2, 2), vec![0; 4])
            .unwrap()
            .encode();
        let good = wire.clone();
        wire[0] = 0x00; // bad magic
        assert!(Frame::decode(&wire).is_none());
        let mut w = good.clone();
        w[2] = 9; // bad version
        assert!(Frame::decode(&w).is_none());
        let mut w = good.clone();
        w[3] = 99; // unknown type
        assert!(Frame::decode(&w).is_none());
    }

    #[test]
    fn rejects_truncated_and_lying_length() {
        let wire = Frame::new(FrameKind::Data, ip(1, 1, 1, 1), ip(2, 2, 2, 2), vec![7; 10])
            .unwrap()
            .encode();
        // Truncated header.
        assert!(Frame::decode(&wire[..HEADER_LEN - 1]).is_none());
        // Header claims 10 bytes but only 3 are present.
        assert!(Frame::decode(&wire[..HEADER_LEN + 3]).is_none());
    }

    #[test]
    fn rejects_oversized_payload() {
        assert!(Frame::new(
            FrameKind::Data,
            ip(1, 1, 1, 1),
            ip(2, 2, 2, 2),
            vec![0; MAX_PAYLOAD + 1]
        )
        .is_none());
        // A hand-built header lying about a huge length is also rejected.
        let mut wire = Vec::new();
        wire.extend_from_slice(&MAGIC);
        wire.push(VERSION);
        wire.push(FrameKind::Data.to_byte());
        wire.extend_from_slice(&[0; 8]);
        wire.extend_from_slice(&((MAX_PAYLOAD as u16) + 1).to_be_bytes());
        assert!(Frame::decode(&wire).is_none());
    }
}
