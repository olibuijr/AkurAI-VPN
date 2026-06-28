//! Authenticated data-packet session — the post-handshake data plane.
//!
//! Each packet is `counter (8 bytes, big-endian) || ChaCha20-Poly1305(send_key,
//! nonce(counter), aad = [], plaintext)`. The 12-byte AEAD nonce is four zero
//! bytes followed by the counter little-endian, so every packet uses a unique
//! nonce under a fixed key (the WireGuard data-packet construction). Inbound
//! packets are checked against a 64-entry sliding replay window so a captured
//! packet cannot be replayed and stale counters are rejected, while
//! within-window reordering is still accepted.

use crate::TransportKeys;

/// Width of the anti-replay sliding window, in packets.
const WINDOW: u64 = 64;

/// A bidirectional data-packet session keyed by a completed handshake.
pub struct Session {
    send_key: [u8; 32],
    recv_key: [u8; 32],
    /// Next outbound counter (monotonic, never reused under `send_key`).
    send_counter: u64,
    /// Highest inbound counter accepted so far.
    recv_max: u64,
    /// Bitmask of accepted counters in `(recv_max - 63 ..= recv_max)`; bit `i`
    /// is set when `recv_max - i` has been accepted.
    recv_mask: u64,
    /// False until the first inbound packet is accepted (so counter 0 is valid).
    recv_started: bool,
}

/// Build the 12-byte AEAD nonce for a counter: `[0,0,0,0] || counter_le`.
fn nonce(counter: u64) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[4..12].copy_from_slice(&counter.to_le_bytes());
    n
}

impl Session {
    /// Build a session from the transport keys a completed handshake produced.
    pub fn new(keys: TransportKeys) -> Self {
        Self {
            send_key: keys.send,
            recv_key: keys.recv,
            send_counter: 0,
            recv_max: 0,
            recv_mask: 0,
            recv_started: false,
        }
    }

    /// Encrypt an outbound packet: `counter_be(8) || AEAD(plaintext)`.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Vec<u8> {
        let counter = self.send_counter;
        self.send_counter += 1;
        let ct =
            akurai_crypto::chacha20poly1305::seal(&self.send_key, &nonce(counter), &[], plaintext);
        let mut packet = Vec::with_capacity(8 + ct.len());
        packet.extend_from_slice(&counter.to_be_bytes());
        packet.extend_from_slice(&ct);
        packet
    }

    /// Decrypt an inbound packet. Returns the plaintext, or `None` on a bad tag,
    /// a replayed counter, or a counter older than the replay window.
    pub fn decrypt(&mut self, packet: &[u8]) -> Option<Vec<u8>> {
        if packet.len() < 8 {
            return None;
        }
        let counter = u64::from_be_bytes(packet[..8].try_into().ok()?);

        // Cheap pre-auth reject of hopelessly old counters (also re-checked
        // authoritatively below). Never trust the counter until the tag verifies.
        if self.recv_started && self.recv_max >= WINDOW && counter <= self.recv_max - WINDOW {
            return None;
        }

        let plaintext = akurai_crypto::chacha20poly1305::open(
            &self.recv_key,
            &nonce(counter),
            &[],
            &packet[8..],
        )?;

        // Tag verified — now enforce anti-replay and slide the window.
        if !self.recv_started {
            self.recv_started = true;
            self.recv_max = counter;
            self.recv_mask = 1;
        } else if counter > self.recv_max {
            let shift = counter - self.recv_max;
            self.recv_mask = if shift >= WINDOW {
                0
            } else {
                self.recv_mask << shift
            };
            self.recv_mask |= 1;
            self.recv_max = counter;
        } else {
            let diff = self.recv_max - counter;
            if diff >= WINDOW {
                return None; // beyond the window (too old)
            }
            let bit = 1u64 << diff;
            if self.recv_mask & bit != 0 {
                return None; // replay
            }
            self.recv_mask |= bit;
        }

        Some(plaintext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair() -> (Session, Session) {
        let ka = [0x11u8; 32];
        let kb = [0x22u8; 32];
        // A sends with ka / receives with kb; B mirrors.
        let a = Session::new(TransportKeys { send: ka, recv: kb });
        let b = Session::new(TransportKeys { send: kb, recv: ka });
        (a, b)
    }

    #[test]
    fn round_trip_both_directions() {
        let (mut a, mut b) = pair();
        let p1 = a.encrypt(b"hello over the overlay");
        assert_eq!(
            b.decrypt(&p1).as_deref(),
            Some(&b"hello over the overlay"[..])
        );
        let p2 = b.encrypt(b"reply from the peer");
        assert_eq!(a.decrypt(&p2).as_deref(), Some(&b"reply from the peer"[..]));
    }

    #[test]
    fn replay_is_rejected() {
        let (mut a, mut b) = pair();
        let p = a.encrypt(b"once");
        assert!(b.decrypt(&p).is_some());
        assert!(b.decrypt(&p).is_none());
    }

    #[test]
    fn reorder_within_window_ok_each_once() {
        let (mut a, mut b) = pair();
        let p: Vec<Vec<u8>> = (0..4)
            .map(|i| a.encrypt(format!("pkt {i}").as_bytes()))
            .collect();
        // Deliver out of order: 0, 2, 1, 3.
        for idx in [0usize, 2, 1, 3] {
            assert!(b.decrypt(&p[idx]).is_some(), "pkt {idx} should decrypt");
        }
        // Each one again → replay.
        for idx in [0usize, 1, 2, 3] {
            assert!(b.decrypt(&p[idx]).is_none(), "pkt {idx} replay should fail");
        }
    }

    #[test]
    fn too_old_beyond_window_is_rejected() {
        let (mut a, mut b) = pair();
        let mut packets = Vec::new();
        for i in 0..72 {
            packets.push(a.encrypt(format!("p{i}").as_bytes()));
        }
        // Accept the newest, advancing recv_max well past the window.
        assert!(b.decrypt(&packets[71]).is_some());
        // Counter 0 is now > WINDOW behind → rejected.
        assert!(b.decrypt(&packets[0]).is_none());
    }

    #[test]
    fn tampered_ciphertext_is_rejected() {
        let (mut a, mut b) = pair();
        let mut p = a.encrypt(b"integrity matters");
        let last = p.len() - 1;
        p[last] ^= 0x01;
        assert!(b.decrypt(&p).is_none());
    }
}
