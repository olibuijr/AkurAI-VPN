//! `akurai-transport` — the encrypted secure-channel layer for AkurAI VPN.
//!
//! A WireGuard-style `Noise_IK` handshake over the zero-dependency
//! [`akurai_crypto`] primitives (X25519 / ChaCha20-Poly1305 / BLAKE2s / HKDF),
//! followed by an authenticated data-packet [`session`] with counter nonces and
//! sliding-window replay protection. Pure `std`, no `unsafe`, no external crates.
//!
//! Layering: [`akurai_crypto`] = primitives → this crate = secure channel →
//! `akurai-node` / `akurai-relay` = sockets + TUN (Phase 3).
#![forbid(unsafe_code)]

pub mod noise;
pub mod session;

/// X25519 public key (32 bytes).
pub type PublicKey = [u8; 32];
/// X25519 secret key (32 bytes, clamped internally by `akurai_crypto`).
pub type SecretKey = [u8; 32];

/// A static identity keypair.
#[derive(Clone)]
pub struct Keypair {
    pub secret: SecretKey,
    pub public: PublicKey,
}

impl Keypair {
    /// Derive the public key from a secret (X25519 base-point multiplication).
    pub fn from_secret(secret: SecretKey) -> Self {
        Self {
            public: akurai_crypto::x25519::public_key(&secret),
            secret,
        }
    }
}

/// The two directional transport keys a completed handshake yields. `send`
/// encrypts outbound packets; `recv` decrypts inbound. The two peers' keys are
/// mirrored — my `send` equals my peer's `recv`, and vice-versa.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TransportKeys {
    pub send: [u8; 32],
    pub recv: [u8; 32],
}

/// Protocol identifiers mixed into the handshake's initial chaining key + hash
/// (AkurAI's analogue of WireGuard's construction/identifier strings). Changing
/// these makes a handshake incompatible with the previous wire format.
pub const CONSTRUCTION: &[u8] = b"Noise_IK_25519_ChaChaPoly_BLAKE2s";
pub const IDENTIFIER: &[u8] = b"AkurAI VPN v1 2026";
