//! `akurai-crypto` — the zero-dependency cryptographic core of AkurAI VPN.
//!
//! **Decision (2026-06-27, resolved by Ólafur):** AkurAI VPN implements its
//! data-plane cryptography FROM SCRATCH in pure Rust (`std` only, no `unsafe`,
//! no third-party crates) rather than linking a vetted crate
//! (rustls/quinn/snow/ed25519). This preserves the project's
//! zero-runtime-dependency identity. The trade-off — hand-rolled crypto carries
//! side-channel and correctness risk — is accepted deliberately.
//!
//! To bound that risk, every primitive in this crate is:
//!   * a well-specified, widely-implemented standard (RFC 7748, RFC 8439, RFC 7693),
//!   * verified IN-CRATE against that standard's official published test vectors,
//!   * written without `unsafe`, and constant-time where feasible.
//!
//! The primitives compose into a WireGuard-style `Noise_IK` handshake (Phase 2):
//!   * [`x25519`]           — Curve25519 ECDH (RFC 7748)
//!   * [`chacha20poly1305`] — AEAD (RFC 8439)
//!   * [`blake2s`]          — hash + keyed MAC (RFC 7693)
//!   * [`hkdf`]             — HKDF over HMAC-BLAKE2s (the Noise key schedule)
#![forbid(unsafe_code)]

pub mod blake2s;
pub mod chacha20poly1305;
pub mod hkdf;
pub mod x25519;
