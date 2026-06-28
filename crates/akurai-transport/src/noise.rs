//! WireGuard-style `Noise_IK` handshake, hand-rolled on the zero-dependency
//! `akurai-crypto` primitives.
//!
//! `Noise_IK` is a one-round-trip mutually-authenticated handshake. The
//! Initiator knows the Responder's static public key up front (the `K` token);
//! the Responder learns and authenticates the Initiator's static key from
//! message 1 (the `I` token). After two messages both peers hold a matched pair
//! of directional [`TransportKeys`].
//!
//! ```text
//!   Initiator                                  Responder
//!   --------- msg1: e, es, s, ss (96 B) ----->
//!   <-------- msg2: e, ee, se     (48 B) ------
//! ```
//!
//! This implements the data-plane handshake WITHOUT the WireGuard hardening
//! layer — no pre-shared key, no MAC1/MAC2/cookie, no timestamp. Those are a
//! later phase. Every handshake AEAD uses a fresh, single-use KDF key, so a
//! constant all-zero nonce is safe.
//!
//! ## Protocol transcript
//!
//! Symmetric state is a chaining key `ck` (feeds the KDF) and a transcript hash
//! `h` (authenticates every AEAD as associated data). Both peers absorb the
//! same values in the same order, so they converge on identical `ck`/`h` and
//! therefore identical transport keys. Authentication is implicit: if any DH
//! input, static key, or ciphertext differs, a downstream AEAD tag check fails
//! and the handshake aborts.

use akurai_crypto::{blake2s, chacha20poly1305 as aead, hkdf::hkdf, x25519};

use crate::{Keypair, PublicKey, TransportKeys, CONSTRUCTION, IDENTIFIER};

/// All handshake AEAD operations use a single all-zero 96-bit nonce. Each key is
/// derived fresh by the KDF and used exactly once, so the nonce never repeats
/// under a given key.
const ZERO_NONCE: [u8; 12] = [0u8; 12];

// Wire layout sizes.
const PUB_LEN: usize = 32; // X25519 public key
const TAG_LEN: usize = 16; // ChaCha20-Poly1305 tag
const ENC_STATIC_LEN: usize = PUB_LEN + TAG_LEN; // 48: sealed static public key
const MSG1_LEN: usize = PUB_LEN + ENC_STATIC_LEN + TAG_LEN; // 96
const MSG2_LEN: usize = PUB_LEN + TAG_LEN; // 48

/// `h <- BLAKE2s(h || data)` — absorb `data` into the running transcript hash.
fn mix_hash(h: [u8; 32], data: &[u8]) -> [u8; 32] {
    blake2s::hash(&[h.as_slice(), data].concat())
}

/// One-output Noise KDF: derive the next chaining key from `ck` and input `x`.
fn kdf1(ck: &[u8; 32], x: &[u8]) -> [u8; 32] {
    hkdf::<1>(ck, x)[0]
}

/// Two-output Noise KDF: derive `(next chaining key, AEAD key)`.
fn kdf2(ck: &[u8; 32], x: &[u8]) -> ([u8; 32], [u8; 32]) {
    let o = hkdf::<2>(ck, x);
    (o[0], o[1])
}

/// The shared handshake prelude `(ck, h)`, seeded from the protocol labels and
/// the Responder's static public key. Computed identically by both peers.
fn prelude(responder_static_pub: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let ck = blake2s::hash(CONSTRUCTION);
    let mut h = blake2s::hash(&[ck.as_slice(), IDENTIFIER].concat());
    h = mix_hash(h, responder_static_pub);
    (ck, h)
}

/// Initiator symmetric state carried from message 1 to message 2.
///
/// Opaque by design: the chaining key, transcript hash, the Initiator's own
/// static key pair, and the per-handshake ephemeral secret are all private.
pub struct Initiator {
    ck: [u8; 32],
    h: [u8; 32],
    static_kp: Keypair,
    ephemeral_secret: [u8; 32],
}

/// Build handshake message 1 (`e, es, s, ss`).
///
/// `ephemeral_secret` is supplied by the caller — deterministic for tests, fresh
/// OS entropy in production. Returns the carried [`Initiator`] state and the
/// 96-byte wire message `e_pub(32) || enc_static(48) || enc_empty(16)`.
pub fn initiate(
    static_kp: &Keypair,
    responder_pub: &PublicKey,
    ephemeral_secret: &[u8; 32],
) -> (Initiator, Vec<u8>) {
    let (mut ck, mut h) = prelude(responder_pub);

    // -- e: mix the Initiator's ephemeral public key.
    let e_pub = x25519::public_key(ephemeral_secret);
    ck = kdf1(&ck, &e_pub);
    h = mix_hash(h, &e_pub);

    // -- es: DH(ephemeral, responder static) -> key encrypting the static key.
    let es = x25519::shared_secret(ephemeral_secret, responder_pub);
    let (new_ck, k) = kdf2(&ck, &es);
    ck = new_ck;
    let enc_static = aead::seal(&k, &ZERO_NONCE, &h, &static_kp.public);
    h = mix_hash(h, &enc_static);

    // -- ss: DH(static, responder static) -> key encrypting the empty payload.
    let ss = x25519::shared_secret(&static_kp.secret, responder_pub);
    let (new_ck, k) = kdf2(&ck, &ss);
    ck = new_ck;
    let enc_empty = aead::seal(&k, &ZERO_NONCE, &h, &[]);
    h = mix_hash(h, &enc_empty);

    let mut msg1 = Vec::with_capacity(MSG1_LEN);
    msg1.extend_from_slice(&e_pub);
    msg1.extend_from_slice(&enc_static);
    msg1.extend_from_slice(&enc_empty);

    let state = Initiator {
        ck,
        h,
        static_kp: static_kp.clone(),
        ephemeral_secret: *ephemeral_secret,
    };
    (state, msg1)
}

/// Consume message 1 and build message 2.
///
/// `static_kp` is the Responder's static key pair; `ephemeral_secret` is its
/// per-handshake ephemeral secret. On success returns the Responder's
/// [`TransportKeys`], the 48-byte message 2 `er_pub(32) || enc_empty2(16)`, and
/// the authenticated static [`PublicKey`] of the Initiator. Returns `None` on
/// any malformed input or AEAD authentication failure.
pub fn respond(
    static_kp: &Keypair,
    ephemeral_secret: &[u8; 32],
    msg1: &[u8],
) -> Option<(TransportKeys, Vec<u8>, PublicKey)> {
    if msg1.len() != MSG1_LEN {
        return None;
    }
    let e_pub: [u8; 32] = msg1[0..PUB_LEN].try_into().ok()?;
    let enc_static = &msg1[PUB_LEN..PUB_LEN + ENC_STATIC_LEN];
    let enc_empty = &msg1[PUB_LEN + ENC_STATIC_LEN..MSG1_LEN];

    let (mut ck, mut h) = prelude(&static_kp.public);

    // -- e
    ck = kdf1(&ck, &e_pub);
    h = mix_hash(h, &e_pub);

    // -- es: DH(responder static, initiator ephemeral) -> decrypt static key.
    let es = x25519::shared_secret(&static_kp.secret, &e_pub);
    let (new_ck, k) = kdf2(&ck, &es);
    ck = new_ck;
    let init_static_pt = aead::open(&k, &ZERO_NONCE, &h, enc_static)?;
    let init_static_pub: [u8; 32] = init_static_pt.as_slice().try_into().ok()?;
    h = mix_hash(h, enc_static);

    // -- ss: DH(responder static, initiator static) -> decrypt empty payload.
    let ss = x25519::shared_secret(&static_kp.secret, &init_static_pub);
    let (new_ck, k) = kdf2(&ck, &ss);
    ck = new_ck;
    let empty = aead::open(&k, &ZERO_NONCE, &h, enc_empty)?;
    if !empty.is_empty() {
        return None;
    }
    h = mix_hash(h, enc_empty);

    // ---- message 2 ----
    let er_pub = x25519::public_key(ephemeral_secret);
    ck = kdf1(&ck, &er_pub);
    h = mix_hash(h, &er_pub);

    // -- ee: DH(responder ephemeral, initiator ephemeral).
    let ee = x25519::shared_secret(ephemeral_secret, &e_pub);
    ck = kdf1(&ck, &ee);
    // -- se: DH(responder ephemeral, initiator static).
    let se = x25519::shared_secret(ephemeral_secret, &init_static_pub);
    ck = kdf1(&ck, &se);

    let (new_ck, k) = kdf2(&ck, &[]);
    ck = new_ck;
    let enc_empty2 = aead::seal(&k, &ZERO_NONCE, &h, &[]);
    // Final transcript absorption — completes the handshake hash; the value is
    // not needed for the key split, so it is intentionally not retained.
    let _ = mix_hash(h, &enc_empty2);

    let mut msg2 = Vec::with_capacity(MSG2_LEN);
    msg2.extend_from_slice(&er_pub);
    msg2.extend_from_slice(&enc_empty2);

    // Split: Responder is the second party, so its send key is the second output.
    let (t1, t2) = kdf2(&ck, &[]);
    let keys = TransportKeys { send: t2, recv: t1 };

    Some((keys, msg2, init_static_pub))
}

/// Consume message 2 and finish the handshake.
///
/// Returns the Initiator's [`TransportKeys`], or `None` if message 2 is
/// malformed or fails AEAD authentication.
pub fn finalize(state: Initiator, msg2: &[u8]) -> Option<TransportKeys> {
    if msg2.len() != MSG2_LEN {
        return None;
    }
    let er_pub: [u8; 32] = msg2[0..PUB_LEN].try_into().ok()?;
    let enc_empty2 = &msg2[PUB_LEN..MSG2_LEN];

    let mut ck = state.ck;
    let mut h = state.h;

    // -- e
    ck = kdf1(&ck, &er_pub);
    h = mix_hash(h, &er_pub);

    // -- ee: DH(initiator ephemeral, responder ephemeral).
    let ee = x25519::shared_secret(&state.ephemeral_secret, &er_pub);
    ck = kdf1(&ck, &ee);
    // -- se: DH(initiator static, responder ephemeral).
    let se = x25519::shared_secret(&state.static_kp.secret, &er_pub);
    ck = kdf1(&ck, &se);

    let (new_ck, k) = kdf2(&ck, &[]);
    ck = new_ck;
    let empty = aead::open(&k, &ZERO_NONCE, &h, enc_empty2)?;
    if !empty.is_empty() {
        return None;
    }
    // Final transcript absorption (see `respond`); value intentionally unused.
    let _ = mix_hash(h, enc_empty2);

    // Split: Initiator is the first party, so its send key is the first output.
    let (t1, t2) = kdf2(&ck, &[]);
    Some(TransportKeys { send: t1, recv: t2 })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Keypair;

    // Fixed, deterministic test material (any 32-byte arrays).
    fn fixtures() -> (Keypair, Keypair, [u8; 32], [u8; 32]) {
        let init_static = Keypair::from_secret([1u8; 32]);
        let resp_static = Keypair::from_secret([2u8; 32]);
        let init_eph = [3u8; 32];
        let resp_eph = [4u8; 32];
        (init_static, resp_static, init_eph, resp_eph)
    }

    /// Full handshake: keys mirror across peers and the Initiator's static key
    /// is recovered by the Responder.
    #[test]
    fn noise_round_trip() {
        let (init_static, resp_static, init_eph, resp_eph) = fixtures();

        let (state, msg1) = initiate(&init_static, &resp_static.public, &init_eph);
        let (resp_keys, msg2, recovered_init_pub) =
            respond(&resp_static, &resp_eph, &msg1).expect("responder must accept msg1");
        let init_keys = finalize(state, &msg2).expect("initiator must accept msg2");

        // Directional keys are mirror images across the two peers.
        assert_eq!(
            init_keys.send, resp_keys.recv,
            "init.send must equal resp.recv"
        );
        assert_eq!(
            init_keys.recv, resp_keys.send,
            "init.recv must equal resp.send"
        );

        // The Responder authenticated and recovered the Initiator's static key.
        assert_eq!(
            recovered_init_pub,
            Keypair::from_secret([1u8; 32]).public,
            "responder must recover the initiator's static public key",
        );

        // Sanity: keys are non-degenerate and the two directions differ.
        assert_ne!(init_keys.send, [0u8; 32]);
        assert_ne!(init_keys.recv, [0u8; 32]);
        assert_ne!(init_keys.send, init_keys.recv);
    }

    /// A single flipped byte in message 1 fails AEAD authentication.
    #[test]
    fn noise_msg1_tamper_rejected() {
        let (init_static, resp_static, init_eph, resp_eph) = fixtures();
        let (_state, mut msg1) = initiate(&init_static, &resp_static.public, &init_eph);

        msg1[40] ^= 0x01; // inside the sealed static key
        assert!(
            respond(&resp_static, &resp_eph, &msg1).is_none(),
            "tampered msg1 must be rejected",
        );
    }

    /// A single flipped byte in message 2 fails AEAD authentication.
    #[test]
    fn noise_msg2_tamper_rejected() {
        let (init_static, resp_static, init_eph, resp_eph) = fixtures();
        let (state, msg1) = initiate(&init_static, &resp_static.public, &init_eph);
        let (_keys, mut msg2, _pub) =
            respond(&resp_static, &resp_eph, &msg1).expect("responder must accept msg1");

        msg2[40] ^= 0x01; // inside enc_empty2's authentication tag
        assert!(
            finalize(state, &msg2).is_none(),
            "tampered msg2 must be rejected",
        );
    }

    /// Wire messages have the exact specified lengths.
    #[test]
    fn noise_message_sizes() {
        let (init_static, resp_static, init_eph, resp_eph) = fixtures();
        let (state, msg1) = initiate(&init_static, &resp_static.public, &init_eph);
        assert_eq!(msg1.len(), 96, "msg1 must be 96 bytes");

        let (_keys, msg2, _pub) =
            respond(&resp_static, &resp_eph, &msg1).expect("responder must accept msg1");
        assert_eq!(msg2.len(), 48, "msg2 must be 48 bytes");

        finalize(state, &msg2).expect("initiator must accept msg2");
    }
}
