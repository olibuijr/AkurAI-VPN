//! End-to-end proof: a full Noise_IK handshake derives mirrored transport keys,
//! which then drive a real encrypted data-packet session in both directions.
//! This is the seam where the two independently-built modules meet.

use akurai_transport::{noise, session::Session, Keypair};

#[test]
fn handshake_then_encrypted_session_both_ways() {
    // Two static identities (e.g. a device and the hub) + per-handshake ephemerals.
    let init_static = Keypair::from_secret([7u8; 32]);
    let resp_static = Keypair::from_secret([9u8; 32]);
    let init_eph = [3u8; 32];
    let resp_eph = [5u8; 32];

    // --- Handshake ---
    let (state, msg1) = noise::initiate(&init_static, &resp_static.public, &init_eph);
    assert_eq!(msg1.len(), 96);
    let (resp_keys, msg2, recovered_init_pub) =
        noise::respond(&resp_static, &resp_eph, &msg1).expect("responder accepts msg1");
    assert_eq!(msg2.len(), 48);
    let init_keys = noise::finalize(state, &msg2).expect("initiator accepts msg2");

    // The responder authenticated who connected, and both sides agree on keys.
    assert_eq!(recovered_init_pub, init_static.public);
    assert_eq!(init_keys.send, resp_keys.recv);
    assert_eq!(init_keys.recv, resp_keys.send);

    // --- Encrypted data plane over the derived keys ---
    let mut device = Session::new(init_keys);
    let mut hub = Session::new(resp_keys);

    let up = device.encrypt(b"overlay 100.88.7.3 -> 100.88.7.9: hello");
    assert_eq!(
        hub.decrypt(&up).as_deref(),
        Some(&b"overlay 100.88.7.3 -> 100.88.7.9: hello"[..])
    );

    let down = hub.encrypt(b"ack from hub");
    assert_eq!(device.decrypt(&down).as_deref(), Some(&b"ack from hub"[..]));

    // A captured uplink packet cannot be replayed.
    assert!(hub.decrypt(&up).is_none());
}
