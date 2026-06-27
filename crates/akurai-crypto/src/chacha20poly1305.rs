//! ChaCha20-Poly1305 AEAD — RFC 8439, pure `std`, no `unsafe`.

// ── ChaCha20 ─────────────────────────────────────────────────────────────────

/// The 16-word ChaCha20 state.
#[derive(Clone)]
struct ChaChaState([u32; 16]);

impl ChaChaState {
    fn new(key: &[u8; 32], nonce: &[u8; 12], counter: u32) -> Self {
        // §2.3 initial state
        let mut s = [0u32; 16];
        // "expa", "nd 3", "2-by", "te k"
        s[0] = 0x6170_7865;
        s[1] = 0x3320_646e;
        s[2] = 0x7962_2d32;
        s[3] = 0x6b20_6574;
        for i in 0..8 {
            s[4 + i] = u32::from_le_bytes(key[i * 4..i * 4 + 4].try_into().unwrap());
        }
        s[12] = counter;
        s[13] = u32::from_le_bytes(nonce[0..4].try_into().unwrap());
        s[14] = u32::from_le_bytes(nonce[4..8].try_into().unwrap());
        s[15] = u32::from_le_bytes(nonce[8..12].try_into().unwrap());
        ChaChaState(s)
    }

    /// Quarter-round in place.
    #[inline]
    fn qr(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
        s[a] = s[a].wrapping_add(s[b]);
        s[d] ^= s[a];
        s[d] = s[d].rotate_left(16);
        s[c] = s[c].wrapping_add(s[d]);
        s[b] ^= s[c];
        s[b] = s[b].rotate_left(12);
        s[a] = s[a].wrapping_add(s[b]);
        s[d] ^= s[a];
        s[d] = s[d].rotate_left(8);
        s[c] = s[c].wrapping_add(s[d]);
        s[b] ^= s[c];
        s[b] = s[b].rotate_left(7);
    }

    /// Produce one 64-byte keystream block.
    fn block(&self) -> [u8; 64] {
        let mut work = self.0;
        for _ in 0..10 {
            // column rounds
            Self::qr(&mut work, 0, 4, 8, 12);
            Self::qr(&mut work, 1, 5, 9, 13);
            Self::qr(&mut work, 2, 6, 10, 14);
            Self::qr(&mut work, 3, 7, 11, 15);
            // diagonal rounds
            Self::qr(&mut work, 0, 5, 10, 15);
            Self::qr(&mut work, 1, 6, 11, 12);
            Self::qr(&mut work, 2, 7, 8, 13);
            Self::qr(&mut work, 3, 4, 9, 14);
        }
        let mut out = [0u8; 64];
        for (i, (&wi, &si)) in work.iter().zip(self.0.iter()).enumerate() {
            let word = wi.wrapping_add(si);
            out[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
        }
        out
    }
}

/// XOR `data` with the ChaCha20 keystream; counter starts at `counter`.
fn chacha20_xor(key: &[u8; 32], nonce: &[u8; 12], counter: u32, data: &mut [u8]) {
    let mut state = ChaChaState::new(key, nonce, counter);
    let mut pos = 0;
    while pos < data.len() {
        let block = state.block();
        let len = (data.len() - pos).min(64);
        for i in 0..len {
            data[pos + i] ^= block[i];
        }
        pos += 64;
        state.0[12] = state.0[12].wrapping_add(1);
    }
}

// ── Poly1305 ──────────────────────────────────────────────────────────────────

/// Process a message with Poly1305 using a 32-byte one-time key.
///
/// Uses 5×u64 limbs in base 2^26, matching the djb reference implementation.
/// All intermediate products stay within u64 (each limb ≤ 2^26, r ≤ 2^26, sum
/// of 5 products ≤ 5 · 2^52 which fits in u64).
fn poly1305_mac(key: &[u8; 32], msg: &[u8]) -> [u8; 16] {
    // clamp r (§2.5.1)
    let mut r_bytes = [0u8; 16];
    r_bytes.copy_from_slice(&key[..16]);
    r_bytes[3] &= 0x0f;
    r_bytes[7] &= 0x0f;
    r_bytes[11] &= 0x0f;
    r_bytes[15] &= 0x0f;
    r_bytes[4] &= 0xfc;
    r_bytes[8] &= 0xfc;
    r_bytes[12] &= 0xfc;

    // load r as little-endian 128-bit, split into 5×26-bit limbs
    let r128 = u128::from_le_bytes(r_bytes);
    let r0 = (r128 & 0x3ff_ffff) as u64;
    let r1 = ((r128 >> 26) & 0x3ff_ffff) as u64;
    let r2 = ((r128 >> 52) & 0x3ff_ffff) as u64;
    let r3 = ((r128 >> 78) & 0x3ff_ffff) as u64;
    let r4 = ((r128 >> 104) & 0x3ff_ffff) as u64;

    // 5 * r[1..4] for the mod-2^130-5 reduction shortcut
    let s1 = r1 * 5;
    let s2 = r2 * 5;
    let s3 = r3 * 5;
    let s4 = r4 * 5;

    let mut h: [u64; 5] = [0; 5];

    let mut offset = 0;
    loop {
        let remaining = msg.len().saturating_sub(offset);
        if remaining == 0 {
            break;
        }
        let chunk_len = remaining.min(16);
        let mut block = [0u8; 17];
        block[..chunk_len].copy_from_slice(&msg[offset..offset + chunk_len]);
        block[chunk_len] = 1; // hibit

        // load as 130-bit little-endian
        let n0 = u64::from_le_bytes(block[0..8].try_into().unwrap());
        let n1 = u64::from_le_bytes(block[8..16].try_into().unwrap());
        let n2 = block[16] as u64;

        // split into 5×26-bit limbs and add to h
        h[0] += n0 & 0x3ff_ffff;
        h[1] += (n0 >> 26) & 0x3ff_ffff;
        h[2] += ((n0 >> 52) | (n1 << 12)) & 0x3ff_ffff;
        h[3] += (n1 >> 14) & 0x3ff_ffff;
        h[4] += ((n1 >> 40) | (n2 << 24)) & 0x3ff_ffff;

        // h = h * r mod p
        // Each d_i is a sum of 5 terms each ≤ (2^26 + some carry) * 2^26 < 2^53,
        // so the sum of 5 fits comfortably in u64.
        let d0 = h[0] * r0 + h[1] * s4 + h[2] * s3 + h[3] * s2 + h[4] * s1;
        let d1 = h[0] * r1 + h[1] * r0 + h[2] * s4 + h[3] * s3 + h[4] * s2;
        let d2 = h[0] * r2 + h[1] * r1 + h[2] * r0 + h[3] * s4 + h[4] * s3;
        let d3 = h[0] * r3 + h[1] * r2 + h[2] * r1 + h[3] * r0 + h[4] * s4;
        let d4 = h[0] * r4 + h[1] * r3 + h[2] * r2 + h[3] * r1 + h[4] * r0;

        // carry propagation
        let c0 = d0 >> 26;
        h[0] = d0 & 0x3ff_ffff;
        let c1 = (d1 + c0) >> 26;
        h[1] = (d1 + c0) & 0x3ff_ffff;
        let c2 = (d2 + c1) >> 26;
        h[2] = (d2 + c1) & 0x3ff_ffff;
        let c3 = (d3 + c2) >> 26;
        h[3] = (d3 + c2) & 0x3ff_ffff;
        let c4 = (d4 + c3) >> 26;
        h[4] = (d4 + c3) & 0x3ff_ffff;
        // c4 * 2^130 ≡ c4 * 5 (mod p)
        h[0] += c4 * 5;
        let c0b = h[0] >> 26;
        h[0] &= 0x3ff_ffff;
        h[1] += c0b;

        offset += 16;
    }

    // final carry propagation
    let c1 = h[1] >> 26;
    h[1] &= 0x3ff_ffff;
    let c2 = (h[2] + c1) >> 26;
    h[2] = (h[2] + c1) & 0x3ff_ffff;
    let c3 = (h[3] + c2) >> 26;
    h[3] = (h[3] + c2) & 0x3ff_ffff;
    let c4 = (h[4] + c3) >> 26;
    h[4] = (h[4] + c3) & 0x3ff_ffff;
    h[0] += c4 * 5;
    let c0 = h[0] >> 26;
    h[0] &= 0x3ff_ffff;
    h[1] += c0;

    // compute h - p conditionally; use constant-time select via mask
    let mut g: [u64; 5] = [0; 5];
    g[0] = h[0].wrapping_add(5);
    let b = g[0] >> 26;
    g[0] &= 0x3ff_ffff;
    g[1] = h[1].wrapping_add(b);
    let b = g[1] >> 26;
    g[1] &= 0x3ff_ffff;
    g[2] = h[2].wrapping_add(b);
    let b = g[2] >> 26;
    g[2] &= 0x3ff_ffff;
    g[3] = h[3].wrapping_add(b);
    let b = g[3] >> 26;
    g[3] &= 0x3ff_ffff;
    g[4] = h[4].wrapping_add(b).wrapping_sub(1 << 26);

    // g[4] >> 63 == 1 → underflow → h < p → keep h (mask = 0)
    // g[4] >> 63 == 0 → no underflow → h >= p → select g (mask = all-ones)
    let mask = (g[4] >> 63).wrapping_sub(1);
    h[0] = (h[0] & !mask) | (g[0] & mask);
    h[1] = (h[1] & !mask) | (g[1] & mask);
    h[2] = (h[2] & !mask) | (g[2] & mask);
    h[3] = (h[3] & !mask) | (g[3] & mask);
    h[4] = (h[4] & !mask) | (g[4] & mask);

    // reassemble 128-bit h, then add s (key[16..32] as little-endian u128)
    let h128 = (h[0] as u128)
        | ((h[1] as u128) << 26)
        | ((h[2] as u128) << 52)
        | ((h[3] as u128) << 78)
        | ((h[4] as u128) << 104);
    let s128 = u128::from_le_bytes(key[16..32].try_into().unwrap());
    let tag128 = h128.wrapping_add(s128);
    tag128.to_le_bytes()
}

// ── AEAD MAC input ────────────────────────────────────────────────────────────

fn pad16_len(n: usize) -> usize {
    let r = n % 16;
    if r == 0 {
        0
    } else {
        16 - r
    }
}

fn mac_data(aad: &[u8], ciphertext: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(
        aad.len() + pad16_len(aad.len()) + ciphertext.len() + pad16_len(ciphertext.len()) + 16,
    );
    v.extend_from_slice(aad);
    v.extend(std::iter::repeat_n(0u8, pad16_len(aad.len())));
    v.extend_from_slice(ciphertext);
    v.extend(std::iter::repeat_n(0u8, pad16_len(ciphertext.len())));
    v.extend_from_slice(&(aad.len() as u64).to_le_bytes());
    v.extend_from_slice(&(ciphertext.len() as u64).to_le_bytes());
    v
}

// ── Public AEAD API ───────────────────────────────────────────────────────────

/// AEAD seal. Returns `ciphertext || 16-byte Poly1305 tag`.
pub fn seal(key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    // one-time Poly1305 key from block counter 0
    let mut poly_key = [0u8; 64];
    let block0 = ChaChaState::new(key, nonce, 0).block();
    poly_key.copy_from_slice(&block0);
    let otk: &[u8; 32] = poly_key[..32].try_into().unwrap();

    // encrypt with counter 1
    let mut ct = plaintext.to_vec();
    chacha20_xor(key, nonce, 1, &mut ct);

    // compute tag
    let mac_input = mac_data(aad, &ct);
    let tag = poly1305_mac(otk, &mac_input);

    ct.extend_from_slice(&tag);
    ct
}

/// AEAD open. Constant-time tag verify; returns plaintext on success.
pub fn open(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext_and_tag: &[u8],
) -> Option<Vec<u8>> {
    if ciphertext_and_tag.len() < 16 {
        return None;
    }
    let (ct, received_tag) = ciphertext_and_tag.split_at(ciphertext_and_tag.len() - 16);

    // one-time Poly1305 key
    let block0 = ChaChaState::new(key, nonce, 0).block();
    let otk: &[u8; 32] = block0[..32].try_into().unwrap();

    // compute expected tag
    let mac_input = mac_data(aad, ct);
    let expected_tag = poly1305_mac(otk, &mac_input);

    // constant-time compare
    let diff = expected_tag
        .iter()
        .zip(received_tag.iter())
        .fold(0u8, |acc, (&a, &b)| acc | (a ^ b));
    if diff != 0 {
        return None;
    }

    // decrypt
    let mut plaintext = ct.to_vec();
    chacha20_xor(key, nonce, 1, &mut plaintext);
    Some(plaintext)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn from_hex(s: &str) -> Vec<u8> {
        let s: String = s
            .chars()
            .filter(|c| !c.is_whitespace() && *c != ':')
            .collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn to_hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{:02x}", x)).collect()
    }

    /// RFC 8439 §2.4.2 — ChaCha20 encryption test vector.
    #[test]
    fn chacha20_rfc8439_2_4_2() {
        let key: [u8; 32] = (0x00u8..=0x1fu8).collect::<Vec<_>>().try_into().unwrap();
        let nonce_bytes = from_hex("000000000000004a00000000");
        let nonce: [u8; 12] = nonce_bytes.try_into().unwrap();

        let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let mut ct = plaintext.to_vec();
        chacha20_xor(&key, &nonce, 1, &mut ct);

        // first 16 bytes
        assert_eq!(&to_hex(&ct[..16]), "6e2e359a2568f98041ba0728dd0d6981");

        // full ciphertext from RFC 8439 §2.4.2
        let expected = from_hex(
            "6e2e359a 2568f980 41ba0728 dd0d6981\
             e97e7aec 1d4360c2 0a27afcc fd9fae0b\
             f91b65c5 524733ab 8f593dab cd62b357\
             1639d624 e65152ab 8f530c35 9f0861d8\
             07ca0dbf 500d6a61 56a38e08 8a22b65e\
             52bc514d 16ccf806 818ce91a b7793736\
             5af90bbf 74a35be6 b40b8eed f2785e42\
             874d",
        );
        assert_eq!(ct, expected, "full ChaCha20 ciphertext mismatch");
    }

    /// RFC 8439 §2.5.2 — Poly1305 MAC test vector.
    #[test]
    fn poly1305_rfc8439_2_5_2() {
        let key_bytes =
            from_hex("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b");
        let key: [u8; 32] = key_bytes.try_into().unwrap();
        let msg = b"Cryptographic Forum Research Group";
        let tag = poly1305_mac(&key, msg);
        assert_eq!(to_hex(&tag), "a8061dc1305136c6c22b8baf0c0127a9");
    }

    /// RFC 8439 §2.8.2 — AEAD seal test vector.
    #[test]
    fn aead_seal_rfc8439_2_8_2() {
        let key_bytes: Vec<u8> = (0x80u8..=0x9fu8).collect();
        let key: [u8; 32] = key_bytes.try_into().unwrap();
        let nonce_bytes = from_hex("070000004041424344454647");
        let nonce: [u8; 12] = nonce_bytes.try_into().unwrap();
        let aad = from_hex("50515253c0c1c2c3c4c5c6c7");
        let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";

        let result = seal(&key, &nonce, &aad, plaintext);
        let ct = &result[..result.len() - 16];
        let tag = &result[result.len() - 16..];

        // full ciphertext from RFC §2.8.2
        let expected_ct = from_hex(
            "d31a8d34648e60db7b86afbc53ef7ec2\
             a4aded51296e08fea9e2b5a736ee62d6\
             3dbea45e8ca9671282fafb69da92728b\
             1a71de0a9e060b2905d6a5b67ecd3b36\
             92ddbd7f2d778b8c9803aee328091b58\
             fab324e4fad675945585808b4831d7bc\
             3ff4def08e4b7a9de576d26586cec64b\
             6116",
        );
        assert_eq!(ct, expected_ct.as_slice(), "ciphertext mismatch");
        assert_eq!(to_hex(tag), "1ae10b594f09e26a7e902ecbd0600691");
    }

    /// Round-trip: open(seal(...)) == plaintext.
    #[test]
    fn round_trip() {
        let key = [0x42u8; 32];
        let nonce = [0x24u8; 12];
        let aad = b"header";
        let plaintext = b"hello world, this is a test message";

        let sealed = seal(&key, &nonce, aad, plaintext);
        let opened = open(&key, &nonce, aad, &sealed).expect("open failed");
        assert_eq!(opened, plaintext);
    }

    /// Tamper: flip a tag byte → open returns None.
    #[test]
    fn tamper_detected() {
        let key = [0x11u8; 32];
        let nonce = [0x22u8; 12];
        let aad = b"aad";
        let plaintext = b"secret";

        let mut sealed = seal(&key, &nonce, aad, plaintext);
        // flip last byte of tag
        let last = sealed.len() - 1;
        sealed[last] ^= 0x01;
        assert!(open(&key, &nonce, aad, &sealed).is_none());
    }

    /// Tamper: flip a ciphertext byte → open returns None.
    #[test]
    fn tamper_ciphertext_detected() {
        let key = [0x33u8; 32];
        let nonce = [0x44u8; 12];
        let aad = b"more-aad";
        let plaintext = b"another secret message";

        let mut sealed = seal(&key, &nonce, aad, plaintext);
        sealed[0] ^= 0xff;
        assert!(open(&key, &nonce, aad, &sealed).is_none());
    }
}
