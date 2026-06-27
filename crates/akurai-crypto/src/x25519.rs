//! Curve25519 X25519 ECDH (RFC 7748), implemented from scratch over
//! GF(2^255 - 19) in pure `std` with no `unsafe`.
//!
//! Field elements are five `u64` limbs in radix 2^51
//! (`x = l0 + l1·2^51 + l2·2^102 + l3·2^153 + l4·2^204`); products are
//! accumulated in `u128`. The Montgomery ladder runs the identical sequence of
//! field operations every iteration and uses a constant-time conditional swap
//! (`cswap`), so control flow and memory access never depend on secret bits.
//!
//! Verified in-crate against the official RFC 7748 §5.2 / §6.1 test vectors.

/// 51-bit limb mask.
const MASK51: u64 = (1u64 << 51) - 1;

/// A field element mod p = 2^255 - 19, as five radix-2^51 limbs.
type Fe = [u64; 5];

const FE_ZERO: Fe = [0, 0, 0, 0, 0];
const FE_ONE: Fe = [1, 0, 0, 0, 0];

/// Load 8 bytes little-endian into a `u64`.
#[inline]
fn load64_le(b: &[u8]) -> u64 {
    (b[0] as u64)
        | ((b[1] as u64) << 8)
        | ((b[2] as u64) << 16)
        | ((b[3] as u64) << 24)
        | ((b[4] as u64) << 32)
        | ((b[5] as u64) << 40)
        | ((b[6] as u64) << 48)
        | ((b[7] as u64) << 56)
}

/// Field addition (no reduction; limbs stay bounded for the next mul/square).
#[inline]
fn fadd(a: &Fe, b: &Fe) -> Fe {
    [
        a[0] + b[0],
        a[1] + b[1],
        a[2] + b[2],
        a[3] + b[3],
        a[4] + b[4],
    ]
}

/// Field subtraction. Adds 2·p (≡ 0 mod p) before subtracting to avoid
/// borrow/underflow; the result stays bounded for the next mul/square.
#[inline]
fn fsub(a: &Fe, b: &Fe) -> Fe {
    // 2·p in radix 2^51: [2^52 - 38, 2^52 - 2, 2^52 - 2, 2^52 - 2, 2^52 - 2].
    [
        (a[0] + 0xF_FFFF_FFFF_FFDA) - b[0],
        (a[1] + 0xF_FFFF_FFFF_FFFE) - b[1],
        (a[2] + 0xF_FFFF_FFFF_FFFE) - b[2],
        (a[3] + 0xF_FFFF_FFFF_FFFE) - b[3],
        (a[4] + 0xF_FFFF_FFFF_FFFE) - b[4],
    ]
}

/// Carry-reduce five 128-bit accumulators down to 51-bit limbs, folding the
/// 2^255 overflow back in via the `·19` reduction identity.
#[inline]
fn carry_reduce(r0: u128, r1: u128, r2: u128, r3: u128, r4: u128) -> Fe {
    let mask = MASK51 as u128;

    let c0 = r0 >> 51;
    let r0 = r0 & mask;
    let r1 = r1 + c0;

    let c1 = r1 >> 51;
    let r1 = r1 & mask;
    let r2 = r2 + c1;

    let c2 = r2 >> 51;
    let r2 = r2 & mask;
    let r3 = r3 + c2;

    let c3 = r3 >> 51;
    let r3 = r3 & mask;
    let r4 = r4 + c3;

    let c4 = r4 >> 51;
    let r4 = r4 & mask;
    let r0 = r0 + 19 * c4;

    let c = r0 >> 51;
    let r0 = r0 & mask;
    let r1 = r1 + c;

    [r0 as u64, r1 as u64, r2 as u64, r3 as u64, r4 as u64]
}

/// Field multiplication mod p = 2^255 - 19 (schoolbook with 19-folding).
#[inline]
fn fmul(a: &Fe, b: &Fe) -> Fe {
    let a0 = a[0] as u128;
    let a1 = a[1] as u128;
    let a2 = a[2] as u128;
    let a3 = a[3] as u128;
    let a4 = a[4] as u128;
    let b0 = b[0] as u128;
    let b1 = b[1] as u128;
    let b2 = b[2] as u128;
    let b3 = b[3] as u128;
    let b4 = b[4] as u128;

    // Limbs that "wrap past" 2^255 are multiplied by 19 (the reduction factor).
    let a1_19 = 19 * a1;
    let a2_19 = 19 * a2;
    let a3_19 = 19 * a3;
    let a4_19 = 19 * a4;

    let r0 = a0 * b0 + a1_19 * b4 + a2_19 * b3 + a3_19 * b2 + a4_19 * b1;
    let r1 = a0 * b1 + a1 * b0 + a2_19 * b4 + a3_19 * b3 + a4_19 * b2;
    let r2 = a0 * b2 + a1 * b1 + a2 * b0 + a3_19 * b4 + a4_19 * b3;
    let r3 = a0 * b3 + a1 * b2 + a2 * b1 + a3 * b0 + a4_19 * b4;
    let r4 = a0 * b4 + a1 * b3 + a2 * b2 + a3 * b1 + a4 * b0;

    carry_reduce(r0, r1, r2, r3, r4)
}

/// Field squaring.
#[inline]
fn fsquare(a: &Fe) -> Fe {
    fmul(a, a)
}

/// Multiply by the curve constant a24 = 121665.
#[inline]
fn fmul121665(a: &Fe) -> Fe {
    const M: u128 = 121665;
    let r0 = a[0] as u128 * M;
    let r1 = a[1] as u128 * M;
    let r2 = a[2] as u128 * M;
    let r3 = a[3] as u128 * M;
    let r4 = a[4] as u128 * M;
    carry_reduce(r0, r1, r2, r3, r4)
}

/// Light carry propagation over 64-bit limbs (inputs < 2^64).
#[inline]
fn carry_propagate(v: &Fe) -> Fe {
    let c0 = v[0] >> 51;
    let c1 = v[1] >> 51;
    let c2 = v[2] >> 51;
    let c3 = v[3] >> 51;
    let c4 = v[4] >> 51;
    [
        (v[0] & MASK51) + c4 * 19,
        (v[1] & MASK51) + c0,
        (v[2] & MASK51) + c1,
        (v[3] & MASK51) + c2,
        (v[4] & MASK51) + c3,
    ]
}

/// Fully reduce to the canonical representative in `[0, p)`.
fn reduce_canonical(v: &Fe) -> Fe {
    let t = carry_propagate(v);
    let (mut l0, mut l1, mut l2, mut l3, mut l4) = (t[0], t[1], t[2], t[3], t[4]);

    // c = 1 iff t >= p (i.e. t + 19 overflows 2^255), else 0.
    let mut c = (l0 + 19) >> 51;
    c = (l1 + c) >> 51;
    c = (l2 + c) >> 51;
    c = (l3 + c) >> 51;
    c = (l4 + c) >> 51;

    l0 += 19 * c;
    l1 += l0 >> 51;
    l0 &= MASK51;
    l2 += l1 >> 51;
    l1 &= MASK51;
    l3 += l2 >> 51;
    l2 &= MASK51;
    l4 += l3 >> 51;
    l3 &= MASK51;
    l4 &= MASK51; // also drops the 2^255 bit

    [l0, l1, l2, l3, l4]
}

/// Modular inverse: z^(p-2) = z^(2^255 - 21) via the ref10 addition chain.
fn finvert(z: &Fe) -> Fe {
    let z2 = fsquare(z); // z^2
    let t = fsquare(&z2); // z^4
    let t = fsquare(&t); // z^8
    let z9 = fmul(&t, z); // z^9
    let z11 = fmul(&z9, &z2); // z^11
    let t = fsquare(&z11); // z^22
    let z2_5_0 = fmul(&t, &z9); // z^(2^5 - 1)

    let mut t = fsquare(&z2_5_0);
    for _ in 0..4 {
        t = fsquare(&t);
    }
    let z2_10_0 = fmul(&t, &z2_5_0); // z^(2^10 - 1)

    let mut t = fsquare(&z2_10_0);
    for _ in 0..9 {
        t = fsquare(&t);
    }
    let z2_20_0 = fmul(&t, &z2_10_0); // z^(2^20 - 1)

    let mut t = fsquare(&z2_20_0);
    for _ in 0..19 {
        t = fsquare(&t);
    }
    let z2_40_0 = fmul(&t, &z2_20_0); // z^(2^40 - 1)

    let mut t = fsquare(&z2_40_0);
    for _ in 0..9 {
        t = fsquare(&t);
    }
    let z2_50_0 = fmul(&t, &z2_10_0); // z^(2^50 - 1)

    let mut t = fsquare(&z2_50_0);
    for _ in 0..49 {
        t = fsquare(&t);
    }
    let z2_100_0 = fmul(&t, &z2_50_0); // z^(2^100 - 1)

    let mut t = fsquare(&z2_100_0);
    for _ in 0..99 {
        t = fsquare(&t);
    }
    let z2_200_0 = fmul(&t, &z2_100_0); // z^(2^200 - 1)

    let mut t = fsquare(&z2_200_0);
    for _ in 0..49 {
        t = fsquare(&t);
    }
    let t = fmul(&t, &z2_50_0); // z^(2^250 - 1)

    let mut t = fsquare(&t);
    for _ in 0..4 {
        t = fsquare(&t);
    }
    fmul(&t, &z11) // z^(2^255 - 21) = z^(p-2)
}

/// Constant-time conditional swap of two field elements when `swap == 1`.
#[inline]
fn cswap(swap: u64, a: &mut Fe, b: &mut Fe) {
    let mask = 0u64.wrapping_sub(swap & 1); // 0x0000… or 0xFFFF…
    let mut i = 0;
    while i < 5 {
        let t = mask & (a[i] ^ b[i]);
        a[i] ^= t;
        b[i] ^= t;
        i += 1;
    }
}

/// `decodeUCoordinate` + `decodeLittleEndian` (RFC 7748): mask the high bit of
/// the u-coordinate, then pack into 51-bit limbs.
fn decode_u(u: &[u8; 32]) -> Fe {
    let mut t = *u;
    t[31] &= 0x7f; // mask bit 255 of the u-coordinate
    [
        load64_le(&t[0..8]) & MASK51,
        (load64_le(&t[6..14]) >> 3) & MASK51,
        (load64_le(&t[12..20]) >> 6) & MASK51,
        (load64_le(&t[19..27]) >> 1) & MASK51,
        (load64_le(&t[24..32]) >> 12) & MASK51,
    ]
}

/// `decodeScalar25519` (RFC 7748): clamp the scalar.
fn decode_scalar(scalar: &[u8; 32]) -> [u8; 32] {
    let mut k = *scalar;
    k[0] &= 248; // clear bits 0, 1, 2
    k[31] &= 127; // clear bit 255
    k[31] |= 64; // set bit 254
    k
}

/// Encode a field element as 32 bytes little-endian (canonical form).
fn encode(v: &Fe) -> [u8; 32] {
    let l = reduce_canonical(v);
    let mut out = [0u8; 32];
    for (i, &limb) in l.iter().enumerate() {
        let bit_offset = i * 51;
        let shifted = (limb as u128) << (bit_offset % 8);
        let bytes = shifted.to_le_bytes();
        let byte_start = bit_offset / 8;
        for (j, &byte) in bytes.iter().enumerate().take(8) {
            let off = byte_start + j;
            if off < 32 {
                out[off] |= byte;
            }
        }
    }
    out
}

/// The Montgomery ladder (RFC 7748 §5): compute x2/z2 = scalar · (u, _).
fn ladder(scalar: &[u8; 32], u: &Fe) -> Fe {
    let x1 = *u;
    let mut x2 = FE_ONE;
    let mut z2 = FE_ZERO;
    let mut x3 = *u;
    let mut z3 = FE_ONE;
    let mut swap: u64 = 0;

    for t in (0..=254usize).rev() {
        let bit = ((scalar[t >> 3] >> (t & 7)) & 1) as u64;
        swap ^= bit;
        cswap(swap, &mut x2, &mut x3);
        cswap(swap, &mut z2, &mut z3);
        swap = bit;

        let a = fadd(&x2, &z2);
        let aa = fsquare(&a);
        let b = fsub(&x2, &z2);
        let bb = fsquare(&b);
        let e = fsub(&aa, &bb);
        let c = fadd(&x3, &z3);
        let d = fsub(&x3, &z3);
        let da = fmul(&d, &a);
        let cb = fmul(&c, &b);
        x3 = fsquare(&fadd(&da, &cb));
        z3 = fmul(&x1, &fsquare(&fsub(&da, &cb)));
        x2 = fmul(&aa, &bb);
        z2 = fmul(&e, &fadd(&aa, &fmul121665(&e)));
    }

    cswap(swap, &mut x2, &mut x3);
    cswap(swap, &mut z2, &mut z3);

    fmul(&x2, &finvert(&z2))
}

/// X25519 scalar multiplication. Clamps `scalar` per RFC 7748 internally.
pub fn x25519(scalar: &[u8; 32], u: &[u8; 32]) -> [u8; 32] {
    let k = decode_scalar(scalar);
    let u_fe = decode_u(u);
    encode(&ladder(&k, &u_fe))
}

/// Public key = X25519(secret, basepoint=9).
pub fn public_key(secret: &[u8; 32]) -> [u8; 32] {
    let mut basepoint = [0u8; 32];
    basepoint[0] = 9;
    x25519(secret, &basepoint)
}

/// ECDH shared secret = X25519(secret, peer_public).
pub fn shared_secret(secret: &[u8; 32], peer_public: &[u8; 32]) -> [u8; 32] {
    x25519(secret, peer_public)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_val(c: u8) -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            _ => panic!("invalid hex digit"),
        }
    }

    fn hex_decode(s: &str) -> [u8; 32] {
        let bytes = s.as_bytes();
        assert_eq!(bytes.len(), 64, "expected 32-byte hex string");
        let mut out = [0u8; 32];
        let mut i = 0;
        while i < 32 {
            out[i] = (hex_val(bytes[2 * i]) << 4) | hex_val(bytes[2 * i + 1]);
            i += 1;
        }
        out
    }

    #[test]
    fn rfc7748_x25519_vector1() {
        let k = hex_decode("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
        let u = hex_decode("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
        let want = hex_decode("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552");
        assert_eq!(x25519(&k, &u), want);
    }

    #[test]
    fn rfc7748_x25519_vector2() {
        let k = hex_decode("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d");
        let u = hex_decode("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493");
        let want = hex_decode("95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957");
        assert_eq!(x25519(&k, &u), want);
    }

    #[test]
    fn rfc7748_x25519_iterated() {
        let mut k = [0u8; 32];
        k[0] = 9;
        let mut u = k;
        for i in 1..=1000 {
            let out = x25519(&k, &u);
            u = k;
            k = out;
            if i == 1 {
                assert_eq!(
                    k,
                    hex_decode("422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079")
                );
            }
        }
        assert_eq!(
            k,
            hex_decode("684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51")
        );
    }

    #[test]
    fn rfc7748_x25519_diffie_hellman() {
        let alice_secret =
            hex_decode("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        let bob_secret =
            hex_decode("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");

        let alice_public = public_key(&alice_secret);
        let bob_public = public_key(&bob_secret);
        assert_eq!(
            alice_public,
            hex_decode("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
        );
        assert_eq!(
            bob_public,
            hex_decode("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
        );

        let shared = hex_decode("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
        assert_eq!(shared_secret(&alice_secret, &bob_public), shared);
        assert_eq!(shared_secret(&bob_secret, &alice_public), shared);
    }
}
