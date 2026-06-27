//! Noise-spec HKDF over HMAC-BLAKE2s (the Noise protocol key schedule).
//!
//! Follows the Noise Protocol Framework spec §4.4:
//! <https://noiseprotocol.org/noise.html#the-handshakestate-object>
//!
//! `temp_key  = HMAC(chaining_key, ikm)`
//! `out1      = HMAC(temp_key, [0x01])`
//! `out2      = HMAC(temp_key, out1 || [0x02])`   (if N >= 2)
//! `out3      = HMAC(temp_key, out2 || [0x03])`   (if N == 3)

use crate::blake2s::hmac;

/// Noise HKDF over HMAC-BLAKE2s.
///
/// Returns `N` 32-byte output blocks (`N` must be 1, 2, or 3).
///
/// * `chaining_key` — 32-byte chaining key from the Noise handshake state.
/// * `ikm`          — input key material (may be empty).
pub fn hkdf<const N: usize>(chaining_key: &[u8; 32], ikm: &[u8]) -> [[u8; 32]; N] {
    assert!(N >= 1, "hkdf: N must be >= 1");
    assert!(N <= 3, "hkdf: N must be <= 3");

    let temp_key = hmac(chaining_key, ikm);

    let out1 = hmac(&temp_key, &[0x01u8]);
    if N == 1 {
        return core::array::from_fn(|i| if i == 0 { out1 } else { [0u8; 32] });
    }

    let mut in2 = [0u8; 33];
    in2[..32].copy_from_slice(&out1);
    in2[32] = 0x02;
    let out2 = hmac(&temp_key, &in2);
    if N == 2 {
        return core::array::from_fn(|i| match i {
            0 => out1,
            1 => out2,
            _ => [0u8; 32],
        });
    }

    let mut in3 = [0u8; 33];
    in3[..32].copy_from_slice(&out2);
    in3[32] = 0x03;
    let out3 = hmac(&temp_key, &in3);
    core::array::from_fn(|i| match i {
        0 => out1,
        1 => out2,
        2 => out3,
        _ => [0u8; 32],
    })
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blake2s::hmac;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn hkdf1_correct_length() {
        let ck = [0u8; 32];
        let ikm = b"test ikm";
        let out = hkdf::<1>(&ck, ikm);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].len(), 32);
    }

    #[test]
    fn hkdf2_correct_length() {
        let ck = [0u8; 32];
        let ikm = b"test ikm";
        let out = hkdf::<2>(&ck, ikm);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].len(), 32);
        assert_eq!(out[1].len(), 32);
    }

    #[test]
    fn hkdf3_correct_length() {
        let ck = [0u8; 32];
        let ikm = b"test ikm";
        let out = hkdf::<3>(&ck, ikm);
        assert_eq!(out.len(), 3);
    }

    #[test]
    fn hkdf2_outputs_differ() {
        let ck = [0xAAu8; 32];
        let ikm = b"differentiation check";
        let out = hkdf::<2>(&ck, ikm);
        assert_ne!(hex(&out[0]), hex(&out[1]), "HKDF out1 and out2 must differ");
    }

    #[test]
    fn hkdf2_deterministic() {
        let ck = [0x11u8; 32];
        let ikm = b"noise handshake";
        let a = hkdf::<2>(&ck, ikm);
        let b = hkdf::<2>(&ck, ikm);
        assert_eq!(hex(&a[0]), hex(&b[0]));
        assert_eq!(hex(&a[1]), hex(&b[1]));
    }

    #[test]
    fn hkdf2_out1_matches_manual_construction() {
        // out1 must equal HMAC(HMAC(ck, ikm), [0x01]).
        let ck = [0x42u8; 32];
        let ikm = b"akurai ikm";
        let out = hkdf::<2>(&ck, ikm);

        let temp_key = hmac(&ck, ikm);
        let manual_out1 = hmac(&temp_key, &[0x01u8]);
        assert_eq!(
            hex(&out[0]),
            hex(&manual_out1),
            "hkdf out1 must equal HMAC(temp, 0x01)"
        );
    }

    #[test]
    fn hkdf2_out2_matches_manual_construction() {
        // out2 must equal HMAC(temp_key, out1 || 0x02).
        let ck = [0x42u8; 32];
        let ikm = b"akurai ikm";
        let out = hkdf::<2>(&ck, ikm);

        let temp_key = hmac(&ck, ikm);
        let out1 = hmac(&temp_key, &[0x01u8]);
        let mut in2 = [0u8; 33];
        in2[..32].copy_from_slice(&out1);
        in2[32] = 0x02;
        let manual_out2 = hmac(&temp_key, &in2);
        assert_eq!(
            hex(&out[1]),
            hex(&manual_out2),
            "hkdf out2 must equal HMAC(temp, out1 || 0x02)"
        );
    }

    #[test]
    fn hkdf3_all_outputs_distinct() {
        let ck = [0xBBu8; 32];
        let ikm = b"triple output";
        let out = hkdf::<3>(&ck, ikm);
        assert_ne!(hex(&out[0]), hex(&out[1]));
        assert_ne!(hex(&out[1]), hex(&out[2]));
        assert_ne!(hex(&out[0]), hex(&out[2]));
    }

    #[test]
    fn hkdf_empty_ikm() {
        // Must not panic; empty IKM is valid in Noise.
        let ck = [0u8; 32];
        let out = hkdf::<2>(&ck, &[]);
        assert_eq!(out.len(), 2);
    }

    #[test]
    fn hkdf1_vs_hkdf2_out1_agrees() {
        // The first output of hkdf::<1> and hkdf::<2> must be identical.
        let ck = [0x77u8; 32];
        let ikm = b"consistency";
        let o1 = hkdf::<1>(&ck, ikm);
        let o2 = hkdf::<2>(&ck, ikm);
        assert_eq!(hex(&o1[0]), hex(&o2[0]));
    }
}
