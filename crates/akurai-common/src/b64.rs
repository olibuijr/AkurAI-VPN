//! Minimal standard Base64 (RFC 4648) — encode/decode, zero dependencies.
//!
//! Node identities are X25519 public keys exchanged as Base64 text in the
//! control-plane record, the peer map, and the installer. A tiny std-only codec
//! keeps that consistent without linking a crate.

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const PAD: u8 = b'=';

/// Encode bytes to standard Base64 with `=` padding.
pub fn encode(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[(n >> 18 & 0x3f) as usize] as char);
        out.push(ALPHABET[(n >> 12 & 0x3f) as usize] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[(n >> 6 & 0x3f) as usize] as char
        } else {
            PAD as char
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[(n & 0x3f) as usize] as char
        } else {
            PAD as char
        });
    }
    out
}

/// Decode standard Base64. Returns `None` on any invalid character, bad length,
/// or misplaced padding. Whitespace is not tolerated (callers pass trimmed text).
pub fn decode(input: &str) -> Option<Vec<u8>> {
    let bytes = input.as_bytes();
    if bytes.is_empty() || !bytes.len().is_multiple_of(4) {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    for quad in bytes.chunks(4) {
        let mut n: u32 = 0;
        let mut pad = 0;
        for (i, &c) in quad.iter().enumerate() {
            n <<= 6;
            if c == PAD {
                // Padding only allowed in the last one or two positions.
                if i < 2 {
                    return None;
                }
                pad += 1;
            } else {
                let v = sextet(c)?;
                if pad > 0 {
                    return None; // non-pad after pad
                }
                n |= v as u32;
            }
        }
        out.push((n >> 16 & 0xff) as u8);
        if pad < 2 {
            out.push((n >> 8 & 0xff) as u8);
        }
        if pad < 1 {
            out.push((n & 0xff) as u8);
        }
    }
    Some(out)
}

/// Decode exactly `N` bytes (e.g. a 32-byte X25519 key). `None` if the decoded
/// length differs.
pub fn decode_array<const N: usize>(input: &str) -> Option<[u8; N]> {
    let v = decode(input)?;
    if v.len() != N {
        return None;
    }
    let mut a = [0u8; N];
    a.copy_from_slice(&v);
    Some(a)
}

fn sextet(c: u8) -> Option<u8> {
    match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_vectors() {
        assert_eq!(encode(b""), "");
        assert_eq!(encode(b"f"), "Zg==");
        assert_eq!(encode(b"fo"), "Zm8=");
        assert_eq!(encode(b"foo"), "Zm9v");
        assert_eq!(encode(b"foob"), "Zm9vYg==");
        assert_eq!(encode(b"fooba"), "Zm9vYmE=");
        assert_eq!(encode(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn round_trip_all_byte_lengths() {
        for n in 1..=64usize {
            let data: Vec<u8> = (0..n).map(|i| (i * 7 % 256) as u8).collect();
            assert_eq!(decode(&encode(&data)).unwrap(), data, "n={n}");
        }
    }

    #[test]
    fn x25519_key_round_trips_as_array() {
        let key = [0x42u8; 32];
        let s = encode(&key);
        assert_eq!(decode_array::<32>(&s), Some(key));
    }

    #[test]
    fn rejects_garbage() {
        assert_eq!(decode("Zg="), None); // bad length
        assert_eq!(decode("****"), None); // invalid chars
        assert_eq!(decode("Z==="), None); // padding too early
        assert_eq!(decode("Zg=v"), None); // data after pad
        assert_eq!(decode_array::<32>(&encode(b"short")), None); // wrong length
    }
}
