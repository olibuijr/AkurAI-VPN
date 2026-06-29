//! A minimal DNS message codec (RFC 1035) — only the subset MagicDNS needs.
//!
//! We parse a single-question query and build a single-answer response. There
//! is no recursion, no additional/authority sections, and the only record type
//! we ever emit is `A`. Everything is pure `std`; malformed input is rejected
//! with `None` rather than panicking.
//!
//! Wire layout (big-endian throughout):
//!
//! ```text
//! Header (12 bytes): ID | FLAGS | QDCOUNT | ANCOUNT | NSCOUNT | ARCOUNT
//! Question:          QNAME (length-prefixed labels, 0x00 terminator) | QTYPE | QCLASS
//! Answer RR:         NAME | TYPE | CLASS | TTL | RDLENGTH | RDATA
//! ```

use std::net::Ipv4Addr;

/// `A` record — host address (IPv4). RFC 1035 §3.2.2.
pub const TYPE_A: u16 = 1;
/// `AAAA` record — host address (IPv6). RFC 3596. We recognise but never serve it.
pub const TYPE_AAAA: u16 = 28;
/// `IN` class — the Internet. RFC 1035 §3.2.4.
pub const CLASS_IN: u16 = 1;

/// `NOERROR` response code (RFC 1035 §4.1.1).
pub const RCODE_NOERROR: u8 = 0;
/// `NXDOMAIN` response code — the queried name does not exist.
pub const RCODE_NXDOMAIN: u8 = 3;

/// Fixed DNS header length in bytes.
const HEADER_LEN: usize = 12;
/// Maximum total length of a domain name (RFC 1035 §2.3.4).
const MAX_NAME_LEN: usize = 255;
/// Maximum length of a single label (RFC 1035 §2.3.4).
const MAX_LABEL_LEN: usize = 63;
/// Top two bits of a length octet set ⇒ compression pointer (RFC 1035 §4.1.4).
const COMPRESSION_MASK: u8 = 0xC0;
/// Recursion-Desired bit inside the 16-bit flags field.
const FLAG_RD: u16 = 0x0100;

/// A parsed DNS query: the transaction id plus the first question.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Query {
    /// Transaction id — echoed verbatim in the response.
    pub id: u16,
    /// The question's QNAME as a dotted name (no trailing dot), e.g. `nodeb.akurai`.
    pub name: String,
    /// QTYPE — [`TYPE_A`], [`TYPE_AAAA`], or any other requested type.
    pub qtype: u16,
    /// QCLASS — normally [`CLASS_IN`].
    pub qclass: u16,
    /// Whether the client set the Recursion-Desired bit (echoed in the response).
    pub recursion_desired: bool,
}

/// Parse a DNS query, returning the id and its first question.
///
/// Returns `None` for any malformed or truncated input (too short, a label that
/// runs past the buffer, a compression pointer in the question, or a missing
/// QTYPE/QCLASS). Never panics.
pub fn parse_query(buf: &[u8]) -> Option<Query> {
    if buf.len() < HEADER_LEN {
        return None;
    }
    let id = u16::from_be_bytes([buf[0], buf[1]]);
    let flags = u16::from_be_bytes([buf[2], buf[3]]);
    let qdcount = u16::from_be_bytes([buf[4], buf[5]]);
    if qdcount == 0 {
        return None;
    }

    let mut pos = HEADER_LEN;
    let mut name = String::new();
    loop {
        let len = *buf.get(pos)?;
        pos += 1;
        if len == 0 {
            break;
        }
        // The question name is never compressed; reject pointers outright.
        if len & COMPRESSION_MASK != 0 {
            return None;
        }
        let len = len as usize;
        let end = pos.checked_add(len)?;
        let label = buf.get(pos..end)?;
        if !name.is_empty() {
            name.push('.');
        }
        for &b in label {
            name.push(char::from(b));
        }
        if name.len() > MAX_NAME_LEN {
            return None;
        }
        pos = end;
    }

    let qtype = u16::from_be_bytes([*buf.get(pos)?, *buf.get(pos + 1)?]);
    let qclass = u16::from_be_bytes([*buf.get(pos + 2)?, *buf.get(pos + 3)?]);

    Some(Query {
        id,
        name,
        qtype,
        qclass,
        recursion_desired: flags & FLAG_RD != 0,
    })
}

/// Build a standard query for `name`/`qtype` (RD set). Handy for clients/tests.
pub fn build_query(id: u16, name: &str, qtype: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(32);
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&FLAG_RD.to_be_bytes()); // standard query, recursion desired
    out.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
    encode_name(name, &mut out);
    out.extend_from_slice(&qtype.to_be_bytes());
    out.extend_from_slice(&CLASS_IN.to_be_bytes());
    out
}

/// Build a response to `query`.
///
/// - `A` query with a resolved IP ⇒ one answer RR (NAME = compression pointer to
///   the question, TYPE=A, CLASS=IN, the given `ttl`, RDLENGTH=4, RDATA=octets),
///   RCODE=NOERROR.
/// - `A` query with no match ⇒ NXDOMAIN, no answers.
/// - `AAAA` (or any other type) for a name that resolves ⇒ NODATA (NOERROR, no
///   answer RR) — the name exists but has no record of that type.
/// - any type for a name that does not resolve ⇒ NXDOMAIN.
///
/// The response always sets QR=1 and AA=1 and echoes the id, question, and the
/// client's Recursion-Desired bit.
pub fn build_response(query: &Query, resolved: Option<Ipv4Addr>, ttl: u32) -> Vec<u8> {
    let (answer, rcode) = match (query.qtype, resolved) {
        (TYPE_A, Some(ip)) => (Some(ip), RCODE_NOERROR),
        (TYPE_A, None) => (None, RCODE_NXDOMAIN),
        // We hold no record of this type; the name exists ⇒ NODATA, else NXDOMAIN.
        (_, Some(_)) => (None, RCODE_NOERROR),
        (_, None) => (None, RCODE_NXDOMAIN),
    };
    let ancount: u16 = if answer.is_some() { 1 } else { 0 };

    let mut out = Vec::with_capacity(64);
    // Header.
    out.extend_from_slice(&query.id.to_be_bytes());
    let mut flags: u16 = 0x8400; // QR=1, AA=1
    if query.recursion_desired {
        flags |= FLAG_RD;
    }
    flags |= u16::from(rcode);
    out.extend_from_slice(&flags.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    out.extend_from_slice(&ancount.to_be_bytes()); // ANCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT

    // Question (echoed). The answer's NAME pointer below targets offset 12.
    encode_name(&query.name, &mut out);
    out.extend_from_slice(&query.qtype.to_be_bytes());
    out.extend_from_slice(&query.qclass.to_be_bytes());

    // Answer RR, when present.
    if let Some(ip) = answer {
        out.extend_from_slice(&[0xC0, 0x0C]); // NAME = pointer to the question (offset 12)
        out.extend_from_slice(&TYPE_A.to_be_bytes());
        out.extend_from_slice(&CLASS_IN.to_be_bytes());
        out.extend_from_slice(&ttl.to_be_bytes());
        out.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH
        out.extend_from_slice(&ip.octets()); // RDATA
    }
    out
}

/// Encode a dotted name as length-prefixed labels terminated by a zero octet.
/// Empty labels are skipped and over-long labels are clamped to 63 bytes; our
/// names come from a parsed query (already validated) or short host labels.
fn encode_name(name: &str, out: &mut Vec<u8>) {
    for label in name.split('.') {
        if label.is_empty() {
            continue;
        }
        let bytes = label.as_bytes();
        let len = bytes.len().min(MAX_LABEL_LEN);
        out.push(len as u8);
        out.extend_from_slice(&bytes[..len]);
    }
    out.push(0);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn round_trip_query_for_nodeb_akurai() {
        let buf = build_query(0x1234, "nodeb.akurai", TYPE_A);
        let q = parse_query(&buf).expect("query parses");
        assert_eq!(q.id, 0x1234);
        assert_eq!(q.name, "nodeb.akurai");
        assert_eq!(q.qtype, TYPE_A);
        assert_eq!(q.qclass, CLASS_IN);
        assert!(q.recursion_desired);
    }

    #[test]
    fn builds_a_response_carrying_the_ip() {
        let q = parse_query(&build_query(0x1, "nodeb.akurai", TYPE_A)).unwrap();
        let ip = Ipv4Addr::new(100, 88, 0, 3);
        let resp = build_response(&q, Some(ip), 60);

        assert_eq!(u16::from_be_bytes([resp[0], resp[1]]), 0x1); // id echoed
        assert_eq!(resp[2] & 0x80, 0x80); // QR=1
        assert_eq!(resp[2] & 0x04, 0x04); // AA=1
        assert_eq!(resp[3] & 0x0f, RCODE_NOERROR);
        assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 1); // ANCOUNT=1

        // The question still parses cleanly back out of the response.
        let echoed = parse_query(&resp).unwrap();
        assert_eq!(echoed.name, "nodeb.akurai");

        // The answer NAME is the compression pointer 0xC00C and the RDATA is the IP.
        let ans = resp.len() - 16; // ptr(2)+type(2)+class(2)+ttl(4)+rdlen(2)+rdata(4)
        assert_eq!(&resp[ans..ans + 2], &[0xC0, 0x0C]);
        assert!(resp.ends_with(&ip.octets()));
        assert_eq!(answer_ip(&resp), Some(ip));
    }

    #[test]
    fn nxdomain_when_no_match() {
        let q = parse_query(&build_query(7, "ghost.akurai", TYPE_A)).unwrap();
        let resp = build_response(&q, None, 60);
        assert_eq!(resp[3] & 0x0f, RCODE_NXDOMAIN);
        assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 0); // no answers
    }

    #[test]
    fn aaaa_query_is_nodata_when_name_exists() {
        let q = parse_query(&build_query(9, "nodeb.akurai", TYPE_AAAA)).unwrap();
        let resp = build_response(&q, Some(Ipv4Addr::new(100, 88, 0, 3)), 60);
        assert_eq!(resp[3] & 0x0f, RCODE_NOERROR); // NODATA, not an error
        assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 0); // but no answer RR
    }

    #[test]
    fn rejects_truncated_buffers() {
        assert!(parse_query(&[]).is_none());
        assert!(parse_query(&[0u8; 5]).is_none()); // shorter than the header
                                                   // A buffer whose label runs off the end, with QTYPE/QCLASS chopped too.
        let mut buf = build_query(1, "nodeb.akurai", TYPE_A);
        buf.truncate(buf.len() - 6);
        assert!(parse_query(&buf).is_none());
    }

    // Test-only: extract the single A record's IPv4 from a response.
    fn answer_ip(resp: &[u8]) -> Option<Ipv4Addr> {
        let mut pos = HEADER_LEN;
        loop {
            let len = *resp.get(pos)? as usize;
            pos += 1;
            if len == 0 {
                break;
            }
            pos += len;
        }
        pos += 4; // QTYPE + QCLASS
                  // Answer RR: NAME(2) TYPE(2) CLASS(2) TTL(4) RDLENGTH(2) RDATA(4)
        let rdata = resp.get(pos + 12..pos + 16)?;
        Some(Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3]))
    }
}
