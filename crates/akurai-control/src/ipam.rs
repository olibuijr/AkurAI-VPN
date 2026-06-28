//! Overlay IP allocation (IPAM) — control-plane allocator.
//!
//! Hands each enrolled node a stable, globally-unique overlay IPv4 from the
//! fixed `100.88.0.0/16` range. The address arithmetic lives in
//! [`akurai_common::OverlayIpv4`]; this module owns the *policy*: which index a
//! new node receives, reuse of indices freed by deletion, and backfill of nodes
//! enrolled before allocation existed.
//!
//! Reserved indices: `0` is the network address, `1` is the control plane
//! itself; allocatable node indices therefore start at [`FIRST_NODE_INDEX`].
//!
//! Allocation is pure control-plane bookkeeping — it creates no routes, no TUN
//! device, and has no host-network side effects. Addresses are persisted inside
//! each node's `allowed_ips` (as a `100.88.0.N/32` entry), so no schema change
//! is required.

use std::collections::BTreeSet;
use std::net::Ipv4Addr;

use akurai_common::overlay::OVERLAY_IPV4_NET;
use akurai_common::OverlayIpv4;

use crate::vpn_endpoint::VpnEndpoint;

/// Index `1` is reserved for the control plane (index `0` is the network address).
pub const CONTROL_PLANE_INDEX: u32 = 1;

/// Lowest index an enrolled node may receive (one past the control plane).
pub const FIRST_NODE_INDEX: u32 = CONTROL_PLANE_INDEX + 1;

/// The `/16` host index of an overlay address, e.g. `100.88.0.7` -> `7`.
fn index_of(addr: Ipv4Addr) -> u32 {
    u32::from(addr).wrapping_sub(u32::from(OVERLAY_IPV4_NET))
}

/// Parse a single `allowed_ips` entry as an overlay `/16` host index, tolerating
/// a CIDR suffix (`100.88.0.2/32`). Returns `None` if it is not an overlay address.
fn parse_overlay_index(entry: &str) -> Option<u32> {
    let ip_part = entry.split('/').next().unwrap_or(entry).trim();
    ip_part
        .parse::<Ipv4Addr>()
        .ok()
        .filter(|addr| OverlayIpv4::contains(*addr))
        .map(index_of)
}

/// The overlay `/16` host index carried by an `allowed_ips` list (the first
/// overlay entry), or `None` if the list carries no overlay address.
pub fn overlay_index_of(allowed_ips: &[String]) -> Option<u32> {
    allowed_ips.iter().find_map(|e| parse_overlay_index(e))
}

/// Every overlay index present in an `allowed_ips` list. Normally one, but a
/// legacy/crafted record can carry several — counting all of them prevents a
/// stray index from being silently re-allocated to a second node.
pub fn overlay_indices_of(allowed_ips: &[String]) -> Vec<u32> {
    allowed_ips
        .iter()
        .filter_map(|e| parse_overlay_index(e))
        .collect()
}

/// Every overlay index currently allocated across all endpoints (all entries
/// per endpoint, not just the first).
pub fn used_indices(endpoints: &[VpnEndpoint]) -> BTreeSet<u32> {
    endpoints
        .iter()
        .flat_map(|e| overlay_indices_of(&e.allowed_ips))
        .collect()
}

/// Allocate the lowest free overlay address at or above [`FIRST_NODE_INDEX`].
///
/// Indices freed by node deletion are reused (the scan always returns the
/// smallest gap). Returns `None` only when the `/16` is exhausted.
pub fn allocate(used: &BTreeSet<u32>) -> Option<OverlayIpv4> {
    (FIRST_NODE_INDEX..=OverlayIpv4::MAX_INDEX)
        .find(|idx| !used.contains(idx))
        .and_then(|idx| OverlayIpv4::from_index(idx).ok())
}

/// Choose the overlay address for a newly-enrolling node.
///
/// A caller-supplied index is respected only if it is a valid node index
/// (`>= FIRST_NODE_INDEX`, within the `/16`) and currently free — this rejects
/// reserved indices (`0` network, `1` control plane) and collisions. Otherwise
/// the lowest free address is allocated. Returns `None` only when the pool is
/// exhausted.
pub fn choose_for_enrollment(supplied: Option<u32>, used: &BTreeSet<u32>) -> Option<OverlayIpv4> {
    match supplied {
        Some(idx)
            if (FIRST_NODE_INDEX..=OverlayIpv4::MAX_INDEX).contains(&idx)
                && !used.contains(&idx) =>
        {
            OverlayIpv4::from_index(idx).ok()
        }
        _ => allocate(used),
    }
}

/// Format an overlay address as the `/32` CIDR string stored in `allowed_ips`.
pub fn overlay_cidr(ip: OverlayIpv4) -> String {
    format!("{}/32", ip.addr())
}

/// The bare overlay address string (e.g. `100.88.0.7`) carried by an
/// `allowed_ips` list, if any — for surfacing in API/JSON without the suffix.
pub fn overlay_addr_string(allowed_ips: &[String]) -> Option<String> {
    overlay_index_of(allowed_ips)
        .and_then(|idx| OverlayIpv4::from_index(idx).ok())
        .map(|ip| ip.addr().to_string())
}

/// Assign an overlay IP to every endpoint that lacks one, in place.
///
/// Idempotent: endpoints that already carry a `100.88.*` address are skipped.
/// The `used` set accumulates as it goes, so multiple newly-assigned endpoints
/// in a single pass receive distinct indices. Returns the number changed.
pub fn assign_missing(endpoints: &mut [VpnEndpoint]) -> usize {
    let mut used = used_indices(endpoints);
    let mut changed = 0;
    for e in endpoints.iter_mut() {
        if overlay_index_of(&e.allowed_ips).is_some() {
            continue;
        }
        if let Some(ip) = allocate(&used) {
            used.insert(index_of(ip.addr()));
            e.allowed_ips.insert(0, overlay_cidr(ip));
            changed += 1;
        }
    }
    changed
}

/// One-line status of the IP-allocation subsystem, naming the next free address
/// given the live endpoint set.
pub fn status(endpoints: &[VpnEndpoint]) -> String {
    let used = used_indices(endpoints);
    match allocate(&used) {
        Some(next) => format!(
            "ipam: 100.88.0.0/16 active — {} allocated, next free {} (lowest-free, reused on delete)",
            used.len(),
            next.addr()
        ),
        None => "ipam: 100.88.0.0/16 exhausted".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ep(allowed: &[&str]) -> VpnEndpoint {
        VpnEndpoint {
            id: "id".to_string(),
            name: "n".to_string(),
            public_key: "pk".to_string(),
            endpoint_addr: String::new(),
            allowed_ips: allowed.iter().map(|s| s.to_string()).collect(),
            added_by: "u@example.com".to_string(),
            added_at: 0,
        }
    }

    #[test]
    fn parses_overlay_index_from_cidr() {
        assert_eq!(overlay_index_of(&["100.88.0.7/32".to_string()]), Some(7));
        assert_eq!(overlay_index_of(&["100.88.1.0/32".to_string()]), Some(256));
        assert_eq!(overlay_index_of(&["100.88.0.2".to_string()]), Some(2));
    }

    #[test]
    fn no_overlay_address_yields_none() {
        assert_eq!(overlay_index_of(&[]), None);
        assert_eq!(overlay_index_of(&["0.0.0.0/0".to_string()]), None);
        assert_eq!(overlay_index_of(&["10.0.0.5/32".to_string()]), None);
    }

    #[test]
    fn used_indices_collects_across_endpoints() {
        let eps = vec![
            ep(&["100.88.0.2/32"]),
            ep(&["10.0.0.1/24", "100.88.0.5/32"]),
        ];
        let used = used_indices(&eps);
        assert!(used.contains(&2));
        assert!(used.contains(&5));
        assert_eq!(used.len(), 2);
    }

    #[test]
    fn allocate_skips_reserved_indices() {
        let used = BTreeSet::new();
        let first = allocate(&used).unwrap();
        // First node gets index 2 -> 100.88.0.2 (0 = network, 1 = control plane).
        assert_eq!(first.addr().to_string(), "100.88.0.2");
    }

    #[test]
    fn allocate_reuses_freed_gap() {
        let used: BTreeSet<u32> = [2u32, 4u32].into_iter().collect();
        let next = allocate(&used).unwrap();
        assert_eq!(next.addr().to_string(), "100.88.0.3");
    }

    #[test]
    fn allocate_returns_next_after_contiguous_block() {
        let used: BTreeSet<u32> = [2u32, 3u32, 4u32].into_iter().collect();
        let next = allocate(&used).unwrap();
        assert_eq!(next.addr().to_string(), "100.88.0.5");
    }

    #[test]
    fn assign_missing_fills_and_is_idempotent() {
        let mut eps = vec![ep(&[]), ep(&["100.88.0.9/32"]), ep(&[])];
        let changed = assign_missing(&mut eps);
        assert_eq!(changed, 2);
        // The pre-set endpoint keeps its address.
        assert_eq!(overlay_index_of(&eps[1].allowed_ips), Some(9));
        // The two filled endpoints get distinct, non-colliding indices.
        let a = overlay_index_of(&eps[0].allowed_ips).unwrap();
        let b = overlay_index_of(&eps[2].allowed_ips).unwrap();
        assert_ne!(a, b);
        assert_ne!(a, 9);
        assert_ne!(b, 9);
        assert!(a >= FIRST_NODE_INDEX && b >= FIRST_NODE_INDEX);
        // Second pass changes nothing.
        assert_eq!(assign_missing(&mut eps), 0);
    }

    #[test]
    fn assign_missing_empty_is_safe() {
        let mut eps: Vec<VpnEndpoint> = Vec::new();
        assert_eq!(assign_missing(&mut eps), 0);
    }

    #[test]
    fn overlay_addresses_are_unique_across_a_fill() {
        let mut eps: Vec<VpnEndpoint> = (0..50).map(|_| ep(&[])).collect();
        assign_missing(&mut eps);
        let indices: Vec<u32> = eps
            .iter()
            .map(|e| overlay_index_of(&e.allowed_ips).unwrap())
            .collect();
        let unique: BTreeSet<u32> = indices.iter().copied().collect();
        assert_eq!(indices.len(), unique.len(), "no duplicate overlay indices");
        assert!(unique.iter().all(|&i| i >= FIRST_NODE_INDEX));
    }

    #[test]
    fn status_names_next_free_for_fresh_plane() {
        let s = status(&[]);
        assert!(s.contains("100.88.0.2"), "status names next free: {s}");
        assert!(!s.contains("not implemented"));
    }

    #[test]
    fn used_indices_counts_every_overlay_entry_on_an_endpoint() {
        // A single endpoint carrying two overlay addresses must contribute BOTH
        // indices, so a stray second address can never be re-allocated.
        let eps = vec![ep(&["100.88.0.5/32", "100.88.0.6/32"])];
        let used = used_indices(&eps);
        assert!(used.contains(&5) && used.contains(&6));
        // The next allocation skips both, not just the first.
        assert_eq!(allocate(&used).unwrap().addr().to_string(), "100.88.0.2");
    }

    #[test]
    fn choose_respects_a_free_supplied_index() {
        let used = BTreeSet::new();
        let ip = choose_for_enrollment(Some(7), &used).unwrap();
        assert_eq!(ip.addr().to_string(), "100.88.0.7");
    }

    #[test]
    fn choose_rejects_reserved_indices() {
        let used = BTreeSet::new();
        // Index 0 (network) and 1 (control plane) are never honored; falls back
        // to the lowest free node index, 2.
        assert_eq!(
            choose_for_enrollment(Some(0), &used)
                .unwrap()
                .addr()
                .to_string(),
            "100.88.0.2"
        );
        assert_eq!(
            choose_for_enrollment(Some(1), &used)
                .unwrap()
                .addr()
                .to_string(),
            "100.88.0.2"
        );
    }

    #[test]
    fn choose_reallocates_when_supplied_index_is_taken() {
        let used: BTreeSet<u32> = [2u32, 3u32].into_iter().collect();
        // Supplied index 2 is in use -> allocate the next free (4).
        let ip = choose_for_enrollment(Some(2), &used).unwrap();
        assert_eq!(ip.addr().to_string(), "100.88.0.4");
    }

    #[test]
    fn choose_allocates_when_nothing_supplied() {
        let used: BTreeSet<u32> = [2u32].into_iter().collect();
        let ip = choose_for_enrollment(None, &used).unwrap();
        assert_eq!(ip.addr().to_string(), "100.88.0.3");
    }
}
