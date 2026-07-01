//! Fine-grained ACL enforcement for the data path — a **fail-closed** tag
//! policy layered on top of network-level peer membership.
//!
//! Network membership (the peer map) answers *"is this peer reachable at all?"*.
//! The ACL answers the finer *"is THIS node permitted to send to that peer?"*.
//! It is purely additive and opt-in:
//!
//! - **No ACL file** ⇒ [`Acl`] is absent and the data plane preserves today's
//!   behavior: any peer in the map is reachable (pure membership).
//! - **An ACL file exists** ⇒ it is enforced. Every outbound flow is evaluated
//!   `this-node → routing-peer` against [`akurai_common::Policy`]; a denied flow
//!   is dropped before any handshake or send. Because the policy evaluator is
//!   fail-closed, an enabled ACL with no matching rule (or a node that declares
//!   no identity via `--my-tags`) reaches nothing.
//!
//! Tailscale-style: this node carries principals (tags, and optionally a user),
//! each peer carries tags, and a rule `tag:X -> tag:Y` permits `X → Y`; the
//! default is deny.

use std::path::Path;

use akurai_common::{AclRule, Decision, Policy, Principal};

use crate::peers::{Peer, PeerTable};

/// A loaded, enforceable ACL: the [`Policy`] plus THIS node's principals (the
/// `from` side of every evaluation). Its mere presence means "enforce"; absence
/// (an `Option::None` at the call site) means "allow all reachable peers".
pub struct Acl {
    policy: Policy,
    my_principals: Vec<Principal>,
}

impl Acl {
    /// Build from an already-parsed policy and this node's principals.
    pub fn new(policy: Policy, my_principals: Vec<Principal>) -> Self {
        Self {
            policy,
            my_principals,
        }
    }

    /// Load an ACL file (see [`parse_acl`]) and bind this node's principals.
    /// A missing/unreadable file yields an empty policy — which, being
    /// fail-closed, denies everything; the caller only constructs an [`Acl`]
    /// when the file exists, so that case does not regress membership.
    pub fn load(path: &Path, my_principals: Vec<Principal>) -> Self {
        let content = std::fs::read_to_string(path).unwrap_or_default();
        Self::new(parse_acl(&content), my_principals)
    }

    /// May THIS node send to `peer`? Fail-closed: permitted only when a rule
    /// allows `this-node → one-of-the-peer's-tags` (with `tag:*` matching any
    /// tag). An untagged peer is reachable only via a `tag:*` rule.
    pub fn permits(&self, peer: &Peer) -> bool {
        let tos = PeerTable::peer_principals(peer);
        self.policy.evaluate_sets(&self.my_principals, &tos) == Decision::Allow
    }
}

/// Parse an ACL config: one rule per line, `allow <from> -> <to>` (the leading
/// `allow` verb is optional and forward-compatible). `<from>`/`<to>` are
/// principal tokens — `tag:<name>`, the wildcard `tag:*`, or `user:<name>`.
/// Blank lines and `#` comments are ignored, and any line that does not parse
/// is skipped: a dropped rule can only ever remove access, never grant it
/// (fail-closed).
pub fn parse_acl(content: &str) -> Policy {
    let mut policy = Policy::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(rule) = parse_acl_line(line) {
            policy.allow(rule);
        }
    }
    policy
}

/// Parse one `allow <from> -> <to>` rule line. `None` ⇒ skip (fail-closed).
fn parse_acl_line(line: &str) -> Option<AclRule> {
    let body = line
        .strip_prefix("allow")
        .map(str::trim_start)
        .unwrap_or(line);
    let (from_s, to_s) = body.split_once("->")?;
    let from = Principal::parse(from_s.trim())?;
    let to = Principal::parse(to_s.trim())?;
    Some(AclRule { from, to })
}

/// Parse a `--my-tags` / `my_tags` value: comma-separated principal tokens that
/// describe THIS node (`tag:a,tag:b`; a `user:oli` token is accepted too).
/// Unrecognized tokens are skipped.
pub fn parse_my_principals(s: &str) -> Vec<Principal> {
    s.split(',')
        .filter_map(|t| Principal::parse(t.trim()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use akurai_common::Tag;
    use std::net::Ipv4Addr;

    fn peer(name: &str, tags: &[&str]) -> Peer {
        Peer {
            overlay_ip: Ipv4Addr::new(100, 88, 0, 9),
            public_key: [0u8; 32],
            name: name.into(),
            endpoint: None,
            advertised: vec![],
            tags: tags.iter().map(|t| Tag((*t).to_string())).collect(),
        }
    }

    #[test]
    fn parses_allow_rules_and_skips_junk() {
        let policy = parse_acl(
            "# comment\n\
             allow tag:trusted -> tag:server\n\
             allow user:oli -> tag:*\n\
             this is not a rule\n",
        );
        assert_eq!(policy.rules().len(), 2);
    }

    #[test]
    fn permits_allowed_and_denies_others_fail_closed() {
        let acl = Acl::new(
            parse_acl("allow tag:trusted -> tag:server\n"),
            parse_my_principals("tag:trusted"),
        );
        assert!(acl.permits(&peer("srv", &["server"])));
        assert!(!acl.permits(&peer("ws", &["workstation"])));
        // An untagged peer is denied (no matching rule).
        assert!(!acl.permits(&peer("untagged", &[])));
    }

    #[test]
    fn wildcard_destination_allows_any_tagged_peer() {
        let acl = Acl::new(
            parse_acl("allow user:oli -> tag:*\n"),
            parse_my_principals("user:oli"),
        );
        assert!(acl.permits(&peer("anything", &["whatever"])));
    }

    #[test]
    fn enabled_acl_with_no_node_identity_denies_all() {
        // ACL turned on but this node declares no principals → reaches nothing.
        let acl = Acl::new(parse_acl("allow tag:trusted -> tag:server\n"), vec![]);
        assert!(!acl.permits(&peer("srv", &["server"])));
    }
}
