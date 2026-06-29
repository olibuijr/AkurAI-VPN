//! The policy model — ACL tags, principals, routes, gateway modes, and a
//! **fail-closed** ACL evaluator.
//!
//! Authority is always explicit (design doc §"Policy Model"):
//!
//! - Unknown node ⇒ no traffic.
//! - Unknown route ⇒ no install.
//! - Unapproved gateway advertisement ⇒ reject + audit.
//! - Missing ACL ⇒ deny.
//!
//! [`Policy::evaluate`] encodes that default: a flow is allowed only when a
//! rule explicitly permits it.

use crate::cidr::Cidr;
use crate::ids::NodeId;

/// An ACL tag such as `trusted`, `server`, or `gateway`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Tag(pub String);

/// The subject of an ACL rule — who is acting, or what is being reached.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Principal {
    /// An enrolled user, e.g. `oli`.
    User(String),
    /// Everything bearing an ACL tag.
    Tag(Tag),
    /// A specific node.
    Node(NodeId),
}

impl Principal {
    /// Parse a textual ACL principal token: `tag:<name>` (including the
    /// wildcard `tag:*`) or `user:<name>`. Returns `None` for an unrecognized
    /// or empty token so the caller can fail-closed — a token that does not
    /// parse can never grant access. (`Node` principals are not expressed in
    /// the text ACL surface yet.)
    pub fn parse(token: &str) -> Option<Principal> {
        let token = token.trim();
        if let Some(name) = token.strip_prefix("tag:") {
            let name = name.trim();
            (!name.is_empty()).then(|| Principal::Tag(Tag(name.to_string())))
        } else if let Some(name) = token.strip_prefix("user:") {
            let name = name.trim();
            (!name.is_empty()).then(|| Principal::User(name.to_string()))
        } else {
            None
        }
    }
}

/// Does a rule's principal `pattern` match a concrete `candidate` presented by
/// a node or peer? Exact equality, except a tag pattern of `tag:*`
/// (i.e. `Tag("*")`) matches any tag.
fn principal_matches(pattern: &Principal, candidate: &Principal) -> bool {
    match (pattern, candidate) {
        (Principal::Tag(p), Principal::Tag(c)) => p.0 == "*" || p == c,
        _ => pattern == candidate,
    }
}

/// Gateway capabilities. First-class and explicit — nothing is implied, and a
/// node never gains a capability without admin approval.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GatewayMode {
    /// Default: reach other approved overlay devices only.
    InternalMesh,
    /// Advertise a LAN/private subnet sitting behind this node.
    Subnet,
    /// Advertise a default route (full-tunnel exit).
    Exit,
    /// Forward selected public domains/ports to an internal service.
    Ingress,
}

/// A route a node advertises (or is allowed to reach), bound to its origin node
/// and carrying its approval state. Fail-closed: an unapproved route must not
/// be installed on clients.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Route {
    /// The destination prefix.
    pub cidr: Cidr,
    /// The node that advertises / fronts this route.
    pub via: NodeId,
    /// Whether an admin has approved the advertisement.
    pub approved: bool,
}

/// A single ACL rule: `from` is permitted to reach `to`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AclRule {
    /// The originating principal.
    pub from: Principal,
    /// The destination principal.
    pub to: Principal,
}

/// The result of an ACL evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// The flow is explicitly permitted.
    Allow,
    /// The flow is denied (including the fail-closed default).
    Deny,
}

/// An ordered set of ACL rules with a fail-closed default.
#[derive(Debug, Clone, Default)]
pub struct Policy {
    rules: Vec<AclRule>,
}

impl Policy {
    /// An empty policy. Because evaluation is fail-closed, an empty policy
    /// denies everything.
    pub fn new() -> Self {
        Self::default()
    }

    /// Append a permit rule.
    pub fn allow(&mut self, rule: AclRule) {
        self.rules.push(rule);
    }

    /// The rules in declaration order.
    pub fn rules(&self) -> &[AclRule] {
        &self.rules
    }

    /// Evaluate a flow. Returns [`Decision::Allow`] only if a rule explicitly
    /// permits `from → to`; otherwise [`Decision::Deny`] (fail-closed).
    pub fn evaluate(&self, from: &Principal, to: &Principal) -> Decision {
        for rule in &self.rules {
            if &rule.from == from && &rule.to == to {
                return Decision::Allow;
            }
        }
        Decision::Deny
    }

    /// Evaluate a flow where each side presents a SET of principals — a node
    /// and a peer each typically carry several tags (and possibly a user
    /// identity). [`Decision::Allow`] iff some rule permits some
    /// `(from ∈ froms, to ∈ tos)` pair; a rule destination of `tag:*` matches
    /// any tag. Otherwise [`Decision::Deny`] — fail-closed, exactly like
    /// [`evaluate`](Self::evaluate). An empty `froms` (no identity) denies all.
    pub fn evaluate_sets(&self, froms: &[Principal], tos: &[Principal]) -> Decision {
        for rule in &self.rules {
            let from_ok = froms.iter().any(|f| principal_matches(&rule.from, f));
            let to_ok = tos.iter().any(|t| principal_matches(&rule.to, t));
            if from_ok && to_ok {
                return Decision::Allow;
            }
        }
        Decision::Deny
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_policy_denies_by_default() {
        let policy = Policy::new();
        let oli = Principal::User("oli".to_string());
        let server = Principal::Tag(Tag("server".to_string()));
        assert_eq!(policy.evaluate(&oli, &server), Decision::Deny);
    }

    #[test]
    fn explicit_rule_allows_only_the_matching_flow() {
        let oli = Principal::User("oli".to_string());
        let trusted = Principal::Tag(Tag("trusted".to_string()));
        let server = Principal::Tag(Tag("server".to_string()));

        let mut policy = Policy::new();
        policy.allow(AclRule {
            from: oli.clone(),
            to: trusted.clone(),
        });

        assert_eq!(policy.evaluate(&oli, &trusted), Decision::Allow);
        // A different destination is still denied — fail-closed.
        assert_eq!(policy.evaluate(&oli, &server), Decision::Deny);
        assert_eq!(policy.rules().len(), 1);
    }

    #[test]
    fn parses_principal_tokens() {
        assert_eq!(
            Principal::parse("tag:server"),
            Some(Principal::Tag(Tag("server".to_string())))
        );
        assert_eq!(
            Principal::parse("  user:oli "),
            Some(Principal::User("oli".to_string()))
        );
        assert_eq!(
            Principal::parse("tag:*"),
            Some(Principal::Tag(Tag("*".to_string())))
        );
        // Unrecognized / empty tokens fail-closed (cannot grant access).
        assert!(Principal::parse("server").is_none());
        assert!(Principal::parse("tag:").is_none());
        assert!(Principal::parse("").is_none());
    }

    #[test]
    fn evaluate_sets_allows_matching_tag_pair_and_fails_closed() {
        let trusted = Principal::Tag(Tag("trusted".to_string()));
        let server = Principal::Tag(Tag("server".to_string()));
        let other = Principal::Tag(Tag("other".to_string()));
        let mut policy = Policy::new();
        policy.allow(AclRule {
            from: trusted.clone(),
            to: server.clone(),
        });
        let me = [trusted];
        let server_only = [server];
        let other_only = [other];
        // me=[trusted] → peer=[server] is permitted.
        assert_eq!(policy.evaluate_sets(&me, &server_only), Decision::Allow);
        // A peer with a non-matching tag is denied.
        assert_eq!(policy.evaluate_sets(&me, &other_only), Decision::Deny);
        // No source identity at all → deny everything (fail-closed).
        assert_eq!(policy.evaluate_sets(&[], &server_only), Decision::Deny);
    }

    #[test]
    fn evaluate_sets_honours_tag_wildcard() {
        let oli = Principal::User("oli".to_string());
        let mut policy = Policy::new();
        policy.allow(AclRule {
            from: oli.clone(),
            to: Principal::Tag(Tag("*".to_string())),
        });
        let me = [oli];
        // `tag:*` matches any tag on the destination.
        assert_eq!(
            policy.evaluate_sets(&me, &[Principal::Tag(Tag("anything".to_string()))]),
            Decision::Allow
        );
        // …but the wildcard is tag-only: a non-tag destination is not matched.
        assert_eq!(
            policy.evaluate_sets(&me, &[Principal::User("x".to_string())]),
            Decision::Deny
        );
    }
}
