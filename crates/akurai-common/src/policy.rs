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
}
