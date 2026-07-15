//! Shared application state — sessions and VPN endpoint list.
//!
//! Wrapped in `Arc<Mutex<_>>` so it can be shared across the per-connection
//! threads spawned by the TCP listener.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use crate::auth::SessionStore;
use crate::heartbeat::Heartbeat;
use crate::vpn_endpoint::VpnEndpoint;

/// All mutable runtime state for the control plane.
pub struct AppState {
    /// Persistent session store (keyed by opaque session token).
    /// Sessions survive restarts: loaded from disk at startup, written
    /// atomically on every login/logout. CSRF tokens are stored inside
    /// each session record rather than in a separate map.
    pub sessions: SessionStore,
    /// Registered VPN endpoints, mirrored to disk on every write.
    pub endpoints: Vec<VpnEndpoint>,
    /// Pending OIDC `state` nonces — used for CSRF validation on the callback.
    pub pending_states: HashSet<String>,
    /// Per-node heartbeat liveness, keyed by node id. In-memory only — a node's
    /// liveness is re-established by its next heartbeat after a restart.
    pub heartbeats: HashMap<String, Heartbeat>,
}

impl AppState {
    pub fn new() -> Self {
        // Backfill: assign an overlay IP to any node enrolled before allocation
        // existed, then persist so the on-disk record surfaces the address.
        let mut endpoints = crate::vpn_endpoint::load();
        let assigned = crate::ipam::assign_missing(&mut endpoints);
        if assigned > 0 {
            if let Err(e) = crate::vpn_endpoint::save(&endpoints) {
                eprintln!("akurai-control: failed to persist backfilled overlay IPs: {e}");
            }
        }

        // Backfill: assign a durable node token to any endpoint enrolled before
        // token authentication existed. Persisted so nodes can bootstrap their
        // token on the next restart without a new OIDC login.
        let mut tokens_assigned = 0usize;
        for ep in &mut endpoints {
            if ep.node_token.is_empty() {
                ep.node_token = crate::vpn_endpoint::generate_node_token();
                tokens_assigned += 1;
            }
        }
        if tokens_assigned > 0 {
            if let Err(e) = crate::vpn_endpoint::save(&endpoints) {
                eprintln!("akurai-control: failed to persist backfilled node tokens: {e}");
            }
        }

        Self {
            sessions: SessionStore::load(),
            endpoints,
            pending_states: HashSet::new(),
            heartbeats: HashMap::new(),
        }
    }
}

/// Convenience alias.
pub type SharedState = Arc<Mutex<AppState>>;

/// Create a new, freshly-loaded shared state.
pub fn new_shared() -> SharedState {
    Arc::new(Mutex::new(AppState::new()))
}

/// Create isolated in-memory state for tests. Tests must not load or mutate the
/// process working directory's persistent endpoint registry.
#[cfg(test)]
pub fn new_test_shared() -> SharedState {
    Arc::new(Mutex::new(AppState {
        sessions: SessionStore::new(),
        endpoints: Vec::new(),
        pending_states: HashSet::new(),
        heartbeats: HashMap::new(),
    }))
}
