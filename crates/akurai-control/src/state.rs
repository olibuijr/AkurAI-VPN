//! Shared application state — sessions and VPN endpoint list.
//!
//! Wrapped in `Arc<Mutex<_>>` so it can be shared across the per-connection
//! threads spawned by the TCP listener.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use crate::auth::SessionStore;
use crate::vpn_endpoint::VpnEndpoint;

/// All mutable runtime state for the control plane.
pub struct AppState {
    /// In-memory session store (keyed by opaque session token).
    pub sessions: SessionStore,
    /// Registered VPN endpoints, mirrored to disk on every write.
    pub endpoints: Vec<VpnEndpoint>,
    /// Pending OIDC `state` nonces — used for CSRF validation on the callback.
    pub pending_states: HashSet<String>,
    /// Per-session CSRF tokens for state-changing dashboard/API requests.
    pub csrf_tokens: HashMap<String, String>,
}

impl AppState {
    pub fn new() -> Self {
        Self {
            sessions: SessionStore::new(),
            endpoints: crate::vpn_endpoint::load(),
            pending_states: HashSet::new(),
            csrf_tokens: HashMap::new(),
        }
    }
}

/// Convenience alias.
pub type SharedState = Arc<Mutex<AppState>>;

/// Create a new, freshly-loaded shared state.
pub fn new_shared() -> SharedState {
    Arc::new(Mutex::new(AppState::new()))
}
