//! Admin CLI error type.

use std::fmt;

/// Errors surfaced by the admin CLI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdminError {
    /// A control-plane action that is a stub in 0.0.1.
    NotImplemented(&'static str),
    /// A command-line usage problem.
    Usage(String),
}

impl fmt::Display for AdminError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AdminError::NotImplemented(what) => {
                write!(f, "{what} is not implemented in 0.0.1")
            }
            AdminError::Usage(msg) => write!(f, "{msg}"),
        }
    }
}

impl std::error::Error for AdminError {}
