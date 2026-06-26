//! Node daemon error type.

use std::fmt;

/// Errors surfaced by the node daemon. In 0.0.1 the data-plane operations are
/// all [`NodeError::NotImplemented`]; argument problems are
/// [`NodeError::Usage`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeError {
    /// A data-plane operation that is deliberately a stub in 0.0.1.
    NotImplemented(&'static str),
    /// A command-line usage problem.
    Usage(String),
}

impl fmt::Display for NodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NodeError::NotImplemented(what) => {
                write!(f, "{what} is not implemented in 0.0.1")
            }
            NodeError::Usage(msg) => write!(f, "{msg}"),
        }
    }
}

impl std::error::Error for NodeError {}
