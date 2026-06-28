//! Node daemon error type.

use std::fmt;

/// Errors surfaced by the node daemon. In 0.0.1 the data-plane operations are
/// all [`NodeError::NotImplemented`]; argument problems are
/// [`NodeError::Usage`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeError {
    /// Filesystem or process I/O failed.
    Io(String),
    /// A command-line usage problem.
    Usage(String),
}

impl fmt::Display for NodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NodeError::Io(msg) => write!(f, "{msg}"),
            NodeError::Usage(msg) => write!(f, "{msg}"),
        }
    }
}

impl std::error::Error for NodeError {}

impl From<std::io::Error> for NodeError {
    fn from(value: std::io::Error) -> Self {
        NodeError::Io(value.to_string())
    }
}
