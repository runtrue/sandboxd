use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CoreError {
    #[error("invalid {kind} identifier `{value}`")]
    InvalidIdentifier { kind: &'static str, value: String },
    #[error("invalid lifecycle transition from {from} to {to}")]
    InvalidLifecycleTransition { from: String, to: String },
    #[error("invalid sandbox specification: {0}")]
    InvalidSpecification(String),
    #[error("invalid snapshot manifest: {0}")]
    InvalidSnapshot(String),
    #[error("invalid work order: {0}")]
    InvalidWorkOrder(String),
}
