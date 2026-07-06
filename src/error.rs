use thiserror::Error;

pub type Result<T> = std::result::Result<T, AgentZkError>;

#[derive(Debug, Error)]
pub enum AgentZkError {
    #[error("serialization error: {0}")]
    Serialization(String),
    #[error("signature verification failed")]
    BadSignature,
    #[error("packet schema mismatch: expected {expected}, got {got}")]
    SchemaMismatch { expected: String, got: String },
    #[error("invalid detached delta")]
    InvalidDelta,
    #[error("missing detached delta body")]
    MissingDeltaBody,
}
