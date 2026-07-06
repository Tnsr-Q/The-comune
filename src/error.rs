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
    #[error("packet HLC node id does not match packet source")]
    NidMismatch,
    #[error("delta length {0} exceeds maximum allowed size")]
    DeltaTooLarge(usize),
    #[error("equivocation detected for {src} at seq {seq}")]
    Equivocation { src: String, seq: u64 },
    #[error("too many pending packets for source")]
    PendingOverflow,
    #[error("packet chain break for {src} at seq {seq}")]
    ChainBreak { src: String, seq: u64 },
}
