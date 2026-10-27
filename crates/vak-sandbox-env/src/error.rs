use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("toml error: {0}")]
    Toml(#[from] toml::de::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("hash mismatch: expected {expected}, got {got}")]
    HashMismatch { expected: String, got: String },
    #[error("artifact not found: {0}")]
    NotFound(String),
    #[error("invalid spec: {0}")]
    InvalidSpec(String),
    #[error("materialization failed: {0}")]
    Materialize(String),
    #[error("check failed: {0}")]
    Check(String),
}

pub type Result<T> = std::result::Result<T, Error>;
