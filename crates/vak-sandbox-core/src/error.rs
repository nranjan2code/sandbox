use std::path::PathBuf;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("path escapes sandbox root: {0}")]
    PathEscape(String),

    #[error("path not allowed: {0}")]
    PathNotAllowed(String),

    #[error("symlink escape detected: {0}")]
    SymlinkEscape(String),

    #[error("candidate file missing: {0}")]
    MissingFile(PathBuf),

    #[error("candidate changed after review: {0}")]
    CandidateChanged(String),

    #[error("workspace conflict: {0}")]
    Conflict(String),

    #[error("backend not available: {0}")]
    BackendNotAvailable(String),

    #[error("backend error: {0}")]
    Backend(String),

    #[error("promotion journal error: {0}")]
    Journal(String),

    #[error("promotion failed: {0}")]
    Promotion(String),

    #[error("invalid policy: {0}")]
    InvalidPolicy(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
