//! Error types for the injection subsystem.

use std::path::PathBuf;

/// Top-level error type for all injection operations.
#[derive(Debug, thiserror::Error)]
pub enum InjectError {
    #[error("target database not found: {path}")]
    DatabaseNotFound { path: PathBuf },

    #[error("target database is locked (browser may be running): {path}")]
    DatabaseLocked { path: PathBuf },

    #[error("SQLite error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error("schema mismatch in {database}: expected {expected}, found {found}")]
    SchemaMismatch {
        database: String,
        expected: String,
        found: String,
    },

    #[error("failed to deserialize artifact: {0}")]
    Deserialization(#[from] serde_json::Error),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("verification failed: {reason}")]
    VerificationFailed { reason: String },

    #[error("rollback failed: {reason}")]
    RollbackFailed { reason: String },

    #[error("unsupported target: {description}")]
    UnsupportedTarget { description: String },

    #[error("unsupported strategy {strategy} for target {target}")]
    UnsupportedStrategy { strategy: String, target: String },

    #[error("backup failed for {path}: {reason}")]
    BackupFailed { path: PathBuf, reason: String },

    #[error("artifact contains no injectable records")]
    EmptyArtifact,

    #[error("sanitization failed: found marker '{marker}' in output")]
    SanitizationFailed { marker: String },

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("{0}")]
    Other(String),
}

/// Convenience alias used throughout the injection crates.
pub type Result<T> = std::result::Result<T, InjectError>;
