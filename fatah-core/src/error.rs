use thiserror::Error;

/// Crate-wide result alias.
pub type Result<T> = std::result::Result<T, FatahError>;

/// Top-level error type. Variants are deliberately coarse — concrete
/// protocols wrap their own errors into [`FatahError::Protocol`] with a
/// short, human-readable cause.
#[derive(Debug, Error)]
pub enum FatahError {
    #[error("network i/o: {0}")]
    Io(#[from] std::io::Error),

    #[error("tls: {0}")]
    Tls(String),

    #[error("dns: {0}")]
    Dns(String),

    #[error("protocol: {0}")]
    Protocol(String),

    #[error("auth: {0}")]
    Auth(String),

    #[error("config: {0}")]
    Config(String),

    #[error("storage: {0}")]
    Storage(String),

    #[error("rate-limited by target")]
    RateLimited,

    #[error("operation timed out")]
    Timeout,

    #[error("aborted by user")]
    Aborted,

    #[error("internal: {0}")]
    Internal(String),
}

impl FatahError {
    pub fn protocol(msg: impl Into<String>) -> Self {
        Self::Protocol(msg.into())
    }

    pub fn config(msg: impl Into<String>) -> Self {
        Self::Config(msg.into())
    }

    /// True if the engine should treat the failure as transient and
    /// potentially retry the attempt against the same target/credential.
    pub fn is_transient(&self) -> bool {
        matches!(self, Self::Io(_) | Self::Timeout | Self::RateLimited)
    }
}
