use std::time::Duration;

use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::credential::CredentialPair;
use crate::target::Target;

/// Outcome of a single authentication attempt. Protocols MUST classify
/// every outcome into one of these — surfacing raw I/O errors as
/// `Error` rather than propagating them through `Result` lets the engine
/// keep going and report per-attempt failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttemptOutcome {
    /// Credentials authenticated successfully.
    Success,
    /// Server explicitly rejected the credentials.
    Failure,
    /// Account exists but is locked / disabled — distinct from `Failure`
    /// because the same credential against the same account won't recover.
    Locked,
    /// Server throttled us. Caller should back off.
    RateLimited,
    /// Transient or protocol-level failure with a short description.
    Error(String),
}

impl AttemptOutcome {
    pub fn is_success(&self) -> bool {
        matches!(self, Self::Success)
    }

    pub fn is_terminal_failure(&self) -> bool {
        matches!(self, Self::Failure | Self::Locked)
    }
}

/// A finished attempt, ready to be reported and persisted.
#[derive(Debug, Clone)]
pub struct Attempt {
    pub id: Uuid,
    pub target: Target,
    pub credential: CredentialPair,
    pub outcome: AttemptOutcome,
    pub started_at: DateTime<Utc>,
    pub elapsed: Duration,
}

impl Attempt {
    pub fn new(
        target: Target,
        credential: CredentialPair,
        outcome: AttemptOutcome,
        started_at: DateTime<Utc>,
        elapsed: Duration,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            target,
            credential,
            outcome,
            started_at,
            elapsed,
        }
    }
}
