//! Session bookkeeping: a small, serialisable progress record the engine
//! checkpoints into the repository so an interrupted attack can resume.
//!
//! Kept deliberately simple — we persist the *cursor* (how many pairs
//! have been consumed from the credential source) plus plan metadata.
//! Each [`fatah_database::Repository`] implementation can hold sessions
//! without knowing anything about attack internals.

#![allow(
    clippy::missing_errors_doc,
    clippy::module_name_repetitions,
    clippy::must_use_candidate
)]

use chrono::{DateTime, Utc};
use fatah_core::{FatahError, Result, Target};
use fatah_database::Repository;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionState {
    pub id: Uuid,
    pub target: Target,
    pub tried: u64,
    pub found: usize,
    pub started_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl SessionState {
    pub fn new(target: Target) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            target,
            tried: 0,
            found: 0,
            started_at: now,
            updated_at: now,
        }
    }

    pub fn touch(&mut self) {
        self.updated_at = Utc::now();
    }
}

/// Persist a session through any [`Repository`].
pub async fn save<R: Repository + ?Sized>(repo: &R, state: &SessionState) -> Result<()> {
    let bytes = serde_json::to_vec(state).map_err(|e| FatahError::Storage(e.to_string()))?;
    repo.save_session(state.id, bytes).await
}

/// Load a previously persisted session by id, if it exists.
pub async fn load<R: Repository + ?Sized>(repo: &R, id: Uuid) -> Result<Option<SessionState>> {
    let Some(bytes) = repo.load_session(id).await? else {
        return Ok(None);
    };
    let state = serde_json::from_slice(&bytes).map_err(|e| FatahError::Storage(e.to_string()))?;
    Ok(Some(state))
}
