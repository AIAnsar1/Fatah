use chrono::{DateTime, Utc};
use fatah_core::Attempt;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Persisted view of a successful authentication attempt. Decoupled
/// from [`Attempt`] so storage doesn't have to chase every domain
/// field — the engine emits findings, this is what hits disk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredFinding {
    pub id: Uuid,
    pub target: String,
    pub protocol: String,
    pub login: Option<String>,
    pub secret: String,
    pub at: DateTime<Utc>,
}

impl StoredFinding {
    pub fn from_attempt(a: &Attempt) -> Self {
        Self {
            id: a.id,
            target: a.target.endpoint.to_string(),
            protocol: a.target.protocol.clone(),
            login: a.credential.login_str().map(str::to_owned),
            secret: a.credential.secret.expose().to_owned(),
            at: a.started_at,
        }
    }
}
