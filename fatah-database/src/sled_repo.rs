use std::path::Path;
use std::sync::Arc;

use async_trait::async_trait;
use fatah_core::{FatahError, Result};
use sled::Db;
use uuid::Uuid;

use crate::finding::StoredFinding;
use crate::repository::Repository;

const FINDINGS_TREE: &str = "findings";
const SESSIONS_TREE: &str = "sessions";

// Pass-by-value is required: this is used as `Fn(E) -> _` in `.map_err`,
// which moves the error into the closure.
#[allow(clippy::needless_pass_by_value)]
fn storage_err(e: impl ToString) -> FatahError {
    FatahError::Storage(e.to_string())
}

/// Embedded `sled` repository. Cheap to clone (Arc inside).
#[derive(Clone)]
pub struct SledRepository {
    db: Arc<Db>,
}

impl SledRepository {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let db = sled::open(path).map_err(storage_err)?;
        Ok(Self { db: Arc::new(db) })
    }
}

#[async_trait]
impl Repository for SledRepository {
    async fn save_finding(&self, finding: &StoredFinding) -> Result<()> {
        let db = self.db.clone();
        let key = finding.id.as_bytes().to_vec();
        let bytes = serde_json::to_vec(finding).map_err(storage_err)?;
        tokio::task::spawn_blocking(move || {
            let tree = db.open_tree(FINDINGS_TREE).map_err(storage_err)?;
            tree.insert(key, bytes).map_err(storage_err)?;
            tree.flush().map_err(storage_err)?;
            Ok::<_, FatahError>(())
        })
        .await
        .map_err(storage_err)?
    }

    async fn list_findings(&self) -> Result<Vec<StoredFinding>> {
        let db = self.db.clone();
        tokio::task::spawn_blocking(move || {
            let tree = db.open_tree(FINDINGS_TREE).map_err(storage_err)?;
            let mut out = Vec::new();
            for kv in &tree {
                let (_k, v) = kv.map_err(storage_err)?;
                let f: StoredFinding = serde_json::from_slice(&v).map_err(storage_err)?;
                out.push(f);
            }
            Ok::<_, FatahError>(out)
        })
        .await
        .map_err(storage_err)?
    }

    async fn save_session(&self, id: Uuid, payload: Vec<u8>) -> Result<()> {
        let db = self.db.clone();
        let key = id.as_bytes().to_vec();
        tokio::task::spawn_blocking(move || {
            let tree = db.open_tree(SESSIONS_TREE).map_err(storage_err)?;
            tree.insert(key, payload).map_err(storage_err)?;
            tree.flush().map_err(storage_err)?;
            Ok::<_, FatahError>(())
        })
        .await
        .map_err(storage_err)?
    }

    async fn load_session(&self, id: Uuid) -> Result<Option<Vec<u8>>> {
        let db = self.db.clone();
        let key = id.as_bytes().to_vec();
        tokio::task::spawn_blocking(move || {
            let tree = db.open_tree(SESSIONS_TREE).map_err(storage_err)?;
            let val = tree.get(key).map_err(storage_err)?;
            Ok::<_, FatahError>(val.map(|v| v.to_vec()))
        })
        .await
        .map_err(storage_err)?
    }
}
