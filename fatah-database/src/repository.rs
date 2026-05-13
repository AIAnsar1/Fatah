use async_trait::async_trait;
use fatah_core::Result;
use uuid::Uuid;

use crate::finding::StoredFinding;

/// Persistence boundary. Implementations must be safe to share across
/// tasks (`Send + Sync`). All methods are async so blocking backends
/// can spawn-blocking internally without polluting their callers.
#[async_trait]
pub trait Repository: Send + Sync {
    async fn save_finding(&self, finding: &StoredFinding) -> Result<()>;
    async fn list_findings(&self) -> Result<Vec<StoredFinding>>;

    async fn save_session(&self, id: Uuid, payload: Vec<u8>) -> Result<()>;
    async fn load_session(&self, id: Uuid) -> Result<Option<Vec<u8>>>;
}
