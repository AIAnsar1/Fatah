//! Output sinks for engine events (Observer pattern).
//!
//! The engine emits [`EngineEvent`] values; reporters consume them.
//! Multiple reporters can be active simultaneously — the engine
//! broadcasts every event to every reporter in registration order.

#![allow(
    clippy::missing_errors_doc,
    clippy::module_name_repetitions,
    clippy::must_use_candidate
)]

pub mod console;
pub mod jsonl;

use async_trait::async_trait;
use fatah_core::EngineEvent;

pub use console::ConsoleReporter;
pub use jsonl::JsonlReporter;

/// Receives every event the engine emits. Implementations must be
/// `Send + Sync` (typically wrapped in `Arc<dyn Reporter>`).
#[async_trait]
pub trait Reporter: Send + Sync {
    async fn on_event(&self, event: &EngineEvent);
}
