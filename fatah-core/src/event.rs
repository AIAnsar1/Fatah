use uuid::Uuid;

use crate::outcome::Attempt;

/// Events emitted by the attack engine. Subscribed to by reporters
/// (Observer pattern) — see `fatah-report`.
#[derive(Debug, Clone)]
pub enum EngineEvent {
    /// Engine has started running a plan.
    Started { plan_id: Uuid },
    /// A single attempt has finished (success or not).
    AttemptCompleted(Attempt),
    /// Working credentials were discovered.
    Found(Attempt),
    /// Periodic progress tick.
    Progress { tried: u64, total: Option<u64> },
    /// Engine finished. `found` is the count of successful attempts.
    Finished { tried: u64, found: usize },
    /// Non-fatal engine-level error.
    Warning(String),
}
