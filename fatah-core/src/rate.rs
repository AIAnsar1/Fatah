use serde::{Deserialize, Serialize};

/// Global rate limit applied across all workers. `None` on
/// [`crate::AttackPlan::rate`] means "no software-side limit" — workers
/// are bounded only by `concurrency`.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct RateLimit {
    /// Maximum attempts per second across the whole engine. Must be > 0.
    pub per_second: u32,
}

impl RateLimit {
    pub fn per_second(rate: u32) -> Option<Self> {
        (rate > 0).then_some(Self { per_second: rate })
    }
}
