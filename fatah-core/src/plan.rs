use std::time::Duration;

use bon::Builder;
use serde::{Deserialize, Serialize};

use crate::rate::RateLimit;
use crate::target::Target;

/// High-level attack strategy. Concrete implementations live in
/// `fatah-attack` / `fatah-spray` and are selected by this discriminator.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum StrategyKind {
    /// Classic brute-force: iterate every (login, password) the source
    /// emits, in order.
    BruteForce,
    /// Password spraying: outer loop is passwords, inner loop is logins,
    /// with a sleep between successive passwords to avoid lockouts.
    Spray {
        #[serde(with = "humantime_serde", default = "default_spray_window")]
        per_password_window: Duration,
    },
}

fn default_spray_window() -> Duration {
    Duration::from_secs(300)
}

impl Default for StrategyKind {
    fn default() -> Self {
        Self::BruteForce
    }
}

/// Declarative description of an attack. Built with [`bon`] for ergonomic
/// fluent construction (`AttackPlan::builder()...build()`) and round-trips
/// through any serde format (TOML/YAML/JSON via `figment`).
#[derive(Debug, Clone, Builder, Serialize, Deserialize)]
pub struct AttackPlan {
    pub target: Target,

    #[builder(default)]
    #[serde(default)]
    pub strategy: StrategyKind,

    /// Concurrent in-flight attempts.
    #[builder(default = 16)]
    #[serde(default = "default_concurrency")]
    pub concurrency: usize,

    /// Per-attempt connect/read timeout.
    #[builder(default = Duration::from_secs(10))]
    #[serde(with = "humantime_serde", default = "default_timeout")]
    pub timeout: Duration,

    /// Optional global rate limit (requests per second across all workers).
    #[serde(default)]
    pub rate: Option<RateLimit>,

    /// Stop the engine after the first successful credential is found.
    #[builder(default = true)]
    #[serde(default = "default_stop_on_first")]
    pub stop_on_first: bool,
}

fn default_concurrency() -> usize {
    16
}
fn default_timeout() -> Duration {
    Duration::from_secs(10)
}
fn default_stop_on_first() -> bool {
    true
}
