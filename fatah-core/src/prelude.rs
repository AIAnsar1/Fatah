//! Bring the most-used types into scope with one glob: `use fatah_core::prelude::*;`.

pub use crate::credential::{Credential, CredentialPair, Secret};
pub use crate::error::{FatahError, Result};
pub use crate::event::EngineEvent;
pub use crate::outcome::{Attempt, AttemptOutcome};
pub use crate::plan::{AttackPlan, StrategyKind};
pub use crate::protocol::{AttemptContext, Protocol, ProtocolDescriptor};
pub use crate::rate::RateLimit;
pub use crate::target::{Endpoint, Target};
