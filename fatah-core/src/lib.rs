//! Core domain types and traits for the Fatah credential-auditing engine.
//!
//! This crate defines the *kernel* of the system: errors, value-objects
//! (Target, Credential, Outcome, Attempt), the [`Protocol`] strategy trait
//! every authentication module implements, and the [`AttackPlan`] aggregate
//! that drives an attack. Nothing in this crate depends on a concrete I/O
//! backend — that lives in `fatah-net`, `fatah-database`, etc.

#![allow(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::module_name_repetitions,
    clippy::must_use_candidate
)]

pub mod credential;
pub mod error;
pub mod event;
pub mod outcome;
pub mod plan;
pub mod prelude;
pub mod protocol;
pub mod rate;
pub mod target;

pub use credential::{Credential, CredentialPair, Secret};
pub use error::{FatahError, Result};
pub use event::EngineEvent;
pub use outcome::{Attempt, AttemptOutcome};
pub use plan::{AttackPlan, StrategyKind};
pub use protocol::{AttemptContext, Protocol, ProtocolDescriptor};
pub use rate::RateLimit;
pub use target::{Endpoint, Target};
