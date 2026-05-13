//! Attack orchestrator. Consumes an [`AttackPlan`] and a credential
//! stream, drives a bounded pool of async workers, fans events out to
//! every registered reporter, and persists a final summary.
//!
//! Design patterns at play:
//! * **Strategy** — caller picks the credential stream (brute / spray /
//!   custom) before handing it to the engine; the engine itself is
//!   strategy-agnostic.
//! * **Observer** — events flow to `Vec<Arc<dyn Reporter>>`.
//! * **Builder** — [`Engine::builder`] (via `bon` indirectly through
//!   chainable methods) for fluent setup.

#![allow(
    clippy::missing_errors_doc,
    clippy::module_name_repetitions,
    clippy::must_use_candidate
)]

pub mod engine;

pub use engine::{Engine, RunSummary};
