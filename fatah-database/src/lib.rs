//! Storage abstraction for findings and session state.
//!
//! The [`Repository`] trait is the seam — concrete implementations
//! (sled embedded, future SQLite/Postgres) plug in behind it without
//! the rest of the workspace knowing the difference.

#![allow(
    clippy::missing_errors_doc,
    clippy::module_name_repetitions,
    clippy::must_use_candidate
)]

pub mod finding;
pub mod repository;
pub mod sled_repo;

pub use finding::StoredFinding;
pub use repository::Repository;
pub use sled_repo::SledRepository;
