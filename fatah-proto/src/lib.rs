//! Protocol registry and built-in modules.
//!
//! Every protocol module — built-in or external — registers itself with
//! the global [`Registry`] via the [`inventory`] crate. The engine never
//! enumerates protocols by name; it asks the registry to construct one
//! from the [`Target::protocol`](fatah_core::Target::protocol) string.
//!
//! Adding a protocol from a third-party crate is one struct + one
//! `inventory::submit!` (or one `#[fatah_macros::fatah_proto]` attribute).

#![allow(
    clippy::missing_errors_doc,
    clippy::module_name_repetitions,
    clippy::must_use_candidate
)]

pub mod modules;
pub mod registry;

pub use registry::{ProtoEntry, Registry};

/// Internal re-exports the `fatah_macros::fatah_proto` attribute needs
/// in scope at the call site. Not part of the public API.
#[doc(hidden)]
pub mod __private {
    pub use inventory;
}
