//! Credential sources for the attack engine.
//!
//! A [`CredentialSource`] is any async `Stream<Item = CredentialPair>`
//! the engine can pull from. Concrete sources include single static
//! values, line-oriented wordlist files, and cartesian-product combos
//! built from a login list × password list.

#![allow(
    clippy::missing_errors_doc,
    clippy::module_name_repetitions,
    clippy::must_use_candidate
)]

pub mod sources;

use std::pin::Pin;

use fatah_core::CredentialPair;
use futures::Stream;

pub use sources::combo::ComboSource;
pub use sources::file::FileWordlist;
pub use sources::static_list::StaticSource;

/// Boxed credential stream — the canonical type the engine consumes.
pub type CredentialStream = Pin<Box<dyn Stream<Item = CredentialPair> + Send>>;

/// Trait for everything that knows how to materialise itself into a
/// boxed credential stream. Sources are *factories*: calling `build`
/// twice should yield two independent streams (important for retries
/// and for the spray strategy).
pub trait CredentialSource: Send + Sync {
    fn build(&self) -> CredentialStream;

    /// Optional best-effort total. Used by progress reporters; `None`
    /// means "unknown / infinite".
    fn total(&self) -> Option<u64> {
        None
    }
}
