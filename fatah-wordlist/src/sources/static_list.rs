use fatah_core::CredentialPair;
use futures::stream;

use crate::{CredentialSource, CredentialStream};

/// In-memory list of pre-built credential pairs. Mostly useful for
/// tests and for trying a known small set of credentials.
pub struct StaticSource {
    pairs: Vec<CredentialPair>,
}

impl StaticSource {
    pub fn new(pairs: Vec<CredentialPair>) -> Self {
        Self { pairs }
    }
}

impl CredentialSource for StaticSource {
    fn build(&self) -> CredentialStream {
        let pairs = self.pairs.clone();
        Box::pin(stream::iter(pairs))
    }

    fn total(&self) -> Option<u64> {
        Some(self.pairs.len() as u64)
    }
}
