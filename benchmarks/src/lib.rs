//! Shared scaffolding for the criterion bench crate. The benches live
//! under `benches/` and pull helpers from here so we don't duplicate
//! credential / engine setup across cases.

use std::sync::Arc;

use async_trait::async_trait;
use fatah_core::{
    AttemptContext, AttemptOutcome, Credential, CredentialPair, Endpoint, Protocol,
    ProtocolDescriptor, Result, Secret, Target,
};
use fatah_wordlist::{CredentialSource, StaticSource};

/// Build a static credential source of `n` pairs.
pub fn static_pairs(n: usize) -> StaticSource {
    StaticSource::new(
        (0..n)
            .map(|i| {
                CredentialPair::with_login(
                    Credential::from(format!("user{i}")),
                    Secret::new(format!("pw{i}")),
                )
            })
            .collect(),
    )
}

/// In-process protocol that completes immediately. Used to isolate
/// engine overhead from network/protocol cost in throughput benches.
pub struct NoopProtocol;

#[async_trait]
impl Protocol for NoopProtocol {
    fn descriptor(&self) -> ProtocolDescriptor {
        ProtocolDescriptor {
            id: "bench-noop",
            default_port: 0,
            supports_tls: false,
            summary: "no-op bench protocol",
        }
    }

    async fn attempt(
        &self,
        _t: &Target,
        _c: &CredentialPair,
        _x: &AttemptContext,
    ) -> Result<AttemptOutcome> {
        Ok(AttemptOutcome::Failure)
    }
}

pub fn bench_target() -> Target {
    Target::new(Endpoint::new("127.0.0.1", 0), "bench-noop")
}

/// Drain a source into a Vec, returning total pairs seen.
pub async fn drain<S: CredentialSource + ?Sized>(source: &S) -> usize {
    use futures::StreamExt;
    let mut s = source.build();
    let mut n = 0usize;
    while s.next().await.is_some() {
        n += 1;
    }
    n
}

/// Convert a Vec<Arc<T>> into Vec<Arc<dyn Reporter>> in one line for
/// terser bench setup.
pub fn reporters() -> Vec<Arc<dyn fatah_report::Reporter>> {
    Vec::new()
}
