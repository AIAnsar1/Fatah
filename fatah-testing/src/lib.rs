//! Test utilities shared across the workspace.
//!
//! In particular a [`MockProtocol`] that returns a scripted outcome
//! without touching the network — handy for engine-level tests and
//! examples.

#![allow(clippy::missing_errors_doc, clippy::module_name_repetitions)]

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use fatah_core::{
    AttemptContext, AttemptOutcome, CredentialPair, Protocol, ProtocolDescriptor, Result, Target,
};

/// Predictable protocol stub. Marks any pair whose secret matches
/// `expected_secret` as success, everything else as failure, and counts
/// total attempts.
pub struct MockProtocol {
    pub expected_login: Option<String>,
    pub expected_secret: String,
    pub attempts: Arc<AtomicU64>,
}

impl MockProtocol {
    pub fn new(expected_secret: impl Into<String>) -> Self {
        Self {
            expected_login: None,
            expected_secret: expected_secret.into(),
            attempts: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn with_login(mut self, login: impl Into<String>) -> Self {
        self.expected_login = Some(login.into());
        self
    }
}

#[async_trait]
impl Protocol for MockProtocol {
    fn descriptor(&self) -> ProtocolDescriptor {
        ProtocolDescriptor {
            id: "mock",
            default_port: 0,
            supports_tls: false,
            summary: "in-memory test stub",
        }
    }

    async fn attempt(
        &self,
        _target: &Target,
        cred: &CredentialPair,
        _ctx: &AttemptContext,
    ) -> Result<AttemptOutcome> {
        self.attempts.fetch_add(1, Ordering::Relaxed);
        let login_ok = self
            .expected_login
            .as_deref()
            .map_or(true, |l| cred.login_str() == Some(l));
        let secret_ok = cred.secret.expose() == self.expected_secret;
        Ok(if login_ok && secret_ok {
            AttemptOutcome::Success
        } else {
            AttemptOutcome::Failure
        })
    }
}
