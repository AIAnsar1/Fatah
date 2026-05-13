use std::collections::BTreeMap;
use std::time::Duration;

use async_trait::async_trait;

use crate::credential::CredentialPair;
use crate::error::Result;
use crate::outcome::AttemptOutcome;
use crate::target::Target;

/// Static metadata describing a protocol module. Returned by every
/// [`Protocol`] implementation and used by the registry/CLI to list
/// supported services and their defaults.
#[derive(Debug, Clone, Copy)]
pub struct ProtocolDescriptor {
    /// Stable identifier (e.g. `"ftp"`, `"ssh"`). Matches [`Target::protocol`].
    pub id: &'static str,
    /// Default TCP/UDP port.
    pub default_port: u16,
    /// Whether the module supports TLS-wrapped transport.
    pub supports_tls: bool,
    /// Short, single-line description.
    pub summary: &'static str,
}

/// Per-attempt context — anything the engine wants to hand to a module
/// that isn't intrinsic to the target itself. Lives in core so modules
/// don't need to depend on `fatah-attack`.
#[derive(Debug, Clone)]
pub struct AttemptContext {
    pub timeout: Duration,
    pub options: BTreeMap<String, String>,
}

impl AttemptContext {
    pub fn new(timeout: Duration) -> Self {
        Self {
            timeout,
            options: BTreeMap::new(),
        }
    }

    pub fn with_options(mut self, options: BTreeMap<String, String>) -> Self {
        self.options = options;
        self
    }

    pub fn option(&self, key: &str) -> Option<&str> {
        self.options.get(key).map(String::as_str)
    }
}

/// The Strategy that every authentication module implements.
///
/// `attempt` must return `Ok(AttemptOutcome::Error(_))` for transient,
/// non-fatal protocol errors (so the engine reports them per-attempt and
/// keeps going) and only `Err(_)` for outright bugs / unrecoverable state
/// that should propagate.
#[async_trait]
pub trait Protocol: Send + Sync + 'static {
    fn descriptor(&self) -> ProtocolDescriptor;

    async fn attempt(
        &self,
        target: &Target,
        credential: &CredentialPair,
        ctx: &AttemptContext,
    ) -> Result<AttemptOutcome>;
}
