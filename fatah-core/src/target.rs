use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// A host/port pair. Host is kept as a string so DNS resolution can be
/// deferred to the transport layer (and so IPv6 literals survive
/// round-tripping through config).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Endpoint {
    pub host: String,
    pub port: u16,
}

impl Endpoint {
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        Self {
            host: host.into(),
            port,
        }
    }
}

impl std::fmt::Display for Endpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.host.contains(':') {
            write!(f, "[{}]:{}", self.host, self.port)
        } else {
            write!(f, "{}:{}", self.host, self.port)
        }
    }
}

/// An attack target: where to connect, which protocol to speak, optional
/// TLS wrap, and protocol-specific options (paths, realms, DBs, etc.).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Target {
    pub endpoint: Endpoint,
    /// Stable protocol identifier matching [`Protocol::descriptor().id`].
    pub protocol: String,
    #[serde(default)]
    pub tls: bool,
    /// Free-form protocol options (e.g. `path=/login`, `realm=corp`).
    #[serde(default)]
    pub options: BTreeMap<String, String>,
}

impl Target {
    pub fn new(endpoint: Endpoint, protocol: impl Into<String>) -> Self {
        Self {
            endpoint,
            protocol: protocol.into(),
            tls: false,
            options: BTreeMap::new(),
        }
    }

    pub fn with_tls(mut self, tls: bool) -> Self {
        self.tls = tls;
        self
    }

    pub fn with_option(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.options.insert(key.into(), value.into());
        self
    }

    pub fn option(&self, key: &str) -> Option<&str> {
        self.options.get(key).map(String::as_str)
    }
}
