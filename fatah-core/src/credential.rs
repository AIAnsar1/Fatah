use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Single login identifier (username, email, etc.). Some protocols don't
/// need it (e.g. SNMPv1 community strings, Redis without ACL); represent
/// that by leaving the login `None` in [`CredentialPair`].
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Credential(pub String);

impl<S: Into<String>> From<S> for Credential {
    fn from(s: S) -> Self {
        Self(s.into())
    }
}

/// A secret value (password, token, key material). Stored in a wrapper
/// that zeroises on drop and never reveals itself in `Debug`/`Display`.
#[derive(Clone, Zeroize, ZeroizeOnDrop, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Secret(String);

impl Secret {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    /// Borrow the inner secret. Callers must avoid logging the result.
    pub fn expose(&self) -> &str {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Secret(***)")
    }
}

impl<S: Into<String>> From<S> for Secret {
    fn from(s: S) -> Self {
        Self::new(s)
    }
}

/// A (login, secret) tuple emitted by a credential source and consumed by
/// a [`crate::Protocol`]. `login` is optional — some protocols accept a
/// secret without a user, and some attacks (e.g. user enumeration) flip
/// the relationship.
#[derive(Debug, Clone)]
pub struct CredentialPair {
    pub login: Option<Credential>,
    pub secret: Secret,
}

impl CredentialPair {
    pub fn new(login: Option<impl Into<Credential>>, secret: impl Into<Secret>) -> Self {
        Self {
            login: login.map(Into::into),
            secret: secret.into(),
        }
    }

    pub fn with_login(login: impl Into<Credential>, secret: impl Into<Secret>) -> Self {
        Self {
            login: Some(login.into()),
            secret: secret.into(),
        }
    }

    pub fn login_str(&self) -> Option<&str> {
        self.login.as_ref().map(|c| c.0.as_str())
    }
}
