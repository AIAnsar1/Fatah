//! SSH password-auth probe using `async-ssh2-tokio`.
//!
//! The high-level client either connects + authenticates or returns an
//! error. We classify any auth-related error as `Failure` and surface
//! everything else (TCP error, kex error, timeout) as `Error(_)`. Host
//! key checking is disabled by default (`ServerCheckMethod::NoCheck`)
//! since we're auditing whether credentials work, not setting up a
//! persistent trust relationship.

use async_ssh2_tokio::{AuthMethod, Client, ServerCheckMethod};
use async_trait::async_trait;
use fatah_core::{
    AttemptContext, AttemptOutcome, CredentialPair, Protocol, ProtocolDescriptor, Result, Target,
};

use crate::registry::ProtoEntry;

const DESCRIPTOR: ProtocolDescriptor = ProtocolDescriptor {
    id: "ssh",
    default_port: 22,
    supports_tls: false,
    summary: "SSH password-auth probe (async-ssh2-tokio)",
};

#[derive(Default)]
pub struct SshProtocol;

#[async_trait]
impl Protocol for SshProtocol {
    fn descriptor(&self) -> ProtocolDescriptor {
        DESCRIPTOR
    }

    async fn attempt(
        &self,
        target: &Target,
        credential: &CredentialPair,
        ctx: &AttemptContext,
    ) -> Result<AttemptOutcome> {
        let login = credential.login_str().unwrap_or("root");
        let auth = AuthMethod::with_password(credential.secret.expose());

        let connect_fut = Client::connect(
            (target.endpoint.host.as_str(), target.endpoint.port),
            login,
            auth,
            ServerCheckMethod::NoCheck,
        );

        match tokio::time::timeout(ctx.timeout, connect_fut).await {
            Ok(Ok(_client)) => Ok(AttemptOutcome::Success),
            Ok(Err(err)) => Ok(classify(&err.to_string())),
            Err(_) => Ok(AttemptOutcome::Error("timeout".into())),
        }
    }
}

/// async-ssh2-tokio's error type is opaque (one variant wrapping
/// `russh::Error`), so classify on the rendered message. This is brittle
/// but keeps us decoupled from the underlying `russh` version.
fn classify(message: &str) -> AttemptOutcome {
    let lower = message.to_ascii_lowercase();
    if lower.contains("authentication") || lower.contains("denied") || lower.contains("no auth") {
        AttemptOutcome::Failure
    } else if lower.contains("timed out") || lower.contains("timeout") {
        AttemptOutcome::Error("timeout".into())
    } else if lower.contains("connection refused") || lower.contains("reset") {
        AttemptOutcome::Error(format!("transport: {message}"))
    } else {
        AttemptOutcome::Error(message.to_owned())
    }
}

inventory::submit! {
    ProtoEntry { factory: || Box::new(SshProtocol) }
}
