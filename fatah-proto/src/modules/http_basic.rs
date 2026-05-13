//! HTTP Basic-Auth credential probe (RFC 7617).
//!
//! Sends a single GET to the configured URL with `Authorization: Basic`
//! and classifies by status code:
//!   * 2xx / 3xx          → Success (credentials accepted)
//!   * 401 / 403          → Failure
//!   * 429                → RateLimited
//!   * anything else      → Error(<status + reason>)
//!
//! Target options:
//!   * `path`   — request path (defaults to `/`)
//!   * `method` — HTTP method, defaults to `GET`
//!
//! Scheme is `https` when `target.tls`, otherwise `http`.
//! Certificate validation is **not** bypassed by default; set
//! `insecure=true` in target options for self-signed targets.

use async_trait::async_trait;
use fatah_core::{
    AttemptContext, AttemptOutcome, CredentialPair, Protocol, ProtocolDescriptor, Result, Target,
};
use reqwest::Method;

use crate::registry::ProtoEntry;

const DESCRIPTOR: ProtocolDescriptor = ProtocolDescriptor {
    id: "http-basic",
    default_port: 80,
    supports_tls: true,
    summary: "HTTP Basic auth probe (GET with Basic <creds>)",
};

#[derive(Default)]
pub struct HttpBasicProtocol;

#[async_trait]
impl Protocol for HttpBasicProtocol {
    fn descriptor(&self) -> ProtocolDescriptor {
        DESCRIPTOR
    }

    async fn attempt(
        &self,
        target: &Target,
        credential: &CredentialPair,
        ctx: &AttemptContext,
    ) -> Result<AttemptOutcome> {
        let scheme = if target.tls { "https" } else { "http" };
        let path = ctx
            .option("path")
            .or_else(|| target.option("path"))
            .unwrap_or("/");
        let method = ctx
            .option("method")
            .or_else(|| target.option("method"))
            .unwrap_or("GET");
        let insecure = ctx
            .option("insecure")
            .or_else(|| target.option("insecure"))
            .is_some_and(|v| matches!(v, "1" | "true" | "yes"));

        let url = format!(
            "{scheme}://{host}:{port}{path}",
            host = target.endpoint.host,
            port = target.endpoint.port,
            path = if path.starts_with('/') { path.to_owned() } else { format!("/{path}") },
        );

        let client = reqwest::Client::builder()
            .timeout(ctx.timeout)
            .redirect(reqwest::redirect::Policy::none())
            .danger_accept_invalid_certs(insecure)
            .build()
            .map_err(|e| fatah_core::FatahError::Protocol(format!("http client: {e}")))?;

        let method = Method::from_bytes(method.as_bytes())
            .map_err(|e| fatah_core::FatahError::Protocol(format!("method: {e}")))?;

        let req = client
            .request(method, &url)
            .basic_auth(credential.login_str().unwrap_or(""), Some(credential.secret.expose()));

        let resp = match req.send().await {
            Ok(r) => r,
            Err(e) if e.is_timeout() => return Ok(AttemptOutcome::Error("timeout".into())),
            Err(e) => return Ok(AttemptOutcome::Error(format!("send: {e}"))),
        };

        Ok(match resp.status().as_u16() {
            200..=399 => AttemptOutcome::Success,
            401 | 403 => AttemptOutcome::Failure,
            429 => AttemptOutcome::RateLimited,
            code => AttemptOutcome::Error(format!("HTTP {code}")),
        })
    }
}

inventory::submit! {
    ProtoEntry { factory: || Box::new(HttpBasicProtocol) }
}
