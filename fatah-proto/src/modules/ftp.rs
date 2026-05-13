//! Plain-FTP credential check (RFC 959).
//!
//! Wire flow per attempt:
//!     S: 220 <banner>
//!     C: USER <login>
//!     S: 331 need password    | 230 already logged in | 530 rejected
//!     C: PASS <secret>
//!     S: 230 success          | 530 failure           | 421/etc error
//!     C: QUIT
//!
//! `230` -> Success, `530` -> Failure, anything else -> Error(_) with the
//! raw response line attached. Per-attempt timeout from
//! [`AttemptContext::timeout`] applies to each read/write segment.

use async_trait::async_trait;
use fatah_core::{
    AttemptContext, AttemptOutcome, CredentialPair, FatahError, Protocol, ProtocolDescriptor,
    Result, Target,
};
use fatah_net::{LineStream, connect};

use crate::registry::ProtoEntry;

const DESCRIPTOR: ProtocolDescriptor = ProtocolDescriptor {
    id: "ftp",
    default_port: 21,
    supports_tls: false,
    summary: "RFC 959 FTP USER/PASS login probe",
};

#[derive(Default)]
pub struct FtpProtocol;

#[async_trait]
impl Protocol for FtpProtocol {
    fn descriptor(&self) -> ProtocolDescriptor {
        DESCRIPTOR
    }

    async fn attempt(
        &self,
        target: &Target,
        credential: &CredentialPair,
        ctx: &AttemptContext,
    ) -> Result<AttemptOutcome> {
        let stream = connect(&target.endpoint, ctx.timeout).await?;
        let mut conn = LineStream::new(stream);

        let banner = conn.read_line(ctx.timeout).await?;
        if !banner.starts_with("220") {
            return Ok(AttemptOutcome::Error(format!(
                "unexpected banner: {banner}"
            )));
        }

        let login = credential.login_str().unwrap_or("anonymous");
        conn.write_line(&format!("USER {login}"), ctx.timeout)
            .await?;
        let user_resp = conn.read_line(ctx.timeout).await?;
        match classify_code(&user_resp) {
            Some(230) => {
                let _ = conn.write_line("QUIT", ctx.timeout).await;
                return Ok(AttemptOutcome::Success);
            }
            Some(331) => { /* server asks for PASS */ }
            Some(530) => return Ok(AttemptOutcome::Failure),
            Some(421) => return Ok(AttemptOutcome::RateLimited),
            _ => {
                return Ok(AttemptOutcome::Error(format!("USER: {user_resp}")));
            }
        }

        conn.write_line(&format!("PASS {}", credential.secret.expose()), ctx.timeout)
            .await?;
        let pass_resp = conn.read_line(ctx.timeout).await?;
        let _ = conn.write_line("QUIT", ctx.timeout).await;

        Ok(match classify_code(&pass_resp) {
            Some(230) => AttemptOutcome::Success,
            Some(530) => AttemptOutcome::Failure,
            Some(421) => AttemptOutcome::RateLimited,
            _ => AttemptOutcome::Error(format!("PASS: {pass_resp}")),
        })
    }
}

fn classify_code(line: &str) -> Option<u16> {
    line.split_ascii_whitespace()
        .next()
        .and_then(|c| c.parse().ok())
}

/// Silence unused-import lint for `FatahError` while keeping the
/// import in case future variants are emitted from this module.
const _: fn() = || {
    let _ = std::marker::PhantomData::<FatahError>;
};

inventory::submit! {
    ProtoEntry { factory: || Box::new(FtpProtocol) }
}
