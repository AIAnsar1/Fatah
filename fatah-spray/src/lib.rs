//! Password-spraying credential source.
//!
//! Inverts the usual brute-force order: for every password, iterate
//! over every login and then sleep `per_password_window` before moving
//! to the next password. That avoids per-account lockouts on services
//! with login-attempt thresholds.

#![allow(
    clippy::missing_errors_doc,
    clippy::module_name_repetitions,
    clippy::must_use_candidate
)]

use std::path::PathBuf;
use std::time::Duration;

use fatah_core::{Credential, CredentialPair, Secret};
use fatah_wordlist::{CredentialSource, CredentialStream};
use futures::FutureExt;
use futures::stream::{self, StreamExt};
use tokio::fs;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::time::sleep;

pub struct SpraySource {
    pub logins: PathBuf,
    pub passwords: PathBuf,
    pub per_password_window: Duration,
}

impl SpraySource {
    pub fn new(
        logins: impl Into<PathBuf>,
        passwords: impl Into<PathBuf>,
        per_password_window: Duration,
    ) -> Self {
        Self {
            logins: logins.into(),
            passwords: passwords.into(),
            per_password_window,
        }
    }
}

async fn read_lines(path: PathBuf) -> Vec<String> {
    let Ok(file) = fs::File::open(&path).await else {
        tracing::error!(?path, "spray: open list");
        return Vec::new();
    };
    let mut out = Vec::new();
    let mut lines = BufReader::new(file).lines();
    while let Ok(Some(line)) = lines.next_line().await {
        let t = line.trim();
        if !t.is_empty() && !t.starts_with('#') {
            out.push(t.to_owned());
        }
    }
    out
}

impl CredentialSource for SpraySource {
    fn build(&self) -> CredentialStream {
        let logins_path = self.logins.clone();
        let passwords_path = self.passwords.clone();
        let window = self.per_password_window;

        Box::pin(
            stream::once(async move {
                let logins = read_lines(logins_path).await;
                let passwords = read_lines(passwords_path).await;
                (logins, passwords, window)
            })
            .flat_map(|(logins, passwords, window)| {
                // For each password, sleep then emit (login, password) for every login.
                stream::iter(passwords.into_iter().enumerate()).flat_map(move |(idx, pass)| {
                    let logins = logins.clone();
                    let pre_sleep = if idx == 0 { Duration::ZERO } else { window };
                    Box::pin(async move {
                        if !pre_sleep.is_zero() {
                            sleep(pre_sleep).await;
                        }
                        stream::iter(logins.into_iter().map(move |l| {
                            CredentialPair::with_login(
                                Credential::from(l),
                                Secret::new(pass.clone()),
                            )
                        }))
                    })
                    .into_stream()
                    .flatten()
                })
            }),
        )
    }
}
