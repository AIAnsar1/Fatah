use std::path::PathBuf;

use fatah_core::{Credential, CredentialPair, Secret};
use futures::stream::{self, StreamExt};
use tokio::fs;
use tokio::io::{AsyncBufReadExt, BufReader};

use crate::{CredentialSource, CredentialStream};

/// Cartesian product `logins × passwords`. Inner loop is passwords,
/// outer loop is logins — i.e. all passwords for `alice`, then all
/// passwords for `bob`. The spray strategy in `fatah-spray` provides
/// the inverted iteration order.
pub struct ComboSource {
    pub logins: PathBuf,
    pub passwords: PathBuf,
}

impl ComboSource {
    pub fn new(logins: impl Into<PathBuf>, passwords: impl Into<PathBuf>) -> Self {
        Self {
            logins: logins.into(),
            passwords: passwords.into(),
        }
    }
}

async fn read_lines(path: PathBuf) -> Vec<String> {
    let Ok(file) = fs::File::open(&path).await else {
        tracing::error!(?path, "open list");
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

impl CredentialSource for ComboSource {
    fn build(&self) -> CredentialStream {
        let logins_path = self.logins.clone();
        let passwords_path = self.passwords.clone();
        Box::pin(
            stream::once(async move {
                let logins = read_lines(logins_path).await;
                let passwords = read_lines(passwords_path).await;
                (logins, passwords)
            })
            .flat_map(|(logins, passwords)| {
                let pairs: Vec<CredentialPair> = logins
                    .into_iter()
                    .flat_map(|l| {
                        passwords.iter().cloned().map(move |p| {
                            CredentialPair::with_login(Credential::from(l.clone()), Secret::new(p))
                        })
                    })
                    .collect();
                stream::iter(pairs)
            }),
        )
    }
}
