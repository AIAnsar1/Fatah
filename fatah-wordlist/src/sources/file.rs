use std::path::{Path, PathBuf};

use fatah_core::{Credential, CredentialPair, Secret};
use futures::stream::{self, StreamExt};
use tokio::fs::File;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio_util::io::ReaderStream;

use crate::{CredentialSource, CredentialStream};

/// Wordlist file backed by a tokio async reader. The file is opened
/// lazily inside [`build`] so the source can be cheaply constructed
/// from config and re-streamed multiple times.
///
/// Format is one entry per line. Empty lines and lines starting with
/// `#` are skipped.
pub struct FileWordlist {
    path: PathBuf,
    /// If set, every line becomes `(login, secret)` with this fixed
    /// login. Otherwise lines are emitted as secret-only entries (e.g.
    /// for SNMP communities).
    fixed_login: Option<String>,
}

impl FileWordlist {
    pub fn passwords_for(path: impl AsRef<Path>, login: impl Into<String>) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
            fixed_login: Some(login.into()),
        }
    }

    pub fn secrets_only(path: impl AsRef<Path>) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
            fixed_login: None,
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

// We avoid the dead `tokio_util::io::ReaderStream` import warning by
// hiding it behind a small static used only for type-system anchoring.
const _: fn() = || {
    let _ = std::marker::PhantomData::<ReaderStream<File>>;
};

impl CredentialSource for FileWordlist {
    fn build(&self) -> CredentialStream {
        let path = self.path.clone();
        let fixed_login = self.fixed_login.clone();
        Box::pin(
            stream::once(async move {
                let file = File::open(&path).await.map_err(|e| {
                    tracing::error!(?path, error=%e, "open wordlist");
                    e
                });
                file
            })
            .filter_map(|res| async move { res.ok() })
            .flat_map(move |file| {
                let lines = BufReader::new(file).lines();
                let login = fixed_login.clone();
                Box::pin(stream::unfold(
                    (lines, login),
                    |(mut lines, login)| async move {
                        loop {
                            match lines.next_line().await {
                                Ok(Some(line)) => {
                                    let trimmed = line.trim();
                                    if trimmed.is_empty() || trimmed.starts_with('#') {
                                        continue;
                                    }
                                    let pair = match &login {
                                        Some(l) => CredentialPair::with_login(
                                            Credential::from(l.clone()),
                                            Secret::new(trimmed),
                                        ),
                                        None => CredentialPair {
                                            login: None,
                                            secret: Secret::new(trimmed),
                                        },
                                    };
                                    return Some((pair, (lines, login)));
                                }
                                Ok(None) => return None,
                                Err(e) => {
                                    tracing::warn!(error=%e, "wordlist read");
                                    return None;
                                }
                            }
                        }
                    },
                )) as CredentialStream
            }),
        )
    }
}
