use std::time::Duration;

use fatah_core::{FatahError, Result};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::time;

/// CRLF-aware text protocol helper. Wraps any AsyncRead+AsyncWrite and
/// exposes `read_line` / `write_line` with per-call timeouts. Used by
/// every line-oriented protocol module (FTP, SMTP, POP3, IMAP, …).
pub struct LineStream<S> {
    reader: BufReader<S>,
    buf: String,
}

impl<S: AsyncRead + AsyncWrite + Unpin> LineStream<S> {
    pub fn new(stream: S) -> Self {
        Self { reader: BufReader::new(stream), buf: String::with_capacity(256) }
    }

    /// Read one line (terminated by `\n`, with the trailing CR/LF
    /// trimmed). Returns `Err(FatahError::Protocol)` on EOF.
    pub async fn read_line(&mut self, timeout: Duration) -> Result<String> {
        self.buf.clear();
        let n = match time::timeout(timeout, self.reader.read_line(&mut self.buf)).await {
            Ok(Ok(n)) => n,
            Ok(Err(e)) => return Err(FatahError::Io(e)),
            Err(_) => return Err(FatahError::Timeout),
        };
        if n == 0 {
            return Err(FatahError::protocol("connection closed by peer"));
        }
        // Trim trailing CRLF / LF.
        while matches!(self.buf.chars().last(), Some('\n' | '\r')) {
            self.buf.pop();
        }
        Ok(std::mem::take(&mut self.buf))
    }

    /// Write `line` followed by CRLF, flushing the underlying writer.
    pub async fn write_line(&mut self, line: &str, timeout: Duration) -> Result<()> {
        let writer = self.reader.get_mut();
        let fut = async {
            writer.write_all(line.as_bytes()).await?;
            writer.write_all(b"\r\n").await?;
            writer.flush().await?;
            Ok::<_, std::io::Error>(())
        };
        match time::timeout(timeout, fut).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) => Err(FatahError::Io(e)),
            Err(_) => Err(FatahError::Timeout),
        }
    }

    pub fn into_inner(self) -> S {
        self.reader.into_inner()
    }
}
