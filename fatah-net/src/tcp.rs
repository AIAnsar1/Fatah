use std::time::Duration;

use fatah_core::{Endpoint, FatahError, Result};
use tokio::net::TcpStream;
use tokio::time;

/// TCP connect with a hard wall-clock timeout. Any `tokio::io` error
/// other than timeout propagates as [`FatahError::Io`].
pub async fn connect(endpoint: &Endpoint, timeout: Duration) -> Result<TcpStream> {
    let addr = format!("{}:{}", endpoint.host, endpoint.port);
    let fut = TcpStream::connect(addr);
    match time::timeout(timeout, fut).await {
        Ok(Ok(stream)) => Ok(stream),
        Ok(Err(e)) => Err(FatahError::Io(e)),
        Err(_) => Err(FatahError::Timeout),
    }
}
