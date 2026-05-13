use std::sync::{Arc, OnceLock};
use std::time::Duration;

use fatah_core::{Endpoint, FatahError, Result};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;

use crate::tcp::connect;

/// Connect TCP and wrap with a rustls client session using webpki-roots
/// as the trust anchor set. `endpoint.host` is used both for SNI and
/// for certificate name validation.
pub async fn connect_tls(
    endpoint: &Endpoint,
    timeout: Duration,
) -> Result<TlsStream<TcpStream>> {
    let tcp = connect(endpoint, timeout).await?;
    let connector = connector();
    let server_name = ServerName::try_from(endpoint.host.clone())
        .map_err(|e| FatahError::Tls(format!("invalid server name: {e}")))?;

    match tokio::time::timeout(timeout, connector.connect(server_name, tcp)).await {
        Ok(Ok(stream)) => Ok(stream),
        Ok(Err(e)) => Err(FatahError::Tls(e.to_string())),
        Err(_) => Err(FatahError::Timeout),
    }
}

fn connector() -> TlsConnector {
    static CONNECTOR: OnceLock<TlsConnector> = OnceLock::new();
    CONNECTOR
        .get_or_init(|| {
            // rustls 0.23 requires an explicit crypto provider. Install
            // aws-lc-rs once; ignore the error if a provider was already
            // installed by some other code in the binary.
            let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

            let mut roots = RootCertStore::empty();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

            let cfg = ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth();
            TlsConnector::from(Arc::new(cfg))
        })
        .clone()
}
