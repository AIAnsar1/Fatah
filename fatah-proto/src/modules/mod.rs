//! Built-in protocol modules. Each is feature-gated so binaries can
//! trim their attack surface and compile time.

#[cfg(feature = "ftp")]
pub mod ftp;

#[cfg(feature = "http-basic")]
pub mod http_basic;

#[cfg(feature = "ssh")]
pub mod ssh;
