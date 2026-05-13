//! Async transport primitives shared by every protocol module.
//!
//! * [`connect`] — bounded-timeout TCP connect.
//! * [`LineStream`] — CRLF helper for line-oriented protocols.
//! * [`tls::connect_tls`] (feature `tls`) — rustls-backed TLS connect on
//!   top of [`connect`]. System roots come from `webpki-roots`.

#![allow(
    clippy::missing_errors_doc,
    clippy::module_name_repetitions,
    clippy::must_use_candidate
)]

pub mod line;
pub mod tcp;

#[cfg(feature = "tls")]
pub mod tls;

pub use line::LineStream;
pub use tcp::connect;
