//! Observability bootstrap for Fatah binaries.
//!
//! Wraps `tracing-subscriber` so every binary (CLI, future daemon, tests)
//! initialises logging the same way: env-driven level, optional JSON
//! output, optional file appender.

#![allow(clippy::missing_errors_doc)]

use std::path::PathBuf;

use anyhow::{Context, Result};
use tracing_subscriber::filter::EnvFilter;
use tracing_subscriber::fmt;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

/// Output format for the human-facing log layer.
#[derive(Debug, Clone, Copy, Default)]
pub enum Format {
    #[default]
    Pretty,
    Compact,
    Json,
}

/// Telemetry configuration. Construct with `TelemetryConfig::default()`
/// or via the public fields directly.
#[derive(Debug, Clone, Default)]
pub struct TelemetryConfig {
    /// Falls back to the `RUST_LOG` env var, then `"info"`.
    pub filter: Option<String>,
    pub format: Format,
    /// If set, also append logs to this file in JSON.
    pub log_file: Option<PathBuf>,
    pub with_ansi: bool,
}

/// Install the global tracing subscriber. Safe to call exactly once per
/// process; subsequent calls return an error.
pub fn init(config: TelemetryConfig) -> Result<()> {
    let filter = config
        .filter
        .clone()
        .map(EnvFilter::try_new)
        .transpose()
        .context("invalid log filter")?
        .unwrap_or_else(|| {
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"))
        });

    let registry = tracing_subscriber::registry().with(filter);

    let fmt_layer: Box<dyn tracing_subscriber::Layer<_> + Send + Sync> = match config.format {
        Format::Pretty => Box::new(fmt::layer().with_ansi(config.with_ansi).pretty()),
        Format::Compact => Box::new(fmt::layer().with_ansi(config.with_ansi).compact()),
        Format::Json => Box::new(fmt::layer().json()),
    };

    if let Some(path) = config.log_file {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .with_context(|| format!("opening log file {}", path.display()))?;
        let file_layer = fmt::layer().json().with_writer(file);
        registry.with(fmt_layer).with(file_layer).try_init()?;
    } else {
        registry.with(fmt_layer).try_init()?;
    }

    Ok(())
}
