use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use fatah_core::{Attempt, AttemptOutcome, EngineEvent};
use serde::Serialize;
use tokio::fs::OpenOptions;
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;

use crate::Reporter;

/// Append-only JSON-Lines reporter. One record per engine event,
/// useful for piping into downstream pipelines or for post-mortem
/// inspection.
pub struct JsonlReporter {
    path: PathBuf,
    lock: Arc<Mutex<()>>,
}

impl JsonlReporter {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            lock: Arc::new(Mutex::new(())),
        }
    }
}

#[derive(Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum Record<'a> {
    Started {
        plan_id: String,
    },
    Attempt {
        at: DateTime<Utc>,
        target: String,
        protocol: &'a str,
        login: Option<&'a str>,
        outcome: &'static str,
        detail: Option<&'a str>,
        elapsed_ms: u128,
        hit: bool,
    },
    Progress {
        tried: u64,
        total: Option<u64>,
    },
    Finished {
        tried: u64,
        found: usize,
    },
    Warning {
        message: &'a str,
    },
}

fn outcome_label(o: &AttemptOutcome) -> (&'static str, Option<&str>) {
    match o {
        AttemptOutcome::Success => ("success", None),
        AttemptOutcome::Failure => ("failure", None),
        AttemptOutcome::Locked => ("locked", None),
        AttemptOutcome::RateLimited => ("rate_limited", None),
        AttemptOutcome::Error(e) => ("error", Some(e.as_str())),
    }
}

fn attempt_record(a: &Attempt, hit: bool) -> Record<'_> {
    let (label, detail) = outcome_label(&a.outcome);
    Record::Attempt {
        at: a.started_at,
        target: a.target.endpoint.to_string(),
        protocol: &a.target.protocol,
        login: a.credential.login_str(),
        outcome: label,
        detail,
        elapsed_ms: a.elapsed.as_millis(),
        hit,
    }
}

#[async_trait]
impl Reporter for JsonlReporter {
    async fn on_event(&self, event: &EngineEvent) {
        let record = match event {
            EngineEvent::Started { plan_id } => Record::Started {
                plan_id: plan_id.to_string(),
            },
            EngineEvent::AttemptCompleted(a) => attempt_record(a, false),
            EngineEvent::Found(a) => attempt_record(a, true),
            EngineEvent::Progress { tried, total } => Record::Progress {
                tried: *tried,
                total: *total,
            },
            EngineEvent::Finished { tried, found } => Record::Finished {
                tried: *tried,
                found: *found,
            },
            EngineEvent::Warning(m) => Record::Warning {
                message: m.as_str(),
            },
        };
        let Ok(mut line) = serde_json::to_vec(&record) else {
            tracing::warn!("jsonl: serialise failed");
            return;
        };
        line.push(b'\n');
        let _guard = self.lock.lock().await;
        match OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .await
        {
            Ok(mut f) => {
                if let Err(e) = f.write_all(&line).await {
                    tracing::warn!(error=%e, "jsonl: write");
                }
            }
            Err(e) => tracing::warn!(error=%e, path=?self.path, "jsonl: open"),
        }
    }
}
