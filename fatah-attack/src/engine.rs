use std::num::NonZeroU32;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use chrono::Utc;
use fatah_core::{
    AttackPlan, Attempt, AttemptContext, AttemptOutcome, EngineEvent, FatahError, Protocol, Result,
};
use fatah_database::Repository;
use fatah_proto::Registry;
use fatah_report::Reporter;
use fatah_session::SessionState;
use fatah_wordlist::CredentialStream;
use futures::StreamExt;
use governor::clock::DefaultClock;
use governor::state::{InMemoryState, NotKeyed};
use governor::{Quota, RateLimiter};
use parking_lot::Mutex;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use uuid::Uuid;

type DirectLimiter = RateLimiter<NotKeyed, InMemoryState, DefaultClock>;

/// Final result of an engine run.
#[derive(Debug, Clone)]
pub struct RunSummary {
    pub plan_id: Uuid,
    pub session_id: Uuid,
    pub tried: u64,
    pub findings: Vec<Attempt>,
}

/// Attack orchestrator. Wires together the credential stream, the
/// protocol registry, rate-limiting, the worker pool, observers, and
/// (optionally) persistent session checkpoints.
#[derive(Default)]
pub struct Engine {
    reporters: Vec<Arc<dyn Reporter>>,
    repository: Option<Arc<dyn Repository>>,
    checkpoint_every: u64,
}

impl Engine {
    pub fn new() -> Self {
        Self {
            reporters: Vec::new(),
            repository: None,
            checkpoint_every: 50,
        }
    }

    pub fn with_reporter(mut self, reporter: Arc<dyn Reporter>) -> Self {
        self.reporters.push(reporter);
        self
    }

    pub fn add_reporter(&mut self, reporter: Arc<dyn Reporter>) {
        self.reporters.push(reporter);
    }

    /// Attach a repository to enable session checkpointing and
    /// (caller-driven) resume. The engine writes a [`SessionState`]
    /// snapshot every `checkpoint_every` consumed pairs.
    pub fn with_repository(mut self, repo: Arc<dyn Repository>) -> Self {
        self.repository = Some(repo);
        self
    }

    pub fn checkpoint_every(mut self, n: u64) -> Self {
        self.checkpoint_every = n.max(1);
        self
    }

    /// Run an attack plan against a credential stream.
    ///
    /// If `session` is `Some`, its `tried` value is used as the starting
    /// counter — the *caller* is responsible for skipping that many
    /// pairs in the stream (e.g. via `futures::StreamExt::skip`). The
    /// engine simply continues incrementing from there and checkpoints
    /// back to the supplied (or freshly created) [`SessionState`].
    pub async fn run(
        &self,
        plan: AttackPlan,
        mut stream: CredentialStream,
        session: Option<SessionState>,
    ) -> Result<RunSummary> {
        let plan_id = Uuid::new_v4();
        self.broadcast(&EngineEvent::Started { plan_id }).await;

        let proto_box = Registry::create(&plan.target.protocol).ok_or_else(|| {
            FatahError::config(format!("unknown protocol: {}", plan.target.protocol))
        })?;
        let proto: Arc<dyn Protocol> = Arc::from(proto_box);

        let semaphore = Arc::new(Semaphore::new(plan.concurrency.max(1)));
        let limiter: Option<Arc<DirectLimiter>> = plan
            .rate
            .and_then(|r| NonZeroU32::new(r.per_second))
            .map(|n| Arc::new(RateLimiter::direct(Quota::per_second(n))));
        let stop = Arc::new(AtomicBool::new(false));
        let tried = Arc::new(AtomicU64::new(0));
        let findings: Arc<Mutex<Vec<Attempt>>> = Arc::new(Mutex::new(Vec::new()));
        let ctx =
            Arc::new(AttemptContext::new(plan.timeout).with_options(plan.target.options.clone()));

        let mut state = session.unwrap_or_else(|| SessionState::new(plan.target.clone()));
        let baseline_tried = state.tried;

        let mut set: JoinSet<()> = JoinSet::new();
        let mut consumed: u64 = baseline_tried;

        while let Some(cred) = stream.next().await {
            if stop.load(Ordering::Relaxed) {
                break;
            }
            if let Some(l) = &limiter {
                l.until_ready().await;
            }
            let permit = match semaphore.clone().acquire_owned().await {
                Ok(p) => p,
                Err(_) => break,
            };

            let proto = proto.clone();
            let ctx = ctx.clone();
            let target = plan.target.clone();
            let reporters = self.reporters.clone();
            let stop_c = stop.clone();
            let tried_c = tried.clone();
            let findings_c = findings.clone();
            let stop_on_first = plan.stop_on_first;

            set.spawn(async move {
                let _permit = permit;
                let started = Utc::now();
                let started_instant = std::time::Instant::now();
                let outcome = match proto.attempt(&target, &cred, &ctx).await {
                    Ok(o) => o,
                    Err(e) => AttemptOutcome::Error(e.to_string()),
                };
                let attempt = Attempt::new(
                    target,
                    cred,
                    outcome.clone(),
                    started,
                    started_instant.elapsed(),
                );
                tried_c.fetch_add(1, Ordering::Relaxed);

                for r in &reporters {
                    r.on_event(&EngineEvent::AttemptCompleted(attempt.clone()))
                        .await;
                }
                if matches!(outcome, AttemptOutcome::Success) {
                    findings_c.lock().push(attempt.clone());
                    for r in &reporters {
                        r.on_event(&EngineEvent::Found(attempt.clone())).await;
                    }
                    if stop_on_first {
                        stop_c.store(true, Ordering::Relaxed);
                    }
                }
            });

            consumed = consumed.saturating_add(1);
            if consumed.is_multiple_of(self.checkpoint_every) {
                let found_now = findings.lock().len();
                self.checkpoint(&mut state, consumed, found_now).await;
            }
        }

        while set.join_next().await.is_some() {}

        let completed_run = tried.load(Ordering::Relaxed);
        let total_tried = baseline_tried.saturating_add(completed_run);
        state.tried = total_tried;
        state.found = findings.lock().len();
        state.touch();
        if let Some(repo) = &self.repository
            && let Err(e) = fatah_session::save(repo.as_ref(), &state).await
        {
            tracing::warn!(error=%e, "final session save");
        }

        let summary = RunSummary {
            plan_id,
            session_id: state.id,
            tried: total_tried,
            findings: findings.lock().clone(),
        };
        self.broadcast(&EngineEvent::Finished {
            tried: summary.tried,
            found: summary.findings.len(),
        })
        .await;
        Ok(summary)
    }

    async fn checkpoint(&self, state: &mut SessionState, consumed: u64, found: usize) {
        let Some(repo) = &self.repository else { return };
        state.tried = consumed;
        state.found = found;
        state.touch();
        if let Err(e) = fatah_session::save(repo.as_ref(), state).await {
            tracing::warn!(error=%e, "checkpoint save");
        }
    }

    async fn broadcast(&self, event: &EngineEvent) {
        for r in &self.reporters {
            r.on_event(event).await;
        }
    }
}
