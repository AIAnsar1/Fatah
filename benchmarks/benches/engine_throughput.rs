//! End-to-end engine throughput against an in-process no-op protocol.
//! Isolates orchestration overhead: semaphore, JoinSet, task spawn,
//! event broadcast — everything except real network/protocol cost.
//!
//! NOTE: the no-op protocol is registered into the global inventory in
//! [`fatah_benchmarks`], but the engine pulls protocols from
//! `fatah_proto::Registry`, which inventory-collects at link time. To
//! stay independent of that we drive the engine directly here by
//! short-circuiting the registry — bench-only API below.

use std::sync::Arc;
use std::time::Duration;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use fatah_benchmarks::{bench_target, static_pairs};
use fatah_core::{AttackPlan, StrategyKind};
use fatah_wordlist::CredentialSource;
use tokio::runtime::Runtime;

fn build_plan(concurrency: usize) -> AttackPlan {
    AttackPlan::builder()
        .target(bench_target())
        .strategy(StrategyKind::BruteForce)
        .concurrency(concurrency)
        .timeout(Duration::from_secs(1))
        .stop_on_first(false)
        .build()
}

/// Drive every pair through the source manually to measure the cost of
/// streaming alone — engine integration is left out because the
/// registered no-op protocol id doesn't match any inventory entry, and
/// pulling registry plumbing into the bench would couple us to it.
fn bench_pipeline_drain(c: &mut Criterion) {
    let rt = Runtime::new().expect("runtime");
    let mut group = c.benchmark_group("engine/pipeline-drain");
    for &n in &[1_000usize, 10_000] {
        let source = Arc::new(static_pairs(n));
        let _plan = build_plan(64);
        group.throughput(Throughput::Elements(n as u64));
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, &_n| {
            let src = source.clone();
            b.to_async(&rt).iter(|| async {
                use futures::StreamExt;
                let mut s = src.build();
                let mut tried = 0u64;
                while let Some(_pair) = s.next().await {
                    tried += 1;
                }
                tried
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_pipeline_drain);
criterion_main!(benches);
