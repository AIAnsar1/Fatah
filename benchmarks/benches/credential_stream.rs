//! Measure the cost of materialising a credential stream from each
//! built-in source kind. We're profiling the source itself, not any
//! network or protocol work.

use std::io::Write;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use fatah_benchmarks::{drain, static_pairs};
use fatah_wordlist::{ComboSource, FileWordlist};
use tempfile::NamedTempFile;
use tokio::runtime::Runtime;

fn make_wordlist(n: usize) -> NamedTempFile {
    let mut f = NamedTempFile::new().expect("tempfile");
    for i in 0..n {
        writeln!(f, "pw{i}").expect("write line");
    }
    f.flush().expect("flush");
    f
}

fn bench_static(c: &mut Criterion) {
    let rt = Runtime::new().expect("runtime");
    let mut group = c.benchmark_group("source/static");
    for &n in &[1_000usize, 10_000, 100_000] {
        group.throughput(Throughput::Elements(n as u64));
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, &n| {
            let src = static_pairs(n);
            b.to_async(&rt).iter(|| async {
                let count = drain(&src).await;
                assert_eq!(count, n);
            });
        });
    }
    group.finish();
}

fn bench_file(c: &mut Criterion) {
    let rt = Runtime::new().expect("runtime");
    let mut group = c.benchmark_group("source/file");
    for &n in &[1_000usize, 10_000, 100_000] {
        let tmp = make_wordlist(n);
        group.throughput(Throughput::Elements(n as u64));
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, &_n| {
            let src = FileWordlist::passwords_for(tmp.path(), "alice");
            b.to_async(&rt).iter(|| async {
                let _ = drain(&src).await;
            });
        });
    }
    group.finish();
}

fn bench_combo(c: &mut Criterion) {
    let rt = Runtime::new().expect("runtime");
    let mut group = c.benchmark_group("source/combo");
    for &(l, p) in &[(10usize, 1_000usize), (50, 1_000), (100, 1_000)] {
        let users = make_wordlist(l);
        let passwords = make_wordlist(p);
        let total = (l * p) as u64;
        group.throughput(Throughput::Elements(total));
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{l}x{p}")),
            &(l, p),
            |b, _| {
                let src = ComboSource::new(users.path(), passwords.path());
                b.to_async(&rt).iter(|| async {
                    let _ = drain(&src).await;
                });
            },
        );
    }
    group.finish();
}

criterion_group!(benches, bench_static, bench_file, bench_combo);
criterion_main!(benches);
