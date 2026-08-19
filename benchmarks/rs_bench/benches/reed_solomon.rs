//! Reed-Solomon erasure coding: `reed-solomon-erasure` (this repository) vs
//! `commonware-coding`.
//!
//! Run everything:
//!
//! ```text
//! cargo bench
//! ```
//!
//! The sweep has two axes, both comma-separated env vars. `RS_BENCH_SIZES`
//! fixes the *message* size; `RS_BENCH_SHARD_SIZES` fixes the *per-shard* size
//! and derives the message as `k x shard`, which is the one to use when you
//! care about megabyte-scale shards (a 1 MiB message at n=64 only yields 47 KiB
//! shards). Set either to an empty string to drop that axis.
//!
//! ```text
//! RS_BENCH_N=16,64 RS_BENCH_SIZES= RS_BENCH_SHARD_SIZES=4194304 cargo bench
//! ```
//!
//! Filter by group, e.g. only the like-for-like dealer-side comparison:
//!
//! ```text
//! cargo bench -- encode_committed
//! ```

use std::hint::black_box;
use std::num::NonZeroUsize;
use std::time::Duration;

use bytes::Bytes;
use criterion::{
    criterion_group, criterion_main, measurement::WallTime, BatchSize, BenchmarkGroup, BenchmarkId,
    Criterion, Throughput,
};

use commonware_parallel::{Rayon, Sequential};
use rs_bench::{cw, payload, repo, Params};

const MIB: usize = 1024 * 1024;

/// One point in the sweep.
struct Case {
    p: Params,
    /// Message size in bytes.
    len: usize,
    /// Bytes of coded payload each node receives.
    shard: usize,
    label: String,
}

/// Every (committee size, message size) pair to measure.
///
/// `RS_BENCH_SIZES` entries are message sizes; `RS_BENCH_SHARD_SIZES` entries
/// are per-shard sizes, expanded to `k x shard` so the shard size stays fixed
/// as `n` grows.
fn cases() -> Vec<Case> {
    let mut out = Vec::new();
    for n in parse_env("RS_BENCH_N", &[4, 16, 64, 128, 256]) {
        let p = Params::for_n(n);
        for len in parse_env("RS_BENCH_SIZES", &[1024, 100 * 1024, MIB, 10 * MIB, 100 * MIB]) {
            out.push(Case {
                p,
                len,
                shard: len.div_ceil(p.k),
                label: format!("n={}/k={}/msg={}", p.n, p.k, human(len)),
            });
        }
        for shard in parse_env("RS_BENCH_SHARD_SIZES", &[MIB, 4 * MIB]) {
            out.push(Case {
                p,
                len: shard * p.k,
                shard,
                label: format!("n={}/k={}/shard={}", p.n, p.k, human(shard)),
            });
        }
    }
    out
}

fn parse_env(var: &str, default: &[usize]) -> Vec<usize> {
    match std::env::var(var) {
        Ok(v) => v
            .split(',')
            .filter(|s| !s.trim().is_empty())
            .map(|s| s.trim().parse().unwrap_or_else(|_| panic!("bad {var}: {s}")))
            .collect(),
        Err(_) => default.to_vec(),
    }
}

fn human(bytes: usize) -> String {
    if bytes >= MIB {
        format!("{}MiB", bytes / MIB)
    } else if bytes >= 1024 {
        format!("{}KiB", bytes / 1024)
    } else {
        format!("{bytes}B")
    }
}

/// Big messages at large `n` mean multi-second iterations: GF(2^8) encoding
/// costs `k*m` multiply-adds per byte, which at n=256 is 86*170 = 14620 —
/// roughly 16x the n=64 cost. Spend the sampling budget where it buys
/// precision and keep the big cases bounded (10 is criterion's floor).
fn tune(group: &mut BenchmarkGroup<'_, WallTime>, len: usize) {
    let (samples, secs) = match len {
        l if l >= 64 * MIB => (10, 5),
        l if l >= 16 * MIB => (10, 8),
        l if l >= MIB => (20, 5),
        _ => (50, 3),
    };
    group.sample_size(samples);
    group.measurement_time(Duration::from_secs(secs));
}

/// Cloning an 88 MiB input 100x over is not a useful way to spend RAM.
fn batch(len: usize) -> BatchSize {
    if len >= MIB {
        BatchSize::PerIteration
    } else {
        BatchSize::SmallInput
    }
}

/// Erasure coding in isolation.
///
/// commonware cannot code without also committing, so its bar here is the same
/// work as in `encode_committed`. The comparison that matters is that one; this
/// group exists to show how much of the repo's encode budget is coding alone.
fn bench_encode_raw(c: &mut Criterion) {
    let mut group = c.benchmark_group("encode_raw");
    for case in cases() {
        let Case { p, len, .. } = case;
        let data = payload(len);
        let bytes = Bytes::from(data.clone());
        let cfg = cw::config(p);

        tune(&mut group, len);
        group.throughput(Throughput::Bytes(len as u64));
        group.bench_with_input(
            BenchmarkId::new("repo/rs-erasure", &case.label),
            &p,
            |b, &p| {
                b.iter_batched(
                    || data.clone(),
                    |d| black_box(repo::encode_raw(d, p)),
                    batch(len),
                )
            },
        );
        group.bench_with_input(
            BenchmarkId::new("commonware (incl. commitment)", &case.label),
            &cfg,
            |b, cfg| {
                b.iter(|| black_box(cw::encode(cfg, bytes.clone(), &Sequential).unwrap()));
            },
        );
    }
    group.finish();
}

/// The like-for-like dealer-side comparison: code the message, commit to the
/// shards, and produce every peer's inclusion proof.
fn bench_encode_committed(c: &mut Criterion) {
    let mut group = c.benchmark_group("encode_committed");
    for case in cases() {
        let Case { p, len, .. } = case;
        let data = payload(len);
        let bytes = Bytes::from(data.clone());
        let hc = repo::hash_state();
        let cfg = cw::config(p);

        tune(&mut group, len);
        group.throughput(Throughput::Bytes(len as u64));
        group.bench_with_input(
            BenchmarkId::new("repo/rs-erasure+merkle", &case.label),
            &p,
            |b, &p| {
                b.iter_batched(
                    || data.clone(),
                    |d| black_box(repo::encode_committed(d, p, &hc)),
                    batch(len),
                )
            },
        );
        group.bench_with_input(BenchmarkId::new("commonware", &case.label), &cfg, |b, cfg| {
            b.iter(|| black_box(cw::encode(cfg, bytes.clone(), &Sequential).unwrap()));
        });
    }
    group.finish();
}

/// Receiver-side verification of a single inbound shard. Throughput is reported
/// per shard byte, since that is what the work scales with here.
fn bench_check_shard(c: &mut Criterion) {
    let mut group = c.benchmark_group("check_one_shard");
    for case in cases() {
        let Case { p, len, .. } = case;
        let data = payload(len);
        let hc = repo::hash_state();
        let (root, shards, proofs) = repo::encode_committed(data.clone(), p, &hc);

        let cfg = cw::config(p);
        let (commitment, cw_shards) =
            cw::encode(&cfg, Bytes::from(data), &Sequential).expect("commonware encode");

        tune(&mut group, case.shard);
        group.throughput(Throughput::Bytes(shards[0].len() as u64));
        group.bench_with_input(
            BenchmarkId::new("repo/verify_mr_proof", &case.label),
            &p,
            |b, _| {
                b.iter(|| black_box(repo::check_shard(&shards[0], &proofs[0], &root, &hc)));
            },
        );
        group.bench_with_input(
            BenchmarkId::new("commonware/check", &case.label),
            &cfg,
            |b, cfg| {
                b.iter(|| black_box(cw::check(cfg, &commitment, 0, &cw_shards[0]).unwrap()));
            },
        );
    }
    group.finish();
}

/// Verifying a full quorum of shards, which is what a node does over the course
/// of one broadcast instance.
fn bench_check_all(c: &mut Criterion) {
    let mut group = c.benchmark_group("check_all_shards");
    for case in cases() {
        let Case { p, len, .. } = case;
        let data = payload(len);
        let hc = repo::hash_state();
        let (root, shards, proofs) = repo::encode_committed(data.clone(), p, &hc);

        let cfg = cw::config(p);
        let (commitment, cw_shards) =
            cw::encode(&cfg, Bytes::from(data), &Sequential).expect("commonware encode");

        tune(&mut group, len);
        group.throughput(Throughput::Bytes(len as u64));
        group.bench_with_input(BenchmarkId::new("repo", &case.label), &p, |b, _| {
            b.iter(|| {
                for i in 0..shards.len() {
                    black_box(repo::check_shard(&shards[i], &proofs[i], &root, &hc));
                }
            });
        });
        group.bench_with_input(BenchmarkId::new("commonware", &case.label), &cfg, |b, cfg| {
            b.iter(|| black_box(cw::check_all(cfg, &commitment, &cw_shards).unwrap()));
        });
    }
    group.finish();
}

/// Reconstruction from `k` shards chosen uniformly at random out of `n` — the
/// `2f` erasures the protocols tolerate. Most survivors are parity shards, so
/// the missing data shards really are interpolated.
///
/// Both variants re-derive the commitment: the repo rebuilds the Merkle tree
/// over the repaired shards (as `ctrbc::handle_ready` does), and commonware's
/// `decode` validates internally. `repo/reconstruct only` isolates the
/// erasure-decoding half.
fn bench_decode(c: &mut Criterion) {
    let mut group = c.benchmark_group("decode");
    for case in cases() {
        let Case { p, len, .. } = case;
        let data = payload(len);
        let hc = repo::hash_state();
        let (root, shards, _) = repo::encode_committed(data.clone(), p, &hc);

        // One fixed random draw per case, so every implementation decodes from
        // exactly the same surviving set.
        let keep = repo::random_k_indices(p, 0xDEC0DE ^ p.n as u64 ^ len as u64);
        let erased = repo::keep_indices(&shards, &keep);
        drop(shards);

        let cfg = cw::config(p);
        let (commitment, cw_shards) =
            cw::encode(&cfg, Bytes::from(data), &Sequential).expect("commonware encode");
        let checked = cw::check_all(&cfg, &commitment, &cw_shards).expect("commonware check");
        let quorum: Vec<_> = keep.iter().map(|&i| checked[i].clone()).collect();
        let quorum = &quorum[..];

        tune(&mut group, len);
        group.throughput(Throughput::Bytes(len as u64));
        group.bench_with_input(
            BenchmarkId::new("repo/reconstruct only", &case.label),
            &p,
            |b, &p| {
                b.iter_batched(
                    || erased.clone(),
                    |s| black_box(repo::decode(s, p, len).unwrap()),
                    batch(len),
                )
            },
        );
        group.bench_with_input(
            BenchmarkId::new("repo/reconstruct+merkle", &case.label),
            &p,
            |b, &p| {
                b.iter_batched(
                    || erased.clone(),
                    |s| black_box(repo::decode_verified(s, p, len, &root, &hc).unwrap()),
                    batch(len),
                )
            },
        );
        group.bench_with_input(BenchmarkId::new("commonware", &case.label), &cfg, |b, cfg| {
            b.iter(|| black_box(cw::decode(cfg, &commitment, quorum, &Sequential).unwrap()));
        });
    }
    group.finish();
}

/// commonware's `Strategy` parameter has no counterpart on the repo side: its
/// coder can spread work over a rayon pool. Worth knowing before reading the
/// single-threaded numbers as the whole story.
fn bench_commonware_parallelism(c: &mut Criterion) {
    let threads = std::thread::available_parallelism().unwrap_or(NonZeroUsize::new(1).unwrap());
    let rayon = Rayon::new(threads).expect("build rayon pool");

    let mut group = c.benchmark_group("commonware_strategy");
    for case in cases() {
        let Case { p, len, .. } = case;
        let bytes = Bytes::from(payload(len));
        let cfg = cw::config(p);

        tune(&mut group, len);
        group.throughput(Throughput::Bytes(len as u64));
        group.bench_with_input(
            BenchmarkId::new("encode/sequential", &case.label),
            &cfg,
            |b, cfg| {
                b.iter(|| black_box(cw::encode(cfg, bytes.clone(), &Sequential).unwrap()));
            },
        );
        group.bench_with_input(
            BenchmarkId::new(format!("encode/rayon-{threads}"), &case.label),
            &cfg,
            |b, cfg| {
                b.iter(|| black_box(cw::encode(cfg, bytes.clone(), &rayon).unwrap()));
            },
        );
    }
    group.finish();
}

fn configure() -> Criterion {
    Criterion::default().warm_up_time(Duration::from_secs(1))
}

criterion_group! {
    name = benches;
    config = configure();
    targets =
        bench_encode_raw,
        bench_encode_committed,
        bench_check_shard,
        bench_check_all,
        bench_decode,
        bench_commonware_parallelism,
}
criterion_main!(benches);
