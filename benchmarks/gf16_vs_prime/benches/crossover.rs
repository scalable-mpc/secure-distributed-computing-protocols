//! Where does the NTT actually overtake a naive matrix multiply?
//!
//! Both encoders live in [`gf16_vs_prime::rs`], run over the same field
//! (`F_12289`), use the same Shoup-based AVX2 primitives, and are
//! cross-validated against each other by `cargo run --bin agree`. So the only
//! variable is `O(n*k)` vs `O(n log n)`.
//!
//! # Rate
//!
//! Parameters follow this repository's protocols: `n` total shards with
//! `f = (n-1)/3` faults, `k = n - 2f` data shards and `m = 2f` parity, so **2/3
//! of the shards may be erased**. That low rate matters: the matrix cost is
//! `m*k`, which shrinks as the rate drops, while the NTT cost `(n/2) log n`
//! depends only on `n`. A rate-1/2 comparison would flatter the NTT.
//!
//! # Three encoders
//!
//! * `matrix systematic` — Cauchy, emits only the `m` parity shards. This is
//!   what `reed-solomon-erasure` does and what the protocols here deploy.
//! * `matrix full codeword` — Vandermonde on `w^j`, emits all `n`. Present
//!   because it is bit-identical to the NTT output, which is what validates
//!   both implementations.
//! * `ntt full codeword` — one size-`N` NTT, `N = next_pow2(n)`.
//!
//! commonware's encoder is included unmodified as a reference line only. It
//! works over GF(2^16) and is systematic, so it is not part of the tradeoff
//! measurement.
//!
//! ```text
//! cargo bench --bench crossover
//! ```

use std::hint::black_box;
use std::time::Duration;

use commonware_cryptography::reed_solomon::Encoder;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use gf16_vs_prime::rs::{
    matrix_ops, ntt_ops, systematic_matrix_ops, systematic_ntt_ops, MatrixEncoder, NttEncoder,
    SystematicMatrixEncoder, SystematicNttEncoder,
};

/// Total shards, capped at 256 — the most this repository's protocols use.
const NS: &[usize] = &[4, 8, 16, 32, 64, 128, 256];

/// Shard lengths in field elements (2 bytes each): 1 KiB, 16 KiB, 256 KiB.
/// The largest exposes the NTT's `log n` passes over memory.
const LENS: &[usize] = &[512, 8192, 131_072];

/// `n = 3f + 1` split: `k` data, `m = 2f` parity, tolerating `2f` erasures.
fn split(n: usize) -> (usize, usize) {
    let f = (n - 1) / 3;
    (n - 2 * f, 2 * f)
}

fn human_shard(l: usize) -> String {
    let bytes = l * 2;
    if bytes >= 1024 * 1024 {
        format!("{}MiB", bytes / (1024 * 1024))
    } else {
        format!("{}KiB", bytes / 1024)
    }
}

fn bench_crossover(c: &mut Criterion) {
    let mut group = c.benchmark_group("encode");
    group.warm_up_time(Duration::from_secs(1));
    group.measurement_time(Duration::from_secs(3));

    for &l in LENS {
        for &n in NS {
            let (k, m) = split(n);
            let id = format!("n={n}/k={k}/shard={}", human_shard(l));
            group.throughput(Throughput::Bytes((k * l * 2) as u64));

            let data: Vec<u16> = (0..k * l).map(|i| ((i * 7919) % 12289) as u16).collect();

            // ---- systematic matrix: parity only, O(m*k) ----
            {
                let enc = SystematicMatrixEncoder::new(k, m);
                let mut parity = vec![0u16; m * l];
                group.bench_with_input(
                    BenchmarkId::new("matrix systematic O(m*k)", &id),
                    &n,
                    |b, _| b.iter(|| enc.encode(black_box(&data), l, black_box(&mut parity))),
                );
            }

            // ---- systematic NTT: ifft + coset fft, the deployable shape ----
            {
                let enc = SystematicNttEncoder::new(k, m);
                let (mut s1, mut s2) = enc.scratch(l);
                let mut parity = vec![0u16; m * l];
                group.bench_with_input(
                    BenchmarkId::new("ntt systematic O(ifft+fft)", &id),
                    &n,
                    |b, _| {
                        b.iter(|| {
                            enc.encode(
                                black_box(&data),
                                l,
                                black_box(&mut parity),
                                &mut s1,
                                &mut s2,
                            )
                        })
                    },
                );
            }

            // ---- full codeword matrix, O(n*k) ----
            {
                let enc = MatrixEncoder::new(k, n);
                let mut out = vec![0u16; n * l];
                group.bench_with_input(
                    BenchmarkId::new("matrix full codeword O(n*k)", &id),
                    &n,
                    |b, _| b.iter(|| enc.encode(black_box(&data), l, black_box(&mut out))),
                );
            }

            // ---- NTT, O(n log n) ----
            {
                let enc = NttEncoder::new(n);
                let mut buf = vec![0u16; n * l];
                group.bench_with_input(
                    BenchmarkId::new("ntt full codeword O(n log n)", &id),
                    &n,
                    |b, _| {
                        b.iter(|| {
                            buf[..k * l].copy_from_slice(&data);
                            buf[k * l..].fill(0);
                            enc.encode_in_place(black_box(&mut buf), l)
                        })
                    },
                );
            }

            // ---- commonware, unmodified, reference only ----
            {
                let shard_bytes = l * 2;
                if Encoder::supports(k, m) {
                    let mut enc = Encoder::new(k, m, shard_bytes).expect("encoder");
                    let shard = vec![0u8; shard_bytes];
                    group.bench_with_input(
                        BenchmarkId::new("commonware GF(2^16) reference", &id),
                        &n,
                        |b, _| {
                            b.iter(|| {
                                for _ in 0..k {
                                    enc.add_original_shard(&shard).unwrap();
                                }
                                black_box(enc.encode().unwrap());
                            })
                        },
                    );
                }
            }
        }
    }
    group.finish();
}

/// The operation counts the timings should be explained by.
fn report_op_counts() {
    println!("\n  shard-length operations per encode, n = 3f+1, k = n-2f, m = 2f");
    println!("  (systematic rows are the deployable ones; full-codeword rows are what the");
    println!("   cross-validation compares)\n");
    println!(
        "  {:>5} {:>5} {:>5} | {:>12} {:>13} {:>9} | {:>12} {:>11} {:>9}",
        "n", "k", "m", "matrix m*k", "ntt ifft+fft", "ratio", "matrix n*k", "ntt nlogn", "ratio"
    );
    for &n in NS {
        let f = (n - 1) / 3;
        let (k, m) = (n - 2 * f, 2 * f);
        let sm = systematic_matrix_ops(k, m);
        let sn = systematic_ntt_ops(k, m);
        let fm = matrix_ops(k, n);
        let fn_ = ntt_ops(n);
        println!(
            "  {:>5} {:>5} {:>5} | {:>12} {:>13} {:>8.2}x | {:>12} {:>11} {:>8.2}x",
            n,
            k,
            m,
            sm,
            sn,
            sm as f64 / sn as f64,
            fm,
            fn_,
            fm as f64 / fn_ as f64
        );
    }
    println!();
}

fn setup(c: &mut Criterion) {
    report_op_counts();
    bench_crossover(c);
}

criterion_group!(benches, setup);
criterion_main!(benches);
