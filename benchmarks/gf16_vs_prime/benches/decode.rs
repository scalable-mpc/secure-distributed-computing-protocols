//! Decode: reconstruct the message from `k` shards chosen at random out of `n`.
//!
//! `k = n - 2f` with `f = (n-1)/3`, so `2f` shards are erased — the maximum the
//! protocols in this repository tolerate, and roughly `n/3` survivors.
//!
//! * `matrix decode` is ours, over `F_12289`: invert the `k x k` Vandermonde
//!   submatrix on the surviving evaluation points (`O(k^3)` scalar operations,
//!   once, independent of shard length), then apply it (`k^2` shard-length
//!   multiply-adds). Validated end-to-end by `cargo run --bin agree`.
//! * `commonware decode` is theirs, run unmodified over GF(2^16) with its
//!   FFT-based erasure decoder. Different field and a far more tuned
//!   implementation, so read it as a system-level reference, not as an
//!   algorithm-vs-algorithm result.
//!
//! The `O(k^3)` setup is deliberately inside the timed region for one variant
//! and hoisted in another, because which one applies depends on whether a
//! deployment can cache the inverse for a given erasure pattern.
//!
//! ```text
//! cargo bench --bench decode
//! ```

use std::hint::black_box;
use std::time::Duration;

use commonware_cryptography::reed_solomon::{Decoder, Encoder};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use gf16_vs_prime::rs::{matrix_decode_ops, MatrixDecoder, MatrixEncoder};

const NS: &[usize] = &[4, 16, 32, 64, 128, 256];
const LENS: &[usize] = &[512, 8192, 131_072];

fn split(n: usize) -> (usize, usize) {
    let f = (n - 1) / 3;
    (n - 2 * f, 2 * f)
}

fn human_shard(l: usize) -> String {
    format!("{}KiB", l * 2 / 1024)
}

/// Deterministic choice of `k` survivors out of `n`.
fn survivors(n: usize, k: usize, seed: u64) -> Vec<usize> {
    let mut idx: Vec<usize> = (0..n).collect();
    let mut s = seed | 1;
    for i in (1..n).rev() {
        s = s
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let j = (s >> 33) as usize % (i + 1);
        idx.swap(i, j);
    }
    idx.truncate(k);
    idx.sort_unstable();
    idx
}

fn bench_decode(c: &mut Criterion) {
    let mut group = c.benchmark_group("decode_from_random_k");
    group.warm_up_time(Duration::from_secs(1));
    group.measurement_time(Duration::from_secs(3));

    for &l in LENS {
        for &n in NS {
            let (k, m) = split(n);
            let keep = survivors(n, k, 0xD0D0 ^ n as u64);
            let data_survivors = keep.iter().filter(|&&j| j < k).count();
            let id = format!(
                "n={n}/k={k}/shard={}/data_surv={data_survivors}",
                human_shard(l)
            );
            group.throughput(Throughput::Bytes((k * l * 2) as u64));

            // ---- ours: F_12289 matrix decode ----
            let data: Vec<u16> = (0..k * l).map(|i| ((i * 3571) % 12289) as u16).collect();
            let enc = MatrixEncoder::new(k, n);
            let mut code = vec![0u16; n * l];
            enc.encode(&data, l, &mut code);

            let mut received = vec![0u16; k * l];
            for (a, &j) in keep.iter().enumerate() {
                received[a * l..(a + 1) * l].copy_from_slice(&code[j * l..(j + 1) * l]);
            }

            let dec = MatrixDecoder::new(k, n, &keep).expect("submatrix invertible");
            let mut out = vec![0u16; k * l];

            group.bench_with_input(
                BenchmarkId::new("matrix apply O(k^2), inverse cached", &id),
                &n,
                |b, _| b.iter(|| dec.decode(black_box(&received), l, black_box(&mut out))),
            );

            group.bench_with_input(
                BenchmarkId::new("matrix invert+apply O(k^3+k^2)", &id),
                &n,
                |b, _| {
                    b.iter(|| {
                        let d = MatrixDecoder::new(k, n, black_box(&keep)).unwrap();
                        d.decode(&received, l, black_box(&mut out));
                    })
                },
            );

            // ---- commonware, unmodified, reference only ----
            let shard_bytes = l * 2;
            if Encoder::supports(k, m) {
                let mut enc = Encoder::new(k, m, shard_bytes).expect("encoder");
                let orig: Vec<Vec<u8>> = (0..k)
                    .map(|i| vec![(i % 251) as u8; shard_bytes])
                    .collect();
                for s in &orig {
                    enc.add_original_shard(s).unwrap();
                }
                let recovery: Vec<Vec<u8>> = {
                    let r = enc.encode().unwrap();
                    r.recovery_iter().map(|s| s.to_vec()).collect()
                };

                let mut dec = Decoder::new(k, m, shard_bytes).expect("decoder");
                group.bench_with_input(
                    BenchmarkId::new("commonware GF(2^16) reference", &id),
                    &n,
                    |b, _| {
                        b.iter(|| {
                            for &j in &keep {
                                if j < k {
                                    dec.add_original_shard(j, &orig[j]).unwrap();
                                } else {
                                    dec.add_recovery_shard(j - k, &recovery[j - k]).unwrap();
                                }
                            }
                            black_box(dec.decode().unwrap());
                        })
                    },
                );
            }
        }
    }
    group.finish();
}

fn report_op_counts() {
    println!("\n  decode work, n = 3f+1, k = n-2f survivors chosen at random\n");
    println!(
        "  {:>5} {:>5} {:>16} {:>18}",
        "n", "k", "apply k^2 (shard)", "invert k^3 (scalar)"
    );
    for &n in NS {
        let (k, _) = split(n);
        println!(
            "  {:>5} {:>5} {:>16} {:>18}",
            n,
            k,
            matrix_decode_ops(k),
            k * k * k
        );
    }
    println!();
}

fn setup(c: &mut Criterion) {
    report_op_counts();
    bench_decode(c);
}

criterion_group!(benches, setup);
criterion_main!(benches);
