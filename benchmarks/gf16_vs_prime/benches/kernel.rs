//! The Reed-Solomon inner loop, GF(2^16) vs prime fields.
//!
//! Every entry does the same logical work: scale a buffer of `n` field
//! elements by one constant. Throughput is reported in **elements per second**
//! so the fields compare on equal algebraic terms; the fact that a GF(2^16)
//! element carries a full 16 payload bits while `F_12289` carries 13.58 is
//! accounted for separately (see `--bin verify` and the README).
//!
//! ```text
//! cargo bench
//! ```

use std::hint::black_box;
use std::time::Duration;

use commonware_cryptography::reed_solomon::engine::{
    tables, Engine, Naive, NoSimd, SHARD_CHUNK_BYTES,
};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use gf16_vs_prime::prime::{self, P_LARGE, P_SMALL};

/// Element counts: one comfortably inside L2, one that must stream from L3/RAM.
/// Both are multiples of 32 so every lane width divides evenly.
const SIZES: &[usize] = &[32 * 1024, 512 * 1024];

fn label(n: usize) -> String {
    let bytes = n * 2;
    if bytes >= 1024 * 1024 {
        format!("{}Kelem/{}MiB", n / 1024, bytes / (1024 * 1024))
    } else {
        format!("{}Kelem/{}KiB", n / 1024, bytes / 1024)
    }
}

fn gf16_buffer(n: usize) -> Vec<[u8; SHARD_CHUNK_BYTES]> {
    // 32 field elements per 64-byte chunk.
    (0..n / 32)
        .map(|c| core::array::from_fn(|i| (c.wrapping_mul(31).wrapping_add(i)) as u8))
        .collect()
}

fn bench_scale(c: &mut Criterion) {
    let exp_log = tables::get_exp_log();
    // An arbitrary non-trivial multiplier; the engines take its logarithm.
    let m: u16 = 0xB1E5;
    let log_m = exp_log.log[m as usize];

    let naive = Naive::new();
    let nosimd = NoSimd::new();

    let mut group = c.benchmark_group("scale_by_constant");
    group.warm_up_time(Duration::from_secs(1));
    group.measurement_time(Duration::from_secs(3));

    for &n in SIZES {
        let id = label(n);
        group.throughput(Throughput::Elements(n as u64));

        // ---- GF(2^16), commonware's own engines ----
        #[cfg(target_arch = "x86_64")]
        {
            use commonware_cryptography::reed_solomon::engine::Avx2;
            if is_x86_feature_detected!("avx2") {
                let avx2 = Avx2::new();
                let mut buf = gf16_buffer(n);
                group.bench_with_input(
                    BenchmarkId::new("GF(2^16) commonware Avx2", &id),
                    &n,
                    |b, _| b.iter(|| avx2.mul(black_box(&mut buf), log_m)),
                );
            }
        }
        {
            let mut buf = gf16_buffer(n);
            group.bench_with_input(
                BenchmarkId::new("GF(2^16) commonware NoSimd", &id),
                &n,
                |b, _| b.iter(|| nosimd.mul(black_box(&mut buf), log_m)),
            );
        }
        {
            let mut buf = gf16_buffer(n);
            group.bench_with_input(
                BenchmarkId::new("GF(2^16) commonware Naive", &id),
                &n,
                |b, _| b.iter(|| naive.mul(black_box(&mut buf), log_m)),
            );
        }

        // ---- F_12289: the prime field at its best (16-bit lanes, Shoup) ----
        {
            let mut buf: Vec<u16> = (0..n).map(|i| (i % P_SMALL as usize) as u16).collect();
            group.bench_with_input(BenchmarkId::new("F_12289 avx2 Shoup", &id), &n, |b, _| {
                b.iter(|| prime::scale_small(black_box(&mut buf), 9001))
            });
        }
        {
            let mut buf: Vec<u16> = (0..n).map(|i| (i % P_SMALL as usize) as u16).collect();
            group.bench_with_input(BenchmarkId::new("F_12289 scalar Shoup", &id), &n, |b, _| {
                b.iter(|| prime::scale_scalar_small_shoup(black_box(&mut buf), 9001))
            });
        }

        // ---- F_65521: same magnitude as GF(2^16), forced into 32-bit lanes ----
        {
            let mut buf: Vec<u32> = (0..n).map(|i| (i as u32) % P_LARGE).collect();
            group.bench_with_input(BenchmarkId::new("F_65521 avx2 Shoup", &id), &n, |b, _| {
                b.iter(|| prime::scale_large(black_box(&mut buf), 40009))
            });
        }
        {
            let mut buf: Vec<u32> = (0..n).map(|i| (i as u32) % P_LARGE).collect();
            group.bench_with_input(BenchmarkId::new("F_65521 scalar rem", &id), &n, |b, _| {
                b.iter(|| prime::scale_scalar_large(black_box(&mut buf), 40009))
            });
        }
    }
    group.finish();
}

criterion_group!(benches, bench_scale);
criterion_main!(benches);
