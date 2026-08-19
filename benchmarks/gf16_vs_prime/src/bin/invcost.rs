//! Time the O(k^3) submatrix inversion on its own, with no shard work at all,
//! to check whether it depends on shard length (it must not: `l` is not a
//! parameter of `MatrixDecoder::new`).
use std::time::Instant;
use gf16_vs_prime::rs::MatrixDecoder;

fn survivors(n: usize, k: usize, seed: u64) -> Vec<usize> {
    let mut idx: Vec<usize> = (0..n).collect();
    let mut s = seed | 1;
    for i in (1..n).rev() {
        s = s.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        let j = (s >> 33) as usize % (i + 1);
        idx.swap(i, j);
    }
    idx.truncate(k);
    idx.sort_unstable();
    idx
}

fn main() {
    println!("{:>5} {:>5} {:>12} {:>14} {:>12}", "n", "k", "invert", "per k^3 (ns)", "vs prev");
    let mut prev: Option<(usize, f64)> = None;
    for n in [4usize, 16, 32, 64, 128, 256] {
        let f = (n - 1) / 3;
        let k = n - 2 * f;
        let keep = survivors(n, k, 0xD0D0 ^ n as u64);

        // warm up
        for _ in 0..3 { std::hint::black_box(MatrixDecoder::new(k, n, &keep)); }

        let reps = if k <= 12 { 2000 } else { 200 };
        let t = Instant::now();
        for _ in 0..reps {
            std::hint::black_box(MatrixDecoder::new(k, n, &keep).unwrap());
        }
        let per = t.elapsed().as_secs_f64() / reps as f64;

        let ratio = match prev {
            Some((pk, pt)) => format!("{:.2}x (k^3 -> {:.2}x)", per / pt,
                                      (k as f64 / pk as f64).powi(3)),
            None => "-".to_string(),
        };
        println!("{:>5} {:>5} {:>12} {:>14.2} {:>12}",
                 n, k,
                 if per < 1e-3 { format!("{:.1} us", per * 1e6) } else { format!("{:.2} ms", per * 1e3) },
                 per * 1e9 / (k * k * k) as f64,
                 ratio);
        prev = Some((k, per));
    }
}
