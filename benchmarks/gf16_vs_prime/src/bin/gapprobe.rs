//! Measure the apply-only vs invert+apply gap directly, alternating the two so
//! drift affects both equally, at the shard size where I mis-attributed it.
use std::time::Instant;
use gf16_vs_prime::rs::{MatrixDecoder, MatrixEncoder};

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
    for &l in &[512usize, 8192, 131_072] {
        let (n, k) = (256usize, 86usize);
        let keep = survivors(n, k, 0xD0D0 ^ n as u64);
        let data: Vec<u16> = (0..k * l).map(|i| ((i * 3571) % 12289) as u16).collect();
        let enc = MatrixEncoder::new(k, n);
        let mut code = vec![0u16; n * l];
        enc.encode(&data, l, &mut code);
        let mut received = vec![0u16; k * l];
        for (a, &j) in keep.iter().enumerate() {
            received[a * l..(a + 1) * l].copy_from_slice(&code[j * l..(j + 1) * l]);
        }
        let dec = MatrixDecoder::new(k, n, &keep).unwrap();
        let mut out = vec![0u16; k * l];

        let reps = if l >= 131_072 { 12 } else { 60 };
        let (mut ta, mut tb) = (0f64, 0f64);
        for _ in 0..reps {
            let t = Instant::now();
            dec.decode(std::hint::black_box(&received), l, std::hint::black_box(&mut out));
            ta += t.elapsed().as_secs_f64();

            let t = Instant::now();
            let d = MatrixDecoder::new(k, n, std::hint::black_box(&keep)).unwrap();
            d.decode(&received, l, std::hint::black_box(&mut out));
            tb += t.elapsed().as_secs_f64();
        }
        let (a, b) = (ta / reps as f64, tb / reps as f64);
        println!(
            "shard={:>7}  apply {:>9.3} ms   invert+apply {:>9.3} ms   gap {:>8.3} ms   (isolated invert 0.897 ms)",
            format!("{}KiB", l * 2 / 1024), a * 1e3, b * 1e3, (b - a) * 1e3
        );
    }
}
