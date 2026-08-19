//! Verification pass, run before trusting any timing number.
//!
//! 1. commonware's table-driven GF(2^16) engines are checked against a
//!    from-scratch carry-less-multiply-and-reduce reference.
//! 2. The AVX2 and scalar engines are checked against each other.
//! 3. The prime-field Shoup kernels are checked against plain `%`.
//! 4. The structural limits (NTT length, packing loss) are printed.
//!
//! ```text
//! cargo run --release --bin verify
//! ```

use commonware_cryptography::reed_solomon::engine::{
    tables, Engine, Naive, NoSimd, SHARD_CHUNK_BYTES,
};
use gf16_vs_prime::{
    gf_mul_cantor_reference,
    gf_mul_reference,
    ntt_limits::{max_ntt_len, packing_overhead, payload_bits, two_adicity},
    prime::{self, P_LARGE, P_SMALL},
};

/// Lay out 32 field elements in the split low/high form the engines expect:
/// first 32 bytes are the low halves, last 32 the high halves.
fn pack(elems: &[u16; 32]) -> [u8; SHARD_CHUNK_BYTES] {
    let mut out = [0u8; SHARD_CHUNK_BYTES];
    for (i, e) in elems.iter().enumerate() {
        out[i] = *e as u8;
        out[32 + i] = (*e >> 8) as u8;
    }
    out
}

fn unpack(chunk: &[u8; SHARD_CHUNK_BYTES]) -> [u16; 32] {
    let mut out = [0u16; 32];
    for (i, o) in out.iter_mut().enumerate() {
        *o = chunk[i] as u16 | (chunk[32 + i] as u16) << 8;
    }
    out
}

fn check_engine<E: Engine>(name: &str, engine: &E, phi_inv: &[u16]) -> bool {
    let exp_log = tables::get_exp_log();
    let mut failures = 0usize;
    let mut checked = 0usize;

    // A spread of multipliers, including the awkward ones.
    for &m in &[1u16, 2, 3, 255, 256, 4097, 12289, 32768, 65535] {
        let log_m = exp_log.log[m as usize];

        let elems: [u16; 32] = core::array::from_fn(|i| (i as u16).wrapping_mul(2477).wrapping_add(7));
        let mut buf = [pack(&elems)];
        engine.mul(&mut buf, log_m);
        let got = unpack(&buf[0]);

        for (i, (&input, &output)) in elems.iter().zip(got.iter()).enumerate() {
            let want = gf_mul_cantor_reference(input, m, phi_inv);
            checked += 1;
            if want != output {
                if failures < 5 {
                    println!(
                        "   MISMATCH {name}: {input} * {m} = {want} (reference), got {output} at lane {i}"
                    );
                }
                failures += 1;
            }
        }
    }
    println!(
        "   {name:<8} {checked} products checked against carry-less reference: {}",
        if failures == 0 { "ALL MATCH".to_string() } else { format!("{failures} FAILURES") }
    );
    failures == 0
}

/// Independent check that the Cantor basis is what the docs claim: `b_0 = 1`
/// and `b_(i-1) = b_i^2 + b_i` in the polynomial basis. This is the property
/// that makes the additive FFT's subspace polynomials work.
fn check_cantor_basis() -> bool {
    let mut ok = gf16_vs_prime::CANTOR_BASIS[0] == 1;
    for i in 1..16 {
        let b = gf16_vs_prime::CANTOR_BASIS[i];
        let lhs = gf_mul_reference(b, b) ^ b;
        ok &= lhs == gf16_vs_prime::CANTOR_BASIS[i - 1];
    }
    println!(
        "   Cantor basis: b_0 == 1 and b_(i-1) == b_i^2 + b_i for all i: {}",
        if ok { "HOLDS" } else { "VIOLATED" }
    );
    ok
}

fn check_prime_small() -> bool {
    let c = 9001u16;
    let n = 1 << 12;
    let src: Vec<u16> = (0..n).map(|i| ((i * 7919) % P_SMALL as usize) as u16).collect();

    let mut want = src.clone();
    for v in want.iter_mut() {
        *v = ((*v as u32 * c as u32) % P_SMALL as u32) as u16;
    }

    let mut shoup = src.clone();
    prime::scale_scalar_small_shoup(&mut shoup, c);
    let scalar_ok = shoup == want;

    let mut simd = src;
    prime::scale_small(&mut simd, c);
    let simd_ok = simd == want;

    println!("   p={P_SMALL:<6} scalar Shoup vs `%`: {}, AVX2 Shoup vs `%`: {}",
        if scalar_ok { "MATCH" } else { "MISMATCH" },
        if simd_ok { "MATCH" } else { "MISMATCH" });
    scalar_ok && simd_ok
}

fn check_prime_large() -> bool {
    let c = 40009u32;
    let n = 1 << 12;
    let src: Vec<u32> = (0..n).map(|i| ((i * 7919) as u32) % P_LARGE).collect();

    let mut want = src.clone();
    for v in want.iter_mut() {
        *v = (*v * c) % P_LARGE;
    }

    let mut simd = src;
    prime::scale_large(&mut simd, c);
    let ok = simd == want;
    println!("   p={P_LARGE:<6} AVX2 Shoup vs `%`: {}", if ok { "MATCH" } else { "MISMATCH" });
    ok
}

fn main() {
    println!("== 1. commonware's GF(2^16) engines vs a from-scratch field reference ==");
    println!("   field polynomial 0x{GF:X} = x^16 + x^5 + x^3 + x^2 + 1", GF = gf16_vs_prime::GF_POLYNOMIAL);
    println!("   elements are stored as Cantor-basis coordinates, so the reference");
    println!("   multiplies as phi^-1(phi(a) * phi(b)) in the polynomial basis");
    let phi_inv = gf16_vs_prime::phi_inverse_table();
    let mut ok = check_cantor_basis();
    ok &= check_engine("Naive", &Naive::new(), &phi_inv);
    ok &= check_engine("NoSimd", &NoSimd::new(), &phi_inv);
    #[cfg(target_arch = "x86_64")]
    {
        use commonware_cryptography::reed_solomon::engine::Avx2;
        if is_x86_feature_detected!("avx2") {
            ok &= check_engine("Avx2", &Avx2::new(), &phi_inv);
        } else {
            println!("   Avx2     not available on this CPU, skipped");
        }
    }

    println!("\n== 2. prime-field kernels vs plain `%` ==");
    ok &= check_prime_small();
    ok &= check_prime_large();

    println!("\n== 3. structural limits ==");
    println!(
        "   {:<10} {:>10} {:>16} {:>14} {:>16}",
        "field", "elements", "max radix-2 NTT", "bits/element", "packing overhead"
    );
    println!(
        "   {:<10} {:>10} {:>16} {:>14} {:>16}",
        "GF(2^16)", 65536, "65536 (additive)", "16.000", "0.00%"
    );
    for p in [P_SMALL as u32, 40961, P_LARGE] {
        println!(
            "   {:<10} {:>10} {:>16} {:>14.3} {:>15.2}%",
            format!("F_{p}"),
            p,
            format!("{} (2^{})", max_ntt_len(p), two_adicity(p)),
            payload_bits(p),
            packing_overhead(p) * 100.0
        );
    }

    println!("\n{}", if ok { "VERIFIED: all implementations agree" } else { "FAILED" });
    if !ok {
        std::process::exit(1);
    }
}
