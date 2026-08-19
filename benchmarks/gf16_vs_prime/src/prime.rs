//! Prime-field counterparts to commonware's GF(2^16) kernel.
//!
//! The operation under test is the one commonware's `Engine::mul` performs and
//! the one that dominates every Reed-Solomon inner loop, FFT-based or not:
//!
//! ```text
//! for i in 0..n { x[i] = c * x[i] }        // c fixed across the whole buffer
//! ```
//!
//! Because `c` is a *constant* over the buffer, both sides get to hoist
//! per-multiplier precomputation out of the loop. That is what lets
//! GF(2^16) build its PSHUFB tables once, and it is what lets a prime field
//! use **Shoup's** algorithm rather than a general Montgomery multiply — so
//! this is the prime field's best case, not a strawman.
//!
//! # Shoup multiplication by a constant
//!
//! For fixed `w`, precompute `w' = floor(w * 2^B / p)`. Then for `x < p`:
//!
//! ```text
//! q = floor(x * w' / 2^B)      // high half of a B-bit multiply
//! r = x*w - q*p                // low half; r is in [0, 2p)
//! if r >= p { r -= p }
//! ```
//!
//! With `B = 16` this needs `2p < 2^16`, i.e. **p < 32768**. That constraint
//! is the whole story for lane width:
//!
//! * `p = 12289` (the most NTT-friendly prime in range) fits, so it runs in
//!   16-bit lanes: 16 elements per AVX2 register.
//! * `p = 65521` (the largest prime below 2^16, the "same size as GF(2^16)"
//!   choice) does not fit, and must fall back to 32-bit lanes: 8 elements per
//!   register, with 32-bit multiplies that AVX2 supports far less well.

#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

/// Most 2-adic prime below 2^16 that still fits Shoup's 16-bit constraint:
/// `12289 - 1 = 2^12 * 3`, so it supports a radix-2 NTT up to 4096 points.
pub const P_SMALL: u16 = 12289;

/// Largest prime below 2^16. `65521 - 1 = 2^4 * 3^2 * 5 * 7 * 13`, so its
/// radix-2 NTT tops out at **16** points — unusable as a coding field, but it
/// is the natural "same magnitude as GF(2^16)" comparison for the raw kernel.
pub const P_LARGE: u32 = 65521;

// ======================================================================
// scalar reference implementations

/// `x[i] = c * x[i] mod p`, scalar, 16-bit prime.
pub fn scale_scalar_small(x: &mut [u16], c: u16) {
    let p = P_SMALL as u32;
    let c = c as u32;
    for v in x.iter_mut() {
        *v = ((*v as u32 * c) % p) as u16;
    }
}

/// `x[i] = c * x[i] mod p`, scalar, using Shoup so the scalar path is not
/// penalised by a hardware division the SIMD path avoids.
pub fn scale_scalar_small_shoup(x: &mut [u16], c: u16) {
    let p = P_SMALL;
    let cp = (((c as u32) << 16) / p as u32) as u16;
    for v in x.iter_mut() {
        let q = ((*v as u32 * cp as u32) >> 16) as u16;
        let mut r = v.wrapping_mul(c).wrapping_sub(q.wrapping_mul(p));
        if r >= p {
            r -= p;
        }
        *v = r;
    }
}

/// `x[i] = c * x[i] mod p`, scalar, 65521.
pub fn scale_scalar_large(x: &mut [u32], c: u32) {
    for v in x.iter_mut() {
        *v = (*v * c) % P_LARGE;
    }
}

// ======================================================================
// AVX2 - 16-bit lanes, p = 12289

/// `x[i] = c * x[i] mod 12289` over AVX2, 16 elements per register.
///
/// # Safety
/// Caller must ensure AVX2 is available. `x.len()` must be a multiple of 16.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
pub unsafe fn scale_avx2_small(x: &mut [u16], c: u16) {
    debug_assert_eq!(x.len() % 16, 0);
    let p = P_SMALL;
    // Shoup precomputation, hoisted out of the loop exactly as GF(2^16) hoists
    // its multiplication tables.
    let cp = (((c as u32) << 16) / p as u32) as u16;

    let v_c = _mm256_set1_epi16(c as i16);
    let v_cp = _mm256_set1_epi16(cp as i16);
    let v_p = _mm256_set1_epi16(p as i16);

    for chunk in x.chunks_exact_mut(16) {
        let ptr = chunk.as_mut_ptr().cast::<__m256i>();
        let v = _mm256_loadu_si256(ptr);

        // q = mulhi_u16(v, c'); r = v*c - q*p, landing in [0, 2p)
        let q = _mm256_mulhi_epu16(v, v_cp);
        let lo = _mm256_mullo_epi16(v, v_c);
        let qp = _mm256_mullo_epi16(q, v_p);
        let r = _mm256_sub_epi16(lo, qp);

        // conditional subtract: min_epu16(r, r - p) picks r when r < p, since
        // the wrapped r - p is then huge.
        let r = _mm256_min_epu16(r, _mm256_sub_epi16(r, v_p));

        _mm256_storeu_si256(ptr, r);
    }
}

// ======================================================================
// AVX2 - 32-bit lanes, p = 65521

/// `x[i] = c * x[i] mod 65521` over AVX2, 8 elements per register.
///
/// AVX2 has no 32-bit high-multiply, so the Shoup quotient is formed with
/// `_mm256_mul_epu32` on the even and odd lanes separately and shuffled back
/// together — the structural cost of moving above `p = 32768`.
///
/// # Safety
/// Caller must ensure AVX2 is available. `x.len()` must be a multiple of 8.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
pub unsafe fn scale_avx2_large(x: &mut [u32], c: u32) {
    debug_assert_eq!(x.len() % 8, 0);
    let p = P_LARGE;
    let cp = (((c as u64) << 32) / p as u64) as u32;

    let v_c = _mm256_set1_epi32(c as i32);
    let v_cp = _mm256_set1_epi32(cp as i32);
    let v_p = _mm256_set1_epi32(p as i32);

    for chunk in x.chunks_exact_mut(8) {
        let ptr = chunk.as_mut_ptr().cast::<__m256i>();
        let v = _mm256_loadu_si256(ptr);

        // 32x32->64 products on even lanes, then on odd lanes, to recover the
        // high halves that mulhi would have given us for free at 16 bits.
        let even = _mm256_mul_epu32(v, v_cp);
        let odd = _mm256_mul_epu32(_mm256_srli_epi64(v, 32), _mm256_srli_epi64(v_cp, 32));
        // take the high 32 bits of each 64-bit product
        let q = _mm256_blend_epi32(
            _mm256_srli_epi64(even, 32),
            odd,
            0b1010_1010,
        );

        let lo = _mm256_mullo_epi32(v, v_c);
        let qp = _mm256_mullo_epi32(q, v_p);
        let r = _mm256_sub_epi32(lo, qp);

        let r = _mm256_min_epu32(r, _mm256_sub_epi32(r, v_p));

        _mm256_storeu_si256(ptr, r);
    }
}

// ======================================================================
// dispatch helpers

/// Runtime-dispatched `x[i] *= c mod 12289`.
pub fn scale_small(x: &mut [u16], c: u16) {
    #[cfg(target_arch = "x86_64")]
    {
        if is_x86_feature_detected!("avx2") && x.len() % 16 == 0 {
            // SAFETY: feature checked above, length checked above.
            unsafe { scale_avx2_small(x, c) };
            return;
        }
    }
    scale_scalar_small_shoup(x, c);
}

/// Runtime-dispatched `x[i] *= c mod 65521`.
pub fn scale_large(x: &mut [u32], c: u32) {
    #[cfg(target_arch = "x86_64")]
    {
        if is_x86_feature_detected!("avx2") && x.len() % 8 == 0 {
            // SAFETY: feature checked above, length checked above.
            unsafe { scale_avx2_large(x, c) };
            return;
        }
    }
    scale_scalar_large(x, c);
}
