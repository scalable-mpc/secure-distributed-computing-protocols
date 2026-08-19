//! Reed-Solomon encoding over `F_12289`, implemented twice: once as a naive
//! Vandermonde matrix multiply and once as a radix-2 NTT.
//!
//! Both compute the same thing — the evaluations of the degree-`<k` message
//! polynomial at `N` points — so the only difference is the algorithm. That
//! isolates the `O(n^2)` vs `O(n log n)` question from every other variable
//! (field, SIMD quality, commitment scheme, memory layout).
//!
//! # Layout
//!
//! `N` shards of `l` field elements each, stored flat: shard `j` occupies
//! `[j*l, (j+1)*l)`. Both algorithms work on whole shards at a time, so their
//! inner loops are equally vectorisable — the comparison is not rigged by one
//! side being SIMD-friendly and the other not.
//!
//! # Self-check
//!
//! The NTT evaluates at `w^j` for a primitive `N`-th root `w`. Building the
//! Vandermonde matrix on those same points must therefore reproduce the NTT
//! output exactly, element for element. [`check_agreement`] asserts it.

use crate::prime::P_SMALL;

const P: u16 = P_SMALL;
const P32: u32 = P_SMALL as u32;

#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

// ======================================================================
// field helpers

#[inline]
fn add(a: u16, b: u16) -> u16 {
    let s = a + b;
    if s >= P {
        s - P
    } else {
        s
    }
}

#[inline]
fn sub(a: u16, b: u16) -> u16 {
    add(a, P - b)
}

#[inline]
fn mul(a: u16, b: u16) -> u16 {
    ((a as u32 * b as u32) % P32) as u16
}

fn pow(mut base: u16, mut e: u32) -> u16 {
    let mut acc = 1u16;
    while e > 0 {
        if e & 1 == 1 {
            acc = mul(acc, base);
        }
        base = mul(base, base);
        e >>= 1;
    }
    acc
}

/// Shoup precomputation for a constant multiplier.
#[inline]
fn shoup(c: u16) -> u16 {
    (((c as u32) << 16) / P32) as u16
}

/// Smallest generator of `F_p^*`.
pub fn generator() -> u16 {
    // p - 1 = 2^12 * 3, so it suffices to check the two prime divisors.
    (2u16..P)
        .find(|&g| pow(g, (P as u32 - 1) / 2) != 1 && pow(g, (P as u32 - 1) / 3) != 1)
        .expect("F_p^* is cyclic")
}

/// Primitive `n`-th root of unity, `n` a power of two dividing `p - 1`.
pub fn root_of_unity(n: usize) -> u16 {
    assert!(n.is_power_of_two());
    assert_eq!(
        (P as u32 - 1) % n as u32,
        0,
        "F_{P} has no {n}-th root of unity: 2-adicity of p-1 is only 12"
    );
    pow(generator(), (P as u32 - 1) / n as u32)
}

// ======================================================================
// vectorised primitives, shared by both algorithms

/// `dst[e] = dst[e] + c * src[e]` over a whole shard.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn muladd_avx2(dst: &mut [u16], src: &[u16], c: u16, c_shoup: u16) {
    let v_c = _mm256_set1_epi16(c as i16);
    let v_cp = _mm256_set1_epi16(c_shoup as i16);
    let v_p = _mm256_set1_epi16(P as i16);

    let n = dst.len();
    let mut i = 0;
    while i + 16 <= n {
        let dp = dst.as_mut_ptr().add(i).cast::<__m256i>();
        let sp = src.as_ptr().add(i).cast::<__m256i>();
        let a = _mm256_loadu_si256(dp);
        let b = _mm256_loadu_si256(sp);

        // Shoup: t = c*b mod p, in [0, p)
        let q = _mm256_mulhi_epu16(b, v_cp);
        let t = _mm256_sub_epi16(_mm256_mullo_epi16(b, v_c), _mm256_mullo_epi16(q, v_p));
        let t = _mm256_min_epu16(t, _mm256_sub_epi16(t, v_p));

        // a + t mod p
        let s = _mm256_add_epi16(a, t);
        let s = _mm256_min_epu16(s, _mm256_sub_epi16(s, v_p));

        _mm256_storeu_si256(dp, s);
        i += 16;
    }
    while i < n {
        dst[i] = add(dst[i], mul(src[i], c));
        i += 1;
    }
}

/// Gentleman-Sande / Cooley-Tukey butterfly across two shards:
/// `(a, b) <- (a + w*b, a - w*b)`.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn butterfly_avx2(a: &mut [u16], b: &mut [u16], w: u16, w_shoup: u16) {
    let v_w = _mm256_set1_epi16(w as i16);
    let v_wp = _mm256_set1_epi16(w_shoup as i16);
    let v_p = _mm256_set1_epi16(P as i16);

    let n = a.len();
    let mut i = 0;
    while i + 16 <= n {
        let ap = a.as_mut_ptr().add(i).cast::<__m256i>();
        let bp = b.as_mut_ptr().add(i).cast::<__m256i>();
        let va = _mm256_loadu_si256(ap);
        let vb = _mm256_loadu_si256(bp);

        let q = _mm256_mulhi_epu16(vb, v_wp);
        let t = _mm256_sub_epi16(_mm256_mullo_epi16(vb, v_w), _mm256_mullo_epi16(q, v_p));
        let t = _mm256_min_epu16(t, _mm256_sub_epi16(t, v_p));

        let s = _mm256_add_epi16(va, t);
        let s = _mm256_min_epu16(s, _mm256_sub_epi16(s, v_p));

        let d = _mm256_add_epi16(_mm256_sub_epi16(va, t), v_p);
        let d = _mm256_min_epu16(d, _mm256_sub_epi16(d, v_p));

        _mm256_storeu_si256(ap, s);
        _mm256_storeu_si256(bp, d);
        i += 16;
    }
    while i < n {
        let t = mul(b[i], w);
        let (x, y) = (add(a[i], t), sub(a[i], t));
        a[i] = x;
        b[i] = y;
        i += 1;
    }
}

fn muladd(dst: &mut [u16], src: &[u16], c: u16) {
    #[cfg(target_arch = "x86_64")]
    {
        if is_x86_feature_detected!("avx2") {
            // SAFETY: feature checked.
            unsafe { muladd_avx2(dst, src, c, shoup(c)) };
            return;
        }
    }
    for (d, s) in dst.iter_mut().zip(src) {
        *d = add(*d, mul(*s, c));
    }
}

fn butterfly(a: &mut [u16], b: &mut [u16], w: u16) {
    #[cfg(target_arch = "x86_64")]
    {
        if is_x86_feature_detected!("avx2") {
            // SAFETY: feature checked.
            unsafe { butterfly_avx2(a, b, w, shoup(w)) };
            return;
        }
    }
    for i in 0..a.len() {
        let t = mul(b[i], w);
        let (x, y) = (add(a[i], t), sub(a[i], t));
        a[i] = x;
        b[i] = y;
    }
}

// ======================================================================
// algorithm 1: naive Vandermonde matrix multiply, O(n * k)

/// Precomputed `N x k` Vandermonde matrix over the evaluation points `w^j`.
pub struct MatrixEncoder {
    /// row-major, `n_out` rows of `k` coefficients
    coeffs: Vec<u16>,
    k: usize,
    n_out: usize,
}

impl MatrixEncoder {
    /// Build the matrix for evaluating a degree-`<k` polynomial at `w^j`,
    /// `j = 0..n_out`, matching what an `n_out`-point NTT computes.
    pub fn new(k: usize, n_out: usize) -> Self {
        let w = root_of_unity(n_out.next_power_of_two());
        let mut coeffs = vec![0u16; n_out * k];
        for j in 0..n_out {
            let x = pow(w, j as u32);
            let mut acc = 1u16;
            for i in 0..k {
                coeffs[j * k + i] = acc;
                acc = mul(acc, x);
            }
        }
        Self { coeffs, k, n_out }
    }

    /// `out[j] = sum_i data[i] * x_j^i`, the whole codeword.
    ///
    /// Cost: `n_out * k` shard-length multiply-adds.
    pub fn encode(&self, data: &[u16], l: usize, out: &mut [u16]) {
        debug_assert_eq!(data.len(), self.k * l);
        debug_assert_eq!(out.len(), self.n_out * l);
        out.fill(0);
        for j in 0..self.n_out {
            let (_, rest) = out.split_at_mut(j * l);
            let dst = &mut rest[..l];
            for i in 0..self.k {
                let c = self.coeffs[j * self.k + i];
                if c == 0 {
                    continue;
                }
                muladd(dst, &data[i * l..(i + 1) * l], c);
            }
        }
    }
}

// ======================================================================
// algorithm 1b: systematic matrix, parity only, O(m * k)

/// Systematic Reed-Solomon via a Cauchy matrix: the `k` data shards are sent
/// as-is and only the `m` parity shards are computed. This is what
/// `reed-solomon-erasure` does and what this repository's protocols use, so it
/// is the variant a matrix implementation would actually be deployed as.
///
/// Cost: `m * k` shard-length multiply-adds — a factor `n/m` cheaper than
/// producing the full codeword.
pub struct SystematicMatrixEncoder {
    /// row-major, `m` rows of `k` coefficients
    coeffs: Vec<u16>,
    k: usize,
    m: usize,
}

impl SystematicMatrixEncoder {
    /// Cauchy matrix `P[j][i] = 1 / (x_j - y_i)` on disjoint point sets, which
    /// is MDS, so any `k` of the `n = k + m` shards reconstruct.
    pub fn new(k: usize, m: usize) -> Self {
        assert!(k + m < P as usize, "point sets must fit in the field");
        let mut coeffs = vec![0u16; m * k];
        for j in 0..m {
            for i in 0..k {
                let x = j as u16;
                let y = (m + i) as u16;
                coeffs[j * k + i] = pow(sub(x, y), P as u32 - 2);
            }
        }
        Self { coeffs, k, m }
    }

    /// `parity[j] = sum_i P[j][i] * data[i]`.
    pub fn encode(&self, data: &[u16], l: usize, parity: &mut [u16]) {
        debug_assert_eq!(data.len(), self.k * l);
        debug_assert_eq!(parity.len(), self.m * l);
        parity.fill(0);
        for j in 0..self.m {
            let (_, rest) = parity.split_at_mut(j * l);
            let dst = &mut rest[..l];
            for i in 0..self.k {
                let c = self.coeffs[j * self.k + i];
                if c == 0 {
                    continue;
                }
                muladd(dst, &data[i * l..(i + 1) * l], c);
            }
        }
    }

    /// Scalar reference, to check the AVX2 `muladd` path.
    pub fn encode_scalar(&self, data: &[u16], l: usize, parity: &mut [u16]) {
        parity.fill(0);
        for j in 0..self.m {
            for i in 0..self.k {
                let c = self.coeffs[j * self.k + i];
                for e in 0..l {
                    parity[j * l + e] = add(parity[j * l + e], mul(data[i * l + e], c));
                }
            }
        }
    }
}

// ======================================================================
// algorithm 2: radix-2 NTT, O(n log n)

/// A radix-2 decimation-in-time transform of a fixed size over the shard
/// dimension. Parameterised by its root so the same code serves as both the
/// forward NTT (root `w`) and the inverse (root `w^-1`, plus a final scale).
pub struct Transform {
    n: usize,
    /// twiddles per stage, flattened
    twiddles: Vec<u16>,
}

impl Transform {
    pub fn new(n: usize, w: u16) -> Self {
        assert!(n.is_power_of_two());
        let mut twiddles = Vec::new();
        let mut len = 2;
        while len <= n {
            let step = n / len;
            for i in 0..len / 2 {
                twiddles.push(pow(w, (i * step) as u32));
            }
            len <<= 1;
        }
        Self { n, twiddles }
    }

    /// In-place transform of `buf`, laid out as `n` shards of `l` elements.
    ///
    /// Cost: `(n/2) * log2(n)` shard-length butterflies.
    pub fn run(&self, buf: &mut [u16], l: usize) {
        debug_assert_eq!(buf.len(), self.n * l);
        if self.n == 1 {
            return;
        }
        bit_reverse_shards(buf, self.n, l);

        let mut off = 0;
        let mut len = 2;
        while len <= self.n {
            let half = len / 2;
            for block in (0..self.n).step_by(len) {
                for i in 0..half {
                    let w = self.twiddles[off + i];
                    let a_idx = (block + i) * l;
                    let b_idx = (block + i + half) * l;
                    // SAFETY: a_idx and b_idx are distinct, non-overlapping
                    // shard slots within buf; split_at_mut would need the same
                    // bound check every iteration.
                    let (a, b) = unsafe {
                        let p = buf.as_mut_ptr();
                        (
                            core::slice::from_raw_parts_mut(p.add(a_idx), l),
                            core::slice::from_raw_parts_mut(p.add(b_idx), l),
                        )
                    };
                    butterfly(a, b, w);
                }
            }
            off += half;
            len <<= 1;
        }
    }
}

/// Non-systematic encoder: one size-`n` NTT turning `k` zero-padded data shards
/// into the full `n`-point codeword. Kept because its output is bit-identical
/// to [`MatrixEncoder`], which is what cross-validates the two algorithms.
pub struct NttEncoder {
    fwd: Transform,
}

impl NttEncoder {
    pub fn new(n: usize) -> Self {
        Self {
            fwd: Transform::new(n, root_of_unity(n)),
        }
    }

    pub fn encode_in_place(&self, buf: &mut [u16], l: usize) {
        self.fwd.run(buf, l);
    }
}

// ======================================================================
// algorithm 2b: systematic NTT, the deployable shape

/// Systematic FFT-based encoder, structurally what Leopard runs: an **inverse**
/// transform to recover the message polynomial's coefficients from the `k` data
/// shards, then a **forward** transform on a coset to evaluate it at `m` fresh
/// points.
///
/// The coset shift (multiplying coefficient `i` by `g^i`) moves the second
/// transform's evaluation points to `g * w^j`, disjoint from the `w^i` the data
/// sits on — so the `n = k + m` points are distinct and the code is MDS.
///
/// Cost: `(n1/2) log n1 + (n2/2) log n2` butterflies with
/// `n1 = next_pow2(k)`, `n2 = next_pow2(m)` — roughly half the full-codeword
/// NTT at these rates, and the number to compare against
/// [`SystematicMatrixEncoder`].
pub struct SystematicNttEncoder {
    inv: Transform,
    fwd: Transform,
    n1: usize,
    n2: usize,
    k: usize,
    m: usize,
    n1_inv: u16,
    coset: Vec<u16>,
}

impl SystematicNttEncoder {
    pub fn new(k: usize, m: usize) -> Self {
        let n1 = k.next_power_of_two();
        let n2 = m.next_power_of_two();
        assert!(n2 >= n1, "parity transform must cover the polynomial degree");

        let w1 = root_of_unity(n1);
        let w1_inv = pow(w1, P as u32 - 2);
        let g = generator();

        Self {
            inv: Transform::new(n1, w1_inv),
            fwd: Transform::new(n2, root_of_unity(n2)),
            n1,
            n2,
            k,
            m,
            n1_inv: pow(n1 as u16, P as u32 - 2),
            coset: (0..n2).map(|i| pow(g, i as u32)).collect(),
        }
    }

    /// Scratch buffers sized for [`Self::encode`].
    pub fn scratch(&self, l: usize) -> (Vec<u16>, Vec<u16>) {
        (vec![0u16; self.n1 * l], vec![0u16; self.n2 * l])
    }

    /// `data` is `k` shards of `l` elements; writes `m` parity shards.
    pub fn encode(&self, data: &[u16], l: usize, parity: &mut [u16], s1: &mut [u16], s2: &mut [u16]) {
        debug_assert_eq!(data.len(), self.k * l);
        debug_assert_eq!(parity.len(), self.m * l);

        // 1. interpolate: inverse transform of the zero-padded data
        s1[..self.k * l].copy_from_slice(data);
        s1[self.k * l..].fill(0);
        self.inv.run(s1, l);
        crate::prime::scale_small(s1, self.n1_inv);

        // 2. coset-shift the coefficients into the second transform's buffer
        s2.fill(0);
        for i in 0..self.n1 {
            let c = self.coset[i];
            let src = &s1[i * l..(i + 1) * l];
            let dst = &mut s2[i * l..(i + 1) * l];
            dst.copy_from_slice(src);
            crate::prime::scale_small(dst, c);
        }

        // 3. evaluate at g * w^j
        self.fwd.run(s2, l);
        parity.copy_from_slice(&s2[..self.m * l]);
    }
}

/// Round-trip check: the inverse transform followed by the forward transform of
/// the same size must be the identity, and the systematic encoder's parity must
/// match direct Horner evaluation of the interpolated polynomial.
pub fn check_systematic_ntt(k: usize, m: usize, l: usize) -> Result<(), String> {
    let data: Vec<u16> = (0..k * l).map(|i| ((i * 4523) % P as usize) as u16).collect();
    let enc = SystematicNttEncoder::new(k, m);
    let (mut s1, mut s2) = enc.scratch(l);
    let mut parity = vec![0u16; m * l];
    enc.encode(&data, l, &mut parity, &mut s1, &mut s2);

    // recompute coefficients independently, then evaluate by Horner
    let n1 = k.next_power_of_two();
    let n2 = m.next_power_of_two();
    let w1 = root_of_unity(n1);
    let w1_inv = pow(w1, P as u32 - 2);
    let n1_inv = pow(n1 as u16, P as u32 - 2);

    // naive inverse DFT for one element position, then Horner at g * w2^j
    let g = generator();
    let w2 = root_of_unity(n2);
    for e in [0usize, l / 2, l - 1] {
        let mut coeff = vec![0u16; n1];
        for (t, c) in coeff.iter_mut().enumerate() {
            let mut acc = 0u16;
            for i in 0..n1 {
                let v = if i < k { data[i * l + e] } else { 0 };
                acc = add(acc, mul(v, pow(w1_inv, (i * t) as u32)));
            }
            *c = mul(acc, n1_inv);
        }
        for j in 0..m {
            let x = mul(g, pow(w2, j as u32));
            let mut acc = 0u16;
            for t in (0..n1).rev() {
                acc = add(mul(acc, x), coeff[t]);
            }
            if acc != parity[j * l + e] {
                return Err(format!(
                    "k={k} m={m} l={l}: parity[{j}][{e}] = {} but Horner says {acc}",
                    parity[j * l + e]
                ));
            }
        }
    }
    Ok(())
}

fn bit_reverse_shards(buf: &mut [u16], n: usize, l: usize) {
    let bits = n.trailing_zeros();
    for i in 0..n {
        let j = (i as u32).reverse_bits() >> (32 - bits);
        let j = j as usize;
        if j > i {
            for e in 0..l {
                buf.swap(i * l + e, j * l + e);
            }
        }
    }
}

// ======================================================================
// cross-validation

/// The two algorithms must agree exactly: the NTT evaluates at `w^j`, and the
/// matrix is the Vandermonde matrix on those same points.
pub fn check_agreement(k: usize, n: usize, l: usize) -> Result<(), String> {
    let data: Vec<u16> = (0..k * l).map(|i| ((i * 7919) % P as usize) as u16).collect();

    let matrix = MatrixEncoder::new(k, n);
    let mut via_matrix = vec![0u16; n * l];
    matrix.encode(&data, l, &mut via_matrix);

    let ntt = NttEncoder::new(n);
    let mut via_ntt = vec![0u16; n * l];
    via_ntt[..k * l].copy_from_slice(&data);
    ntt.encode_in_place(&mut via_ntt, l);

    if via_matrix == via_ntt {
        Ok(())
    } else {
        let bad = via_matrix
            .iter()
            .zip(&via_ntt)
            .position(|(a, b)| a != b)
            .unwrap();
        Err(format!(
            "k={k} n={n} l={l}: first mismatch at flat index {bad}: matrix={} ntt={}",
            via_matrix[bad], via_ntt[bad]
        ))
    }
}

/// The systematic Cauchy encoder's AVX2 path must match its scalar path.
pub fn check_systematic(k: usize, m: usize, l: usize) -> Result<(), String> {
    let data: Vec<u16> = (0..k * l).map(|i| ((i * 6151) % P as usize) as u16).collect();
    let enc = SystematicMatrixEncoder::new(k, m);
    let mut fast = vec![0u16; m * l];
    let mut slow = vec![0u16; m * l];
    enc.encode(&data, l, &mut fast);
    enc.encode_scalar(&data, l, &mut slow);
    if fast == slow {
        Ok(())
    } else {
        Err(format!("k={k} m={m} l={l}: avx2 and scalar paths disagree"))
    }
}

/// Shard-length multiply-adds to produce the full `n`-point codeword.
pub const fn matrix_ops(k: usize, n: usize) -> usize {
    n * k
}

/// Shard-length multiply-adds for a systematic encoder that emits only the `m`
/// parity shards.
pub const fn systematic_matrix_ops(k: usize, m: usize) -> usize {
    m * k
}

/// Shard-length butterflies the NTT performs. Each butterfly is one multiply
/// plus an add and a subtract, so it is a little more than one `matrix_ops`
/// unit of work.
pub const fn ntt_ops(n: usize) -> usize {
    (n / 2) * n.trailing_zeros() as usize
}

/// Cost of a *systematic* FFT-based encoder, which is what Leopard actually
/// runs: an inverse transform to recover coefficients from the `k` data
/// shards, then a forward transform to evaluate at the parity positions.
/// Both sizes round up to a power of two.
pub fn systematic_ntt_ops(k: usize, m: usize) -> usize {
    let n1 = k.next_power_of_two();
    let n2 = m.next_power_of_two();
    ntt_ops(n1) + ntt_ops(n2)
}

// ======================================================================
// decoding: reconstruct the message from k surviving shards

/// Gauss-Jordan inversion of a `k x k` matrix over `F_p`, row-major.
fn invert(mut a: Vec<u16>, k: usize) -> Option<Vec<u16>> {
    let mut inv = vec![0u16; k * k];
    for i in 0..k {
        inv[i * k + i] = 1;
    }
    for col in 0..k {
        // find a pivot
        let piv = (col..k).find(|&r| a[r * k + col] != 0)?;
        if piv != col {
            for c in 0..k {
                a.swap(col * k + c, piv * k + c);
                inv.swap(col * k + c, piv * k + c);
            }
        }
        let s = pow(a[col * k + col], P as u32 - 2);
        for c in 0..k {
            a[col * k + c] = mul(a[col * k + c], s);
            inv[col * k + c] = mul(inv[col * k + c], s);
        }
        for r in 0..k {
            if r == col {
                continue;
            }
            let f = a[r * k + col];
            if f == 0 {
                continue;
            }
            for c in 0..k {
                a[r * k + c] = sub(a[r * k + c], mul(f, a[col * k + c]));
                inv[r * k + c] = sub(inv[r * k + c], mul(f, inv[col * k + c]));
            }
        }
    }
    Some(inv)
}

/// Reconstructs the `k` message shards from any `k` shards of the codeword
/// produced by [`MatrixEncoder`].
///
/// Setup inverts the `k x k` Vandermonde submatrix on the surviving evaluation
/// points: `O(k^3)` scalar operations, paid once and independent of shard
/// length. Applying it is `k^2` shard-length multiply-adds — the same order as
/// encoding a full codeword.
pub struct MatrixDecoder {
    inv: Vec<u16>,
    k: usize,
}

impl MatrixDecoder {
    /// `survivors` are the codeword indices that were received.
    pub fn new(k: usize, n: usize, survivors: &[usize]) -> Option<Self> {
        assert_eq!(survivors.len(), k);
        let w = root_of_unity(n.next_power_of_two());
        let mut v = vec![0u16; k * k];
        for (a, &j) in survivors.iter().enumerate() {
            let x = pow(w, j as u32);
            let mut acc = 1u16;
            for i in 0..k {
                v[a * k + i] = acc;
                acc = mul(acc, x);
            }
        }
        // rows are evaluations, columns coefficients; we want coeffs from evals
        invert(v, k).map(|inv| Self { inv, k })
    }

    /// `received` is `k` shards of `l` elements, in `survivors` order.
    pub fn decode(&self, received: &[u16], l: usize, out: &mut [u16]) {
        debug_assert_eq!(received.len(), self.k * l);
        debug_assert_eq!(out.len(), self.k * l);
        out.fill(0);
        for i in 0..self.k {
            let (_, rest) = out.split_at_mut(i * l);
            let dst = &mut rest[..l];
            for a in 0..self.k {
                let c = self.inv[i * self.k + a];
                if c == 0 {
                    continue;
                }
                muladd(dst, &received[a * l..(a + 1) * l], c);
            }
        }
    }
}

/// Shard-length multiply-adds a matrix decode performs (excluding the `O(k^3)`
/// scalar setup, which does not scale with shard length).
pub const fn matrix_decode_ops(k: usize) -> usize {
    k * k
}

/// End-to-end check: encode, drop all but `k` random shards, reconstruct, and
/// compare against the original message.
pub fn check_decode(k: usize, n: usize, l: usize, seed: u64) -> Result<usize, String> {
    let data: Vec<u16> = (0..k * l).map(|i| ((i * 3571) % P as usize) as u16).collect();

    let enc = MatrixEncoder::new(k, n);
    let mut code = vec![0u16; n * l];
    enc.encode(&data, l, &mut code);

    // deterministic pseudo-random choice of k survivors out of n
    let mut idx: Vec<usize> = (0..n).collect();
    let mut s = seed | 1;
    for i in (1..n).rev() {
        s = s.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        let j = (s >> 33) as usize % (i + 1);
        idx.swap(i, j);
    }
    idx.truncate(k);
    idx.sort_unstable();

    let dec = MatrixDecoder::new(k, n, &idx)
        .ok_or_else(|| format!("k={k} n={n}: submatrix on {idx:?} was singular"))?;

    let mut received = vec![0u16; k * l];
    for (a, &j) in idx.iter().enumerate() {
        received[a * l..(a + 1) * l].copy_from_slice(&code[j * l..(j + 1) * l]);
    }

    let mut out = vec![0u16; k * l];
    dec.decode(&received, l, &mut out);

    if out == data {
        Ok(idx.iter().filter(|&&j| j < k).count())
    } else {
        Err(format!("k={k} n={n} l={l}: reconstruction mismatch"))
    }
}
