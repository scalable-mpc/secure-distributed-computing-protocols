//! Is commonware right to build Reed-Solomon over GF(2^16) rather than over a
//! prime field of similar size?
//!
//! commonware's `ReedSolomon` delegates to `commonware_cryptography::reed_solomon`,
//! which is a vendored copy of `reed-solomon-simd` — an implementation of
//! **Leopard-RS**, i.e. the Lin-Chung-Han *additive* FFT over GF(2^16) with a
//! Cantor basis. That makes encoding O(n log n) rather than the O(n^2) of a
//! Vandermonde matrix multiply.
//!
//! Two things follow, and this crate measures both:
//!
//! 1. **The kernel.** Both fields must do `x[i] = c * x[i]` over a buffer with
//!    `c` constant. See [`prime`] for the prime-field side, written with
//!    Shoup's constant-multiplier algorithm so the comparison is against a
//!    prime field at its best.
//! 2. **The algorithm.** The additive FFT exists only in characteristic 2. A
//!    prime field must use a multiplicative NTT, whose length is capped by the
//!    2-adicity of `p - 1`. [`ntt_limits`] computes that cap exactly.

pub mod prime;
pub mod rs;

/// Field polynomial commonware uses: `x^16 + x^5 + x^3 + x^2 + 1`.
pub const GF_POLYNOMIAL: usize = 0x1002D;

/// Carry-less multiply followed by reduction mod [`GF_POLYNOMIAL`]: the
/// textbook definition of GF(2^16) multiplication, used to check the
/// table-driven engine against something with no tables in it.
pub fn gf_mul_reference(a: u16, b: u16) -> u16 {
    let mut acc: u32 = 0;
    let mut a = a as u32;
    let mut b = b as u32;
    while b != 0 {
        if b & 1 != 0 {
            acc ^= a;
        }
        a <<= 1;
        b >>= 1;
    }
    // reduce mod the field polynomial
    for i in (16..32).rev() {
        if acc >> i & 1 != 0 {
            acc ^= (GF_POLYNOMIAL as u32) << (i - 16);
        }
    }
    acc as u16
}

/// The Cantor basis Leopard uses, from `engine.rs`. Reproduced here rather than
/// imported so the reference check does not share an input with the code it is
/// checking.
pub const CANTOR_BASIS: [u16; 16] = [
    0x0001, 0xACCA, 0x3C0E, 0x163E, 0xC582, 0xED2E, 0x914C, 0x4012, 0x6C98, 0x10D8, 0x6A72, 0xB900,
    0xFDB8, 0xFB34, 0xFF38, 0x991E,
];

/// Basis change `phi`: interpret `x`'s bits as coordinates in the Cantor basis
/// and return the corresponding element in the standard polynomial basis,
/// `phi(x) = XOR of CANTOR_BASIS[i] over set bits i`.
///
/// Leopard stores field elements as *Cantor* coordinates, which is why a naive
/// polynomial-basis multiply disagrees with its engines. Both bases are
/// `F_2`-linear, so XOR (field addition) is identical in either — only
/// multiplication needs the change of basis.
pub fn phi(x: u16) -> u16 {
    let mut acc = 0u16;
    for (i, b) in CANTOR_BASIS.iter().enumerate() {
        if x >> i & 1 != 0 {
            acc ^= b;
        }
    }
    acc
}

/// Table-free inverse of [`phi`], found by search over all 65536 elements.
pub fn phi_inverse_table() -> Vec<u16> {
    let mut inv = vec![0u16; 65536];
    for x in 0..=u16::MAX {
        inv[phi(x) as usize] = x;
    }
    inv
}

/// Reference for what commonware's engines actually compute: multiply in the
/// polynomial basis, but with operands and result carried through the Cantor
/// basis change.
pub fn gf_mul_cantor_reference(a: u16, b: u16, phi_inv: &[u16]) -> u16 {
    phi_inv[gf_mul_reference(phi(a), phi(b)) as usize]
}

/// Largest radix-2 NTT a prime field admits: the 2-adicity of `p - 1`, since a
/// primitive `2^k`-th root of unity exists in `F_p` exactly when `2^k | p - 1`.
///
/// GF(2^16)'s additive FFT has no analogous constraint — its evaluation points
/// form an additive subgroup, so every one of the 65536 field elements is
/// usable and any power-of-two transform length up to 65536 exists.
pub mod ntt_limits {
    /// `k` such that `2^k || p - 1`.
    pub const fn two_adicity(p: u32) -> u32 {
        (p - 1).trailing_zeros()
    }

    /// Maximum radix-2 NTT length, i.e. the largest number of shards a
    /// prime-field FFT-based Reed-Solomon could address.
    pub const fn max_ntt_len(p: u32) -> u32 {
        1u32 << two_adicity(p)
    }

    /// Bits of arbitrary data that pack losslessly into one field element.
    ///
    /// GF(2^16) stores a full 16 bits per element with no waste: the map from
    /// 16-bit words to field elements is a bijection. `F_p` has `p < 2^16`
    /// elements, so some 16-bit words are unrepresentable and a byte-oriented
    /// erasure code must either widen its shards or escape those values.
    pub fn payload_bits(p: u32) -> f64 {
        (p as f64).log2()
    }

    /// Fraction of shard bandwidth lost to that packing gap, relative to
    /// GF(2^16)'s 16 bits per element.
    pub fn packing_overhead(p: u32) -> f64 {
        16.0 / payload_bits(p) - 1.0
    }
}
