# GF(2^16) vs prime fields for Reed-Solomon

Does commonware's choice of GF(2^16) cost it performance against a prime field
of similar size, and is its FFT-based coder actually the right algorithm at the
committee sizes this repository uses (`n <= 256`)?

Short answers, all measured: **a small prime field is genuinely faster at the
kernel** (1.31× with AVX2, 8.5× without); **the NTT does not overtake a naive
matrix multiply until n ≈ 32**; and **commonware's FFT decode carries a fixed
~300 µs-1 ms cost** that dominates small messages entirely.

## 1. What commonware actually runs (verified)

`commonware_coding::ReedSolomon` delegates to
`commonware_cryptography::reed_solomon`, which `mod.rs` documents as a vendored
copy of [`reed-solomon-simd`](https://crates.io/crates/reed-solomon-simd),
itself based on [Leopard-RS](https://github.com/catid/leopard). So this is
**not** a Vandermonde matrix multiply. It is the Lin-Chung-Han **additive FFT**
over GF(2^16), making encode/decode `O(n log n)` instead of `O(n^2)`:

```text
recovery_chunk = FFT( IFFT(chunk_0, skew_0) xor IFFT(chunk_1, skew_1) xor ... )
```

`cargo run --release --bin verify` checks the implementation rather than taking
it on faith:

| check | result |
|---|---|
| `GF_POLYNOMIAL = 0x1002D` = `x^16 + x^5 + x^3 + x^2 + 1` irreducible over GF(2) | yes |
| Cantor basis satisfies `b_0 = 1`, `b_(i-1) = b_i^2 + b_i` | holds for all 16 |
| `Naive`, `NoSimd`, `Avx2` engines vs a from-scratch carry-less reference | 288 products each, all match |
| prime-field Shoup kernels vs plain `%` | match |

One subtlety worth knowing if you ever read these tables directly: elements are
stored as **Cantor-basis coordinates**, not polynomial-basis ones. A naive
polynomial-basis multiply disagrees with the engines; the reference has to go
through `phi^-1(phi(a) * phi(b))`. Addition is unaffected — both bases are
`F_2`-linear, so XOR is XOR either way.

### The multiply kernel

`mul_256` (in `engine_avx2.rs`) scales 32 field elements per call with roughly
20 AVX2 instructions — 8 `vpshufb`, 6 `vpxor`, 6 mask/shift — about **0.63
instructions per element**. It works because the multiplier is *constant across
the whole butterfly*, so the 4-bit split tables (`Multiply128lutT`, an 8 MiB
table indexed by multiplier) are loaded once and reused over the entire shard.

That same "constant multiplier" structure is what a prime field needs to use
**Shoup's** algorithm rather than a general Montgomery multiply — so the
comparison below gives the prime field its best case, not a strawman.

## 2. Kernel results

`x[i] = c * x[i]` over a buffer, `c` fixed. Throughput in elements/s, so the
fields compare on equal algebraic terms. Intel i7-8565U, AVX2, no AVX-512.

| implementation | 64 KiB (L2) | 1 MiB (streaming) | vs GF(2^16) SIMD |
|---|---|---|---|
| **GF(2^16) commonware `Avx2`** | 12.82 Gelem/s | 10.10 Gelem/s | 1.00× |
| **F_12289 AVX2 Shoup** (16-bit lanes) | 15.08 | **13.23** | **1.31×** |
| **F_65521 AVX2 Shoup** (32-bit lanes) | 4.10 | 4.22 | 0.42× |
| GF(2^16) commonware `NoSimd` | 0.84 | 0.85 | 0.08× |
| F_12289 scalar Shoup | 6.32 | **7.19** | 0.71× |
| GF(2^16) commonware `Naive` | 0.56 | 0.55 | 0.05× |
| F_65521 scalar `%` | 1.49 | 1.42 | 0.14× |

Two things stand out:

* **The intuition holds for a small prime.** `F_12289` beats the PSHUFB kernel
  by **1.31×** with SIMD and by **8.5×** without it (7.19 vs 0.85 Gelem/s).
  Shoup needs ~6 instructions per 16 lanes; GF(2^16) needs ~20 per 32.
* **It inverts for a same-sized prime.** `F_65521` is **2.4× slower**. Shoup at
  16-bit lanes requires `2p < 2^16`, i.e. `p < 32768`. Above that you drop to
  32-bit lanes — half the elements per register — and AVX2 has no 32-bit high
  multiply, so the quotient needs `vpmuludq` on even and odd lanes plus a blend.

Normalising for packing (below), `F_12289`'s 1.31× becomes **1.11×** per byte
of actual payload.

## 3. Why the kernel is not the whole story

### Transform length

An additive FFT's evaluation points form an *additive* subgroup, so every one of
the 65536 field elements is usable and any power-of-two length up to 65536
exists. A prime field must use a multiplicative NTT, whose length is capped by
the 2-adicity of `p - 1`:

| field | elements | max radix-2 NTT | bits/element | packing overhead |
|---|---|---|---|---|
| **GF(2^16)** | 65536 | **65536** (additive) | 16.000 | 0.00% |
| F_12289 | 12289 | 4096 (`2^12`) | 13.585 | 17.78% |
| F_40961 | 40961 | 8192 (`2^13`) | 15.322 | 4.43% |
| F_65521 | 65521 | **16** (`2^4`) | 16.000 | 0.00% |

`65521 - 1 = 2^4 * 3^2 * 5 * 7 * 13`, so the largest prime under 2^16 supports a
**16-point** NTT. It is unusable as an FFT coding field regardless of how fast
its multiply is.

Searching every prime below 65536, the best 2-adicity available is `2^13`
(p = 40961). **No prime field under 2^16 can address 65536 shards**; GF(2^16)
can. For the committee sizes in this repository that headroom is irrelevant —
but it is why Leopard picked the field it did.

### Packing

GF(2^16) maps 16-bit words to field elements bijectively: zero waste on
arbitrary byte data. `F_p` has fewer than 2^16 elements, so a byte-oriented
erasure code must either widen shards or escape unrepresentable words —
**17.8% more shard bytes** for `F_12289`. And the constraints fight each other:
you want `p` large for packing, small (`< 32768`) for 16-bit Shoup lanes, and
highly 2-adic for transform length. `F_12289` is the only real sweet spot, and
it pays 17.8% and caps at 4096 points.

### Addition

In GF(2^k) addition is XOR: one instruction, no reduction. In `F_p` it needs a
conditional subtract. The FFT butterfly does both an add and a multiply
(`fftb_256` is `muladd` + `xor`), so GF(2^16) gets the add half for free while a
prime field pays for it. The kernel benchmark above measures multiplication
only, which flatters the prime field.

## 4. Does the NTT actually beat a matrix multiply at n <= 256?

The `O(n^2)` vs `O(n log n)` argument is asymptotic, and these committees are
small. `benches/crossover.rs` settles it *within our own prime field*, so field,
SIMD primitives, memory layout and output are all held constant — the encoders
are cross-validated to produce bit-identical results by `cargo run --bin agree`.

Rate is this repository's: `k = n - 2f`, `m = 2f`, `2/3` of shards erasable.

Operation counts predict the NTT wins everywhere, even at `n = 4`:

| n | k | m | matrix `m*k` | ntt `ifft+fft` | predicted |
|---|---|---|---|---|---|
| 4 | 2 | 2 | 4 | 2 | NTT 2.00× |
| 16 | 6 | 10 | 60 | 44 | NTT 1.36× |
| 64 | 22 | 42 | 924 | 272 | NTT 3.40× |
| 256 | 86 | 170 | 14620 | 1472 | NTT 9.93× |

Measured, it does not:

| shard | n=4 | n=8 | n=16 | n=32 | n=64 | n=128 | n=256 |
|---|---|---|---|---|---|---|---|
| 1 KiB | **matrix 1.43×** | **matrix 1.10×** | **matrix 1.20×** | NTT 1.37× | NTT 1.85× | NTT 3.23× | NTT 5.77× |
| 16 KiB | **matrix 1.69×** | **matrix 1.02×** | **matrix 1.28×** | NTT 1.20× | NTT 2.25× | NTT 3.06× | NTT 6.93× |
| 256 KiB | **matrix 1.70×** | **matrix 1.30×** | **matrix 1.23×** | **matrix 1.10×** | NTT 1.68× | NTT 2.70× | NTT 5.10× |

**The crossover is around n = 32**, moving out to n = 64 for 256 KiB shards.
What eats the NTT's theoretical margin: the bit-reversal permutation (a full
memory shuffle over `n*l` elements), two transforms with separate buffers, a
full coset-scaling pass, and padding waste (at n=16, `k=6` rounds to 8 and
`m=10` to 16). The matrix inner loop is a single streaming multiply-add with
perfect locality. That the crossover moves *later* as shards grow is the NTT's
`log n` passes over memory showing up.

## 5. Decode from k random survivors

`benches/decode.rs` reconstructs the message from `k` shards drawn at random out
of `n` — the `2f` erasures the protocols tolerate — validated end-to-end by
`cargo run --bin agree`. Matrix decode inverts the `k x k` Vandermonde submatrix
on the surviving points (`O(k^3)` scalars, once) and applies it (`k^2`
shard-length multiply-adds).

Our `F_12289` matrix decode (inverse cached) vs commonware's FFT decode, run
unmodified:

| shard | n=4 | n=16 | n=32 | n=64 | n=128 | n=256 |
|---|---|---|---|---|---|---|
| 1 KiB | **matrix 757×** | **213×** | **47×** | **12.9×** | **4.6×** | **1.4×** |
| 16 KiB | **63×** | **14×** | **4.7×** | **3.0×** | **1.16×** | cw 1.56× |
| 256 KiB | **5.1×** | **5.2×** | **4.3×** | **2.5×** | **1.39×** | cw 1.09× |

This is a different field and a far more tuned implementation on commonware's
side, so it is not a clean algorithm-vs-algorithm result. What it *does*
independently confirm is the fixed cost: commonware's decode takes 280 µs to
1 ms at 1 KiB shards regardless of `n`, because the Leopard error-locator
evaluates over all 65536 field elements.

### Cost of the O(k^3) inversion

Measured on its own by `cargo run --release --bin invcost`, it is **constant in
shard length** — `l` is not a parameter of `MatrixDecoder::new`:

| n | k | invert | ns per k^3 |
|---|---|---|---|
| 16 | 6 | 1.5 µs | 7.16 |
| 64 | 22 | 26.1 µs | 2.45 |
| 128 | 44 | 132.6 µs | 1.56 |
| 256 | 86 | **896.7 µs** | 1.41 |

So it amortises away purely because the `k^2` apply grows with `l`, not because
inversion gets more expensive: at k=86 it is 0.9 ms against a 0.46 ms apply on
1 KiB shards, and 0.9 ms against a 171 ms apply on 256 KiB shards.

> **Measurement note.** Do not derive this cost by subtracting the two criterion
> bars. At 256 KiB the working set is ~44 MB streaming from RAM and run-to-run
> drift is ~10%, which completely buries a 0.9 ms difference — subtracting them
> yields nonsense (an apparent 19 ms). `bin/gapprobe` interleaves the two
> variants in one loop so drift cancels, and recovers the constant ~1.1 ms gap.

## Verdict

**At this repository's scale (n <= 256), the case for GF(2^16) is much weaker
than it looks in general.**

The prime field's arithmetic advantage is real: `F_12289` with Shoup beats
table-driven GF(2^16) by 1.31× with AVX2, 1.11× after packing overhead, and
8.5× on any target without a byte-shuffle instruction.

The usual counter-arguments mostly do not bind here:

* **Transform length.** GF(2^16) addresses 65536 shards; `F_12289` caps at 4096.
  Irrelevant at `n <= 256` — 16× headroom either way.
* **Packing.** 17.8% more shard bytes for `F_12289` is a genuine, permanent
  bandwidth tax, and the strongest remaining argument for GF(2^16).
* **Free addition.** Real, and the kernel benchmark (multiply only) does not
  capture it.

Meanwhile two findings cut the other way at small `n`:

* The NTT does not beat a matrix multiply until **n ≈ 32**, so for n=4 and n=16
  the asymptotically-worse algorithm is the faster one.
* commonware's FFT decode carries a **fixed ~300 µs-1 ms cost** independent of
  message size, which dominates small-message consensus traffic entirely.

So: GF(2^16) plus an additive FFT is the right engineering choice for a general
coding library that must scale to tens of thousands of shards. For a fixed
`n <= 256` committee moving small messages, a Cauchy matrix coder over
`F_12289` — or over GF(2^8), as this repository already does — is the better
fit, and the measurements here say so at both encode and decode.

Worth noting the 1.3× kernel gap is also within GF(2^16)'s reach on newer
silicon: **GFNI** (`vgf2p8affineqb`) does GF(2^8) affine maps in one
instruction, and AVX-512 doubles the lane count. This CPU (Whiskey Lake) has
neither.

## Running

```bash
cd benchmarks/gf16_vs_prime

cargo run --release --bin verify    # commonware's GF(2^16) vs a field reference,
                                    # prime kernels vs `%`, structural limits
cargo run --release --bin agree     # matrix == ntt, systematic ntt vs Horner,
                                    # decode from k random shards round-trips

cargo bench --bench kernel          # scale-by-constant throughput per field
cargo bench --bench crossover       # matrix vs NTT encode, n = 4..256
cargo bench --bench decode          # reconstruct from k random survivors
```

Every benchmark has a correctness gate in front of it: the two encoders are
cross-validated to bit-identical output, the systematic NTT against Horner
evaluation, and decode end-to-end against the original message.

Toolchain is pinned to 1.97.1 and the crate is its own workspace, same as
`../rs_bench`, so it stays out of the main build.
