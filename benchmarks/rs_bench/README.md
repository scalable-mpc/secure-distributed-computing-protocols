# `rs_bench` — Reed-Solomon: `reed-solomon-erasure` vs `commonware-coding`

Benchmarks the erasure-coding stack this repository uses against
[`commonware_coding::ReedSolomon`](https://docs.rs/commonware-coding/latest/commonware_coding/struct.ReedSolomon.html).

| | stack A (`repo`) | stack B (`cw`) |
|---|---|---|
| coding | `reed-solomon-erasure` 4.0, GF(2^8) | `commonware-coding` 2026.7, SIMD |
| commitment | repo's AES-keyed Merkle tree (`crypto::aes_hash`), built by the caller | binary Merkle tree, built inside `encode` |
| proofs | `MerkleTree::gen_proof(i)`, attached by the caller | embedded in every returned shard |
| parallelism | none (callers use rayon around it) | `Strategy`: `Sequential`, `Rayon`, `Manual` |

## The comparison is not symmetric

`consensus::get_shards` does erasure coding and nothing else. commonware's
`encode` also hashes every shard, builds a Merkle tree over them and attaches an
inclusion proof to each — and offers no way to skip that. Timing `get_shards`
against `RS::encode` compares different amounts of work.

So the benchmark measures the *pipelines* the protocols actually run:

| group | stack A | stack B |
|---|---|---|
| `encode_raw` | `get_shards` | `RS::encode` (still commits — upper bound) |
| `encode_committed` | `get_shards` + `construct_merkle_tree` + `gen_proof` × n<br>(the body of `ctrbc::start_init`) | `RS::encode` |
| `check_one_shard` | `CTRBCMsg::verify_mr_proof` + root compare | `RS::check` |
| `check_all_shards` | the above × n | `RS::check` × n |
| `decode` | `reconstruct_data` + concat, and the same again with the Merkle tree rebuilt as `ctrbc::handle_ready` does | `RS::decode` (validates internally) |
| `commonware_strategy` | — | `Sequential` vs `Rayon` |

`encode_committed`, `check_*` and `decode` are the like-for-like numbers.
`encode_raw`'s repo column is useful on its own: it says how much of the repo's
encode budget is coding rather than hashing.

The erasure-coding functions are not copied into this crate —
`src/repo.rs` compiles `consensus/src/reed_solomon.rs` in via `#[path]`, so the
benchmark tracks the real code.

## Running

```bash
cd benchmarks/rs_bench

cargo test --release        # both stacks round-trip, and reject a bad shard
cargo bench                 # full sweep, ~15 min
cargo bench -- encode_committed   # just the headline comparison
cargo run --release --bin sizes   # per-shard wire overhead
```

Narrow the sweep with three comma-separated env vars:

```bash
# fix the message size
RS_BENCH_N=16,64 RS_BENCH_SIZES=1048576 cargo bench

# fix the per-shard size instead (message becomes k x shard)
RS_BENCH_N=16,64 RS_BENCH_SIZES= RS_BENCH_SHARD_SIZES=4194304 cargo bench
```

Setting either size axis to an empty string drops it.

Criterion writes HTML reports to `target/criterion/report/index.html`, and
compares against the previous run automatically.

### Toolchain

`commonware-coding` 2026.7.0 needs rustc ≥ 1.89 (via `crc-fast`), while the rest
of the repository builds on 1.88. Two things keep those apart:

* `rust-toolchain.toml` here pins **1.97.1**, applying only to this directory.
* `Cargo.toml` declares its own `[workspace]`, so this crate is **not** a member
  of the root workspace and never enters the main build.

Install the toolchain once with `rustup toolchain install 1.97.1`.

## Sweep

`n ∈ {4, 16, 64}` with `f = (n-1)/3`, `k = n - 2f` data shards and `2f` parity —
the split the protocols use.

Two size axes, because they answer different questions:

* **Message sizes** 1 KiB / 100 KiB / 1 MiB. Shards shrink as `n` grows (a 1 MiB
  message at n=64 gives 47 KiB shards), so this axis shows how the per-node
  constant costs — proof length, tree depth, matrix setup — behave.
* **Shard sizes** 1 MiB / 4 MiB, with the message derived as `k × shard`. This
  holds the per-node work fixed and is the axis to read for megabyte-scale
  shards; at n=64 a 4 MiB shard means an 88 MiB message.

Criterion's sample count and measurement time scale down automatically for the
large cases (`tune()` in the bench), and inputs above 1 MiB use
`BatchSize::PerIteration` so setup clones don't dominate RAM.

## Measured results

8-core x86-64, rustc 1.97.1, `lto = true`, `codegen-units = 1`. Ratios are
repo ÷ commonware, so >1 means commonware is faster. Reproduce with:

```bash
RS_BENCH_SIZES= RS_BENCH_SHARD_SIZES=1048576,4194304 cargo bench
```

### encode, like-for-like (code + commit + all proofs)

| shard | n=4 | n=16 | n=64 |
|---|---|---|---|
| 1 MiB | 21.0 / 18.6 ms → 1.13× | 108 / 69.5 ms → 1.55× | 742 / 336 ms → **2.21×** |
| 4 MiB | 93.3 / 70.1 ms → 1.33× | 448 / 334 ms → 1.34× | 3.01 / 1.44 s → **2.09×** |

### decode from k *random* survivors

> **Correction.** An earlier version of this benchmark selected survivors with
> `keep_first_k`, which keeps shards `0..k` — exactly the data shards. Both
> stacks were handed a complete systematic set and interpolated nothing, so
> those decode numbers measured the trivial case. The benchmark now draws `k`
> of the `n` shards uniformly at random (the `2f` erasures the protocols
> tolerate), and the round-trip tests assert the draw is not accidentally
> all-data. **Any decode figure predating this change should be discarded.**

Ratios below are repo ÷ commonware for the deployable pair (repo
`reconstruct+merkle` vs commonware `decode`; both re-derive the commitment).

| message | n=4 | n=16 | n=64 | n=128 | n=256 |
|---|---|---|---|---|---|
| 1 KiB | **repo 22×** | **repo 20.8×** | **repo 3.7×** | cw 1.75× | cw 8.2× |
| 100 KiB | cw 1.22× | ~tie | cw 1.70× | cw 3.10× | cw 7.0× |
| 1 MiB | cw 1.79× | cw 1.62× | cw 2.23× | cw 3.65× | cw 5.4× |
| 10 MiB | cw 1.90× | cw 1.28× | cw 2.20× | cw 3.01× | cw 5.1× |

**commonware's decode carries a large fixed cost — roughly 300 µs to 1 ms,
independent of message size.** Reading the 1 KiB row across `n`: 309 µs, 671,
662, 770, 997. That floor is the Leopard error-locator, which evaluates over
the **entire 65536-element field** no matter how few shards are involved.
Encode has no equivalent floor.

For small consensus messages at `n <= 64` the existing matrix decoder is
4-22x faster, and the gap is structural rather than an implementation detail.
commonware's decode only pays off above roughly 100 KiB messages, or at
`n >= 128`.

### the erasure coding alone

`encode_raw` puts `get_shards` (coding only) against commonware's `encode`
(coding + commitment + proofs). The repo wins that unfair matchup at small
committees and *loses* it at n=64:

| shard | n=4 | n=16 | n=64 |
|---|---|---|---|
| 1 MiB | 5.9 / 16.7 ms | 39.8 / 69.3 ms | 424 / 331 ms |
| 4 MiB | 26.7 / 67.4 ms | 163 / 315 ms | 1.71 / 1.40 s |

GF(2^8) encoding is O(k·m) per byte — at n=64 that is 22×42 = 924 multiply-adds
per byte position, and the scalar implementation stops keeping up with
commonware's SIMD one. Past roughly n=32 the erasure coding itself, not the
hashing, is what dominates the repo's dealer cost.

### verification is a wash at this scale

`check_one_shard` and `check_all_shards` come out within noise of each other for
megabyte shards (~4.6 ms per 1 MiB shard, ~18 ms per 4 MiB shard, both stacks) —
the cost is hashing the shard, and both use SHA-256 for that. The repo's
advantage on *small* shards is real but shrinks to nothing here: at n=64 with a
1 KiB message it verifies in 540 ns against commonware's 4.75 µs (8.8×), because
its proof check is a handful of AES-based node hashes with no codec work.

### with commonware's rayon backend

The repo's coder is single-threaded; commonware takes a `Strategy`. On 8 cores
`Rayon` buys it another 2.3–2.5× at these sizes, which compounds into the
headline number: at n=64 with 4 MiB shards, encode is **3.01 s vs 628 ms, 4.8×**.

## Reading the results

One thing the wall-clock numbers do not capture: **bandwidth**.
`cargo run --release --bin sizes` reports bytes per shard. commonware's proofs
are consistently smaller (139 B vs 196 B of overhead at n=16, 203 B vs 262 B at
n=64), because the repo's `Proof` ships a `path: Vec<bool>` and carries both the
leaf and the root inside `lemma`. The gap is a fixed per-shard constant, so it
matters for small messages and disappears into the noise at megabyte shards.
