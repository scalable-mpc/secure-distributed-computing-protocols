//! Side-by-side benchmark harness for two Reed-Solomon erasure-coding stacks.
//!
//! * [`repo`] — `reed-solomon-erasure` over GF(2^8), exactly as this
//!   repository uses it (`consensus::get_shards` / `consensus::reconstruct_data`),
//!   plus the repository's AES-based Merkle tree for the commitment and the
//!   per-shard inclusion proofs.
//! * [`cw`] — `commonware_coding::ReedSolomon`, a SIMD Reed-Solomon coder that
//!   emits a binary-Merkle commitment and a per-shard proof as part of
//!   `encode`.
//!
//! # Why the pipelines, not just `encode`
//!
//! The two libraries do not expose the same unit of work. `get_shards` is
//! *only* erasure coding; commonware's `encode` is erasure coding **plus**
//! hashing every shard, building a Merkle tree over them, and attaching an
//! inclusion proof to each shard. Timing `get_shards` against `RS::encode`
//! therefore compares different amounts of work and flatters the repo side.
//!
//! The benchmarks accordingly measure both:
//!
//! * `encode/raw` — coding only. commonware has no commitment-free mode, so
//!   its number here is the same figure as `encode/committed`; treat it as an
//!   upper bound and read the repo column as "coding cost alone".
//! * `encode/committed` — the apples-to-apples comparison: what a dealer
//!   actually has to do before it can send shard `i` to node `i`. On the repo
//!   side this is `get_shards` + `construct_merkle_tree` + `gen_proof` for
//!   every node, i.e. the body of `ctrbc::start_init`.
//!
//! `check` and `decode` are likewise the receiver-side pipelines
//! (`CTRBCMsg::verify_mr_proof` and the reconstruction in
//! `ctrbc::handle_ready`).

pub mod cw;
pub mod repo;

/// Shard split used by the protocols in this repository: `n = 3f + 1` nodes,
/// `k = n - 2f` data shards and `2f` parity shards, so that any `k` of the `n`
/// shards reconstruct the message.
#[derive(Clone, Copy, Debug)]
pub struct Params {
    pub n: usize,
    pub f: usize,
    /// Data shards (`minimum_shards` in commonware's `Config`).
    pub k: usize,
    /// Parity shards (`extra_shards` in commonware's `Config`).
    pub m: usize,
}

impl Params {
    pub fn for_n(n: usize) -> Self {
        let f = (n - 1) / 3;
        Params {
            n,
            f,
            k: n - 2 * f,
            m: 2 * f,
        }
    }
}

/// Deterministic pseudo-random payload, so both stacks see identical bytes.
pub fn payload(len: usize) -> Vec<u8> {
    use rand::{RngCore, SeedableRng};
    let mut rng = rand::rngs::StdRng::seed_from_u64(0xC0FFEE);
    let mut buf = vec![0u8; len];
    rng.fill_bytes(&mut buf);
    buf
}

#[cfg(test)]
mod shard_limit {
    use super::*;

    /// GF(2^8) has 256 elements, so `reed-solomon-erasure` cannot address more
    /// than 256 total shards. n=256 sits exactly on that boundary.
    #[test]
    fn galois_8_supports_the_sweep() {
        for n in [4usize, 16, 64, 128, 256] {
            let p = Params::for_n(n);
            assert_eq!(p.k + p.m, p.n, "n={n}");
            let rs = reed_solomon_erasure::galois_8::ReedSolomon::new(p.k, p.m);
            assert!(rs.is_ok(), "n={n} k={} m={} rejected: {:?}", p.k, p.m, rs.err());
        }
    }
}
