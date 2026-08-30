//! Correctness gate for the benchmark. A benchmark of code that does not
//! actually round-trip measures nothing, so assert both stacks recover the
//! payload from exactly `k` shards and reject a tampered shard.

use bytes::Bytes;
use commonware_parallel::Sequential;
use rs_bench::{cw, payload, repo, Params};

const CASES: &[(usize, usize)] = &[(4, 1024), (16, 100 * 1024), (64, 4096), (16, 1)];

#[test]
fn repo_roundtrips_from_k_shards() {
    for &(n, len) in CASES {
        let p = Params::for_n(n);
        let data = payload(len);
        let hc = repo::hash_state();

        let (root, shards, proofs) = repo::encode_committed(data.clone(), p, &hc);
        assert_eq!(shards.len(), p.n, "n={n}: expected one shard per node");

        for i in 0..p.n {
            assert!(
                repo::check_shard(&shards[i], &proofs[i], &root, &hc),
                "n={n} len={len}: shard {i} failed its own proof"
            );
        }

        // Decode from k shards chosen at random, not the first k — the first k
        // are the data shards, which makes reconstruction trivial.
        let keep = repo::random_k_indices(p, 42 + n as u64);
        let survivors_that_are_data = repo::surviving_data_shards(&keep, p);
        assert!(
            survivors_that_are_data < p.k || p.n == p.k,
            "n={n}: random draw happened to be all data shards, test is vacuous"
        );

        let recovered = repo::decode_verified(repo::keep_indices(&shards, &keep), p, len, &root, &hc)
            .expect("reconstruction failed");
        assert_eq!(recovered, data, "n={n} len={len} keep={keep:?}");
    }
}

#[test]
fn commonware_roundtrips_from_k_shards() {
    for &(n, len) in CASES {
        let p = Params::for_n(n);
        let data = payload(len);
        let cfg = cw::config(p);

        let (commitment, shards) =
            cw::encode(&cfg, Bytes::from(data.clone()), &Sequential).expect("encode");
        assert_eq!(shards.len(), p.n, "n={n}: expected one shard per node");

        let checked = cw::check_all(&cfg, &commitment, &shards).expect("check");
        // Random survivors, not the first k (which are the data shards).
        let keep = repo::random_k_indices(p, 42 + n as u64);
        let quorum: Vec<_> = keep.iter().map(|&i| checked[i].clone()).collect();
        let recovered = cw::decode(&cfg, &commitment, &quorum, &Sequential).expect("decode");
        assert_eq!(recovered, data, "n={n} len={len} keep={keep:?}");
    }
}

#[test]
fn both_stacks_reject_a_tampered_shard() {
    let p = Params::for_n(16);
    let len = 4096;
    let data = payload(len);

    let hc = repo::hash_state();
    let (root, mut shards, proofs) = repo::encode_committed(data.clone(), p, &hc);
    shards[3][0] ^= 0xff;
    assert!(!repo::check_shard(&shards[3], &proofs[3], &root, &hc));

    let cfg = cw::config(p);
    let (commitment, cw_shards) =
        cw::encode(&cfg, Bytes::from(data), &Sequential).expect("encode");
    assert!(
        cw::check(&cfg, &commitment, 4, &cw_shards[3]).is_err(),
        "a shard presented under the wrong index should not verify"
    );
}
