//! One-shot timing of the worst corner of the sweep, to size the full run.
use std::time::Instant;
use bytes::Bytes;
use commonware_parallel::Sequential;
use rs_bench::{cw, payload, repo, Params};

fn main() {
    for (n, mb) in [(256usize, 100usize), (256, 10), (128, 100)] {
        let p = Params::for_n(n);
        let len = mb * 1024 * 1024;
        let data = payload(len);
        let hc = repo::hash_state();

        let t = Instant::now();
        let (_root, shards, _proofs) = repo::encode_committed(data.clone(), p, &hc);
        let repo_enc = t.elapsed();

        let cfg = cw::config(p);
        let t = Instant::now();
        let (_c, cw_shards) = cw::encode(&cfg, Bytes::from(data), &Sequential).unwrap();
        let cw_enc = t.elapsed();

        println!(
            "n={n:<4} k={:<3} msg={mb:>3}MiB shard={:>8}B | repo encode {:>8.2?}  commonware encode {:>8.2?}  ratio {:.2}x",
            p.k, shards[0].len(), repo_enc, cw_enc,
            repo_enc.as_secs_f64() / cw_enc.as_secs_f64()
        );
        drop((shards, cw_shards));
    }
}
