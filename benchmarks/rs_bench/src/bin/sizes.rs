//! Bandwidth side of the comparison: how many bytes each stack puts on the
//! wire per shard, and how much of that is commitment overhead rather than
//! payload.
//!
//! ```text
//! cargo run --release --bin sizes
//! ```

use bytes::Bytes;
use commonware_parallel::Sequential;
use rs_bench::{cw, payload, repo, Params};

fn main() {
    println!(
        "{:>5} {:>8} {:>10} | {:>10} {:>10} {:>8} | {:>10} {:>10} {:>8}",
        "n", "payload", "shard", "repo/wire", "overhead", "total", "cw/wire", "overhead", "total"
    );

    for n in [4usize, 16, 64, 128] {
        for len in [1024usize, 100 * 1024, 1024 * 1024] {
            let p = Params::for_n(n);
            let data = payload(len);
            let hc = repo::hash_state();

            let (_, shards, proofs) = repo::encode_committed(data.clone(), p, &hc);
            let repo_wire = repo::shard_wire_size(&shards[0], &proofs[0]);
            let repo_overhead = repo_wire - shards[0].len();

            let cfg = cw::config(p);
            let (_, cw_shards) =
                cw::encode(&cfg, Bytes::from(data), &Sequential).expect("commonware encode");
            let cw_wire = cw::shard_wire_size(&cw_shards[0]);

            // commonware's shard carries the same payload split (ceil(len / k)),
            // so attribute everything above that to the commitment.
            let cw_payload = len.div_ceil(p.k);
            let cw_overhead = cw_wire.saturating_sub(cw_payload);

            println!(
                "{:>5} {:>8} {:>10} | {:>10} {:>10} {:>8} | {:>10} {:>10} {:>8}",
                n,
                human(len),
                shards[0].len(),
                repo_wire,
                repo_overhead,
                human(repo_wire * p.n),
                cw_wire,
                cw_overhead,
                human(cw_wire * p.n),
            );
        }
    }

    println!(
        "\nshard   = bytes of coded payload per node\n\
         wire    = shard + inclusion proof (repo: lemma hashes + path bits; commonware: codec size)\n\
         total   = wire x n, i.e. what the dealer sends for one broadcast"
    );
}

fn human(bytes: usize) -> String {
    if bytes >= 1024 * 1024 {
        format!("{:.1}MiB", bytes as f64 / (1024.0 * 1024.0))
    } else if bytes >= 1024 {
        format!("{:.1}KiB", bytes as f64 / 1024.0)
    } else {
        format!("{bytes}B")
    }
}
