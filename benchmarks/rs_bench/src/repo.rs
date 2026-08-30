//! Stack A: `reed-solomon-erasure` + this repository's AES Merkle tree.
//!
//! **Historical.** This side of the comparison is the code the repository ran
//! *before* the switch to commonware. It used to be compiled straight out of
//! `consensus/src/reed_solomon.rs` via `#[path]`, but that file is now the
//! commonware-backed implementation, so the original GF(2^8) coder is vendored
//! below verbatim to keep the "before" measurement reproducible. It is frozen
//! by design and no longer tracks anything the protocols run.

use crypto::{
    aes_hash::{HashState, MerkleTree, Proof},
    hash::{do_hash, Hash},
};
use reed_solomon_erasure::{galois_8::ReedSolomon, Error};

/// The original `consensus::get_shards`, as of commit `b22a6a6`.
pub fn get_shards(data: Vec<u8>, shards: usize, parity_shards: usize) -> Vec<Vec<u8>> {
    let reed_solomon: ReedSolomon = ReedSolomon::new(shards, parity_shards).unwrap();
    let mut vec_vecs = Vec::new();
    let size_of_vec = (data.len() / shards) + 1;
    for b in 0..shards {
        let mut indi_vec: Vec<u8> = Vec::new();
        for x in 0..size_of_vec {
            if b * size_of_vec + x >= data.len() {
                // Padding until filling up all shards
                indi_vec.push(0);
            } else {
                // Fill each shard
                indi_vec.push(data[b * size_of_vec + x]);
            }
        }
        vec_vecs.push(indi_vec);
    }
    // Fill parity shards with zeros
    for _b in 0..parity_shards {
        let mut parity_vec = Vec::new();
        for _x in 0..size_of_vec {
            parity_vec.push(0);
        }
        vec_vecs.push(parity_vec);
    }
    // Use Reed solomon library to generate parity shards.
    reed_solomon.encode(&mut vec_vecs).unwrap();
    vec_vecs
}

/// The original `consensus::reconstruct_data`, as of commit `b22a6a6`.
///
/// The shards are reconstructed inline with the variable data.
pub fn reconstruct_data(
    data: &mut Vec<Option<Vec<u8>>>,
    shards: usize,
    parity_shards: usize,
) -> Result<(), Error> {
    let reed_solomon: ReedSolomon = ReedSolomon::new(shards, parity_shards).unwrap();
    reed_solomon.reconstruct(data)
}

/// The AES keys the protocols instantiate their hash state with
/// (see e.g. `broadcast/ctrbc/src/context.rs`).
pub fn hash_state() -> HashState {
    HashState::new([5u8; 16], [29u8; 16], [23u8; 16])
}

/// Erasure coding only, no commitment: `consensus::get_shards`.
pub fn encode_raw(data: Vec<u8>, p: crate::Params) -> Vec<Vec<u8>> {
    get_shards(data, p.k, p.m)
}

/// Merkle tree over the shards, identical to `ctrbc::construct_merkle_tree`.
pub fn construct_merkle_tree(shards: &[Vec<u8>], hc: &HashState) -> MerkleTree {
    let hashes: Vec<Hash> = shards.iter().map(|x| do_hash(x.as_slice())).collect();
    MerkleTree::new(hashes, hc)
}

/// The dealer-side pipeline of `ctrbc::start_init`: code the message, commit to
/// the shards, and produce the inclusion proof that accompanies each shard.
pub fn encode_committed(
    data: Vec<u8>,
    p: crate::Params,
    hc: &HashState,
) -> (Hash, Vec<Vec<u8>>, Vec<Proof>) {
    let shards = get_shards(data, p.k, p.m);
    let tree = construct_merkle_tree(&shards, hc);
    let proofs = (0..shards.len()).map(|i| tree.gen_proof(i)).collect();
    (tree.root(), shards, proofs)
}

/// Receiver-side check of a single shard: `CTRBCMsg::verify_mr_proof`, plus the
/// root comparison the callers do separately.
pub fn check_shard(shard: &[u8], proof: &Proof, root: &Hash, hc: &HashState) -> bool {
    do_hash(shard) == proof.item() && proof.validate(hc) && proof.root() == *root
}

/// Reconstruct the message from at least `k` shards, as `ctrbc::handle_ready`
/// does: repair the missing shards, then concatenate the `k` data shards.
///
/// `get_shards` zero-pads the payload to a shard boundary and does not record
/// the original length, so the caller supplies it; the protocols recover it
/// from the message framing instead.
pub fn decode(
    mut shards: Vec<Option<Vec<u8>>>,
    p: crate::Params,
    original_len: usize,
) -> Result<Vec<u8>, reed_solomon_erasure::Error> {
    reconstruct_data(&mut shards, p.k, p.m)?;
    let mut message = Vec::with_capacity(original_len);
    for shard in shards.into_iter().take(p.k) {
        message.extend(shard.expect("reconstruct_data fills every shard"));
    }
    message.truncate(original_len);
    Ok(message)
}

/// Reconstruction as the protocol actually performs it: repair, then rebuild
/// the Merkle tree over the repaired shards and check it against the committed
/// root. This is the fair counterpart to commonware's `decode`, which
/// re-derives and validates the commitment internally.
pub fn decode_verified(
    mut shards: Vec<Option<Vec<u8>>>,
    p: crate::Params,
    original_len: usize,
    root: &Hash,
    hc: &HashState,
) -> Option<Vec<u8>> {
    reconstruct_data(&mut shards, p.k, p.m).ok()?;
    let shards: Vec<Vec<u8>> = shards
        .into_iter()
        .map(|s| s.expect("reconstruct_data fills every shard"))
        .collect();

    if construct_merkle_tree(&shards, hc).root() != *root {
        return None;
    }

    let mut message = Vec::with_capacity(original_len);
    for shard in shards.into_iter().take(p.k) {
        message.extend(shard);
    }
    message.truncate(original_len);
    Some(message)
}

/// Bytes a peer must receive for one shard: the shard itself plus the proof's
/// payload (`lemma` hashes and the `path` bits, one byte per bool as bincode
/// serializes them). Length prefixes from the wire codec are excluded on both
/// sides so the two stacks are counted the same way.
pub fn shard_wire_size(shard: &[u8], proof: &Proof) -> usize {
    shard.len() + proof.lemma().len() * 32 + proof.path().len()
}

/// Erase all but the first `k` shards.
///
/// **This is the easy case and not representative**: shards `0..k` are exactly
/// the data shards, so nothing has to be interpolated — the coder only
/// regenerates parity. Use [`keep_random_k`] to measure real erasure decoding.
pub fn keep_first_k(shards: &[Vec<u8>], p: crate::Params) -> Vec<Option<Vec<u8>>> {
    shards
        .iter()
        .enumerate()
        .map(|(i, s)| if i < p.k { Some(s.clone()) } else { None })
        .collect()
}

/// Choose `k` of the `n` shards uniformly at random and erase the rest — the
/// `2f` erasures the protocols are built to tolerate. Most survivors are parity
/// shards, so the missing data shards genuinely have to be interpolated.
pub fn random_k_indices(p: crate::Params, seed: u64) -> Vec<usize> {
    use rand::{seq::SliceRandom, SeedableRng};
    let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
    let mut idx: Vec<usize> = (0..p.n).collect();
    idx.shuffle(&mut rng);
    idx.truncate(p.k);
    idx.sort_unstable();
    idx
}

/// Keep exactly the shards named by `keep`, erase the rest.
pub fn keep_indices(shards: &[Vec<u8>], keep: &[usize]) -> Vec<Option<Vec<u8>>> {
    let mut out = vec![None; shards.len()];
    for &i in keep {
        out[i] = Some(shards[i].clone());
    }
    out
}

/// How many of the survivors are data shards (index `< k`). The remaining
/// `k - this` had to be recovered by interpolation.
pub fn surviving_data_shards(keep: &[usize], p: crate::Params) -> usize {
    keep.iter().filter(|&&i| i < p.k).count()
}
