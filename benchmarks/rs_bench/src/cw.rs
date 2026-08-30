//! Stack B: `commonware_coding::ReedSolomon`.
//!
//! `encode` already returns a commitment and shards carrying their own Merkle
//! proofs, so there is no commitment-free variant to measure. `Sha256` is used
//! as the hasher to match the repository's `do_hash`.

use std::num::NonZeroU16;

use bytes::Bytes;
use commonware_coding::{Config, ReedSolomon, Scheme};
use commonware_cryptography::Sha256;
use commonware_parallel::Strategy;

pub type Rs = ReedSolomon<Sha256>;
pub type Commitment = <Rs as Scheme>::Commitment;
pub type Shard = <Rs as Scheme>::Shard;
pub type CheckedShard = <Rs as Scheme>::CheckedShard;
pub type Error = <Rs as Scheme>::Error;

pub fn config(p: crate::Params) -> Config {
    Config {
        minimum_shards: NonZeroU16::new(p.k as u16).expect("k > 0"),
        extra_shards: NonZeroU16::new(p.m as u16).expect("m > 0"),
    }
}

/// Code the message, commit to the shards and attach a proof to each — the
/// counterpart of [`crate::repo::encode_committed`].
pub fn encode(
    config: &Config,
    data: Bytes,
    strategy: &impl Strategy,
) -> Result<(Commitment, Vec<Shard>), Error> {
    Rs::encode(config, data, strategy)
}

/// Verify one shard against the commitment.
pub fn check(
    config: &Config,
    commitment: &Commitment,
    index: u16,
    shard: &Shard,
) -> Result<CheckedShard, Error> {
    Rs::check(config, commitment, index, shard)
}

pub fn check_all(
    config: &Config,
    commitment: &Commitment,
    shards: &[Shard],
) -> Result<Vec<CheckedShard>, Error> {
    shards
        .iter()
        .enumerate()
        .map(|(i, s)| Rs::check(config, commitment, i as u16, s))
        .collect()
}

/// Recover the message from `k` already-checked shards.
pub fn decode(
    config: &Config,
    commitment: &Commitment,
    shards: &[CheckedShard],
    strategy: &impl Strategy,
) -> Result<Vec<u8>, Error> {
    Rs::decode(config, commitment, shards.iter(), strategy)
}

/// Bytes a peer must receive for one shard, counted the same way as
/// [`crate::repo::shard_wire_size`]: the codec's encoded size of the shard,
/// which already includes the embedded Merkle proof.
pub fn shard_wire_size(shard: &Shard) -> usize {
    use commonware_codec::EncodeSize;
    shard.encode_size()
}
