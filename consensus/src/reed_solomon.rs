//! Erasure coding, backed by [`reed_solomon_simd`] (Leopard-RS over GF(2^16),
//! O(n log n)).
//!
//! Two layers are exposed, because the protocols in this repository commit to
//! shards in two different ways.
//!
//! * The **committed** layer (this module's root). `encode` returns one 32-byte
//!   commitment and `n` shards. The commitment is the root of the AES Merkle
//!   tree of [`crypto::aes_hash`] over the SHA-256 hash of each shard, and each
//!   shard carries its inclusion proof. `ctrbc`, `asks` and `avid` use this
//!   layer.
//!
//! * The **raw** layer ([`raw`]) is the bare coder with no commitment. `ccbrb`
//!   and `ecc_rbc` commit to their shards with a vector of hashes, so they use
//!   this layer.
//!
//! # Data layout
//!
//! The `k` data shards hold `[u32 length (big endian) | data | zero padding]`.
//! The shard width is the smallest even width that holds the prefix and the
//! data. [`decode`] rejects any other layout, so one commitment decodes to at
//! most one message.

use std::collections::BTreeMap;
use std::convert::TryFrom;
use std::fmt;

use crypto::aes_hash::{HashState, MerkleTree, Proof};
use crypto::hash::{do_hash, Hash};
use rayon::prelude::{IntoParallelRefIterator, ParallelIterator};
use reed_solomon_simd::ReedSolomonEncoder;
use serde::{Deserialize, Serialize};

/// A commitment to a full set of shards: the root of the Merkle tree over the
/// shard hashes.
pub type Commitment = Hash;

/// One shard of an erasure-coded message, with its Merkle inclusion proof
/// against the [`Commitment`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Shard {
    bytes: Vec<u8>,
    proof: Proof,
}

/// A shard that [`check`] verified against a [`Commitment`].
///
/// This type is not serializable. It shows that *this* process verified the
/// shard, so the network must not supply it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckedShard {
    commitment: Commitment,
    index: usize,
    bytes: Vec<u8>,
}

/// Errors returned by the coding layer.
#[derive(Debug)]
pub enum Error {
    /// `data_shards` / `parity_shards` cannot be used with this coder. Both
    /// must be non-zero and their sum must be at most 65536.
    InvalidParameters {
        data_shards: usize,
        parity_shards: usize,
    },
    /// Fewer than `data_shards` distinct shards were supplied to [`decode`].
    NotEnoughShards { have: usize, need: usize },
    /// Shards disagreed on their length, or a length was zero or odd. The
    /// GF(2^16) coder reads shards two bytes at a time.
    InconsistentShardLength,
    /// The shard did not verify against the commitment at the given index.
    InvalidShard { index: usize },
    /// Reconstruction produced data that does not match the commitment, or the
    /// coder itself failed.
    Coding(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidParameters {
                data_shards,
                parity_shards,
            } => write!(
                f,
                "unsupported erasure code parameters: {} data + {} parity shards",
                data_shards, parity_shards
            ),
            Error::NotEnoughShards { have, need } => {
                write!(f, "not enough shards to decode: have {}, need {}", have, need)
            }
            Error::InconsistentShardLength => write!(f, "shards have inconsistent lengths"),
            Error::InvalidShard { index } => write!(f, "shard {} failed verification", index),
            Error::Coding(msg) => write!(f, "coding error: {}", msg),
        }
    }
}

impl std::error::Error for Error {}

impl From<reed_solomon_simd::Error> for Error {
    fn from(error: reed_solomon_simd::Error) -> Self {
        Error::Coding(error.to_string())
    }
}

/// Make sure that the coder supports `data_shards + parity_shards`.
fn check_parameters(data_shards: usize, parity_shards: usize) -> Result<(), Error> {
    if data_shards == 0
        || parity_shards == 0
        || !ReedSolomonEncoder::supports(data_shards, parity_shards)
    {
        return Err(Error::InvalidParameters {
            data_shards,
            parity_shards,
        });
    }
    Ok(())
}

/// The shard width for a message of `data_len` bytes: the smallest even width
/// that holds the 4-byte length prefix and the data in `data_shards` shards.
fn shard_width(data_len: usize, data_shards: usize) -> usize {
    let width = (4 + data_len).div_ceil(data_shards);
    width + width % 2
}

/// Add the parity shards to `data`, and build the Merkle tree over all
/// `data_shards + parity_shards` shards.
fn commit(
    mut data: Vec<Vec<u8>>,
    data_shards: usize,
    parity_shards: usize,
    hash_state: &HashState,
) -> Result<(MerkleTree, Vec<Vec<u8>>), Error> {
    let parity = reed_solomon_simd::encode(data_shards, parity_shards, &data)?;
    data.extend(parity);
    let leaves: Vec<Hash> = data.iter().map(|shard| do_hash(shard)).collect();
    Ok((MerkleTree::new(leaves, hash_state), data))
}

/// Erasure-code `data` into `data_shards + parity_shards` shards and commit to
/// them.
///
/// Shard `i` is the shard that node `i` must hold, and it verifies only at
/// index `i`. Any `data_shards` of them reconstruct the message exactly.
pub fn encode(
    data: &[u8],
    data_shards: usize,
    parity_shards: usize,
    hash_state: &HashState,
) -> Result<(Commitment, Vec<Shard>), Error> {
    check_parameters(data_shards, parity_shards)?;
    let data_len = u32::try_from(data.len())
        .map_err(|_| Error::Coding(format!("message of {} bytes is too long", data.len())))?;

    let width = shard_width(data.len(), data_shards);
    let mut padded = vec![0u8; data_shards * width];
    padded[..4].copy_from_slice(&data_len.to_be_bytes());
    padded[4..4 + data.len()].copy_from_slice(data);
    let originals: Vec<Vec<u8>> = padded.chunks(width).map(<[u8]>::to_vec).collect();

    let (tree, shards) = commit(originals, data_shards, parity_shards, hash_state)?;
    let shards = shards
        .into_iter()
        .enumerate()
        .map(|(index, bytes)| Shard {
            bytes,
            proof: tree.gen_proof(index),
        })
        .collect();
    Ok((tree.root(), shards))
}

/// Erasure-code a batch of independent messages, one for each recipient.
///
/// This is the main cost of the AVID dealer: `n` messages, each coded into `n`
/// shards. The messages are independent, so rayon codes them in parallel.
/// `result[i]` belongs to `messages[i]`.
///
/// From async code, call [`encode_batch_async`]. This function blocks until
/// the full batch is done.
pub fn encode_batch(
    messages: &[Vec<u8>],
    data_shards: usize,
    parity_shards: usize,
    hash_state: &HashState,
) -> Result<Vec<(Commitment, Vec<Shard>)>, Error> {
    // Check the split one time, so that a bad split does not give `n` errors.
    check_parameters(data_shards, parity_shards)?;
    messages
        .par_iter()
        .map(|message| encode(message, data_shards, parity_shards, hash_state))
        .collect()
}

/// [`encode_batch`] on the rayon pool, without a block of the caller.
///
/// `par_iter` in an `async fn` does not yield: it parks the tokio worker until
/// the full batch is done. `rayon::spawn` and a oneshot channel let the future
/// wait instead, so the worker can run other tasks. `rayon::spawn` needs a
/// `'static` closure, thus this function takes its own `HashState`.
pub async fn encode_batch_async(
    messages: Vec<Vec<u8>>,
    data_shards: usize,
    parity_shards: usize,
    hash_state: HashState,
) -> Result<Vec<(Commitment, Vec<Shard>)>, Error> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    rayon::spawn(move || {
        // A send fails only if the waiting task stopped. Then nobody needs the
        // result.
        let _ = tx.send(encode_batch(&messages, data_shards, parity_shards, &hash_state));
    });
    rx.await.unwrap_or_else(|_| {
        Err(Error::Coding(
            "the rayon encoding task was dropped before it produced a result".to_string(),
        ))
    })
}

/// Verify `shard` against `commitment` at `index`.
///
/// `index` is the position of the shard in the encoding. In all protocols here,
/// this is the identity of the node that holds the shard. A shard verifies at
/// one index only, so this also authenticates the claim of the sender to that
/// position.
pub fn check(
    commitment: &Commitment,
    index: usize,
    shard: &Shard,
    data_shards: usize,
    parity_shards: usize,
    hash_state: &HashState,
) -> Result<CheckedShard, Error> {
    check_parameters(data_shards, parity_shards)?;
    let invalid = Error::InvalidShard { index };
    let total = data_shards + parity_shards;
    if index >= total {
        return Err(invalid);
    }

    // The tree has one level for each halving of `total`, rounded up. A proof
    // with a different shape can cause `Proof::validate` to panic, thus check
    // the shape first.
    let mut depth = 0;
    let mut width = total;
    while width > 1 {
        width = width.div_ceil(2);
        depth += 1;
    }
    let path = shard.proof.path();
    if path.len() != depth || shard.proof.lemma().len() != depth + 2 {
        return Err(invalid);
    }

    // The path gives the position of the leaf: `true` at level `l` means that
    // bit `l` of the position is zero.
    let position = path
        .iter()
        .enumerate()
        .fold(0usize, |position, (level, is_left)| position | ((!is_left as usize) << level));
    if position != index
        || shard.proof.root() != *commitment
        || shard.proof.item() != do_hash(&shard.bytes)
        || !shard.proof.validate(hash_state)
    {
        return Err(invalid);
    }

    Ok(CheckedShard {
        commitment: *commitment,
        index,
        bytes: shard.bytes.clone(),
    })
}

/// Reconstruct the message and all shards from at least `data_shards` verified
/// shards, and make sure that they match `commitment`.
fn reconstruct<'a, I>(
    commitment: &Commitment,
    shards: I,
    data_shards: usize,
    parity_shards: usize,
    hash_state: &HashState,
) -> Result<(Vec<u8>, MerkleTree, Vec<Vec<u8>>), Error>
where
    I: IntoIterator<Item = &'a CheckedShard>,
{
    check_parameters(data_shards, parity_shards)?;

    // Two shards checked at the same index under one commitment have the same
    // bytes, so a repeated index adds nothing.
    let mut by_index: BTreeMap<usize, &[u8]> = BTreeMap::new();
    for shard in shards {
        if shard.commitment != *commitment {
            return Err(Error::InvalidShard { index: shard.index });
        }
        by_index.entry(shard.index).or_insert(&shard.bytes);
    }
    if by_index.len() < data_shards {
        return Err(Error::NotEnoughShards {
            have: by_index.len(),
            need: data_shards,
        });
    }
    let width = by_index.values().next().map_or(0, |bytes| bytes.len());
    if width == 0 || width % 2 != 0 || by_index.values().any(|bytes| bytes.len() != width) {
        return Err(Error::InconsistentShardLength);
    }

    let restored = if (0..data_shards).all(|index| by_index.contains_key(&index)) {
        BTreeMap::new()
    } else {
        reed_solomon_simd::decode(
            data_shards,
            parity_shards,
            by_index.range(..data_shards).map(|(index, bytes)| (*index, *bytes)),
            by_index.range(data_shards..).map(|(index, bytes)| (index - data_shards, *bytes)),
        )?
    };
    let originals: Vec<Vec<u8>> = (0..data_shards)
        .map(|index| match by_index.get(&index) {
            Some(bytes) => bytes.to_vec(),
            None => restored[&index].clone(),
        })
        .collect();

    // A dealer can commit to shards that are not one codeword. Then different
    // sets of shards decode to different messages. Encode the data shards
    // again and compare the root, so that all honest nodes get the same
    // message or an error.
    let (tree, all_shards) = commit(originals, data_shards, parity_shards, hash_state)?;
    if tree.root() != *commitment {
        return Err(Error::Coding(
            "the decoded shards do not match the commitment".to_string(),
        ));
    }

    // Accept only the layout that `encode` makes, so that one commitment gives
    // at most one message.
    let layout = all_shards[..data_shards].concat();
    let data_len = u32::from_be_bytes([layout[0], layout[1], layout[2], layout[3]]) as usize;
    if 4 + data_len > layout.len()
        || layout[4 + data_len..].iter().any(|byte| *byte != 0)
        || shard_width(data_len, data_shards) != width
    {
        return Err(Error::Coding(
            "the decoded shards do not have the canonical layout".to_string(),
        ));
    }
    Ok((layout[4..4 + data_len].to_vec(), tree, all_shards))
}

/// Reconstruct the message from at least `data_shards` verified shards.
///
/// A successful return means that the message is bound to `commitment`.
pub fn decode<'a, I>(
    commitment: &Commitment,
    shards: I,
    data_shards: usize,
    parity_shards: usize,
    hash_state: &HashState,
) -> Result<Vec<u8>, Error>
where
    I: IntoIterator<Item = &'a CheckedShard>,
{
    reconstruct(commitment, shards, data_shards, parity_shards, hash_state)
        .map(|(message, _, _)| message)
}

/// Reconstruct the message *and* all shards with their proofs.
///
/// A node that reconstructs during the ECHO or READY phase must then send its
/// own shard, which it possibly did not receive. The shards are the same
/// shards that the dealer made.
pub fn decode_with_shards<'a, I>(
    commitment: &Commitment,
    shards: I,
    data_shards: usize,
    parity_shards: usize,
    hash_state: &HashState,
) -> Result<(Vec<u8>, Vec<Shard>), Error>
where
    I: IntoIterator<Item = &'a CheckedShard>,
{
    let (message, tree, all_shards) =
        reconstruct(commitment, shards, data_shards, parity_shards, hash_state)?;
    let shards = all_shards
        .into_iter()
        .enumerate()
        .map(|(index, bytes)| Shard {
            bytes,
            proof: tree.gen_proof(index),
        })
        .collect();
    Ok((message, shards))
}

/// The bare Reed-Solomon coder, with no commitment.
///
/// `ccbrb` and `ecc_rbc` commit to the vector of shard hashes, not to a Merkle
/// root, so they use this layer. For new code, use the committed layer above.
pub mod raw {
    use super::{check_parameters, Error};

    /// Split `data` into `data_shards` zero-padded shards and add
    /// `parity_shards` parity shards.
    ///
    /// The message length is *not* recorded: the first `data_shards` shards
    /// hold the message and then zero padding. The caller must know where the
    /// message stops.
    pub fn get_shards(
        data: Vec<u8>,
        data_shards: usize,
        parity_shards: usize,
    ) -> Result<Vec<Vec<u8>>, Error> {
        check_parameters(data_shards, parity_shards)?;
        let width = data.len() / data_shards + 1;
        let width = width + width % 2;

        let mut padded = data;
        padded.resize(data_shards * width, 0);
        let mut shards: Vec<Vec<u8>> = padded.chunks(width).map(<[u8]>::to_vec).collect();
        let parity = reed_solomon_simd::encode(data_shards, parity_shards, &shards)?;
        shards.extend(parity);
        Ok(shards)
    }

    /// Fill in each missing shard of `data` in place.
    ///
    /// `data` must have `data_shards + parity_shards` slots. At least
    /// `data_shards` of them must be present, all with the same even length.
    /// This function makes the missing data shards and the missing parity
    /// shards again.
    pub fn reconstruct_data(
        data: &mut Vec<Option<Vec<u8>>>,
        data_shards: usize,
        parity_shards: usize,
    ) -> Result<(), Error> {
        check_parameters(data_shards, parity_shards)?;
        if data.len() != data_shards + parity_shards {
            return Err(Error::InvalidParameters {
                data_shards,
                parity_shards,
            });
        }

        let present = data.iter().flatten().count();
        if present < data_shards {
            return Err(Error::NotEnoughShards {
                have: present,
                need: data_shards,
            });
        }
        let width = data.iter().flatten().next().map_or(0, |shard| shard.len());
        if width == 0 || width % 2 != 0 || data.iter().flatten().any(|s| s.len() != width) {
            return Err(Error::InconsistentShardLength);
        }

        if data[..data_shards].iter().any(|s| s.is_none()) {
            let restored = reed_solomon_simd::decode(
                data_shards,
                parity_shards,
                data[..data_shards]
                    .iter()
                    .enumerate()
                    .filter_map(|(index, s)| s.as_ref().map(|s| (index, s))),
                data[data_shards..]
                    .iter()
                    .enumerate()
                    .filter_map(|(index, s)| s.as_ref().map(|s| (index, s))),
            )?;
            for (index, shard) in restored {
                data[index] = Some(shard);
            }
        }

        if data[data_shards..].iter().any(|s| s.is_none()) {
            let parity = reed_solomon_simd::encode(
                data_shards,
                parity_shards,
                data[..data_shards].iter().flatten(),
            )?;
            for (slot, shard) in data[data_shards..].iter_mut().zip(parity) {
                if slot.is_none() {
                    *slot = Some(shard);
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The split every protocol here uses: `n = 3f + 1`, `k = n - 2f`.
    fn split(n: usize) -> (usize, usize) {
        let f = (n - 1) / 3;
        (n - 2 * f, 2 * f)
    }

    fn hash_state() -> HashState {
        HashState::new([1u8; 16], [2u8; 16], [3u8; 16])
    }

    /// Commit to `shards` as they are, with proofs. A malicious dealer can do
    /// this with shards that are not one codeword.
    fn commit_as_dealer(shards: &[Vec<u8>], hs: &HashState) -> (Commitment, Vec<Shard>) {
        let leaves: Vec<Hash> = shards.iter().map(|shard| do_hash(shard)).collect();
        let tree = MerkleTree::new(leaves, hs);
        let shards = shards
            .iter()
            .enumerate()
            .map(|(index, bytes)| Shard {
                bytes: bytes.clone(),
                proof: tree.gen_proof(index),
            })
            .collect();
        (tree.root(), shards)
    }

    /// The batch encoder is the AVID dealer's path. It must agree with encoding
    /// one message at a time *and* keep input order, since the recipient of each
    /// encoding is recovered by position.
    #[test]
    fn batch_encoding_matches_sequential_encoding_and_keeps_order() {
        let hs = hash_state();
        for n in [4usize, 7, 16] {
            let (k, m) = split(n);
            // Distinct lengths and contents, so a reordering cannot go unnoticed.
            let messages: Vec<Vec<u8>> = (0..n)
                .map(|j| (0..(500 + 37 * j) as u32).map(|i| (i % (240 + j as u32)) as u8).collect())
                .collect();

            let expected: Vec<(Commitment, Vec<Shard>)> = messages
                .iter()
                .map(|message| encode(message, k, m, &hs).unwrap())
                .collect();
            let batched = encode_batch(&messages, k, m, &hs).unwrap();
            assert_eq!(batched, expected, "n={}", n);
        }
    }

    /// A bad split is reported once for the batch, not once per message.
    #[test]
    fn batch_encoding_rejects_a_bad_split() {
        let hs = hash_state();
        let messages = vec![vec![1u8; 64], vec![2u8; 64]];
        assert!(encode_batch(&messages, 0, 3, &hs).is_err());
        assert!(encode_batch(&messages, 3, 0, &hs).is_err());
    }

    /// The async bridge exists so the tokio worker is not parked on a rayon
    /// latch; it must still return exactly what the blocking call returns.
    #[tokio::test]
    async fn the_async_bridge_matches_the_blocking_batch() {
        let n = 7usize;
        let (k, m) = split(n);
        let messages: Vec<Vec<u8>> = (0..n)
            .map(|j| (0..(800 + 11 * j) as u32).map(|i| (i % 244) as u8).collect())
            .collect();

        let blocking = encode_batch(&messages, k, m, &hash_state()).unwrap();
        let bridged = encode_batch_async(messages, k, m, hash_state()).await.unwrap();
        assert_eq!(bridged, blocking);
    }

    /// An empty batch is legal: an AVID dealer with nothing to send must not be
    /// turned into a coding error.
    #[test]
    fn an_empty_batch_encodes_to_nothing() {
        let (k, m) = split(4);
        assert!(encode_batch(&[], k, m, &hash_state()).unwrap().is_empty());
    }

    #[test]
    fn committed_round_trip_from_the_last_k_shards() {
        let hs = hash_state();
        for n in [4usize, 7, 16, 64] {
            let (k, m) = split(n);
            let message: Vec<u8> = (0..5000u32).map(|i| (i % 251) as u8).collect();
            let (commitment, shards) = encode(&message, k, m, &hs).unwrap();
            assert_eq!(shards.len(), n);

            // Verify every shard, then decode from the *last* k, so that at
            // least one parity shard is involved and interpolation actually
            // happens.
            let checked: Vec<CheckedShard> = shards
                .iter()
                .enumerate()
                .map(|(i, s)| check(&commitment, i, s, k, m, &hs).unwrap())
                .collect();
            let survivors = &checked[n - k..];

            let (decoded, regenerated) =
                decode_with_shards(&commitment, survivors.iter(), k, m, &hs).unwrap();
            assert_eq!(decoded, message, "n={}", n);
            assert_eq!(regenerated, shards, "n={}", n);
        }
    }

    /// The protocols never hand `decode` exactly `k` shards: CTRBC and ASKS
    /// reconstruct once `n - f` ECHOs have arrived, and AVID once `k` READYs
    /// have, so the common path supplies more shards than are strictly needed.
    #[test]
    fn decoding_with_more_than_k_shards_is_accepted() {
        let hs = hash_state();
        for n in [4usize, 7, 16, 64] {
            let (k, m) = split(n);
            let f = (n - 1) / 3;
            let message: Vec<u8> = (0..4096u32).map(|i| (i % 253) as u8).collect();
            let (commitment, shards) = encode(&message, k, m, &hs).unwrap();

            let survivors: Vec<CheckedShard> = shards
                .iter()
                .enumerate()
                .skip(f)
                .map(|(i, s)| check(&commitment, i, s, k, m, &hs).unwrap())
                .collect();
            assert!(survivors.len() > k, "n={} would not exercise the extras", n);

            let decoded = decode(&commitment, survivors.iter(), k, m, &hs).unwrap();
            assert_eq!(decoded, message, "n={}", n);
        }
    }

    #[test]
    fn decoding_with_fewer_than_k_shards_fails() {
        let hs = hash_state();
        let (k, m) = split(16);
        let (commitment, shards) = encode(b"too few survivors", k, m, &hs).unwrap();
        let checked: Vec<CheckedShard> = shards
            .iter()
            .enumerate()
            .take(k - 1)
            .map(|(i, s)| check(&commitment, i, s, k, m, &hs).unwrap())
            .collect();
        // A repeated shard does not count twice.
        let repeated = checked.iter().chain(checked.first());
        assert!(matches!(
            decode(&commitment, repeated, k, m, &hs),
            Err(Error::NotEnoughShards { .. })
        ));
    }

    #[test]
    fn a_shard_only_verifies_at_its_own_index() {
        let hs = hash_state();
        for n in [4usize, 7, 16, 64] {
            let (k, m) = split(n);
            let (commitment, shards) = encode(b"authenticated position", k, m, &hs).unwrap();
            for (index, shard) in shards.iter().enumerate() {
                for claimed in 0..n + 1 {
                    assert_eq!(
                        check(&commitment, claimed, shard, k, m, &hs).is_ok(),
                        claimed == index,
                        "n={} shard={} claimed={}",
                        n,
                        index,
                        claimed
                    );
                }
            }
        }
    }

    #[test]
    fn a_shard_from_another_message_is_rejected() {
        let hs = hash_state();
        let (k, m) = split(16);
        let (commitment, shards) = encode(b"the real message", k, m, &hs).unwrap();
        let (other_commitment, other) = encode(b"a different message", k, m, &hs).unwrap();
        assert!(check(&commitment, 0, &other[0], k, m, &hs).is_err());

        // A shard checked against another commitment cannot join a decode.
        let mut checked: Vec<CheckedShard> = shards
            .iter()
            .enumerate()
            .map(|(i, s)| check(&commitment, i, s, k, m, &hs).unwrap())
            .collect();
        checked[0] = check(&other_commitment, 0, &other[0], k, m, &hs).unwrap();
        assert!(decode(&commitment, checked.iter(), k, m, &hs).is_err());
    }

    /// A malformed proof from the network must give an error, not a panic in
    /// `Proof::validate`.
    #[test]
    fn a_malformed_proof_is_rejected() {
        let hs = hash_state();
        let (k, m) = split(16);
        let (commitment, shards) = encode(b"proof shape", k, m, &hs).unwrap();
        let lemma = shards[0].proof.lemma().to_vec();
        let path = shards[0].proof.path().to_vec();
        for proof in [
            Proof::new(lemma.clone(), path[1..].to_vec()),
            Proof::new(lemma[1..].to_vec(), path.clone()),
            Proof::new(vec![], vec![]),
        ] {
            let shard = Shard {
                bytes: shards[0].bytes.clone(),
                proof,
            };
            assert!(check(&commitment, 0, &shard, k, m, &hs).is_err());
        }
    }

    /// A dealer that commits to shards which are not one codeword must not make
    /// two honest nodes decode two different messages: every subset fails.
    #[test]
    fn a_commitment_to_a_non_codeword_does_not_decode() {
        let hs = hash_state();
        let (k, m) = split(16);
        let (_, honest) = encode(&[5u8; 300], k, m, &hs).unwrap();
        let mut bytes: Vec<Vec<u8>> = honest.into_iter().map(|s| s.bytes).collect();
        bytes[k][0] ^= 1;
        let (commitment, shards) = commit_as_dealer(&bytes, &hs);

        let checked: Vec<CheckedShard> = shards
            .iter()
            .enumerate()
            .map(|(i, s)| check(&commitment, i, s, k, m, &hs).unwrap())
            .collect();
        assert!(decode(&commitment, checked[..k].iter(), k, m, &hs).is_err());
        assert!(decode(&commitment, checked[m..].iter(), k, m, &hs).is_err());
    }

    /// One commitment decodes to at most one message: a codeword with other
    /// padding or another width is rejected.
    #[test]
    fn a_non_canonical_layout_does_not_decode() {
        let hs = hash_state();
        let (k, m) = split(7);
        let message = [9u8; 10];
        let width = shard_width(message.len(), k);

        let mut canonical = vec![0u8; k * width];
        canonical[..4].copy_from_slice(&(message.len() as u32).to_be_bytes());
        canonical[4..4 + message.len()].copy_from_slice(&message);

        let mut dirty_padding = canonical.clone();
        *dirty_padding.last_mut().unwrap() = 1;
        let mut too_wide = canonical.clone();
        too_wide.resize(k * (width + 2), 0);

        for (layout, shard_len) in [(dirty_padding, width), (too_wide, width + 2)] {
            let originals: Vec<Vec<u8>> = layout.chunks(shard_len).map(<[u8]>::to_vec).collect();
            let (_, all) = commit(originals, k, m, &hs).unwrap();
            let (commitment, shards) = commit_as_dealer(&all, &hs);
            let checked: Vec<CheckedShard> = shards
                .iter()
                .enumerate()
                .map(|(i, s)| check(&commitment, i, s, k, m, &hs).unwrap())
                .collect();
            assert!(decode(&commitment, checked.iter(), k, m, &hs).is_err());
        }
    }

    #[test]
    fn shards_survive_the_serde_wire() {
        let hs = hash_state();
        let (k, m) = split(16);
        let (commitment, shards) = encode(b"over the wire", k, m, &hs).unwrap();
        for (index, shard) in shards.iter().enumerate() {
            let bytes = bincode::serialize(shard).unwrap();
            let restored: Shard = bincode::deserialize(&bytes).unwrap();
            assert_eq!(&restored, shard);
            check(&commitment, index, &restored, k, m, &hs).unwrap();
        }
    }

    #[test]
    fn empty_and_tiny_messages_round_trip() {
        let hs = hash_state();
        let (k, m) = split(16);
        for message in [vec![], vec![7u8], vec![9u8; 3]] {
            let (commitment, shards) = encode(&message, k, m, &hs).unwrap();
            let checked: Vec<CheckedShard> = shards
                .iter()
                .enumerate()
                .map(|(i, s)| check(&commitment, i, s, k, m, &hs).unwrap())
                .collect();
            let decoded = decode(&commitment, checked[m..].iter(), k, m, &hs).unwrap();
            assert_eq!(decoded, message);
        }
    }

    /// `ccbrb` and `ecc_rbc` code their hash vectors with `k = f`, which is 1
    /// at the smallest committee size.
    #[test]
    fn raw_handles_a_single_data_shard() {
        let message: Vec<u8> = (0..777u32).map(|i| (i % 199) as u8).collect();
        let shards = raw::get_shards(message.clone(), 1, 3).unwrap();
        assert_eq!(shards.len(), 4);

        let mut received: Vec<Option<Vec<u8>>> =
            vec![None, Some(shards[1].clone()), None, None];
        raw::reconstruct_data(&mut received, 1, 3).unwrap();
        let restored: Vec<Vec<u8>> = received.into_iter().map(|s| s.unwrap()).collect();
        assert_eq!(restored, shards);

        let mut flat = restored[0].clone();
        flat.truncate(message.len());
        assert_eq!(flat, message);
    }

    #[test]
    fn raw_round_trip_with_2f_erasures() {
        for n in [4usize, 7, 16, 64] {
            let (k, m) = split(n);
            let message: Vec<u8> = (0..3333u32).map(|i| (i % 97) as u8).collect();
            let shards = raw::get_shards(message.clone(), k, m).unwrap();
            assert_eq!(shards.len(), n);

            // Drop the first `m` shards, which erases data shards and forces
            // interpolation.
            let mut received: Vec<Option<Vec<u8>>> = shards
                .iter()
                .enumerate()
                .map(|(i, s)| if i < m { None } else { Some(s.clone()) })
                .collect();
            raw::reconstruct_data(&mut received, k, m).unwrap();

            let restored: Vec<Vec<u8>> = received.into_iter().map(|s| s.unwrap()).collect();
            assert_eq!(restored, shards, "n={}", n);

            let mut flat: Vec<u8> = restored[..k].concat();
            flat.truncate(message.len());
            assert_eq!(flat, message, "n={}", n);
        }
    }

    #[test]
    fn raw_fills_missing_parity_when_all_data_shards_are_present() {
        let (k, m) = split(16);
        let shards = raw::get_shards(vec![3u8; 1000], k, m).unwrap();
        let mut received: Vec<Option<Vec<u8>>> = shards
            .iter()
            .enumerate()
            .map(|(i, s)| if i < k { Some(s.clone()) } else { None })
            .collect();
        raw::reconstruct_data(&mut received, k, m).unwrap();
        let restored: Vec<Vec<u8>> = received.into_iter().map(|s| s.unwrap()).collect();
        assert_eq!(restored, shards);
    }

    #[test]
    fn raw_refuses_to_decode_below_the_threshold() {
        let (k, m) = split(16);
        let shards = raw::get_shards(vec![1u8; 500], k, m).unwrap();
        let mut received: Vec<Option<Vec<u8>>> = shards
            .iter()
            .enumerate()
            .map(|(i, s)| if i < k - 1 { Some(s.clone()) } else { None })
            .collect();
        assert!(raw::reconstruct_data(&mut received, k, m).is_err());
    }
}
