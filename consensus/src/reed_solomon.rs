//! Erasure coding, backed by [`commonware_coding`].
//!
//! Two layers are exposed, because the protocols in this repository commit to
//! shards in two different ways.
//!
//! * The **committed** layer (this module's root) is
//!   [`commonware_coding::ReedSolomon`]. `encode` returns a single 32-byte
//!   commitment plus `n` shards, each of which already carries a Merkle
//!   inclusion proof against that commitment. Protocols that used to call
//!   `get_shards` and then build their own Merkle tree over the shard hashes
//!   (`ctrbc`, `asks`, `avid`) use this and drop their tree entirely.
//!
//! * The **raw** layer ([`raw`]) is the bare Reed-Solomon coder with no
//!   commitment at all, presented with the same signatures the old
//!   `reed-solomon-erasure` helpers had. `ccbrb` commits to its shards with an
//!   explicit vector of hashes rather than a Merkle root, so it needs the coder
//!   without the commitment attached.
//!
//! Both layers run commonware's vendored `reed-solomon-simd` (Leopard-RS over
//! GF(2^16), O(n log n)), replacing `reed-solomon-erasure`'s scalar GF(2^8)
//! matrix coder.
//!
//! # Wire format
//!
//! [`Shard`] and [`Commitment`] both travel inside this repository's
//! `serde`/`bincode` messages, but commonware types implement
//! `commonware_codec` rather than `serde`. [`Shard`] bridges the two: it
//! serializes as the byte string produced by commonware's codec and is read
//! back with [`MAX_SHARD_SIZE`] as the length bound. [`Commitment`] is a
//! SHA-256 digest and is carried as a plain `[u8; 32]`, so it is directly
//! usable as a `HashMap` key the way Merkle roots were before.

use std::convert::TryFrom;
use std::fmt;
use std::num::NonZeroU16;

use commonware_codec::{Decode, Encode};
use commonware_coding::{CodecConfig, Config, ReedSolomon, Scheme};
use commonware_cryptography::{sha256::Digest as Sha256Digest, Sha256};
use commonware_parallel::{Rayon, Sequential};
use crypto::hash::Hash;
use rayon::prelude::{IntoParallelRefIterator, ParallelIterator};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::sync::OnceLock;

/// The coding scheme every protocol in this repository uses.
type Coder = ReedSolomon<Sha256>;

/// Parallelism strategy handed to commonware.
///
/// `Sequential` is deliberate: several protocols (`acs`, `fin_mvba`) run tens
/// of coding instances concurrently on the tokio runtime, and handing each of
/// them a rayon pool oversubscribes the machine rather than speeding any single
/// one up. Switch this one constant to `commonware_parallel::Rayon` if a
/// deployment runs one large broadcast at a time.
const STRATEGY: Sequential = Sequential;

/// Upper bound accepted when reading a [`Shard`] off the wire, in bytes.
///
/// This only bounds the allocation a malformed message can request; it is not a
/// protocol parameter. 256 MiB per shard is far above anything these protocols
/// broadcast, and the previous code (a bare `Vec<u8>` field) had no bound at
/// all.
pub const MAX_SHARD_SIZE: usize = 256 * 1024 * 1024;

/// A commitment to a full set of shards: the root of commonware's binary
/// Merkle tree over the shard hashes.
///
/// This is the same 32 bytes the protocols previously used as their Merkle
/// root, so it drops into the same `HashMap<Hash, _>` state.
pub type Commitment = Hash;

/// A shard that has been verified against a [`Commitment`].
///
/// Produced by [`check`] and consumed by [`decode`]. Not serializable by
/// design: it is evidence that *this* process verified the shard, so it must
/// not be accepted from the network.
pub type CheckedShard = <Coder as Scheme>::CheckedShard;

/// One shard of an erasure-coded message, together with its Merkle inclusion
/// proof against the [`Commitment`].
///
/// Replaces the old `(Vec<u8>, crypto::aes_hash::Proof)` pair.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Shard(<Coder as Scheme>::Shard);

impl Shard {
    /// Size of this shard on the wire, in bytes.
    ///
    /// A `Chunk` does not expose its index, and deliberately so: a shard's
    /// position is asserted by the verifier in [`check`], never read out of the
    /// shard itself.
    pub fn wire_size(&self) -> usize {
        self.0.encode().len()
    }
}

impl Serialize for Shard {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let bytes = self.0.encode();
        serializer.serialize_bytes(bytes.as_ref())
    }
}

impl<'de> Deserialize<'de> for Shard {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let bytes = <Vec<u8>>::deserialize(deserializer)?;
        let cfg = CodecConfig {
            maximum_shard_size: MAX_SHARD_SIZE,
        };
        <Coder as Scheme>::Shard::decode_cfg(bytes.as_slice(), &cfg)
            .map(Shard)
            .map_err(serde::de::Error::custom)
    }
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
    /// Fewer than `data_shards` shards were supplied to [`decode`].
    NotEnoughShards { have: usize, need: usize },
    /// Shards disagreed on their length, or a length was odd. The GF(2^16)
    /// coder reads shards two bytes at a time and requires a uniform, even
    /// width.
    InconsistentShardLength,
    /// The shard did not verify against the commitment at the given index.
    InvalidShard { index: usize },
    /// Reconstruction produced data that does not hash to the commitment, or
    /// the coder itself failed.
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

/// Build a commonware [`Config`] from the `(data, parity)` split the protocols
/// use.
fn config(data_shards: usize, parity_shards: usize) -> Result<Config, Error> {
    let invalid = || Error::InvalidParameters {
        data_shards,
        parity_shards,
    };
    if data_shards + parity_shards > u16::MAX as usize {
        return Err(invalid());
    }
    let minimum_shards =
        NonZeroU16::new(u16::try_from(data_shards).map_err(|_| invalid())?).ok_or_else(invalid)?;
    let extra_shards =
        NonZeroU16::new(u16::try_from(parity_shards).map_err(|_| invalid())?).ok_or_else(invalid)?;
    Ok(Config {
        minimum_shards,
        extra_shards,
    })
}

/// Erasure-code `data` into `data_shards + parity_shards` shards and commit to
/// them.
///
/// The returned shards are in index order: shard `i` is the one node `i` must
/// receive, and it will only verify at that index. Any `data_shards` of them
/// reconstruct the message *exactly* — commonware prefixes the payload with its
/// length, so unlike the old `get_shards` there is no trailing zero padding for
/// the caller to strip.
pub fn encode(
    data: &[u8],
    data_shards: usize,
    parity_shards: usize,
) -> Result<(Commitment, Vec<Shard>), Error> {
    let config = config(data_shards, parity_shards)?;
    let (commitment, shards) =
        Coder::encode(&config, data, &STRATEGY).map_err(|e| Error::Coding(format!("{:?}", e)))?;
    Ok((commitment.0, shards.into_iter().map(Shard).collect()))
}

/// The process-wide rayon strategy used by [`encode_parallel`].
///
/// Built once. `Rayon::new` constructs its own thread pool, so calling it per
/// encode would spawn and tear down a pool for every broadcast. `None` means a
/// pool could not be built, and callers fall back to [`encode`].
fn parallel_strategy() -> Option<&'static Rayon> {
    static PARALLEL: OnceLock<Option<Rayon>> = OnceLock::new();
    PARALLEL
        .get_or_init(|| Rayon::new(std::thread::available_parallelism().ok()?).ok())
        .as_ref()
}

/// [`encode`], with commonware spreading a *single* message's coding across a
/// rayon pool.
///
/// Use this only where a node codes one large message at a time, which is the
/// dealer in `ctrbc::start_init`. [`encode`] stays [`Sequential`] everywhere
/// else on purpose: `acs` and `fin_mvba` drive tens of coding instances
/// concurrently on the tokio runtime, and giving each of those its own pool
/// oversubscribes the machine rather than speeding any single one up.
///
/// Falls back to [`encode`] when no pool can be built.
pub fn encode_parallel(
    data: &[u8],
    data_shards: usize,
    parity_shards: usize,
) -> Result<(Commitment, Vec<Shard>), Error> {
    let Some(strategy) = parallel_strategy() else {
        return encode(data, data_shards, parity_shards);
    };
    let config = config(data_shards, parity_shards)?;
    let (commitment, shards) =
        Coder::encode(&config, data, strategy).map_err(|e| Error::Coding(format!("{:?}", e)))?;
    Ok((commitment.0, shards.into_iter().map(Shard).collect()))
}

/// Erasure-code a whole batch of independent messages, one per recipient.
///
/// This is the dealer's dominant cost in `avid::start_init`: `n` messages, each
/// coded into `n` shards and committed, so `O(n^2)` shard work per
/// dissemination. The messages do not depend on each other, so they go straight
/// onto rayon.
///
/// Each individual encode stays [`Sequential`]. The parallelism is *across*
/// messages, which saturates the pool once rather than nesting a pool inside a
/// pool.
///
/// Results keep input order: `result[i]` belongs to `messages[i]`.
///
/// Call [`encode_batch_async`] from async code — this function blocks until the
/// whole batch is done.
pub fn encode_batch(
    messages: &[Vec<u8>],
    data_shards: usize,
    parity_shards: usize,
) -> Result<Vec<(Commitment, Vec<Shard>)>, Error> {
    // Validate once up front so a bad split is not reported `n` times over.
    config(data_shards, parity_shards)?;
    messages
        .par_iter()
        .map(|message| encode(message, data_shards, parity_shards))
        .collect()
}

/// [`encode_batch`], run on rayon's pool without blocking the caller.
///
/// `par_iter` called directly from an `async fn` does not yield: it injects the
/// job and then parks the calling thread on a latch, so the tokio worker
/// running that task is unavailable until the whole batch finishes and the
/// actor's inbox keeps growing behind it. Handing the batch to `rayon::spawn`
/// and awaiting a oneshot suspends the future instead, leaving the worker free
/// to drive other tasks.
pub async fn encode_batch_async(
    messages: Vec<Vec<u8>>,
    data_shards: usize,
    parity_shards: usize,
) -> Result<Vec<(Commitment, Vec<Shard>)>, Error> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    rayon::spawn(move || {
        // A send failure only means the receiver was dropped, i.e. the awaiting
        // task went away; there is nothing to do about it here.
        let _ = tx.send(encode_batch(&messages, data_shards, parity_shards));
    });
    rx.await.unwrap_or_else(|_| {
        Err(Error::Coding(
            "the rayon encoding task was dropped before it produced a result".to_string(),
        ))
    })
}

/// Verify `shard` against `commitment` at `index`.
///
/// `index` is the position the shard was encoded at, which for every protocol
/// here is the identity of the node that is supposed to hold it. Verifying a
/// shard at the wrong index fails, so this also authenticates the sender's
/// claim to that position.
pub fn check(
    commitment: &Commitment,
    index: usize,
    shard: &Shard,
    data_shards: usize,
    parity_shards: usize,
) -> Result<CheckedShard, Error> {
    let config = config(data_shards, parity_shards)?;
    let index = u16::try_from(index).map_err(|_| Error::InvalidShard { index })?;
    Coder::check(&config, &Sha256Digest(*commitment), index, &shard.0)
        .map_err(|_| Error::InvalidShard {
            index: index as usize,
        })
}

/// Reconstruct the message from at least `data_shards` verified shards.
///
/// commonware re-derives the commitment as part of decoding and rejects the
/// result if it does not match, so a successful return means the message is
/// bound to `commitment` — the explicit "rebuild the Merkle tree and compare
/// roots" step the protocols used to perform is now redundant.
pub fn decode<'a, I>(
    commitment: &Commitment,
    shards: I,
    data_shards: usize,
    parity_shards: usize,
) -> Result<Vec<u8>, Error>
where
    I: IntoIterator<Item = &'a CheckedShard>,
{
    let config = config(data_shards, parity_shards)?;
    Coder::decode(
        &config,
        &Sha256Digest(*commitment),
        shards.into_iter(),
        &STRATEGY,
    )
    .map_err(|e| Error::Coding(format!("{:?}", e)))
}

/// Reconstruct the message *and* regenerate every shard.
///
/// Decoding only yields the message, but a node that reconstructs during the
/// ECHO or READY phase must then forward its own shard, which it may never have
/// received. Encoding is deterministic, so re-encoding the decoded message
/// reproduces exactly the shards the dealer sent; this asserts that by checking
/// the regenerated commitment.
pub fn decode_with_shards<'a, I>(
    commitment: &Commitment,
    shards: I,
    data_shards: usize,
    parity_shards: usize,
) -> Result<(Vec<u8>, Vec<Shard>), Error>
where
    I: IntoIterator<Item = &'a CheckedShard>,
{
    let message = decode(commitment, shards, data_shards, parity_shards)?;
    let (regenerated, shards) = encode(&message, data_shards, parity_shards)?;
    if regenerated != *commitment {
        return Err(Error::Coding(
            "re-encoding the decoded message produced a different commitment".to_string(),
        ));
    }
    Ok((message, shards))
}

/// The bare Reed-Solomon coder, with no commitment attached.
///
/// Same signatures as the `reed-solomon-erasure` helpers this replaces, so that
/// protocols which build their own commitment over the shards (`ccbrb` commits
/// to the vector of shard hashes rather than to a Merkle root) keep working
/// unchanged. Prefer the committed layer above for anything new: it produces
/// inclusion proofs for free and verifies reconstruction against the
/// commitment.
pub mod raw {
    use super::Error;
    use commonware_cryptography::reed_solomon::{Decoder, Encoder};

    /// Round `width` up to the even width the GF(2^16) coder requires.
    fn even(width: usize) -> usize {
        if width % 2 == 0 {
            width
        } else {
            width + 1
        }
    }

    /// Split `data` into `data_shards` zero-padded shards and append
    /// `parity_shards` recovery shards.
    ///
    /// The message length is *not* recorded, matching the previous behaviour:
    /// concatenating the first `data_shards` shards yields the message followed
    /// by zero padding, and callers are responsible for knowing where it ends.
    pub fn get_shards(
        data: Vec<u8>,
        data_shards: usize,
        parity_shards: usize,
    ) -> Result<Vec<Vec<u8>>, Error> {
        if data_shards == 0 || parity_shards == 0 || !Encoder::supports(data_shards, parity_shards)
        {
            return Err(Error::InvalidParameters {
                data_shards,
                parity_shards,
            });
        }
        let width = even((data.len() / data_shards) + 1);

        let mut shards: Vec<Vec<u8>> = Vec::with_capacity(data_shards + parity_shards);
        for i in 0..data_shards {
            let start = (i * width).min(data.len());
            let end = ((i + 1) * width).min(data.len());
            let mut shard = Vec::with_capacity(width);
            shard.extend_from_slice(&data[start..end]);
            shard.resize(width, 0);
            shards.push(shard);
        }

        let mut encoder = Encoder::new(data_shards, parity_shards, width)
            .map_err(|e| Error::Coding(format!("{:?}", e)))?;
        for shard in shards.iter() {
            encoder
                .add_original_shard(shard)
                .map_err(|e| Error::Coding(format!("{:?}", e)))?;
        }
        let result = encoder
            .encode()
            .map_err(|e| Error::Coding(format!("{:?}", e)))?;
        for recovery in result.recovery_iter() {
            shards.push(recovery.to_vec());
        }
        drop(result);

        Ok(shards)
    }

    /// Fill in every missing shard of `data` in place.
    ///
    /// `data` must have exactly `data_shards + parity_shards` slots, at least
    /// `data_shards` of which are present and all of the same even length.
    /// Both the missing data shards and the missing parity shards are
    /// regenerated, as the previous implementation did.
    pub fn reconstruct_data(
        data: &mut Vec<Option<Vec<u8>>>,
        data_shards: usize,
        parity_shards: usize,
    ) -> Result<(), Error> {
        let total = data_shards + parity_shards;
        if data_shards == 0 || parity_shards == 0 || data.len() != total {
            return Err(Error::InvalidParameters {
                data_shards,
                parity_shards,
            });
        }

        let width = match data.iter().flatten().next() {
            Some(shard) => shard.len(),
            None => {
                return Err(Error::NotEnoughShards {
                    have: 0,
                    need: data_shards,
                })
            }
        };
        if width == 0 || width % 2 != 0 || data.iter().flatten().any(|s| s.len() != width) {
            return Err(Error::InconsistentShardLength);
        }

        let present = data.iter().filter(|s| s.is_some()).count();
        if present < data_shards {
            return Err(Error::NotEnoughShards {
                have: present,
                need: data_shards,
            });
        }

        // Reconstruct the missing data shards, if any are missing.
        if data[..data_shards].iter().any(|s| s.is_none()) {
            let mut decoder = Decoder::new(data_shards, parity_shards, width)
                .map_err(|e| Error::Coding(format!("{:?}", e)))?;
            for (index, shard) in data.iter().enumerate() {
                let Some(shard) = shard else { continue };
                let outcome = if index < data_shards {
                    decoder.add_original_shard(index, shard)
                } else {
                    decoder.add_recovery_shard(index - data_shards, shard)
                };
                outcome.map_err(|e| Error::Coding(format!("{:?}", e)))?;
            }
            let result = decoder
                .decode_with_recovery()
                .map_err(|e| Error::Coding(format!("{:?}", e)))?;
            if let Some(result) = result {
                for index in 0..data_shards {
                    if data[index].is_none() {
                        let shard = result.original(index).ok_or(Error::NotEnoughShards {
                            have: present,
                            need: data_shards,
                        })?;
                        data[index] = Some(shard.to_vec());
                    }
                }
                for index in 0..parity_shards {
                    if data[data_shards + index].is_none() {
                        if let Some(shard) = result.recovery(index) {
                            data[data_shards + index] = Some(shard.to_vec());
                        }
                    }
                }
            }
        }

        // Every data shard is present now; regenerate any parity shard that is
        // still missing. `decode` skips this work when nothing had to be
        // reconstructed, so it is not always covered above.
        if data[data_shards..].iter().any(|s| s.is_none()) {
            let mut encoder = Encoder::new(data_shards, parity_shards, width)
                .map_err(|e| Error::Coding(format!("{:?}", e)))?;
            for index in 0..data_shards {
                let shard = data[index].as_ref().ok_or(Error::NotEnoughShards {
                    have: present,
                    need: data_shards,
                })?;
                encoder
                    .add_original_shard(shard)
                    .map_err(|e| Error::Coding(format!("{:?}", e)))?;
            }
            let result = encoder
                .encode()
                .map_err(|e| Error::Coding(format!("{:?}", e)))?;
            let recovery: Vec<Vec<u8>> = result.recovery_iter().map(|s| s.to_vec()).collect();
            drop(result);
            for (index, shard) in recovery.into_iter().enumerate() {
                if data[data_shards + index].is_none() {
                    data[data_shards + index] = Some(shard);
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

    /// `encode_parallel` hands commonware a rayon pool instead of `Sequential`.
    /// The strategy is a scheduling choice, so the shards and the commitment it
    /// produces must be byte-identical to the sequential ones.
    #[test]
    fn parallel_encoding_matches_sequential_encoding() {
        for n in [4usize, 7, 16, 64] {
            let (k, m) = split(n);
            let message: Vec<u8> = (0..9000u32).map(|i| (i % 251) as u8).collect();

            let (sequential_commitment, sequential_shards) = encode(&message, k, m).unwrap();
            let (parallel_commitment, parallel_shards) = encode_parallel(&message, k, m).unwrap();

            assert_eq!(parallel_commitment, sequential_commitment, "n={}", n);
            assert_eq!(parallel_shards, sequential_shards, "n={}", n);
        }
    }

    /// The batch encoder is the AVID dealer's path. It must agree with encoding
    /// one message at a time *and* keep input order, since the recipient of each
    /// encoding is recovered by position.
    #[test]
    fn batch_encoding_matches_sequential_encoding_and_keeps_order() {
        for n in [4usize, 7, 16] {
            let (k, m) = split(n);
            // Distinct lengths and contents, so a reordering cannot go unnoticed.
            let messages: Vec<Vec<u8>> = (0..n)
                .map(|j| (0..(500 + 37 * j) as u32).map(|i| (i % (240 + j as u32)) as u8).collect())
                .collect();

            let expected: Vec<(Commitment, Vec<Shard>)> = messages
                .iter()
                .map(|message| encode(message, k, m).unwrap())
                .collect();
            let batched = encode_batch(&messages, k, m).unwrap();

            assert_eq!(batched.len(), messages.len(), "n={}", n);
            for (index, (batch_entry, expected_entry)) in
                batched.iter().zip(expected.iter()).enumerate()
            {
                assert_eq!(batch_entry.0, expected_entry.0, "n={} index={}", n, index);
                assert_eq!(batch_entry.1, expected_entry.1, "n={} index={}", n, index);
            }
        }
    }

    /// A bad split is reported once for the batch, not once per message.
    #[test]
    fn batch_encoding_rejects_a_bad_split() {
        let messages = vec![vec![1u8; 64], vec![2u8; 64]];
        assert!(encode_batch(&messages, 0, 3).is_err());
        assert!(encode_batch(&messages, 3, 0).is_err());
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

        let blocking = encode_batch(&messages, k, m).unwrap();
        let bridged = encode_batch_async(messages, k, m).await.unwrap();

        assert_eq!(bridged.len(), blocking.len());
        for (bridged_entry, blocking_entry) in bridged.iter().zip(blocking.iter()) {
            assert_eq!(bridged_entry.0, blocking_entry.0);
            assert_eq!(bridged_entry.1, blocking_entry.1);
        }
    }

    /// An empty batch is legal: an AVID dealer with nothing to send must not be
    /// turned into a coding error.
    #[test]
    fn an_empty_batch_encodes_to_nothing() {
        let (k, m) = split(4);
        assert!(encode_batch(&[], k, m).unwrap().is_empty());
    }

    #[test]
    fn committed_round_trip_from_the_last_k_shards() {
        for n in [4usize, 7, 16, 64] {
            let (k, m) = split(n);
            let message: Vec<u8> = (0..5000u32).map(|i| (i % 251) as u8).collect();
            let (commitment, shards) = encode(&message, k, m).unwrap();
            assert_eq!(shards.len(), n);

            // Verify every shard, then decode from the *last* k, so that at
            // least one parity shard is involved and interpolation actually
            // happens.
            let checked: Vec<CheckedShard> = shards
                .iter()
                .enumerate()
                .map(|(i, s)| check(&commitment, i, s, k, m).unwrap())
                .collect();
            let survivors = &checked[n - k..];
            assert!(survivors.iter().count() == k);

            let (decoded, regenerated) =
                decode_with_shards(&commitment, survivors.iter(), k, m).unwrap();
            assert_eq!(decoded, message, "n={}", n);
            assert_eq!(regenerated, shards, "n={}", n);
        }
    }

    /// The protocols never hand `decode` exactly `k` shards: CTRBC and ASKS
    /// reconstruct once `n - f` ECHOs have arrived, and AVID once `k` READYs
    /// have, so the common path supplies more shards than are strictly needed.
    #[test]
    fn decoding_with_more_than_k_shards_is_accepted() {
        for n in [4usize, 7, 16, 64] {
            let (k, m) = split(n);
            let f = (n - 1) / 3;
            let message: Vec<u8> = (0..4096u32).map(|i| (i % 253) as u8).collect();
            let (commitment, shards) = encode(&message, k, m).unwrap();

            // The n-f shards a node would hold after the ECHO phase, taken
            // from the top of the range so parity shards are involved.
            let survivors: Vec<CheckedShard> = shards
                .iter()
                .enumerate()
                .skip(f)
                .map(|(i, s)| check(&commitment, i, s, k, m).unwrap())
                .collect();
            assert_eq!(survivors.len(), n - f);
            assert!(survivors.len() > k, "n={} would not exercise the extras", n);

            let decoded = decode(&commitment, survivors.iter(), k, m).unwrap();
            assert_eq!(decoded, message, "n={}", n);
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
    fn a_shard_only_verifies_at_its_own_index() {
        let (k, m) = split(16);
        let (commitment, shards) = encode(b"authenticated position", k, m).unwrap();
        assert!(check(&commitment, 3, &shards[3], k, m).is_ok());
        assert!(check(&commitment, 4, &shards[3], k, m).is_err());
    }

    #[test]
    fn a_shard_from_another_message_is_rejected() {
        let (k, m) = split(16);
        let (commitment, _) = encode(b"the real message", k, m).unwrap();
        let (_, other) = encode(b"a different message", k, m).unwrap();
        assert!(check(&commitment, 0, &other[0], k, m).is_err());
    }

    #[test]
    fn shards_survive_the_serde_wire() {
        let (k, m) = split(16);
        let (commitment, shards) = encode(b"over the wire", k, m).unwrap();
        for (index, shard) in shards.iter().enumerate() {
            let bytes = bincode::serialize(shard).unwrap();
            let restored: Shard = bincode::deserialize(&bytes).unwrap();
            assert_eq!(&restored, shard);
            check(&commitment, index, &restored, k, m).unwrap();
        }
    }

    #[test]
    fn empty_and_tiny_messages_round_trip() {
        let (k, m) = split(16);
        for message in [vec![], vec![7u8], vec![9u8; 3]] {
            let (commitment, shards) = encode(&message, k, m).unwrap();
            let checked: Vec<CheckedShard> = shards
                .iter()
                .enumerate()
                .map(|(i, s)| check(&commitment, i, s, k, m).unwrap())
                .collect();
            let decoded = decode(&commitment, checked[m..].iter(), k, m).unwrap();
            assert_eq!(decoded, message);
        }
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
