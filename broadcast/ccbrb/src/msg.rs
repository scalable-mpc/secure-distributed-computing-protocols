use std::fmt::Debug;

use crypto::hash::Hash;
use serde::{Deserialize, Serialize};
use types::Replica;

/// One indexed fragment of an erasure-coded value.
///
/// CCBRB commits to its shards with the explicit hash vector `D`, not with a
/// Merkle root, so its fragments carry no inclusion proof — a receiver checks
/// `H(d_j) ∈ D` instead. That is why this protocol uses the bare coder in
/// [`consensus::raw`] rather than the committed layer the other broadcasts use.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct Share {
    /// Index of this fragment in the codeword, needed to place it correctly
    /// when reconstructing.
    pub number: usize,
    pub data: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SendMsg {
    pub id: u64,
    pub d_j: Share,
    pub d_hashes: Vec<Hash>, // D = [H(d₁),...,H(dₙ)]
    pub origin: Replica,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct EchoMsg {
    pub id: u64,
    pub d_i: Share,
    pub pi_i: Share, // Proof pi[i]
    pub c: Hash,
    pub origin: Replica,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ReadyMsg {
    pub id: u64,
    pub c: Hash,
    pub pi_i: Share,
    pub origin: Replica,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum ProtMsg {
    Init(SendMsg, Replica),
    Echo(EchoMsg, Replica),
    Ready(ReadyMsg, Replica),
}
