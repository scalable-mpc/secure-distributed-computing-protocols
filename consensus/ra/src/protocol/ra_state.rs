use std::collections::HashMap;

use crypto::hash::Hash;
use types::Replica;

/// Per-instance state for Reliable Agreement.
///
/// This used to borrow `ctrbc::RBCState`, but the two protocols agree on
/// different things: CTRBC counts erasure-coded *shards* and its state now
/// holds shards verified against a commitment, whereas RA counts votes for a
/// plain `usize` and never codes anything. The vote bytes are kept only so the
/// per-sender maps stay keyed the same way as before.
pub struct RAState {
    pub origin: Replica,

    pub echos: HashMap<Hash, HashMap<Replica, Vec<u8>>>,
    pub echo_root: Option<Hash>,

    pub readys: HashMap<Hash, HashMap<Replica, Vec<u8>>>,

    pub terminated: bool,
}

impl RAState {
    pub fn new(origin: Replica) -> RAState {
        RAState {
            origin: origin,

            echos: HashMap::default(),
            echo_root: None,

            readys: HashMap::default(),

            terminated: false,
        }
    }
}
