use std::collections::HashMap;

use consensus::{CheckedShard, Commitment, Shard};
use types::Replica;

pub struct RBCState{
    pub origin: Replica,

    /// Verified shards received in the ECHO phase, grouped by the commitment
    /// they were checked against. Only shards that passed verification are
    /// stored, so a full group is directly usable for reconstruction.
    pub echos: HashMap<Commitment, HashMap<Replica, CheckedShard>>,
    pub echo_root: Option<Commitment>,

    pub readys: HashMap<Commitment, HashMap<Replica, CheckedShard>>,

    /// This node's own shard, with the commitment it belongs to.
    ///
    /// Cached as soon as it arrives — from the dealer's INIT, or from this
    /// node's own ECHO or READY. Holding it lets reconstruction call `decode`
    /// rather than `decode_with_shards`, which saves re-encoding the whole
    /// message just to recover the one shard this node has to forward.
    pub fragment: Option<(Commitment, Shard)>,
    pub message: Option<Vec<u8>>,

    pub terminated: bool
}

impl RBCState{

    pub fn new(origin: Replica)-> RBCState{
        RBCState {
            origin: origin,

            echos: HashMap::default(),
            echo_root: None,

            readys: HashMap::default(),

            fragment: None,
            message: None,

            terminated:false
        }
    }
}
