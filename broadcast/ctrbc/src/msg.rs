use consensus::{CheckedShard, Commitment, Shard};
use serde::{Deserialize, Serialize};

use types::Replica;

/// One party's fragment of a broadcast message.
///
/// The shard carries its own Merkle inclusion proof against `commitment`, so
/// the pair is self-describing: given the index the shard is claimed to sit at,
/// [`CTRBCMsg::verify`] both authenticates the shard and pins it to that
/// position.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CTRBCMsg {
    pub shard: Shard,
    pub commitment: Commitment,
    pub origin: Replica,
}

impl CTRBCMsg {
    /// Check the shard against the commitment at `index`, returning the
    /// verified shard on success.
    ///
    /// `index` is the position the shard is expected to occupy, which in every
    /// phase is the identity of the node that sent it (for INIT, the receiver's
    /// own identity, since the dealer sends each node its own shard). A shard
    /// verifies at exactly one index, so passing the sender's identity here is
    /// what stops a node from replaying somebody else's fragment.
    pub fn verify(
        &self,
        index: Replica,
        num_nodes: usize,
        num_faults: usize,
    ) -> Option<CheckedShard> {
        consensus::check(
            &self.commitment,
            index,
            &self.shard,
            num_nodes - 2 * num_faults,
            2 * num_faults,
        )
        .ok()
    }
}
/*
this is how the rbc protocol works
1. <sendall, m> (this is broadcast)
2. <echo, m>
3. on (2t+1 <echo, m>) <Ready, m>
4. on (t+1 <ready, m>) <ready, m>
5. on (2t+1 <ready, m>) output m, terminate
*/

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum ProtMsg {
    // Create your custom types of messages'
    Init(CTRBCMsg, usize), // Init
    Echo(CTRBCMsg, usize),
    Ready(CTRBCMsg, usize),
}
