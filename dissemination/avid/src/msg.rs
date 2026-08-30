use std::collections::HashSet;

use consensus::{CheckedShard, Commitment, Shard};
use crypto::aes_hash::{HashState, Proof};

use crypto::hash::Hash;
use serde::{Deserialize, Serialize};

use types::{Replica};

/// One party's fragment of one recipient's message.
///
/// There are two commitment layers. `commitment` is commonware's Merkle root
/// over the shards of a single recipient's message, and `shard` carries its own
/// inclusion proof against it. `master_proof` then places that commitment in
/// the dealer's master tree over all recipients, so a single master root
/// identifies the whole batch.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AVIDShard{
    pub id: usize,
    pub origin: Replica,
    pub recipient: Replica,
    pub shard: Shard,
    pub commitment: Commitment,
    pub master_proof: Proof,
}

impl AVIDShard{
    /// Verify both layers, returning the verified shard.
    ///
    /// `index` is the position the shard is claimed to hold, which is the
    /// identity of the node that holds it.
    pub fn verify(
        &self,
        hash_state: &HashState,
        index: Replica,
        num_nodes: usize,
        num_faults: usize,
    ) -> Option<CheckedShard>{
        // The commitment must be the one the dealer placed in the master tree...
        if self.master_proof.item() != self.commitment || !self.master_proof.validate(hash_state) {
            return None;
        }
        // ...and the shard must sit at `index` under that commitment.
        consensus::check(
            &self.commitment,
            index,
            &self.shard,
            num_nodes - 2 * num_faults,
            2 * num_faults,
        )
        .ok()
    }

    pub fn index_from_shard(&self)-> AVIDIndexMsg{
        AVIDIndexMsg { id: self.id, recipient: self.recipient, proof: self.master_proof.clone(), origin:  self.origin}
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AVIDMsg {
    // Batched AVID for disseminating messages to multiple parties
    // ID of dissemination, recipient, (Shard, Merkle Proof)
    pub shards: Vec<AVIDShard>,
    pub origin: Replica,
    pub concise_root: Hash
}

impl AVIDMsg {

    /// Verify every shard in the batch.
    ///
    /// The dealer sends each node all of the shards that sit at that node's own
    /// index, one per recipient, so `index` is the receiver's identity for all
    /// of them. Every shard must also hang off the same master root.
    pub fn verify_mr_proofs(
        &self,
        hf: &HashState,
        index: Replica,
        num_nodes: usize,
        num_faults: usize,
    ) -> bool {
        let mut state = true;
        // 2. Validate Merkle Proofs
        let mut hashes_vec: HashSet<Hash> = HashSet::default();

        for avid_state in self.shards.iter(){
            state = state && avid_state.verify(hf, index, num_nodes, num_faults).is_some();
            hashes_vec.insert(avid_state.master_proof.root());
        }

        state = state && hashes_vec.len() == 1;
        return state;
    }

    pub fn new(shards: Vec<AVIDShard>, origin: Replica)-> AVIDMsg{
        // create concise root
        let mut hash_vec : Vec<u8> = Vec::new();
        for shard in shards.iter(){
            hash_vec.extend(shard.commitment);
        }
        let root_hash = crypto::hash::do_hash(&hash_vec.as_slice());
        AVIDMsg {
            shards: shards,
            origin: origin,
            concise_root: root_hash
        }
    }

    pub fn indices(&self) -> Vec<AVIDIndexMsg>{

        let mut index_vec = Vec::new();
        for shard in &self.shards{
            index_vec.push(shard.index_from_shard());
        }
        index_vec
    }

}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AVIDIndexMsg{
    pub id: usize,
    pub origin: Replica,
    pub recipient: Replica,
    pub proof: Proof,
}

impl AVIDIndexMsg{

    pub fn new(avidmsg: &AVIDMsg)-> Vec<AVIDIndexMsg>{

        let mut index_msgs = Vec::new();
        for shard in avidmsg.shards.iter(){
            index_msgs.push(AVIDIndexMsg{
                id: shard.id,
                recipient: shard.recipient,
                proof: shard.master_proof.clone(),
                origin: avidmsg.origin
            });
        }
        index_msgs
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
    Init(AVIDMsg, usize), // Init
    // ECHO contains only indices and roots.
    Echo(AVIDIndexMsg,usize),
    // READY contains only indices and roots.
    Ready(Hash, Replica, Option<AVIDShard>,usize),
}
