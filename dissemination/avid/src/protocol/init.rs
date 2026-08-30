use std::collections::{HashMap, HashSet};

use consensus::{Commitment, Shard};
use crypto::{
    aes_hash::MerkleTree,
    hash::Hash,
};
use types::{WrapperMsg, Replica};

use crate::{Context, msg::{AVIDMsg, AVIDShard}, AVIDState};
use crate::{ProtMsg};

impl Context {
    // Dealer sending message to everybody
    pub async fn start_init(self: &mut Context, msgs:Vec<(Replica,Vec<u8>)>, instance_id:usize) {
        // First encrypt messages
        let msg_set: Vec<Replica> = msgs.iter().map(|(x,_y)| *x).collect();
        let hash_set: HashSet<Replica> = HashSet::from_iter(msg_set.into_iter());
        let mut filled_msg_vec = Vec::new();
        for party in 0..self.num_nodes{
            if !hash_set.contains(&party){
                filled_msg_vec.push((party,self.zero_hash.clone().to_vec()));
            }
        }
        filled_msg_vec.extend(msgs);
        
        // Each element of the vector is an AVID for sending a message to a single replica.
        // Serialize first: the batch encoder takes payloads alone, and each one's
        // recipient is recovered by position afterwards.
        let recipients: Vec<Replica> = filled_msg_vec.iter().map(|(party, _)| *party).collect();
        let payloads: Vec<Vec<u8>> = filled_msg_vec
            .into_iter()
            .map(|(_party, msg)| {
                let msg_length = msg.len();
                bincode::serialize(&(msg, msg_length)).unwrap()
            })
            .collect();

        // `n` independent messages, each coded into `n` shards: the dealer's
        // dominant cost. Run the batch on rayon, off this actor's tokio worker.
        let encodings = match consensus::encode_batch_async(
            payloads,
            self.num_nodes - 2 * self.num_faults,
            2 * self.num_faults,
        )
        .await
        {
            Ok(encodings) => encodings,
            Err(error) => {
                log::error!("Failed to erasure code an AVID message: {}", error);
                return;
            }
        };

        let mut avid_tree: Vec<(Replica,Vec<Shard>,Commitment)> = Vec::with_capacity(encodings.len());
        let mut roots_agg: Vec<Hash> = Vec::with_capacity(encodings.len());
        for (recipient, (commitment, shards)) in recipients.into_iter().zip(encodings) {
            roots_agg.push(commitment);
            avid_tree.push((recipient, shards, commitment));
        }

        let master_mt = MerkleTree::new(roots_agg, &self.hash_context);
        let mut party_wise_share_map: HashMap<usize, Vec<AVIDShard>> = HashMap::default();
        for party in 0..self.num_nodes{
            party_wise_share_map.insert(party, Vec::new());
        }
        for (index,tuple) in avid_tree.into_iter().enumerate(){
            // The proof depends only on `index`, not on the recipient, so it is
            // generated once per message instead of once per (message, party).
            let master_proof = master_mt.gen_proof(index);
            for (party,fragment) in (0..self.num_nodes).into_iter().zip(tuple.1.into_iter()){
                let avid_shard = AVIDShard{
                    id: instance_id,
                    origin: self.myid,
                    recipient: tuple.0.clone(),
                    shard: fragment,
                    commitment: tuple.2,
                    master_proof: master_proof.clone(),
                };
                party_wise_share_map.get_mut(&party).unwrap().push(avid_shard);
            }
        }
        
        let concise_root = master_mt.root();
        let sec_key_map = self.sec_key_map.clone();
        for (replica, sec_key) in sec_key_map.into_iter() {
            // TODO: Encryption
            let avid_shards = party_wise_share_map.get(&replica).unwrap().clone();
            
            let avid_msg = AVIDMsg {
                shards: avid_shards,
                origin: self.myid,
                concise_root: concise_root.clone()
            };
            
            let protocol_msg = ProtMsg::Init(avid_msg, instance_id);
            let wrapper_msg = WrapperMsg::new(protocol_msg.clone(), self.myid, &sec_key.as_slice());
            self.send(replica, wrapper_msg).await;
        }
    }

    pub async fn handle_init(self: &mut Context, msg: AVIDMsg, instance_id:usize) {
        
        // Every shard the dealer sends us sits at our own index.
        if !msg.verify_mr_proofs(&self.hash_context, self.myid, self.num_nodes, self.num_faults) {
            log::error!(
                "Invalid shard sent by node {}, abandoning AVID instance",
                msg.origin
            );
            return;
        }

        log::debug!(
            "Received Init message with {} shards from node {}.",
            msg.shards.len(),
            msg.origin,
        );

        if !self.avid_context.contains_key(&instance_id){
            self.avid_context.insert(instance_id, AVIDState::new(msg.origin));
        }
        
        let avid_state = self.avid_context.get_mut(&instance_id).unwrap();
        let indices = msg.indices();
        avid_state.fragments = Some(msg);
        
        // Start echo
        for index_msg in indices{
            let recipient = index_msg.recipient;
            let protocol_msg = ProtMsg::Echo(index_msg, instance_id);
            let sec_key = self.sec_key_map.get(&recipient).unwrap().clone();
            let wrapper_msg = WrapperMsg::new(protocol_msg.clone(), self.myid, &sec_key.as_slice());
            self.send(recipient, wrapper_msg).await;
        }        
    }
}
