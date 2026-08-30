use std::collections::{HashMap};

use consensus::CheckedShard;
use crypto::hash::Hash;
use types::Replica;

use crate::msg::{AVIDShard};
use crate::{AVIDState};

use crate::Context;
impl Context {
    // TODO: handle ready
    pub async fn handle_ready(self: &mut Context, 
        root_hash: Hash, 
        origin: Replica, 
        avid_shard: Option<AVIDShard>, 
        instance_id:usize, 
        ready_sender: usize
    ){
        
        if !self.avid_context.contains_key(&instance_id){
            let avid_state = AVIDState::new(origin);
            self.avid_context.insert(instance_id, avid_state);
        }
        
        let avid_context = self.avid_context.get_mut(&instance_id).unwrap();

        if avid_context.terminated{
            // RBC Already terminated, skip processing this message
            return;
        }

        let ready_senders = avid_context.readys.entry(root_hash).or_default();
        if ready_senders.contains(&ready_sender){
            return;
        }
        ready_senders.insert(ready_sender);


        if !avid_context.deliveries.contains_key(&root_hash){
            let hashmap = HashMap::default();
            avid_context.deliveries.insert(root_hash.clone(), hashmap);
        }
        let shards_map = avid_context.deliveries.get_mut(&root_hash).unwrap();
        if avid_shard.is_some(){
            let avid_shard = avid_shard.unwrap();
            // The forwarding node holds the shard at its own index.
            let checked = avid_shard.verify(
                &self.hash_context,
                ready_sender,
                self.num_nodes,
                self.num_faults,
            );
            match checked {
                Some(checked) if avid_shard.master_proof.root() == root_hash => {
                    shards_map.insert(ready_sender, (avid_shard.commitment, checked));
                }
                _ => {
                    log::error!("Received invalid shard from sender {} in instance_id {}",
                        ready_sender,
                        instance_id
                    );
                    return;
                }
            }
        }

        if shards_map.len() >= self.num_nodes-2*self.num_faults && avid_context.message.is_none(){
            // Sent ECHOs and getting a ready message for the same ECHO
            log::info!("Received enough messages for interpolating AVID message in instance {} sent by origin {}", instance_id, origin);

            // Reconstruct against the commitment the shards were verified
            // under. Decoding rejects any shard checked against a different
            // commitment, so a forwarder that supplies a shard from another
            // recipient's message makes this fail rather than corrupt the
            // result — the check the explicit Merkle root comparison performed.
            let commitment = shards_map.values().next().unwrap().0;
            let checked: Vec<CheckedShard> =
                shards_map.values().map(|(_, shard)| shard.clone()).collect();

            let message = match consensus::decode(
                &commitment,
                checked.iter(),
                self.num_nodes - 2 * self.num_faults,
                2 * self.num_faults,
            ) {
                Ok(message) => message,
                Err(error) => {
                    log::error!("FATAL: Error reconstructing AVID message for instance id {} from sender {}: {}", instance_id, origin, error);
                    return;
                }
            };
            log::info!("Reconstructed message successfully with validation for instance id {} from sender {}", instance_id, origin);
            avid_context.message = Some(message);
        }
        if ready_senders.len() >= self.num_nodes - self.num_faults && !avid_context.terminated{
            if avid_context.message.is_some(){
                log::info!("Received n-f READY messages for AVID Instance ID {} from origin {}, terminating",instance_id, origin);
                // Terminate protocol
                let message = avid_context.message.clone().unwrap();
                avid_context.terminated = true;

                let (deser_message, msg_len): (Vec<u8>, usize) = bincode::deserialize(&message).unwrap();
                
                let truncated_deser_message = deser_message[0..msg_len].to_vec();
                if &truncated_deser_message[0..32] == self.zero_hash{
                    log::info!("Received dummy message, not sending to parent process");
                    return;
                }
                log::info!("Delivered message through AVID from sender {} for instance ID {}",avid_context.sender,instance_id);    
                
                //let msg = decrypt(sec_key.as_slice(), message);
                let status = self.out_avid.send((instance_id,avid_context.sender,Some(truncated_deser_message))).await;
                if status.is_err(){
                    log::error!("Error sending message to parent channel {:?}", status.unwrap_err());
                }
            }
        }
    }
}
