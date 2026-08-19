use consensus::CheckedShard;
use crypto::{hash::Hash, LargeField};
use ctrbc::CTRBCMsg;
use types::Replica;

use crate::{context::Context, protocol::ASKSState, msg::ProtMsg};

impl Context{

    pub async fn process_asks_ready(&mut self, ctrbc_msg: CTRBCMsg, ready_sender: Replica, reconstruct_to_all: bool,instance_id: usize){
        log::info!("Processing ASKS READY from {} for instance {}", ready_sender, instance_id);
        if !self.asks_state.contains_key(&instance_id){
            let asks_state = ASKSState::new(ctrbc_msg.origin, reconstruct_to_all);
            self.asks_state.insert(instance_id, asks_state);
        }

        let asks_context = self.asks_state.get_mut(&instance_id).unwrap();

        if asks_context.terminated{
            return;
            // RBC Context already terminated, skip processing this message
        }
        // check if verifies
        let checked_shard = match ctrbc_msg.verify(ready_sender, self.num_nodes, self.num_faults) {
            Some(shard) => shard,
            None => {
                log::error!(
                    "Invalid shard sent by node {}, abandoning RBC",
                    ready_sender
                );
                return;
            }
        };

        let root = ctrbc_msg.commitment;
        if ready_sender == self.myid {
            // Our own shard, verified above.
            asks_context.rbc_state.fragment = Some((root, ctrbc_msg.shard.clone()));
        }
        let ready_senders = asks_context.rbc_state.readys.entry(root).or_default();

        if ready_senders.contains_key(&ready_sender){
            return;
        }

        ready_senders.insert(ready_sender, checked_shard);

        let size = ready_senders.len().clone();

        if size == self.num_nodes-2*self.num_faults{

            // Sent ECHOs and getting a ready message for the same ECHO
            if asks_context.rbc_state.echo_root.is_some() && asks_context.rbc_state.echo_root.clone().unwrap() == root{
                
                // No need to interpolate the Merkle tree again. 
                // If the echo_root variable is set, then we already sent ready for this message.
                // Nothing else to do here. Quit the execution. 

                return;
            }

            // Reconstruct the commitment vector from the verified READY shards.
            let checked: Vec<CheckedShard> = ready_senders.values().cloned().collect();
            let data_shards = self.num_nodes - 2 * self.num_faults;
            let parity_shards = 2 * self.num_faults;
            let cached = asks_context
                .rbc_state
                .fragment
                .as_ref()
                .filter(|(commitment, _)| *commitment == root)
                .map(|(_, shard)| shard.clone());

            let (message, my_share) = match cached {
                Some(shard) => {
                    match consensus::decode(&root, checked.iter(), data_shards, parity_shards) {
                        Ok(message) => (message, shard),
                        Err(error) => {
                            log::error!("FATAL: Error reconstructing the ASKS commitment vector: {}", error);
                            return;
                        }
                    }
                }
                None => {
                    match consensus::decode_with_shards(
                        &root,
                        checked.iter(),
                        data_shards,
                        parity_shards,
                    ) {
                        Ok((message, shards)) => (message, shards[self.myid].clone()),
                        Err(error) => {
                            log::error!("FATAL: Error reconstructing the ASKS commitment vector: {}", error);
                            return;
                        }
                    }
                }
            };

            let my_checked_share = match consensus::check(
                &root,
                self.myid,
                &my_share,
                data_shards,
                parity_shards,
            ) {
                Ok(shard) => shard,
                Err(error) => {
                    log::error!("FATAL: Re-encoded shard failed its own verification: {}", error);
                    return;
                }
            };

            // Ready phase is completed. Save our share for later purposes and quick access.
            asks_context.rbc_state.fragment = Some((root, my_share.clone()));

            asks_context.rbc_state.message = Some(message.clone());

            let deser_root_vec: Vec<Hash> = match bincode::deserialize(&message) {
                Ok(roots) => roots,
                Err(error) => {
                    log::error!("FATAL: Reconstructed ASKS message is not a root vector: {}", error);
                    return;
                }
            };
            asks_context.roots = Some(deser_root_vec);
            // Insert own ready share
            asks_context.rbc_state.readys.get_mut(&root).unwrap().insert(self.myid, my_checked_share);
            // Send ready message
            let ctrbc_msg = CTRBCMsg{
                shard: my_share,
                commitment: root,
                origin: ctrbc_msg.origin,
            };

            let ready_msg = ProtMsg::Ready(ctrbc_msg.clone(), reconstruct_to_all, instance_id);

            self.broadcast(ready_msg).await;
        }
        else if size >= self.num_nodes - self.num_faults && !asks_context.rbc_state.terminated {
            log::info!("Received n-f READY messages for RBC Instance ID {}, terminating",instance_id);
            // Terminate protocol
            asks_context.rbc_state.terminated = true;
            asks_context.terminated = true;
            self.terminate(instance_id, None).await;
        }
    }

    pub async fn terminate(&mut self, instance_id: usize, secrets: Option<Vec<LargeField>>){
        let instance: usize = instance_id % self.threshold;
        let rep = instance_id/self.threshold;

        if secrets.is_none(){
            // Completed sharing
            let msg = (instance, rep, None);
            let status = self.out_asks_values.send(msg).await;
            log::info!("Sent result back to original channel {:?}", status);
        }
        else{
            // Completed reconstruction of the secret
            let msg = (instance,rep, Some(secrets.unwrap()));
            let status = self.out_asks_values.send(msg).await;
            log::info!("Sent result back to original channel {:?}", status);
        }
    }
}