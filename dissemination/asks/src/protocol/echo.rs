use consensus::CheckedShard;
use crypto::hash::Hash;
use ctrbc::CTRBCMsg;
use types::Replica;

use crate::{context::Context, msg::ProtMsg};

use super::ASKSState;

impl Context{
    pub async fn process_asks_echo(&mut self, ctrbc_msg: CTRBCMsg, echo_sender: Replica, reconstruct_to_all: bool, instance_id: usize){
        log::info!("Processing ASKS ECHO from {} for instance {}", echo_sender, instance_id);
        if !self.asks_state.contains_key(&instance_id){
            let new_state = ASKSState::new(ctrbc_msg.origin, reconstruct_to_all);
            self.asks_state.insert(instance_id, new_state);
        }

        let asks_state = self.asks_state.get_mut(&instance_id).unwrap();

        if asks_state.terminated{
            // ACSS already terminated, skip processing this message
            log::debug!("ASKS {} already terminated, skipping ECHO processing",instance_id);
            return;
        }

        let checked_shard = match ctrbc_msg.verify(echo_sender, self.num_nodes, self.num_faults) {
            Some(shard) => shard,
            None => {
                log::error!(
                    "Invalid shard sent by node {}, abandoning ECHO",
                    echo_sender
                );
                return;
            }
        };

        let root = ctrbc_msg.commitment;
        if echo_sender == self.myid {
            // Our own shard, verified above; holding it lets reconstruction
            // skip re-encoding to recover it.
            asks_state.rbc_state.fragment = Some((root, ctrbc_msg.shard.clone()));
        }
        let echo_senders = asks_state.rbc_state.echos.entry(root).or_default();

        if echo_senders.contains_key(&echo_sender){
            return;
        }

        echo_senders.insert(echo_sender, checked_shard);

        let size = echo_senders.len().clone();
        if size == self.num_nodes - self.num_faults{
            log::info!("Received n-f ECHO messages for ASKS Instance ID {}, sending READY message",instance_id);

            // Reconstruct the commitment vector. Decoding is bound to `root`
            // internally, so a mismatch surfaces as an error rather than
            // needing a separate root comparison.
            let checked: Vec<CheckedShard> = echo_senders.values().cloned().collect();
            let data_shards = self.num_nodes - 2 * self.num_faults;
            let parity_shards = 2 * self.num_faults;
            let cached = asks_state
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

            // ECHO phase is completed. Save our share and the root for later purposes and quick access.
            asks_state.rbc_state.echo_root = Some(root);
            asks_state.rbc_state.fragment = Some((root, my_share.clone()));
            asks_state.rbc_state.message = Some(message.clone());

            let deser_root_vec: Vec<Hash> = match bincode::deserialize(&message) {
                Ok(roots) => roots,
                Err(error) => {
                    log::error!("FATAL: Reconstructed ASKS message is not a root vector: {}", error);
                    return;
                }
            };
            asks_state.roots = Some(deser_root_vec);

            // Send ready message
            let ctrbc_msg = CTRBCMsg{
                shard: my_share,
                commitment: root,
                origin: ctrbc_msg.origin,
            };

            //self.handle_ready(ctrbc_msg.clone(),ctrbc_msg.origin,instance_id).await;
            let ready_msg = ProtMsg::Ready(ctrbc_msg, reconstruct_to_all, instance_id);
            self.broadcast(ready_msg).await;
        }
        // Go for optimistic termination if all n shares have appeared
        else if size == self.num_nodes{
            log::info!("Received n ECHO messages for ASKS Instance ID {}, terminating",instance_id);
            // Do not reconstruct the entire root again. Just send the merkle proof
            
            let echo_root = asks_state.rbc_state.echo_root.clone();

            if echo_root.is_some() && !asks_state.terminated{
                asks_state.terminated = true;
                let _message = asks_state.rbc_state.message.clone().unwrap();
                //self.reconstruct_asks(instance_id).await;
                self.terminate(instance_id, None).await;
            }
        }
    }
}