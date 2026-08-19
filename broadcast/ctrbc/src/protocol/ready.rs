use consensus::CheckedShard;
use types::Replica;

use crate::{CTRBCMsg, ProtMsg, RBCState};

use crate::Context;
impl Context {
    // TODO: handle ready
    pub async fn handle_ready(self: &mut Context, msg: CTRBCMsg, ready_sender: Replica, instance_id:usize){
        log::trace!("Received {:?} as ready", msg);

        if !self.rbc_context.contains_key(&instance_id){
            let rbc_state = RBCState::new(msg.origin);
            self.rbc_context.insert(instance_id, rbc_state);
        }

        let (data_shards, parity_shards) = self.coding_split();
        let rbc_context = self.rbc_context.get_mut(&instance_id).unwrap();

        if rbc_context.terminated{
            return;
            // RBC Context already terminated, skip processing this message
        }
        // check if verifies
        let checked_shard = match msg.verify(ready_sender, self.num_nodes, self.num_faults) {
            Some(shard) => shard,
            None => {
                log::error!(
                    "Invalid shard sent by node {}, abandoning RBC",
                    ready_sender
                );
                return;
            }
        };

        let root = msg.commitment;
        if ready_sender == self.myid {
            // Our own shard, verified above; see the note in `rbc_state`.
            rbc_context.fragment = Some((root, msg.shard.clone()));
        }
        let ready_senders = rbc_context.readys.entry(root).or_default();

        if ready_senders.contains_key(&ready_sender){
            return;
        }

        ready_senders.insert(ready_sender, checked_shard);

        let size = ready_senders.len().clone();

        if size == self.num_nodes-2*self.num_faults{

            // Sent ECHOs and getting a ready message for the same ECHO
            if rbc_context.echo_root.is_some() && rbc_context.echo_root.clone().unwrap() == root{

                // No need to reconstruct the message again.
                // If the echo_root variable is set, then we already sent ready for this message.
                // Nothing else to do here. Quit the execution.

                return;
            }

            // Reconstruct the message from the verified READY shards. As in the
            // ECHO phase, decoding is bound to `root`, and our own shard only
            // has to be re-encoded if we never received it.
            let checked: Vec<CheckedShard> = ready_senders.values().cloned().collect();
            let cached = rbc_context
                .fragment
                .as_ref()
                .filter(|(commitment, _)| *commitment == root)
                .map(|(_, shard)| shard.clone());

            let (message, my_share) = match cached {
                Some(shard) => {
                    match consensus::decode(&root, checked.iter(), data_shards, parity_shards) {
                        Ok(message) => (message, shard),
                        Err(error) => {
                            log::error!("FATAL: Error reconstructing the broadcast message: {}", error);
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
                            log::error!("FATAL: Error reconstructing the broadcast message: {}", error);
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
            rbc_context.fragment = Some((root, my_share.clone()));

            rbc_context.message = Some(message);

            // Insert own ready share
            rbc_context.readys.get_mut(&root).unwrap().insert(self.myid, my_checked_share);
            // Send ready message
            let ctrbc_msg = CTRBCMsg{
                shard: my_share,
                commitment: root,
                origin: msg.origin,
            };

            let ready_msg = ProtMsg::Ready(ctrbc_msg.clone(), instance_id);

            self.broadcast(ready_msg).await;
        }
        else if size >= self.num_nodes - self.num_faults && !rbc_context.terminated {
            log::info!("Received n-f READY messages for RBC Instance ID {}, terminating",instance_id);
            // Terminate protocol
            rbc_context.terminated = true;
            let term_msg = rbc_context.message.clone().unwrap();
            self.terminate(instance_id,term_msg).await;
        }
    }
}
