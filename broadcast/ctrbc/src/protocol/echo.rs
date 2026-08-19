use consensus::CheckedShard;
use types::Replica;

use crate::{CTRBCMsg, Context, RBCState};
use crate::{ProtMsg};

impl Context {
    pub async fn handle_echo(self: &mut Context, msg: CTRBCMsg, echo_sender: Replica, instance_id: usize) {
        /*
        1. verify the shard against the commitment
        2. wait until receiving n - t echos of the same commitment
        3. reconstruct the message from them; decoding is bound to the
           commitment, so no separate root comparison is needed
        4. recover our own shard, by re-encoding only if we never received it
        5. if all pass, send ready <fi, ci>
         */

        if !self.rbc_context.contains_key(&instance_id){
            let rbc_state = RBCState::new(msg.origin);
            self.rbc_context.insert(instance_id, rbc_state);
        }

        let (data_shards, parity_shards) = self.coding_split();
        let rbc_context = self.rbc_context.get_mut(&instance_id).unwrap();

        if rbc_context.terminated{
            // RBC Already terminated, skip processing this message
            return;
        }
        // check if verifies
        let checked_shard = match msg.verify(echo_sender, self.num_nodes, self.num_faults) {
            Some(shard) => shard,
            None => {
                log::error!(
                    "Invalid shard sent by node {}, abandoning RBC",
                    echo_sender
                );
                return;
            }
        };

        let root = msg.commitment;
        if echo_sender == self.myid {
            // Our own shard, verified above: keep it so reconstruction does not
            // have to re-encode the message to recover it.
            rbc_context.fragment = Some((root, msg.shard.clone()));
        }
        let echo_senders = rbc_context.echos.entry(root).or_default();

        if echo_senders.contains_key(&echo_sender){
            return;
        }

        echo_senders.insert(echo_sender, checked_shard);

        let size = echo_senders.len().clone();
        if size == self.num_nodes - self.num_faults{
            log::info!("Received n-f ECHO messages for RBC Instance ID {}, sending READY message",instance_id);

            // Reconstruct the message. Decoding re-derives the commitment and
            // fails if it differs, which is the check the explicit Merkle tree
            // rebuild used to perform.
            let checked: Vec<CheckedShard> = echo_senders.values().cloned().collect();
            let cached = rbc_context
                .fragment
                .as_ref()
                .filter(|(commitment, _)| *commitment == root)
                .map(|(_, shard)| shard.clone());

            let (message, my_share) = match cached {
                // We already hold our own shard, so only the message is missing.
                Some(shard) => {
                    match consensus::decode(&root, checked.iter(), data_shards, parity_shards) {
                        Ok(message) => (message, shard),
                        Err(error) => {
                            log::error!("FATAL: Error reconstructing the broadcast message: {}", error);
                            return;
                        }
                    }
                }
                // We never received our own shard; re-encode to recover it.
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

            // ECHO phase is completed. Save our share and the commitment for later purposes and quick access.
            rbc_context.echo_root = Some(root);
            rbc_context.fragment = Some((root, my_share.clone()));
            rbc_context.message = Some(message);

            // Send ready message
            let ctrbc_msg = CTRBCMsg{
                shard: my_share,
                commitment: root,
                origin: msg.origin,
            };

            // We are the sender of this READY, so it must be recorded against
            // our own identity: the shard inside it is ours and only verifies
            // at our index.
            self.handle_ready(ctrbc_msg.clone(),self.myid,instance_id).await;
            let ready_msg = ProtMsg::Ready(ctrbc_msg, instance_id);
            self.broadcast(ready_msg).await;
        }
        // Go for optimistic termination if all n shares have appeared
        else if size == self.num_nodes{
            log::info!("Received n ECHO messages for RBC Instance ID {}, terminating",instance_id);
            // Do not reconstruct the message again. Just forward our own shard.

            let echo_root = rbc_context.echo_root.clone();

            if echo_root.is_some() && !rbc_context.terminated{
                rbc_context.terminated = true;
                // Send Ready and terminate

                let (commitment, fragment) = rbc_context.fragment.clone().unwrap();
                let ctrbc_msg = CTRBCMsg{
                    shard: fragment,
                    commitment: commitment,
                    origin: msg.origin,
                };

                let message = rbc_context.message.clone().unwrap();

                let ready_msg = ProtMsg::Ready(ctrbc_msg, instance_id);

                self.broadcast(ready_msg).await;
                self.terminate(instance_id, message).await;
            }

        }
    }
}
