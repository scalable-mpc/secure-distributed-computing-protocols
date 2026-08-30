use crate::msg::{EchoMsg, SendMsg, Share};

use crate::Status;
use crate::{Context, ProtMsg};
use bincode;
use crypto::hash::{do_hash};
use types::WrapperMsg;

impl Context {
    pub async fn start_echo(&mut self, msg: SendMsg, instance_id: usize) {
        let d_hashes = msg.d_hashes.clone(); // D = [H(d1), ..., H(dn)]
        let c = do_hash(&bincode::serialize(&d_hashes).unwrap()); // c = H(D)
                                                                  // log::info!(
                                                                  //     "Starting ECHO for instance_id {} with c: {:?}, d_hashes: {:?}",
                                                                  //     instance_id,
                                                                  //     c,
                                                                  //     d_hashes
                                                                  // );

        // Erasure code D itself, so that a node which never receives the hash
        // vector can still reconstruct it from t+1 fragments. This coding needs
        // no commitment of its own: the reconstruction is checked against `c`.
        assert!(d_hashes.len() > 0, "Message content is empty");
        let serialized_hashes = bincode::serialize(&d_hashes).unwrap();
        let pi_shards = match consensus::raw::get_shards(
            serialized_hashes,
            self.num_faults,
            self.num_nodes - self.num_faults,
        ) {
            Ok(shards) => shards,
            Err(error) => {
                log::info!("Encoding of the hash vector failed: {}", error);
                return;
            }
        };
        let mut pi: Vec<Share> = pi_shards
            .into_iter()
            .enumerate()
            .map(|(number, data)| Share { number, data })
            .collect();
        if self.byz {
            // if byzantine, set all shares to empty, but make sure to keep the size consistent, so fill with 0
            for i in 0..self.num_nodes {
                // set p[i].data to 0, but keep the size of data consistent
                pi[i].data = vec![0; pi[i].data.len()];
            }
        }

        // log::info!(
        //     "Echo: Encoded shares for instance_id {}: {:?}",
        //     instance_id,
        //     pi
        // );

        let rbc_context = self.rbc_context.entry(instance_id).or_default();
        rbc_context.fragment = msg.d_j.clone();

        assert!(
            rbc_context.status == Status::ECHO,
            "ECHO: Status is not ECHO for instance id: {:?}",
            instance_id
        );
        // rbc_context.status = Status::ECHO;

        if !self.crash {
            for replica in 0..self.num_nodes {
                let share = if self.byz && replica != self.myid {
                    msg.d_j.clone()
                    // Share {
                    //     number: replica,
                    //     data: vec![],
                    // }
                } else {
                    msg.d_j.clone()
                };
                // send ⟨𝑖𝑑, ECHO, (𝑑𝑖, 𝜋𝑗, 𝑐)⟩ to node 𝑗
                let echo_msg = EchoMsg {
                    id: instance_id as u64,
                    d_i: share,
                    pi_i: pi[replica].clone(), // πj
                    c,
                    origin: self.myid,
                };

                let proto_msg = ProtMsg::Echo(echo_msg.clone(), instance_id);
                if replica == self.myid {
                    self.handle_echo(echo_msg.clone(), instance_id).await;
                    continue;
                }

                let sec_key = &self.sec_key_map[&replica];
                let wrapped = WrapperMsg::new(proto_msg.clone(), self.myid, sec_key);
                self.send(replica, wrapped).await;
            }
        }
    }

    pub async fn handle_echo(&mut self, echo_msg: EchoMsg, instance_id: usize) {
        let rbc_context = self.rbc_context.entry(instance_id).or_default();

        // Serialize πᵢ
        let pi_i_serialized = bincode::serialize(&echo_msg.pi_i).unwrap();

        // Track senders per (c, πᵢ)
        let pi_i_map = rbc_context.echo_senders.entry(echo_msg.c).or_default();
        let senders = pi_i_map.entry(pi_i_serialized.clone()).or_default();

        if !senders.insert(echo_msg.origin) {
            return; // duplicate
        }

        // Store dᵢ
        let data_entry = rbc_context
            .fragments_data
            .entry((instance_id as u64, echo_msg.c))
            .or_default();
        data_entry.push(echo_msg.d_i.clone());

        // Check if 2t + 1 ECHOs for same (c, πᵢ)
        if senders.len() >= self.num_nodes-self.num_faults && rbc_context.status == Status::ECHO {
            rbc_context.status = Status::READY;
            rbc_context.sent_ready = true;
            //send pi i if byzantine, otherwise clear the data of pi_i
            let share = {
                if !self.byz {
                    echo_msg.pi_i.clone()
                } else {
                    Share {
                        number: echo_msg.pi_i.number,
                        data: echo_msg.pi_i.data.iter().map(|_| 0).collect(),
                    }
                }
            };
            self.start_ready(echo_msg.c, share, instance_id).await;
        }
    }
}
