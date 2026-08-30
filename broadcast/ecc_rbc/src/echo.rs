use crypto::hash::{do_hash, Hash};

use crate::msg::Share;
use super::{Context, ShareMsg, ProtMsg};
use types::WrapperMsg;

impl Context {
    pub async fn echo_self(&mut self, hash: Hash, share: Share) {
        let msg = ShareMsg {
            share: share.clone(),
            hash,
            origin: self.myid,
        };
        self.handle_echo(msg).await;
    }
    pub async fn start_echo(self: &mut Context, msg_content: Vec<u8>) {
        let hash = do_hash(&msg_content);

        // t+1 fragments reconstruct the message, so a t-degree polynomial over
        // `num_faults` data shards and the rest recovery.
        let shards = match consensus::raw::get_shards(
            msg_content,
            self.num_faults,
            self.num_nodes - self.num_faults,
        ) {
            Ok(shards) => shards,
            Err(error) => {
                log::info!("Encoding failed with error: {}", error);
                return;
            }
        };
        let shares: Vec<Share> = shards
            .into_iter()
            .enumerate()
            .map(|(number, data)| Share { number, data })
            .collect();

        self.fragment = shares[self.myid].clone();

        log::info!("Shares: {:?}", shares);

        // Echo to every node the encoding corresponding to the replica id
        let sec_key_map = self.sec_key_map.clone();
        for (replica, sec_key) in sec_key_map.into_iter() {
            if replica == self.myid {
                self.echo_self(hash, shares[self.myid].clone()).await;
                continue;
            }
            let msg = ShareMsg {
                share: shares[replica].clone(),
                hash,
                origin: self.myid,
            };
            let protocol_msg = ProtMsg::Echo(msg, self.myid);
            let wrapper_msg = WrapperMsg::new(protocol_msg.clone(), self.myid, &sec_key.as_slice());
            self.send(replica, wrapper_msg).await;
        }
    }

    pub async fn handle_echo(self: &mut Context, msg: ShareMsg) {
        let senders = self.echo_senders.entry(msg.hash).or_default();

        // Only count if we haven't seen an echo from this sender for this message
        if senders.insert(msg.origin) {
            *self.received_echo_count.entry(msg.hash).or_default() += 1;

            // let count = self.received_echo_count.get(&msg.content).unwrap();
            let mut mode_content: Option<Hash> = None;
            let mut max_count = 0;

            for (content, &count) in self.received_echo_count.iter() {
                if count > max_count {
                    max_count = count;
                    mode_content = Some(content.clone());
                }
            }

            // Check if we've received n - techoes for this message
            if max_count == self.num_nodes - self.num_faults {
                //<Ready, f(your own fragment), h> to everyone
                if let Some(hash) = mode_content {
                    self.start_ready(hash).await;
                }
            }
        }

        // Invoke this function after terminating the protocol.
        //self.terminate("1".to_string()).await;
    }
}
