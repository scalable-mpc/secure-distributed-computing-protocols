use types::{WrapperMsg};

use crate::{Context};
use crate::{CTRBCMsg, ProtMsg};
use network::{plaintcp::CancelHandler, Acknowledgement};

impl Context {
    /// Number of data shards and parity shards this broadcast codes with.
    ///
    /// `n = 3f + 1` shards in total, of which any `n - 2f` reconstruct the
    /// message, so the protocol tolerates the `2f` shards that crashed or
    /// Byzantine nodes may withhold.
    pub(crate) fn coding_split(&self) -> (usize, usize) {
        (
            self.num_nodes - 2 * self.num_faults,
            2 * self.num_faults,
        )
    }

    // Dealer sending message to everybody
    pub async fn start_init(self: &mut Context, msg:Vec<u8>, instance_id:usize) {
        let (data_shards, parity_shards) = self.coding_split();
        let (commitment, shards) = match consensus::encode(&msg, data_shards, parity_shards) {
            Ok(encoding) => encoding,
            Err(error) => {
                log::error!("Failed to erasure code the broadcast message: {}", error);
                return;
            }
        };

        let sec_key_map = self.sec_key_map.clone();
        for (replica, sec_key) in sec_key_map.into_iter() {

            let ctrbc_msg = CTRBCMsg {
                shard: shards[replica].clone(),
                commitment: commitment,
                origin: self.myid,
            };

            if replica == self.myid {
                self.handle_init(ctrbc_msg,instance_id).await;
            }

            else {
                let protocol_msg = ProtMsg::Init(ctrbc_msg, instance_id);
                let wrapper_msg = WrapperMsg::new(protocol_msg.clone(), self.myid, &sec_key.as_slice());
                let cancel_handler: CancelHandler<Acknowledgement> = self.net_send.send(replica, wrapper_msg).await;
                self.add_cancel_handler(cancel_handler);
            }

        }
    }

    pub async fn handle_init(self: &mut Context, msg: CTRBCMsg, instance_id:usize) {
        //send echo
        // self.start_echo(msg.content.clone()).await;
        // The dealer sends each node the shard at that node's own index, so
        // this is the position the shard has to verify at.
        if msg.verify(self.myid, self.num_nodes, self.num_faults).is_none() {
            log::error!(
                "Invalid shard sent by node {}, abandoning RBC",
                msg.origin
            );
            return;
        }

        log::debug!(
            "Received Init message for commitment {:?} from node {}.",
            msg.commitment,
            msg.origin,
        );

        let ctrbc_msg = CTRBCMsg {
            shard: msg.shard,
            commitment: msg.commitment,
            origin: msg.origin,
        };

        // Start echo
        self.handle_echo(ctrbc_msg.clone(), self.myid,instance_id).await;
        let protocol_msg = ProtMsg::Echo(ctrbc_msg, instance_id);

        self.broadcast(protocol_msg).await;

        // Invoke this function after terminating the protocol.
        //self.terminate("1".to_string()).await;
    }
}
