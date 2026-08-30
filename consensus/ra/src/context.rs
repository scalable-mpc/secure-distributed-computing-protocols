use std::{
    collections::HashMap,
    net::{SocketAddr, SocketAddrV4},
};

use config::Node;

use crate::protocol::RAState;
use fnv::FnvHashMap;
use futures::StreamExt;
use tcp_receiver::TcpReceiver;
use tcp_reliable_sender::{CancelHandler, TcpReliableSender};

use tokio::sync::{
    mpsc::{unbounded_channel, UnboundedReceiver, Receiver, Sender},
    oneshot,
};
// use tokio_util::time::DelayQueue;
use types::{Replica, WrapperMsg};

use crypto::{aes_hash::HashState};

use crate::msg::ProtMsg;


pub struct Context {
    /// Networking context
    pub net_send: TcpReliableSender<Replica, WrapperMsg<ProtMsg>>,
    pub net_recv: UnboundedReceiver<WrapperMsg<ProtMsg>>,
    
    /// Data context
    pub num_nodes: usize,
    pub myid: usize,
    pub num_faults: usize,
    _byz: bool,

    /// Secret Key map
    pub sec_key_map: HashMap<Replica, Vec<u8>>,

    /// Hardware acceleration context
    pub hash_context: HashState,

    /// Cancel Handlers
    pub cancel_handlers: HashMap<u64, Vec<CancelHandler>>,
    exit_rx: oneshot::Receiver<()>,
    
    // Maximum number of RBCs that can be initiated by a node. Keep this as an identifier for RBC service. 
    pub threshold: usize, 

    pub max_id: usize,

    /// Constants for PRF seeding
    pub nonce_seed: usize,

    /// State for ACSS
    pub ra_state: HashMap<usize, RAState>,

    /// Input and output request channels
    pub inp_ra_requests: Receiver<(usize,usize, usize)>,
    pub out_ra_values: Sender<(usize, Replica, usize)>
}

impl Context {
    pub fn spawn(config: Node,
        input_reqs: Receiver<(usize, usize, usize)>, 
        output_shares: Sender<(usize,Replica,usize)>,
        byz: bool) -> anyhow::Result<oneshot::Sender<()>> {
        // Add a separate configuration for RBC service. 

        let mut consensus_addrs: FnvHashMap<Replica, SocketAddr> = FnvHashMap::default();
        for (replica, address) in config.net_map.iter() {
            let address: SocketAddr = address.parse().expect("Unable to parse address");
            consensus_addrs.insert(*replica, SocketAddr::from(address.clone()));
        }
        let my_port = consensus_addrs.get(&config.id).unwrap();
        let my_address = to_socket_address("0.0.0.0", my_port.port());
        
        // Setup networking
        let (tx_net_to_consensus, rx_net_to_consensus) = unbounded_channel();
        let mut net_receiver =
            TcpReceiver::<WrapperMsg<ProtMsg>>::spawn_with_options(my_address, types::net_options());
        // The upstream receiver is a stream rather than a dispatch handler, and
        // acknowledges every frame itself, so pump it into the channel the
        // protocol already selects on.
        tokio::spawn(async move {
            while let Some(msg) = net_receiver.next().await {
                match msg {
                    Ok(msg) => {
                        if tx_net_to_consensus.send(msg).is_err() {
                            log::error!("Consensus channel closed, stopping the receiver");
                            break;
                        }
                    }
                    Err(e) => log::error!("Failed to decode an incoming message: {}", e),
                }
            }
        });

        let consensus_net = TcpReliableSender::<Replica, WrapperMsg<ProtMsg>>::with_peers_and_options(consensus_addrs.clone(), types::net_options());
        
        let (exit_tx, exit_rx) = oneshot::channel();

        // Keyed AES ciphers
        let key0 = [5u8; 16];
        let key1 = [29u8; 16];
        let key2 = [23u8; 16];
        let hashstate = HashState::new(key0, key1, key2);
        
        tokio::spawn(async move {
            let mut c = Context {
                net_send: consensus_net,
                net_recv: rx_net_to_consensus,
                
                num_nodes: config.num_nodes,
                sec_key_map: HashMap::default(),
                hash_context: hashstate,
                myid: config.id,
                _byz: byz,
                num_faults: config.num_faults,
                cancel_handlers: HashMap::default(),
                exit_rx: exit_rx,
                
                //avid_context:HashMap::default(),
                threshold: 10000,

                max_id: 0, 

                ra_state: HashMap::default(),
                nonce_seed: 1,

                inp_ra_requests: input_reqs,
                out_ra_values: output_shares
            };

            // Populate secret keys from config
            for (id, sk_data) in config.sk_map.clone() {
                c.sec_key_map.insert(id, sk_data.clone());
            }

            // Run the consensus context
            c.run().await;
        });

        Ok(exit_tx)
    }

    pub async fn broadcast(&mut self, protmsg: ProtMsg) {
        let sec_key_map = self.sec_key_map.clone();
        for (replica, sec_key) in sec_key_map.into_iter() {
            let wrapper_msg = WrapperMsg::new(protmsg.clone(), self.myid, &sec_key.as_slice());
            self.send(replica, wrapper_msg).await;
        }
    }

    pub fn add_cancel_handler(&mut self, canc: CancelHandler) {
        self.cancel_handlers.entry(0).or_default().push(canc);
    }

    /// The upstream sender takes raw bytes, so encoding happens here rather
    /// than inside the networking crate.
    pub async fn send(&mut self, replica: Replica, wrapper_msg: WrapperMsg<ProtMsg>) {
        let bytes = match bincode::serialize(&wrapper_msg) {
            Ok(bytes) => bytes::Bytes::from(bytes),
            Err(e) => {
                log::error!("Failed to serialize a message for {}: {}", replica, e);
                return;
            }
        };
        match self.net_send.send(replica, bytes).await {
            Ok(cancel_handler) => self.add_cancel_handler(cancel_handler),
            Err(e) => log::error!("Failed to send a message to {}: {}", replica, e),
        }
    }

    pub async fn run(&mut self){
        // The process starts listening to messages in this process.
        // First, the node sends an alive message
        loop {
            tokio::select! {
                // Receive exit handlers
                _exit_tx = &mut self.exit_rx => {
                    log::info!("Termination signal received by the server. Exiting.");
                    break
                },
                msg = self.net_recv.recv() => {
                    // Received messages are processed here
                    log::trace!("Got a consensus message from the network: {:?}", msg);
                    if msg.is_none(){
                        log::error!("Got none from the consensus layer, most likely it closed");
                        return;
                    }
                    self.process_msg(msg.unwrap()).await;
                },
                req_msg = self.inp_ra_requests.recv() =>{
                    if req_msg.is_none(){
                        log::error!("Request channel closed");
                        return;
                    }
                    let req_msg = req_msg.unwrap();

                    let representative_replica = req_msg.0;
                    let value = req_msg.1;
                    
                    let instance_id = representative_replica*self.threshold + req_msg.2;
                    self.init_ra(instance_id, representative_replica, value).await;
                },
            };
        }
    }
}

pub fn to_socket_address(ip_str: &str, port: u16) -> SocketAddr {
    let addr = SocketAddrV4::new(ip_str.parse().unwrap(), port);
    addr.into()
}
