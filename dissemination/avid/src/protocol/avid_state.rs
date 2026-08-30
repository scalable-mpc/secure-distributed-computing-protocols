use std::collections::{HashMap, HashSet};

use consensus::{CheckedShard, Commitment};
use crypto::{hash::Hash};
use types::Replica;

use crate::msg::AVIDMsg;

pub struct AVIDState{
    pub sender: usize,
    
    pub fragments: Option<AVIDMsg>,
    // Only for the recipient
    // deliveries tracked by the root Hash value
    
    /// Verified shards for our own message, keyed by the master root they were
    /// forwarded under and then by the node that forwarded them. The commitment
    /// is kept alongside because reconstruction happens against it, not against
    /// the master root.
    pub deliveries: HashMap<Hash,HashMap<Replica,(Commitment, CheckedShard)>>,
    pub message: Option<Vec<u8>>,

    pub echos: (HashMap<Hash, HashSet<usize>>, HashMap<Hash, HashSet<usize>>),
    // root Hash followed by all other composing hashes
    pub agreed_root: Option<Hash>,

    pub readys: HashMap<Hash, HashSet<usize>>,

    pub terminated: bool
}

impl AVIDState{
    
    pub fn new(sender: Replica)-> AVIDState{
        AVIDState {
            sender: sender,

            fragments: None, 
            message: None,
            deliveries: HashMap::default(),

            echos: (HashMap::default(), HashMap::default()), 
            agreed_root: None, 
            
            readys: HashMap::default(), 
            
            terminated:false
        }
    }
}