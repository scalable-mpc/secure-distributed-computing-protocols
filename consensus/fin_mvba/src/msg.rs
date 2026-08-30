
use consensus::LargeFieldSer;
use serde::{Serialize, Deserialize};
use types::Replica;

#[derive(Debug,Serialize,Deserialize,Clone)]
pub enum ProtMsg{
    // Instance_id, round, list of witnesses, sender
    L3Witness(usize,usize, Vec<usize>, Replica),
    LeaderCoin(usize,usize,LargeFieldSer,Replica),
}
