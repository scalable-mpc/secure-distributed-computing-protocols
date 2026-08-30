use consensus::LargeFieldSer;
use serde::{Serialize, Deserialize};
use types::{Val, Replica};

#[derive(Debug,Serialize,Deserialize,Clone)]
pub enum ProtMsg{
    // FIN messages
    FinBinAAEcho(Val,Replica,usize,usize),
    FinBinAAEcho2(Val,Replica,usize,usize),
    FinBinAAEcho3(Val,Replica,usize,usize),
    
    // Leader Round, BBA number, Signature, Sender
    BBACoin(usize,usize,LargeFieldSer,Replica)
}
