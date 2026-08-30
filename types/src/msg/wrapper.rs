use std::fmt::Debug;

use crypto::{hash::{do_mac, Hash}};
use serde::{Serialize, Deserialize, de::DeserializeOwned};

use crate::{Replica, WireReady};


#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct WrapperMsg<T: Debug+ Serialize + Clone> {
    pub protmsg: T,
    pub sender: Replica,
    pub mac: Hash,
}

impl<T: Debug+ Serialize+ Clone> WrapperMsg<T> {
    pub fn new(msg: T, sender: Replica, sk: &[u8]) -> Self {
        let new_msg = msg.clone();
        let bytes = bincode::serialize(&new_msg).expect("Failed to serialize protocol message");
        let mac = do_mac(&bytes.as_slice(), sk);
        Self {
            protmsg: new_msg,
            mac: mac,
            sender: sender,
        }
    }
}

impl<T: Debug+Serialize+ DeserializeOwned+Clone+ Sync+ Send> WireReady for WrapperMsg<T> {
    fn from_bytes(bytes: &[u8]) -> Self {
        let c: Self = bincode::deserialize(bytes).expect("failed to decode the protocol message");
        c.init()
    }

    fn to_bytes(&self) -> Vec<u8> {
        let bytes = bincode::serialize(self).expect("Failed to serialize client message");
        bytes
    }

    fn init(self) -> Self {
        match self {
            _x => _x,
        }
    }
}
/// Decoding for the upstream `libnet-rs` receiver.
///
/// Unlike [`WireReady::from_bytes`], this reports malformed input as an error
/// instead of panicking, so a corrupt or adversarial frame cannot take the
/// receiver task down.
impl<T: Debug + Serialize + DeserializeOwned + Clone + Sync + Send> common::Message
    for WrapperMsg<T>
{
    type DeserializationError = bincode::Error;

    fn from_bytes(bytes: &[u8]) -> Result<Self, Self::DeserializationError> {
        bincode::deserialize(bytes)
    }
}
