use std::fmt::Debug;

use crypto::hash::Hash;
use serde::{Deserialize, Serialize};
use types::{Replica};

/// One indexed fragment of an erasure-coded message.
///
/// This protocol commits to the message with a plain hash and reconstructs from
/// fragments, with no per-fragment proof, so it uses the bare coder in
/// [`consensus::raw`] rather than the committed layer.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct Share {
    /// Index of this fragment in the codeword.
    pub number: usize,
    pub data: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Msg {
    pub content: Vec<u8>,
    pub origin: Replica,
    // Add your custom fields here
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ShareMsg {
    pub share: Share,
    pub hash: Hash,
    pub origin: Replica,
    // Add your custom fields here
}

/*
this is how the rbc protocol works
1. <sendall, m> (this is broadcast)
2. <echo, m>
3. on (2t+1 <echo, m>) <Ready, m>
4. on (t+1 <ready, m>) <ready, m>
5. on (2t+1 <ready, m>) output m, terminate
*/

/*
* This is how Das et al's algorithm works:
* 1. Dealer sends message to everybody <M, init>
* 2. After receiving M,
*   a. Hash m -> h = H(m)
*   b. Use reed solomon encoding for m. f = f(1, 2, 3, ..., n). divide m into t+1 blocks, make f = t *      degree polynomial
* 3. <ECHO, f(i), h> to party i
* 4. On receiving n - t same values from n - t different nodes, send
*    <Ready, f(your own fragment), h> to everyone
* 5. As you receive fragments in the form of Ready messages, start error correcting after receibing 2t+1 * fragments. When error correction passes, output message and terminate.
*/
#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum ProtMsg {
    // Create your custom types of messages'
    Init(Msg, Replica), // Init
    Echo(ShareMsg, Replica),
    Ready(ShareMsg, Replica),
    // Example type is a ping message, which takes a Message and the sender replica
    // Ping(Msg, Replica),
}