use aes::{cipher::{generic_array::GenericArray, KeyInit, BlockEncrypt}, Aes128Enc};

use crate::{aes_hash::{MerkleTree, HASH_SIZE}, hash::Hash};
//use sha2::{Sha256, Digest};

//use crate::hash::Hash;

// pub struct HashState{
    
// }

// impl HashState{
//     pub fn new(_k1: [u8;16],_k2: [u8;16],_k3:[u8;16])->HashState{
//         HashState{}
//     }

//     pub fn hash_two(&self, one:Hash, two: Hash)-> Hash{
//         let mut sha256 = Sha256::new();
//         //sha256.update(&[0x00]);
//         sha256.update(one);
//         sha256.update(two);
//         sha256.clone().finalize().into()
//     }

//     pub fn hash_batch(&self, one: Vec<Hash>, two: Vec<Hash>)-> Vec<Hash>{
//         let mut sha256 = Sha256::new();
//         let mut hv = Vec::new();
//         for (o,t) in one.into_iter().zip(two.into_iter()){
//             sha256.reset();
//             sha256.update(o);
//             sha256.update(t);
//             hv.push(sha256.clone().finalize().into())
//         }
//         hv
//     }
// }

pub struct HashState{
    pub aes0: Aes128Enc,
    pub aes1: Aes128Enc,
    pub aes2: Aes128Enc
}

impl HashState{
    pub fn new(key0: [u8;16],key1: [u8;16], key2: [u8;16])-> HashState{
        let key0 = GenericArray::from(key0);
        let key1 = GenericArray::from(key1);
        let key2 = GenericArray::from(key2);
        
        let aes_state = HashState{
            aes0: Aes128Enc::new(&key0),
            aes1: Aes128Enc::new(&key1),
            aes2: Aes128Enc::new(&key2)
        };
        aes_state
    }
    // AES is a 128 bit block cipher. 
    // AES 256 just has a 256 bit key. It is not a 256-bit block cipher. Hence, have to split each SHA256 Hash to multiple layers
    pub fn hash_two(&self, one: [u8;32],two:[u8;32])->[u8;32]{
        let mut x_11 = [0u8;16];
        let mut x_12 = [0u8;16];
        for i in 0..16{
            x_11[i] = one[i].wrapping_add(two[i].wrapping_mul(2));
            x_12[i] = one[16+i].wrapping_add(two[16+i].wrapping_mul(2));
        }
        // Encrypt in place. `GenericArray` is `Copy`, so `&mut [blk_11, blk_12]`
        // encrypts a temporary copy and the result is lost. The same applies below.
        let mut blks = [GenericArray::from(x_11), GenericArray::from(x_12)];
        self.aes0.encrypt_blocks(&mut blks);
        let [blk_11, blk_12] = blks;

        let mut x_21 = [0u8;16];
        let mut x_22 = [0u8;16];
        for i in 0..16{
            x_21[i] = (one[i].wrapping_mul(2)).wrapping_add(two[i].wrapping_mul(2)).wrapping_add(blk_11[i]);
            x_22[i] = (one[16+i].wrapping_mul(2)).wrapping_add(two[16+i].wrapping_mul(2)).wrapping_add(blk_12[i]);
        }
        let mut blks = [GenericArray::from(x_21), GenericArray::from(x_22)];
        self.aes1.encrypt_blocks(&mut blks);
        let [blk_21, blk_22] = blks;

        let mut x_31 = [0u8;16];
        let mut x_32 = [0u8;16];
        
        for i in 0..16{
            x_31[i] = (one[i].wrapping_mul(2)).wrapping_add(two[i]).wrapping_add(blk_21[i]);
            x_32[i] = (one[16+i].wrapping_mul(2)).wrapping_add(two[16+i]).wrapping_add(blk_22[i]);
        }
        let mut blks = [GenericArray::from(x_31), GenericArray::from(x_32)];
        self.aes2.encrypt_blocks(&mut blks);
        let [blk_31, blk_32] = blks;

        let mut w_1 = [0u8;32];
        for i in 0..16{
            w_1[i] = one[i].wrapping_add(blk_11[i]).wrapping_add(blk_21[i]).wrapping_add(blk_31[i].wrapping_mul(2));
        }
        for i in 0..16{
            w_1[16+i] = one[16+i].wrapping_add(blk_12[i]).wrapping_add(blk_22[i]).wrapping_add(blk_32[i].wrapping_mul(2));
        }
        return w_1;
    }

    pub fn hash_batch(&self, one: Vec<[u8;32]>, two: Vec<[u8;32]>)-> Vec<[u8;32]>{
        // Final output vector
        let mut fin_vec = one.clone();
        // Iterator for going over Hash functions
        let it = one.iter().zip(two.iter());
        
        let mut o1_vec = Vec::new();
        let mut o2_vec = Vec::new();
        for (_,(o,t)) in it.clone().enumerate(){
            let mut x_11 = [0u8;16];
            let mut x_12 = [0u8;16];
            for i in 0..16{
                x_11[i] = o[i].wrapping_add(t[i].wrapping_mul(2));
                x_12[i] = o[16+i].wrapping_add(t[16+i].wrapping_mul(2));
            }
            o1_vec.push(GenericArray::from(x_11));
            o2_vec.push(GenericArray::from(x_12));
        }
        self.aes0.encrypt_blocks(&mut o1_vec);
        self.aes0.encrypt_blocks(&mut o2_vec);
        
        let mut p1_vec = Vec::new();
        let mut p2_vec = Vec::new();
        let it2 = fin_vec.iter_mut().zip(it.clone().zip(o1_vec.iter().zip(o2_vec.iter())));
        for(_, (f, m)) in it2.enumerate(){
            let o = m.0;
            let t = m.1;
            let mut x_21 = [0u8;16];
            let mut x_22 = [0u8;16];
            for i in 0..16{
                x_21[i] = (o.0[i].wrapping_mul(2)).wrapping_add(o.1[i].wrapping_mul(2)).wrapping_add(t.0[i]);
                x_22[i] = (o.0[16+i].wrapping_mul(2)).wrapping_add(o.1[16+i].wrapping_mul(2)).wrapping_add(t.1[i]);
                // Aggregate final output too
                f[i] = f[i].wrapping_add(t.0[i]);
                f[16+i] = f[16+i].wrapping_add(t.1[i]); 
            }
            p1_vec.push(GenericArray::from(x_21));
            p2_vec.push(GenericArray::from(x_22));
        }
        self.aes1.encrypt_blocks(&mut p1_vec);
        self.aes1.encrypt_blocks(&mut p2_vec);

        let mut q1_vec= Vec::new();
        let mut q2_vec = Vec::new();
        let it3 = fin_vec.iter_mut().zip(it.zip(p1_vec.iter().zip(p2_vec.iter())));
        for(_, (f,m)) in it3.enumerate(){
            let o = m.0;
            let t = m.1;
            let mut x_31 = [0u8;16];
            let mut x_32 = [0u8;16];
            for i in 0..16{
                x_31[i] = (o.0[i].wrapping_mul(2)).wrapping_add(o.1[i]).wrapping_add(t.0[i]);
                x_32[i] = (o.0[16+i].wrapping_mul(2)).wrapping_add(o.1[16+i]).wrapping_add(t.1[i]);
                // Aggregate vectors
                f[i] = f[i].wrapping_add(t.0[i]);
                f[16+i] = f[16+i].wrapping_add(t.1[i]);
            }
            q1_vec.push(GenericArray::from(x_31));
            q2_vec.push(GenericArray::from(x_32));
        }
        self.aes2.encrypt_blocks(&mut q1_vec);
        self.aes2.encrypt_blocks(&mut q2_vec);
        
        let it4 = fin_vec.iter().zip(q1_vec.iter().zip(q2_vec.iter()));
        let mut output_vec = Vec::new();
        for (_,(f,(o,t))) in it4.enumerate(){
            let mut w_1 = [0u8;32];
            for i in 0..16{
                w_1[i] = f[i].wrapping_add(o[i].wrapping_mul(2));
            }
            for i in 0..16{
                w_1[16+i] = f[16+i].wrapping_add(t[i].wrapping_mul(2));
            }
            output_vec.push(w_1);
        }
        return output_vec;
    }

    pub fn do_hash_aes(&self, bytes: &[u8])->[u8;32]{
        if bytes.len() < 64{
            let mut vec = bytes.to_vec();
            // Append zeros to make the input a multiple of 32 bytes
            let remainder = vec.len() % 64;
            if remainder != 0 {
                let padding_needed = 64 - remainder;
                vec.extend(vec![0u8; padding_needed]);
            }
            let mut slice1: Hash = [0u8;32];
            let mut slice2: Hash = [0u8;32];

            slice1.copy_from_slice(&vec[0..32]);
            slice2.copy_from_slice(&vec[32..64]);
            return self.hash_two(slice1, slice2);
        }
        else{
            let chunks: Vec<Hash> = bytes.chunks(HASH_SIZE).map(|x|{
                let mut hash = [0u8;HASH_SIZE];
                hash[0..x.len()].copy_from_slice(x);
                return hash;
            }).collect();
            return MerkleTree::new(chunks, self).root();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash_state() -> HashState {
        HashState::new([1u8; 16], [2u8; 16], [3u8; 16])
    }

    /// A regression test: without the AES output, `hash_two` was
    /// `15 * one + 16 * two` in each byte and did not depend on the keys.
    #[test]
    fn hash_two_depends_on_the_keys_and_is_not_linear() {
        let (one, two) = ([3u8; 32], [200u8; 32]);
        let hash = hash_state().hash_two(one, two);
        let linear: Vec<u8> = (0..32)
            .map(|i| one[i].wrapping_mul(15).wrapping_add(two[i].wrapping_mul(16)))
            .collect();
        assert_ne!(hash.to_vec(), linear);
        assert_ne!(hash, HashState::new([9u8; 16], [8u8; 16], [7u8; 16]).hash_two(one, two));
    }

    #[test]
    fn hash_batch_agrees_with_hash_two() {
        let hs = hash_state();
        let one: Vec<[u8; 32]> = (0..9u8).map(|j| [j.wrapping_mul(29); 32]).collect();
        let two: Vec<[u8; 32]> = (0..9u8).map(|j| core::array::from_fn(|i| j ^ i as u8)).collect();
        let expected: Vec<[u8; 32]> = one.iter().zip(&two).map(|(o, t)| hs.hash_two(*o, *t)).collect();
        assert_eq!(hs.hash_batch(one, two), expected);
    }

    /// Each leaf must change the root. With the linear `hash_two`, 11 of the
    /// 16 leaves of a 16-leaf tree did not.
    #[test]
    fn every_leaf_changes_the_merkle_root() {
        let hs = hash_state();
        for n in 2..=33u8 {
            let leaves: Vec<Hash> = (0..n).map(|j| [j; 32]).collect();
            let root = MerkleTree::new(leaves.clone(), &hs).root();
            for j in 0..n as usize {
                let mut changed = leaves.clone();
                changed[j][0] ^= 1;
                assert_ne!(MerkleTree::new(changed, &hs).root(), root, "n={} leaf={}", n, j);
            }
        }
    }

    /// `build_trees` hashes with `hash_batch`, and `Proof::validate` with
    /// `hash_two`. The two paths must give the same tree.
    #[test]
    fn build_trees_agrees_with_merkle_tree_new() {
        let hs = hash_state();
        let data: Vec<Vec<Hash>> = (0..3u8)
            .map(|t| (0..7u8).map(|j| [t * 16 + j; 32]).collect())
            .collect();
        for (tree, leaves) in MerkleTree::build_trees(data.clone(), &hs).iter().zip(data) {
            assert_eq!(tree.root(), MerkleTree::new(leaves, &hs).root());
            assert!(tree.gen_proof(5).validate(&hs));
        }
    }
}
