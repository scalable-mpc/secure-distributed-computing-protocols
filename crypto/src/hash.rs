use sha2::{Digest, Sha256};
use serde::Serialize;
use hmac::{Hmac, KeyInit, Mac};

pub const HASH_SIZE:usize = 32;

pub type Hash = [u8; HASH_SIZE];

pub const EMPTY_HASH:Hash = [0 as u8; 32];

type HmacSha256 = Hmac<Sha256>;

pub fn do_hash(bytes: &[u8]) -> Hash {
    let hash = Sha256::digest(bytes);
    return hash.into();
} 

pub fn do_hash_merkle(bytes: &[u8])-> Hash{
    let mut sha256 = Sha256::new();
    sha256.update(&[0x00]);
    sha256.update(bytes);
    sha256.clone().finalize().into()
}

pub fn ser_and_hash(obj: &impl Serialize) -> Hash {
    let serialized_bytes = bincode::serialize(obj).unwrap();
    return do_hash(&serialized_bytes);
}

pub fn do_mac(bytes: &[u8], secret_key:&[u8])-> Hash{
    let mut mac = HmacSha256::new_from_slice(secret_key)
        .expect("HMAC can take secret key of any size");
    mac.update(bytes);
    let result = mac.finalize();
    // is an array copy necessary?
    result.into_bytes().into()
}

pub fn verf_mac(bytes: &[u8], secret_key:&[u8], mac_v:&[u8])-> bool{
    let mut mac = HmacSha256::new_from_slice(secret_key)
        .expect("HMAC can take secret key of any size");
    
    mac.update(bytes);

    let err_c = mac.verify_slice(mac_v);
    match err_c {
        Ok(_)=>{
            true
        },
        Err(_)=>{
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    // FIPS 180-2 example "abc", and RFC 4231 test cases 1 and 2.
    #[test]
    fn hashes_and_macs_match_the_standard_vectors() {
        assert_eq!(hex(&do_hash(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        let case_1 = do_mac(b"Hi There", &[0x0b; 20]);
        assert_eq!(hex(&case_1),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
        let case_2 = do_mac(b"what do ya want for nothing?", b"Jefe");
        assert_eq!(hex(&case_2),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
        assert!(verf_mac(b"Hi There", &[0x0b; 20], &case_1));
        assert!(!verf_mac(b"Hi There!", &[0x0b; 20], &case_1));
        assert!(!verf_mac(b"Hi There", &[0x0b; 20], &case_1[..31]));
    }
}
