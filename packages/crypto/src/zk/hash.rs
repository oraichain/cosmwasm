use crate::{Bls381Fr, Bn254Fr};
use ark_ff::{BigInteger, PrimeField};
use ark_std::vec::Vec;
use sha2::{Digest, Sha256};
use sha3::Keccak256;

pub fn keccak_256(sign_bytes: &[u8]) -> Vec<u8> {
    Keccak256::digest(sign_bytes).to_vec()
}

pub fn sha256(sign_bytes: &[u8]) -> Vec<u8> {
    Sha256::digest(sign_bytes).to_vec()
}

pub fn curve_hash(input: &[u8], curve: u8) -> Vec<u8> {
    // better secure
    let res = keccak_256(input);
    match curve {
        0 => Bls381Fr::from_le_bytes_mod_order(&res)
            .into_repr()
            .to_bytes_le(),
        1 => Bn254Fr::from_le_bytes_mod_order(&res)
            .into_repr()
            .to_bytes_le(),
        _ => vec![],
    }
}
