use ark_bn254::Fr as Bn254Fr;
use ark_ff::{BigInteger, PrimeField};
use ark_std::vec::Vec;
use arkworks_setups::common::keccak_256;

pub fn curve_hash(input: &[u8]) -> Vec<u8> {
    // better secure
    let res = keccak_256(input);
    Bn254Fr::from_le_bytes_mod_order(&res)
        .into_repr()
        .to_bytes_le()
}
