mod errors;

#[allow(clippy::all)]
mod poseidon;

#[allow(clippy::all)]
mod verifier;

#[allow(clippy::all)]
mod hash;

pub use ark_bls12_381::{Bls12_381 as Bls381, Fr as Bls381Fr};
pub use ark_bn254::{Bn254, Fr as Bn254Fr};
pub use errors::{ZKError, ZKResult};
pub use hash::{curve_hash, keccak_256, sha256};
pub use poseidon::Poseidon;
pub use verifier::{
    groth16_verify, ArkworksVerifierBn254, GROTH16_PROOF_LEN, GROTH16_VERIFIER_KEY_LEN,
};
