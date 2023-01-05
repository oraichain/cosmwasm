mod errors;

#[allow(clippy::all)]
mod poseidon;

#[allow(clippy::all)]
mod verifier;

#[allow(clippy::all)]
mod keccak;

pub use errors::{ZKError, ZKResult};
pub use keccak::curve_hash;
pub use poseidon::Poseidon;
pub use verifier::{
    groth16_verify, ArkworksVerifierBn254, GROTH16_PROOF_LEN, GROTH16_VERIFIER_KEY_LEN,
};
