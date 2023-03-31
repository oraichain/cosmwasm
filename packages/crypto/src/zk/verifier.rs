use crate::{Bls381, Bn254, ZKError, ZKResult};
pub const GROTH16_VERIFIER_KEY_LEN: usize = 360;
pub const GROTH16_PROOF_LEN: usize = 128;

#[allow(clippy::all)]
use ark_crypto_primitives::{Error, SNARK};
use ark_ec::PairingEngine;
use ark_groth16::{Groth16, Proof, VerifyingKey};
use ark_serialize::CanonicalDeserialize;
use ark_std::marker::PhantomData;
use arkworks_native_gadgets::to_field_elements;

pub struct ArkworksVerifierGroth16<E: PairingEngine>(PhantomData<E>);

impl<E: PairingEngine> ArkworksVerifierGroth16<E> {
    pub fn verify(
        public_inp_bytes: &[u8],
        proof_bytes: &[u8],
        vk_bytes: &[u8],
    ) -> Result<bool, Error> {
        let public_input_field_elts = to_field_elements::<E::Fr>(public_inp_bytes)?;
        let vk = VerifyingKey::<E>::deserialize(vk_bytes)?;
        let proof = Proof::<E>::deserialize(proof_bytes)?;

        let res = Groth16::<E>::verify(&vk, &public_input_field_elts, &proof)?;
        Ok(res)
    }
}

pub type ArkworksVerifierBn254 = ArkworksVerifierGroth16<Bn254>;
pub type ArkworksVerifierBls381 = ArkworksVerifierGroth16<Bls381>;

pub fn groth16_verify(
    public_inp_bytes: &[u8],
    proof_bytes: &[u8],
    vk_bytes: &[u8],
    curve: u8,
) -> ZKResult<bool> {
    match curve {
        0 => ArkworksVerifierBls381::verify(public_inp_bytes, proof_bytes, &vk_bytes),
        1 => ArkworksVerifierBn254::verify(public_inp_bytes, proof_bytes, &vk_bytes),
        _ => return Err(ZKError::generic_err("Unimplemented")),
    }
    .map_err(|_| ZKError::VerifierError {})
}
