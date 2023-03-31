use crate::{Bls381Fr, Bn254Fr};
use ark_ff::{BigInteger, PrimeField};
use ark_std::vec::Vec;
use arkworks_native_gadgets::poseidon::sbox::PoseidonSbox;
use arkworks_native_gadgets::poseidon::{
    FieldHasher, Poseidon as ArkworksPoseidon, PoseidonParameters,
};
use arkworks_native_gadgets::to_field_elements;
use arkworks_utils::poseidon_params::setup_poseidon_params;
use arkworks_utils::{bytes_matrix_to_f, bytes_vec_to_f, Curve};

use crate::ZKError;

pub type PoseidonHasherBn254 = ArkworksPoseidon<Bn254Fr>;
pub type PoseidonHasherBls381 = ArkworksPoseidon<Bls381Fr>;

#[derive(Debug, Clone)]
pub struct Poseidon {
    hasher_bn254: PoseidonHasherBn254,
    hasher_bls381: PoseidonHasherBls381,
}

fn inner_hash<F: PrimeField>(
    hasher: &ArkworksPoseidon<F>,
    inputs: &[&[u8]],
) -> Result<Vec<u8>, ZKError> {
    let mut packed_inputs = Vec::new();
    for &inp in inputs {
        packed_inputs.extend_from_slice(inp);
    }

    let input_f =
        to_field_elements(&packed_inputs).map_err(|err| ZKError::generic_err(err.to_string()))?;

    let hash_result = hasher.hash(&input_f);

    hash_result
        .map(|h| h.into_repr().to_bytes_le())
        .map_err(|err| ZKError::generic_err(err.to_string()))
}

pub fn setup_params<F: PrimeField>(curve: Curve, exp: i8, width: u8) -> PoseidonParameters<F> {
    let pos_data = setup_poseidon_params(curve, exp, width).unwrap();

    let mds_f = bytes_matrix_to_f(&pos_data.mds);
    let rounds_f = bytes_vec_to_f(&pos_data.rounds);

    let pos = PoseidonParameters {
        mds_matrix: mds_f,
        round_keys: rounds_f,
        full_rounds: pos_data.full_rounds,
        partial_rounds: pos_data.partial_rounds,
        sbox: PoseidonSbox(pos_data.exp),
        width: pos_data.width,
    };

    pos
}

impl Poseidon {
    pub fn new() -> Self {
        Self {
            hasher_bn254: ArkworksPoseidon::new(setup_params(Curve::Bn254, 5, 3)),
            hasher_bls381: ArkworksPoseidon::new(setup_params(Curve::Bls381, 5, 3)),
        }
    }

    pub fn hash(
        &self,
        left_input: &[u8],
        right_input: &[u8],
        curve: u8,
    ) -> Result<Vec<u8>, ZKError> {
        let inputs = &[left_input, right_input];

        match curve {
            0 => inner_hash(&self.hasher_bls381, inputs),
            1 => inner_hash(&self.hasher_bn254, inputs),
            _ => Err(ZKError::Unimplemented {}),
        }
    }
}

impl Default for Poseidon {
    fn default() -> Self {
        Self::new()
    }
}

#[test]
fn test_hash() {
    let p = Poseidon::new();
    let commitment_hash =
        hex::decode("84d6bdcfd953993012f08970d9c9b472d96114b4edc69481968cafc07877381c").unwrap();
    let ret = p.hash(&commitment_hash, &commitment_hash, 0);
    assert!(ret.is_ok())
}
