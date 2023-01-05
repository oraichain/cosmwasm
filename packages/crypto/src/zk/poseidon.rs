use ark_bn254::Fr as Bn254Fr;
use ark_ff::{BigInteger, PrimeField};
use ark_std::vec::Vec;
use arkworks_native_gadgets::poseidon::{FieldHasher, Poseidon as ArkworksPoseidon};
use arkworks_native_gadgets::to_field_elements;
use arkworks_setups::common::setup_params;
use arkworks_setups::Curve;

use crate::ZKError;

pub type PoseidonHasher = ArkworksPoseidon<Bn254Fr>;

#[derive(Debug, Clone)]
pub struct Poseidon {
    poseidon_width_3_bytes: PoseidonHasher,
    poseidon_width_4_bytes: PoseidonHasher,
    poseidon_width_5_bytes: PoseidonHasher,
}

impl Poseidon {
    pub fn new() -> Self {
        Self {
            poseidon_width_3_bytes: PoseidonHasher::new(setup_params(Curve::Bn254, 5, 3)),
            poseidon_width_4_bytes: PoseidonHasher::new(setup_params(Curve::Bn254, 5, 4)),
            poseidon_width_5_bytes: PoseidonHasher::new(setup_params(Curve::Bn254, 5, 5)),
        }
    }

    pub fn hash(&self, inputs: &[&[u8]]) -> Result<Vec<u8>, ZKError> {
        let num_inputs = inputs.len();
        let mut packed_inputs = Vec::new();

        for &inp in inputs {
            packed_inputs.extend_from_slice(inp);
        }

        let input_f = to_field_elements(&packed_inputs)
            .map_err(|err| ZKError::generic_err(err.to_string()))?;

        let hash_result = match num_inputs {
            2 => self.poseidon_width_3_bytes.hash(&input_f),
            3 => self.poseidon_width_4_bytes.hash(&input_f),
            4 => self.poseidon_width_5_bytes.hash(&input_f),
            _ => return Err(ZKError::InvalidHashInput {}),
        };

        hash_result
            .map(|h| h.into_repr().to_bytes_le())
            .map_err(|err| ZKError::generic_err(err.to_string()))
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
    let ret = p.hash(&[&commitment_hash, &commitment_hash]);
    assert!(ret.is_ok())
}
