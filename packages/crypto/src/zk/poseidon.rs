use ark_bn254::Fr as Bn254Fr;
use ark_ff::{BigInteger, PrimeField};
use ark_std::vec::Vec;
use arkworks_native_gadgets::poseidon::FieldHasher;
use arkworks_native_gadgets::poseidon::Poseidon as ArkworksPoseidon;
use arkworks_native_gadgets::to_field_elements;
use arkworks_setups::common::setup_params;
use arkworks_setups::Curve;

pub type PoseidonHasher = ArkworksPoseidon<Bn254Fr>;

#[derive(Debug, Clone)]
pub struct Poseidon {
    poseidon_width_3_bytes: PoseidonHasher,
    poseidon_width_4_bytes: PoseidonHasher,
    poseidon_width_5_bytes: PoseidonHasher,
}

/// The hash error types.
#[derive(Debug)]
pub enum Error {
    /// Returned if there is an error hashing
    HashError,
    /// Invalid hash width
    InvalidHashInputWidth,
}

impl Poseidon {
    pub fn new() -> Self {
        Self {
            poseidon_width_3_bytes: PoseidonHasher::new(setup_params(Curve::Bn254, 5, 3)),
            poseidon_width_4_bytes: PoseidonHasher::new(setup_params(Curve::Bn254, 5, 4)),
            poseidon_width_5_bytes: PoseidonHasher::new(setup_params(Curve::Bn254, 5, 5)),
        }
    }

    pub fn hash(&self, inputs: &[&[u8]]) -> Result<Vec<u8>, Error> {
        let num_inputs = inputs.len();
        let mut packed_inputs = Vec::new();

        for &inp in inputs {
            packed_inputs.extend_from_slice(inp);
        }

        let input_f =
            to_field_elements(&packed_inputs).map_err(|_| Error::InvalidHashInputWidth)?;

        let hash_result = match num_inputs {
            2 => self.poseidon_width_3_bytes.hash(&input_f),
            3 => self.poseidon_width_4_bytes.hash(&input_f),
            4 => self.poseidon_width_5_bytes.hash(&input_f),
            _ => return Err(Error::InvalidHashInputWidth),
        };

        hash_result
            .map(|h| h.into_repr().to_bytes_le())
            .map_err(|_| Error::HashError)
    }
}

impl Default for Poseidon {
    fn default() -> Self {
        Self::new()
    }
}
