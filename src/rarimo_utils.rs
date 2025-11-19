use crate::RarimeError;
use crate::utils::{poseidon_hash_32_bytes, vec_u8_to_u8_32};
use babyjubjub_rs::new_key;
use ff::{PrimeField, PrimeFieldRepr};
use num_bigint::BigInt;

pub struct RarimeUtils;

impl RarimeUtils {
    pub fn new() -> Self {
        RarimeUtils {}
    }
    pub fn generate_bjj_private_key(&self) -> Result<Vec<u8>, RarimeError> {
        let private_key = new_key();
        let scalar = private_key.scalar_key();
        let (_, scalar_bytes) = scalar.to_bytes_be();

        let fixed_bytes: [u8; 32] = scalar_bytes
            .try_into()
            .map_err(|_| RarimeError::GeneratePrivateKeyError)?;

        return Ok(fixed_bytes.to_vec());
    }

    pub fn get_profile_key(&self, private_key: Vec<u8>) -> Result<Vec<u8>, RarimeError> {
        vec_u8_to_u8_32(&private_key)?;

        let scalar_int = BigInt::from_bytes_be(num_bigint::Sign::Plus, &private_key);

        let b8 = babyjubjub_rs::Point {
            x: babyjubjub_rs::Fr::from_str(
                "5299619240641551281634865583518297030282874472190772894086521144482721001553",
            )
            .ok_or(RarimeError::SetupGeneratorPointError(
                "Failed to init Generator point X".to_string(),
            ))?,
            y: babyjubjub_rs::Fr::from_str(
                "16950150798460657717958625567821834550301663161624707787222815936182638968203",
            )
            .ok_or(RarimeError::SetupGeneratorPointError(
                "Failed to init Generator point Y".to_string(),
            ))?,
        };
        let pub_point = b8.mul_scalar(&scalar_int);
        let mut x_raw_bytes = Vec::new();
        let x_raw = pub_point.x.into_repr();
        x_raw.write_be(&mut x_raw_bytes).map_err(|e| {
            RarimeError::SetupGeneratorPointError(format!("Error converting repr to byte: {}", e))
        })?;

        let x_big_int = BigInt::from_bytes_be(num_bigint::Sign::Plus, &x_raw_bytes);

        let mut y_raw_bytes = Vec::new();
        let y_raw = pub_point.y.into_repr();
        y_raw.write_be(&mut y_raw_bytes).map_err(|e| {
            RarimeError::SetupGeneratorPointError(format!("Error converting repr to byte: {}", e))
        })?;

        let y_big_int = BigInt::from_bytes_be(num_bigint::Sign::Plus, &y_raw_bytes);

        let profile_key = poseidon_hash_32_bytes(&vec![x_big_int, y_big_int])?;
        return Ok(profile_key.to_vec());
    }
}
