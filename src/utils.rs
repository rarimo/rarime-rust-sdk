use anyhow::anyhow;
use ff::PrimeField;
use num_bigint::BigInt;
use num_traits::Zero;
use poseidon_rs::Fr;

pub mod rarime_utils {
    use crate::RarimeError;
    use babyjubjub_rs::new_key;

    // GenerateBJJSecretKey generates a new secret key for the Baby JubJub curve.
    pub fn generate_rarime_private_key() -> Result<[u8; 32], RarimeError> {
        let private_key = new_key();
        let scalar = private_key.scalar_key();
        let (_, scalar_bytes) = scalar.to_bytes_be();

        let fixed_bytes: [u8; 32] = scalar_bytes
            .try_into()
            .map_err(|_| RarimeError::GeneratePrivateKeyError)?;

        Ok(fixed_bytes)
    }

    pub fn generate_aa_challenge(data: &[u8]) -> Result<Vec<u8>, RarimeError> {
        todo!();
    }
}

pub fn big_int_to_32_bytes(num: &BigInt) -> [u8; 32] {
    let mut out = [0u8; 32];

    if num.is_zero() {
        return out;
    }

    let num_bytes = num.to_signed_bytes_be();
    let len = num_bytes.len();

    if len > 32 {
        out.copy_from_slice(&num_bytes[len - 32..]);
    } else {
        let start_index = 32 - len;
        out[start_index..].copy_from_slice(&num_bytes);
    }

    return out;
}
fn big_int_to_fr(num: &BigInt) -> Result<poseidon_rs::Fr, anyhow::Error> {
    let decimal_str = num.to_string();

    let fr = poseidon_rs::Fr::from_str(&decimal_str)
        .ok_or_else(|| anyhow!("Failed convert big int to Fr"))?;

    Ok(fr)
}

pub fn unmarshal_fr(fr: Fr) -> Result<String, anyhow::Error> {
    let hash_hex = fr.to_string();

    let hex_str = if hash_hex.starts_with("Fr(0x") && hash_hex.ends_with(')') {
        &hash_hex[5..hash_hex.len() - 1]
    } else if hash_hex.starts_with("0x") {
        &hash_hex[2..]
    } else {
        &hash_hex
    };

    return Ok(hex_str.to_string());
}

pub fn poseidon_hash_32_bytes(vec_big_int: Vec<BigInt>) -> Result<[u8; 32], anyhow::Error> {
    let poseidon = poseidon_rs::Poseidon::new();
    let vec_fr: Vec<Fr> = vec_big_int
        .into_iter()
        .map(|x| big_int_to_fr(&x).unwrap())
        .collect();
    let hash_result = poseidon
        .hash(vec_fr)
        .map_err(|e| anyhow::anyhow!("Poseidon hash failed: {}", e))?;

    let hex_str =
        unmarshal_fr(hash_result).map_err(|e| anyhow::anyhow!("Failed to unmarshal Fr: {}", e))?;

    let hash_big_int = BigInt::parse_bytes(hex_str.as_bytes(), 16)
        .ok_or_else(|| anyhow::anyhow!("Failed to parse Poseidon hash result as BigInt"))?;
    let big_int_32 = big_int_to_32_bytes(&hash_big_int);

    return Ok(big_int_32);
}
