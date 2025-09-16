pub mod rarime_utils {
    use crate::RarimeError;
    use babyjubjub_rs::new_key;
    use num_bigint::ToBigInt;

    // GenerateBJJSecretKey generates a new secret key for the Baby JubJub curve.
    pub fn generate_bjj_secret_key() -> Result<Vec<u8>, RarimeError> {
        let private_key = new_key();
        let scalar = private_key.scalar_key();

        let big_int_scalar = scalar.to_bigint().unwrap();

        let (_, scalar_bytes) = big_int_scalar.to_bytes_be();

        Ok(scalar_bytes)
    }

    pub fn generate_aa_challenge(data: &[u8]) -> Result<Vec<u8>, RarimeError> {
        todo!();
    }
}

#[cfg(test)]
mod tests {
    use crate::utils::rarime_utils::generate_bjj_secret_key;

    #[test]
    fn test_generate_bjj_secret_key_uniqueness() {
        let num_keys_to_generate = 5;

        let mut generated_keys = Vec::new();

        for _ in 0..num_keys_to_generate {
            let key = generate_bjj_secret_key().expect("Failed to generate a key");
            generated_keys.push(key);
        }
        println!("{:?}", generated_keys);

        for i in 0..num_keys_to_generate {
            for j in (i + 1)..num_keys_to_generate {
                assert_ne!(generated_keys[i], generated_keys[j], "Keys are not unique!");
            }
        }
    }
}
