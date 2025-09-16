pub mod rarime_utils {
    use babyjubjub_rs::new_key;
    use crate::RarimeError;

    // NewBJJSecretKey generates a new secret key for the Baby JubJub curve.
    pub fn generate_bjj_secret_key() -> Result<Vec<u8>, RarimeError> {
        let private_key = new_key();
        let scalar = private_key.scalar_key();
        let (_, mut scalar_bytes) = scalar.to_bytes_le();

        // Resize to 32 bytes to match the expected format
        scalar_bytes.resize(32, 0);

         return Ok(scalar_bytes);
    }

    pub fn generate_aa_challenge(data: &[u8]) -> Result<Vec<u8>, RarimeError> {

        todo!()
    }
}
