use crate::utils::vec_u8_to_u8_32;
use crate::{RarimeError, rarime_utils};

pub struct RarimeUtils;

impl RarimeUtils {
    pub fn new() -> Self {
        RarimeUtils {}
    }
    pub fn generate_bjj_private_key(&self) -> Result<Vec<u8>, RarimeError> {
        return Ok(rarime_utils::generate_bjj_private_key()?.to_vec());
    }

    pub fn get_profile_key(&self, private_key: Vec<u8>) -> Result<Vec<u8>, RarimeError> {
        let private_key_validate = vec_u8_to_u8_32(&private_key)?;
        return Ok(rarime_utils::get_profile_key(&private_key_validate)?.to_vec());
    }
}
