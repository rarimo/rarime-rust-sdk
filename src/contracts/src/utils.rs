use crate::ContractsError;
use alloy::primitives::{U256, Uint};

pub fn convert_to_u256(bytes: &[u8; 32]) -> Result<Uint<256, 4>, ContractsError> {
    let result = U256::from_be_bytes(bytes.clone());
    return Ok(result);
}
