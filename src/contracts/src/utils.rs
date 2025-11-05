use crate::ContractsError;
use alloy::dyn_abi::{DynSolType, DynSolValue};
use alloy::primitives::{U256, Uint};

pub fn convert_to_u256(bytes: &[u8; 32]) -> Result<Uint<256, 4>, ContractsError> {
    let result = U256::from_be_bytes(bytes.clone());
    return Ok(result);
}

pub fn abi_decode_vote_criteria(
    data: &[u8],
) -> Result<
    (
        String,
        Vec<String>,
        String,
        String,
        String,
        String,
        String,
        String,
    ),
    ContractsError,
> {
    let dyn_type = DynSolType::Tuple(vec![
        DynSolType::Uint(256),
        DynSolType::Array(Box::new(DynSolType::Uint(256))),
        DynSolType::Uint(256),
        DynSolType::Uint(256),
        DynSolType::Uint(256),
        DynSolType::Uint(256),
        DynSolType::Uint(256),
        DynSolType::Uint(256),
    ]);
    let value: DynSolValue = dyn_type.abi_decode(data)?;

    match value {
        DynSolValue::Tuple(items) => {
            if items.len() != 8 {
                return Err(ContractsError::DynStructTypeError(format!(
                    "Tuple length 8 was expected, but got {}",
                    items.len()
                )));
            }

            let selector = match &items[0] {
                DynSolValue::Uint(u, ..) => u.to_string(),
                other => {
                    return Err(ContractsError::DynStructTypeError(format!(
                        "Expected Uint for selector, got {:?}",
                        other
                    )));
                }
            };

            let citizenship_whitelist = match &items[1] {
                DynSolValue::Array(vec) => {
                    let mut out: Vec<String> = Vec::with_capacity(vec.len());
                    for v in vec.iter() {
                        match v {
                            DynSolValue::Uint(u, ..) => out.push(u.to_string()),
                            other => {
                                return Err(ContractsError::DynStructTypeError(format!(
                                    "Expected Uint in citizenship_whitelist array, got {:?}",
                                    other
                                )));
                            }
                        }
                    }
                    out
                }
                other => {
                    return Err(ContractsError::DynStructTypeError(format!(
                        "Expected Array for citizenship_whitelist, got {:?}",
                        other
                    )));
                }
            };

            let timestamp_upperbound = match &items[2] {
                DynSolValue::Uint(u, ..) => u.to_string(),
                other => {
                    return Err(ContractsError::DynStructTypeError(format!(
                        "Expected Uint for timestamp_upperbound, got {:?}",
                        other
                    )));
                }
            };

            let identity_count_upperbound = match &items[3] {
                DynSolValue::Uint(u, ..) => u.to_string(),
                other => {
                    return Err(ContractsError::DynStructTypeError(format!(
                        "Expected Uint for identity_count_upperbound, got {:?}",
                        other
                    )));
                }
            };

            let sex = match &items[4] {
                DynSolValue::Uint(u, ..) => u.to_string(),
                other => {
                    return Err(ContractsError::DynStructTypeError(format!(
                        "Expected Uint for sex, got {:?}",
                        other
                    )));
                }
            };

            let birth_date_lowerbound = match &items[5] {
                DynSolValue::Uint(u, ..) => u.to_string(),
                other => {
                    return Err(ContractsError::DynStructTypeError(format!(
                        "Expected Uint for birth_date_lowerbound, got {:?}",
                        other
                    )));
                }
            };

            let birth_date_upperbound = match &items[6] {
                DynSolValue::Uint(u, ..) => u.to_string(),
                other => {
                    return Err(ContractsError::DynStructTypeError(format!(
                        "Expected Uint for birth_date_upperbound, got {:?}",
                        other
                    )));
                }
            };

            let expiration_date_lowerbound = match &items[7] {
                DynSolValue::Uint(u, ..) => u.to_string(),
                other => {
                    return Err(ContractsError::DynStructTypeError(format!(
                        "Expected Uint for expiration_date_lowerbound, got {:?}",
                        other
                    )));
                }
            };

            Ok((
                selector,
                citizenship_whitelist,
                timestamp_upperbound,
                identity_count_upperbound,
                sex,
                birth_date_lowerbound,
                birth_date_upperbound,
                expiration_date_lowerbound,
            ))
        }
        other => Err(ContractsError::DynStructTypeError(format!(
            "Tuple was expected, but got {:?}",
            other
        ))),
    }
}
