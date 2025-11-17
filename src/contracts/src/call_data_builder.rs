use crate::{ContractsError, IdCardVoting, RegistrationSimple};
use alloy::dyn_abi::DynSolValue;
use alloy::primitives::U256;
use alloy::sol_types::SolCall;
use std::str::FromStr;

#[derive(Debug, Clone)]
pub struct UserData {
    pub nullifier: String,
    pub citizenship: String,
    pub identity_creation_timestamp: String,
}

#[derive(Debug, Clone)]
pub struct UserPayloadInputs {
    pub proposal_id: String,
    pub vote: Vec<String>,
    pub user_data: UserData,
}
pub struct CallDataBuilder {}

impl CallDataBuilder {
    pub fn new() -> Self {
        Self {}
    }

    pub fn encode_user_payload(
        &self,
        inputs: UserPayloadInputs,
    ) -> Result<Vec<u8>, ContractsError> {
        let user_payload_value = DynSolValue::Tuple(vec![
            DynSolValue::Uint(U256::from_str(inputs.proposal_id.as_str())?, 256),
            DynSolValue::Array(
                inputs
                    .vote
                    .iter()
                    .map(|v| {
                        let val = U256::from_str(v.as_str())?;
                        Ok(DynSolValue::Uint(val, 256))
                    })
                    .collect::<Result<Vec<_>, ContractsError>>()?,
            ),
            DynSolValue::Tuple(vec![
                DynSolValue::Uint(U256::from_str(inputs.user_data.nullifier.as_str())?, 256),
                DynSolValue::Uint(U256::from_str(inputs.user_data.citizenship.as_str())?, 256),
                DynSolValue::Uint(
                    U256::from_str(inputs.user_data.identity_creation_timestamp.as_str())?,
                    256,
                ),
            ]),
        ]);

        let encoded: Vec<u8> = user_payload_value.abi_encode_params();

        return Ok(encoded);
    }

    pub fn build_noir_lite_register_call_data(
        &self,
        inputs: RegistrationSimple::registerSimpleViaNoirCall,
    ) -> Result<Vec<u8>, ContractsError> {
        let result = inputs.abi_encode();
        return Ok(result);
    }

    pub fn build_noir_vote_call_data(
        &self,
        inputs: IdCardVoting::executeTD1NoirCall,
    ) -> Result<Vec<u8>, ContractsError> {
        let result = inputs.abi_encode();
        return Ok(result);
    }
}
