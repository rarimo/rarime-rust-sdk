use crate::{ContractsError, IdCardVoting, RegistrationSimple};
use alloy::sol_types::SolCall;

pub struct CallDataBuilder {}

impl CallDataBuilder {
    pub fn new() -> Self {
        Self {}
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
