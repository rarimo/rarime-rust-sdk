pub mod call_data_builder;
mod poseidon_smt;
mod state_keeper;
pub mod utils;

use crate::SparseMerkleTree::Proof;
use alloy::hex::FromHexError;
use alloy::sol;
use thiserror::Error;

sol!(
    #[sol(rpc)]
    #[derive(Debug)]
    StateKeeper,
    "src/abi/StateKeeper.json"
);

sol!(
    #[sol(rpc)]
    #[derive(Debug)]
    RegistrationSimple,
    "src/abi/RegistrationSimple.json"
);

sol!(
    #[sol(rpc)]
    #[derive(Debug)]
    PoseidonSMT,
    "src/abi/PoseidonSMT.json"
);

#[derive(Debug, Clone)]
pub struct ContractsProviderConfig {
    pub rpc_url: String,
    pub state_keeper_contract_address: String,
    pub poseidon_smt_address: String,
}

pub struct ContractsProvider {
    pub config: ContractsProviderConfig,
}

impl ContractsProvider {
    pub fn new(config: ContractsProviderConfig) -> Self {
        Self { config }
    }

    pub async fn get_passport_info(
        &self,
        passport_key: &[u8; 32],
    ) -> Result<StateKeeper::getPassportInfoReturn, ContractsError> {
        state_keeper::get_passport_info(&self.config, passport_key).await
    }

    pub async fn get_smt_proof(&self, key: &[u8; 32]) -> Result<Proof, ContractsError> {
        poseidon_smt::get_proof_call(&self.config, key).await
    }
}

#[derive(Debug, Error)]
pub enum ContractsError {
    #[error("Failed to parse the RPC URL: {0}")]
    UrlParseError(#[from] url::ParseError),

    #[error("Failed to parse the contract address: {0}")]
    AddressParseError(#[from] FromHexError),

    #[error("Contract call failed: {0}")]
    ContractCallError(#[from] alloy::contract::Error),
}
