use crate::SparseMerkleTree::Proof;
use crate::{ContractCallConfig, ContractsError, PoseidonSMT};
use alloy::primitives::Address;
use alloy::providers::ProviderBuilder;
use std::str::FromStr;

pub struct PoseidonSmtContract {
    config: ContractCallConfig,
}

impl PoseidonSmtContract {
    pub fn new(config: ContractCallConfig) -> Self {
        Self { config }
    }

    pub async fn get_proof_call(&self, key: &[u8; 32]) -> Result<Proof, ContractsError> {
        let provider = ProviderBuilder::new().connect_http(self.config.rpc_url.parse()?);

        let contract_address = Address::from_str(&self.config.contract_address)?;

        let contract = PoseidonSMT::new(contract_address, provider);

        let result = contract.getProof(key.into()).call().await?;

        return Ok(result);
    }
}
