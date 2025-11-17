use crate::{ContractCallConfig, ContractsError, StateKeeper};
use alloy::primitives::Address;
use alloy::providers::ProviderBuilder;
use std::str::FromStr;

pub struct StateKeeperContract {
    config: ContractCallConfig,
}

impl StateKeeperContract {
    pub fn new(config: ContractCallConfig) -> Self {
        Self { config }
    }

    pub async fn get_passport_info(
        &self,
        passport_key: &[u8; 32],
    ) -> Result<StateKeeper::getPassportInfoReturn, ContractsError> {
        let provider = ProviderBuilder::new().connect_http(self.config.rpc_url.parse()?);

        let contract_address = Address::from_str(&self.config.contract_address)?;

        let contract = StateKeeper::new(contract_address, provider);

        let result = contract.getPassportInfo(passport_key.into()).call().await?;

        Ok(result)
    }
}
