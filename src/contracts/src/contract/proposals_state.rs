use crate::ProposalsState::ProposalInfo;
use crate::errors::ContractsError;
use crate::{ContractCallConfig, ProposalsState};
use alloy::primitives::Address;
use alloy::primitives::ruint::aliases::U256;
use alloy::providers::ProviderBuilder;
use std::str::FromStr;

pub struct ProposalStateContract {
    config: ContractCallConfig,
}

impl ProposalStateContract {
    pub fn new(config: ContractCallConfig) -> Self {
        Self { config }
    }

    pub async fn get_proposal_info(
        &self,
        proposal_id: &String,
    ) -> Result<ProposalInfo, ContractsError> {
        let provider = ProviderBuilder::new().connect_http(self.config.rpc_url.parse()?);

        let contract_address = Address::from_str(&self.config.contract_address)?;

        let contract = ProposalsState::new(contract_address, provider);

        let result = contract
            .getProposalInfo(U256::from_str(&proposal_id)?)
            .call()
            .await?;

        return Ok(result);
    }

    pub async fn get_event_id(&self, proposal_id: &String) -> Result<U256, ContractsError> {
        let provider = ProviderBuilder::new().connect_http(self.config.rpc_url.parse()?);

        let contract_address = Address::from_str(&self.config.contract_address)?;

        let contract = ProposalsState::new(contract_address, provider);

        let result = contract
            .getProposalEventId(U256::from_str(&proposal_id)?)
            .call()
            .await?;

        return Ok(result);
    }
}
