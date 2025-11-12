use crate::BaseVoting::ProposalRules;
use crate::errors::ContractsError;
use crate::{ContractCallConfig, IdCardVoting};
use alloy::primitives::{Address, U256};
use alloy::providers::ProviderBuilder;
use std::str::FromStr;

#[derive(Debug, Clone)]
pub struct IdCardVotingContract {
    config: ContractCallConfig,
}

impl IdCardVotingContract {
    pub fn new(config: ContractCallConfig) -> Self {
        Self { config }
    }

    pub async fn get_proposal_rules(
        &self,
        proposal_id: String,
    ) -> Result<ProposalRules, ContractsError> {
        let provider = ProviderBuilder::new().connect_http(self.config.rpc_url.parse()?);

        let contract_address = Address::from_str(&self.config.contract_address)?;

        let contract = IdCardVoting::new(contract_address, provider);
        let proposal_id_uint256 = U256::from_str(&proposal_id)?;
        dbg!(&proposal_id_uint256);

        let result = contract
            .getProposalRules(proposal_id_uint256)
            .call()
            .await?;

        dbg!(&result);
        return Ok(result);
    }
}
