use crate::ProposalsState::ProposalInfo;
use crate::errors::ContractsError;
use crate::{ProposalsState, VotingContractsProviderConfig};
use alloy::primitives::Address;
use alloy::primitives::ruint::aliases::U256;
use alloy::providers::ProviderBuilder;
use std::str::FromStr;

pub(crate) async fn get_proposal_info(
    config: &VotingContractsProviderConfig,
    proposal_id: &String,
) -> Result<ProposalInfo, ContractsError> {
    let provider = ProviderBuilder::new().connect_http(config.rpc_url.parse()?);

    let contract_address = Address::from_str(&config.proposal_state_contract_address)?;

    let contract = ProposalsState::new(contract_address, provider);

    let result = contract
        .getProposalInfo(U256::from_str(&proposal_id)?)
        .call()
        .await?;

    return Ok(result);
}
