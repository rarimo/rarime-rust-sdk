use crate::utils::{calculate_event_nullifier, vec_u8_to_u8_32};
use crate::{QueryProofParams, RarimeError};
use api::IPFSApiProvider;
use api::types::ipfs_voting::IPFSResponseData;
use contracts::ContractCallConfig;
use contracts::ProposalsState::ProposalInfo;
use contracts::contract::poseidon_smt::PoseidonSmtContract;
use contracts::contract::proposals_state::ProposalStateContract;

#[derive(Debug, Clone)]
pub struct FreedomtoolConfiguration {
    pub api_configuration: FreedomtoolAPIConfiguration,
    pub contracts_configuration: FreedomtoolContractsConfiguration,
}

#[derive(Debug, Clone)]
pub struct FreedomtoolAPIConfiguration {
    pub voting_rpc_url: String,
    pub ipfs_url: String,
}

#[derive(Debug, Clone)]
pub struct FreedomtoolContractsConfiguration {
    pub proposals_state_address: String,
}

pub struct Freedomtool {
    config: FreedomtoolConfiguration,
}

impl Freedomtool {
    pub fn new(config: FreedomtoolConfiguration) -> Self {
        return Self { config };
    }

    /// This function returns data in JSON string format.
    /// Make sure to parse it before using the result.
    pub async fn get_polls_data_ipfs(
        &self,
        ipfs_index: &String,
    ) -> Result<IPFSResponseData, RarimeError> {
        let ipfs_provider = IPFSApiProvider::new(&self.config.api_configuration.ipfs_url)?;

        let proposal_data = ipfs_provider.get_proposal_data(&ipfs_index).await?;

        return Ok(proposal_data);
    }

    pub async fn get_polls_data_contract(
        &self,
        poll_id: String,
    ) -> Result<ProposalInfo, RarimeError> {
        let contract_call_config = ContractCallConfig {
            contract_address: self
                .config
                .contracts_configuration
                .proposals_state_address
                .clone(),
            rpc_url: self.config.api_configuration.voting_rpc_url.clone(),
        };

        let proposals_state = ProposalStateContract::new(contract_call_config);

        let proposal_data = proposals_state.get_proposal_info(&poll_id).await?;

        Ok(proposal_data)
    }

    pub async fn is_already_voted(
        &self,
        proposal_smt_address: String,
        private_key: Vec<u8>,
        event_id: &[u8; 32],
    ) -> Result<bool, RarimeError> {
        let poseidon_smt_call_config = ContractCallConfig {
            rpc_url: self.config.api_configuration.voting_rpc_url.clone(),
            contract_address: proposal_smt_address,
        };

        let poseidon_smt = PoseidonSmtContract::new(poseidon_smt_call_config);

        let private_key_u8_32 = vec_u8_to_u8_32(&private_key)?;

        let nullifier = calculate_event_nullifier(event_id, &private_key_u8_32)?;
        let smt_proof = poseidon_smt.get_proof_call(&nullifier).await?;

        return Ok(smt_proof.existence);
    }

    pub fn abi_decode_proposal_rules(
        &self,
        voting_whitelist_data: String,
    ) -> Result<QueryProofParams, RarimeError> {
        todo!()
    }
}
