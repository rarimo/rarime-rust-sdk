pub mod call_data_builder;
pub mod errors;
mod poseidon_smt;
mod proposals_state;
mod state_keeper;
pub mod utils;

use crate::ProposalsState::ProposalInfo;
use crate::SparseMerkleTree::Proof;
use crate::errors::ContractsError;
use alloy::sol;

sol!(
    #[sol(rpc)]
    #[derive(Debug)]
    ProposalsState,
    "src/abi/ProposalsState.json"
);

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
pub struct IdentityContractsProviderConfig {
    pub rpc_url: String,
    pub state_keeper_contract_address: String,
    pub poseidon_smt_address: String,
}

pub struct IdentityContractsProvider {
    config: IdentityContractsProviderConfig,
}

impl IdentityContractsProvider {
    pub fn new(config: IdentityContractsProviderConfig) -> Self {
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

pub struct VotingContractsProviderConfig {
    pub rpc_url: String,
    pub proposal_state_contract_address: String,
}

pub struct VotingContractsProvider {
    config: VotingContractsProviderConfig,
}

impl VotingContractsProvider {
    pub fn new(config: VotingContractsProviderConfig) -> Self {
        Self { config }
    }

    pub async fn get_proposal_info(
        &self,
        proposal_id: &String,
    ) -> Result<ProposalInfo, ContractsError> {
        proposals_state::get_proposal_info(&self.config, proposal_id).await
    }
}
