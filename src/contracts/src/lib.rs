pub mod contract;
pub mod errors;
pub mod utils;

pub mod call_data_builder;

use crate::errors::ContractsError;
use alloy::sol;

sol!(
    #[sol(rpc)]
    #[derive(Debug)]
    IdCardVoting,
    "src/abi/IDCardVoting.json"
);

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

pub struct ContractCallConfig {
    pub rpc_url: String,
    pub contract_address: String,
}
