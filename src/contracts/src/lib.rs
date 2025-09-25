mod state_keeper;

use alloy::sol;
#[cfg(debug_assertions)]
pub(crate) const RPC_URL: &str = "https://rpc.evm.mainnet.rarimo.com";
#[cfg(debug_assertions)]
pub(crate) const STATE_KEEPER_CONTRACT_ADDRESS: &str = "0x9EDADB216C1971cf0343b8C687cF76E7102584DB";

#[cfg(not(debug_assertions))]
pub(crate) const RPC_URL: &str = "https://l2.rarimo.com";
#[cfg(not(debug_assertions))]
pub(crate) const STATE_KEEPER_CONTRACT_ADDRESS: &str = "0x61aa5b68D811884dA4FEC2De4a7AA0464df166E1";

sol!(
    #[sol(rpc)]
    #[derive(Debug)]
    StateKeeper,
    "src/abi/StateKeeper.json"
);
pub use state_keeper::get_passport_info;
