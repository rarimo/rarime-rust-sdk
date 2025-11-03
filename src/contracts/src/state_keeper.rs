use crate::{ContractsError, IdentityContractsProviderConfig, StateKeeper};
use alloy::primitives::Address;
use alloy::providers::ProviderBuilder;
use std::str::FromStr;

pub(crate) async fn get_passport_info(
    config: &IdentityContractsProviderConfig,
    passport_key: &[u8; 32],
) -> Result<StateKeeper::getPassportInfoReturn, ContractsError> {
    let provider = ProviderBuilder::new().connect_http(config.rpc_url.parse()?);

    let contract_address = Address::from_str(&config.state_keeper_contract_address)?;

    let contract = StateKeeper::new(contract_address, provider);

    let result = contract.getPassportInfo(passport_key.into()).call().await?;

    Ok(result)
}
