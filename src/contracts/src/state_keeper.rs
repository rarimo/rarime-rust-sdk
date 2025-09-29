use crate::{ContractsError, RPC_URL, STATE_KEEPER_CONTRACT_ADDRESS, StateKeeper};
use alloy::primitives::Address;
use alloy::providers::ProviderBuilder;
use std::str::FromStr;

pub async fn get_passport_info(
    passport_key: &[u8; 32],
) -> Result<StateKeeper::getPassportInfoReturn, ContractsError> {
    let provider = ProviderBuilder::new().connect_http(RPC_URL.parse()?);

    let contract_address = Address::from_str(STATE_KEEPER_CONTRACT_ADDRESS)?;

    let contract = StateKeeper::new(contract_address, &provider);

    let result = contract.getPassportInfo(passport_key.into()).call().await?;

    Ok(result)
}
