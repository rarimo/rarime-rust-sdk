use crate::StateKeeper::getPassportInfoReturn;
use alloy::{primitives::Address, providers::ProviderBuilder, sol};
use anyhow::Error;
use std::str::FromStr;

sol!(
    #[sol(rpc)]
    #[derive(Debug)]
    StateKeeper,
    "src/abi/StateKeeper.json"
);

pub async fn get_passport_info(passport_key: [u8; 32]) -> Result<getPassportInfoReturn, Error> {
    let provider =
        ProviderBuilder::new().connect_http("https://rpc.evm.mainnet.rarimo.com".parse()?);

    let contract_address = Address::from_str("0x9EDADB216C1971cf0343b8C687cF76E7102584DB")?;

    let contract = StateKeeper::new(contract_address, &provider);

    let result = contract.getPassportInfo(passport_key.into()).call().await?;

    Ok(result)
}
