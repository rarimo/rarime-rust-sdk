use crate::SparseMerkleTree::Proof;
use crate::{ContractsError, IdentityContractsProviderConfig, PoseidonSMT};
use alloy::primitives::Address;
use alloy::providers::ProviderBuilder;
use std::str::FromStr;

pub(crate) async fn get_proof_call(
    config: &IdentityContractsProviderConfig,
    key: &[u8; 32],
) -> Result<Proof, ContractsError> {
    let provider = ProviderBuilder::new().connect_http(config.rpc_url.parse()?);

    let contract_address = Address::from_str(&config.poseidon_smt_address)?;

    let contract = PoseidonSMT::new(contract_address, provider);

    let result = contract.getProof(key.into()).call().await?;

    return Ok(result);
}
