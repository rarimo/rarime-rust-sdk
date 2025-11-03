use alloy::hex::FromHexError;
use alloy::primitives::ruint::ParseError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ContractsError {
    #[error("Failed to parse the RPC URL: {0}")]
    UrlParseError(#[from] url::ParseError),

    #[error("Failed to parse the contract address: {0}")]
    AddressParseError(#[from] FromHexError),

    #[error("Contract call failed: {0}")]
    ContractCallError(#[from] alloy::contract::Error),

    #[error("Parse contract type error: {0}")]
    ParseContractTypeError(#[from] ParseError),
}
