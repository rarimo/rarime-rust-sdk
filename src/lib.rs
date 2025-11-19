pub use crate::document::DocumentStatus;
pub use crate::errors::RarimeError;
pub use api::types::relayer_light_register::{
    LiteRegisterData, LiteRegisterRequest, LiteRegisterResponse, LiteRegisterResponseBody,
    RegisterResponseAttributes,
};
pub use document::RarimePassport;

pub use freedomtool::{
    Freedomtool, FreedomtoolAPIConfiguration, FreedomtoolConfiguration,
    FreedomtoolContractsConfiguration,
};

pub use poll::{ProposalData, Question, VotingCriteria};

pub use rarime::{
    Rarime, RarimeAPIConfiguration, RarimeConfiguration, RarimeContractsConfiguration,
    RarimeUserConfiguration,
};

pub use rarimo_utils::RarimeUtils;

pub mod document;
pub mod errors;
pub mod freedomtool;
mod hash_algorithm;
pub mod poll;
pub mod rarime;
pub mod rarimo_utils;
mod signature_algorithm;
mod utils;

// UniFFI setup
uniffi::include_scaffolding!("rarime_rust_sdk");

#[derive(Debug, Clone)]
pub struct QueryProofParams {
    pub event_id: String,
    pub event_data: String,
    pub selector: String,
    pub timestamp_lowerbound: String,
    pub timestamp_upperbound: String,
    pub identity_count_lowerbound: String,
    pub identity_count_upperbound: String,
    pub birth_date_lowerbound: String,
    pub birth_date_upperbound: String,
    pub expiration_date_lowerbound: String,
    pub expiration_date_upperbound: String,
    pub citizenship_mask: String,
}
