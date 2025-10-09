pub mod masters_certificate_pool;
pub mod passport;
pub mod rfc;

mod base64;
mod document;
mod hash_algorithm;
mod owned_cert;
mod signature_algorithm;
mod treap_tree;
mod utils;

#[derive(Debug, Clone)]
pub struct RarimeUserConfiguration {
    pub user_private_key: Option<[u8; 32]>,
}
#[derive(Debug, Clone)]
pub struct RarimeAPIConfiguration {
    pub json_rpc_evm_url: String,
    pub rarime_api_url: String,
}

#[derive(Debug, Clone)]
pub struct RarimeContractsConfiguration {
    pub state_keeper_contract_address: String,
}

#[derive(Debug, Clone)]
pub struct RarimeConfiguration {
    pub contracts_configuration: RarimeContractsConfiguration,
    pub api_configuration: RarimeAPIConfiguration,
    pub user_configuration: RarimeUserConfiguration,
}

pub struct Rarime {
    config: RarimeConfiguration,
}

impl Rarime {
    pub fn new(config: RarimeConfiguration) -> Self {
        Self { config }
    }

    pub async fn get_identity_status(
        &mut self,
        passport: &RarimePassport,
    ) -> Result<DocumentStatus, RarimeError> {
        let config = ContractsProviderConfig {
            rpc_url: self.config.api_configuration.json_rpc_evm_url.clone(),
            state_keeper_contract_address: self
                .config
                .contracts_configuration
                .state_keeper_contract_address
                .clone(),
        };

        let private_key: [u8; 32] = match self.config.user_configuration.user_private_key.clone() {
            Some(key) => key,
            None => {
                let new_key = RarimeUtils::generate_bjj_private_key()?;
                self.config.user_configuration.user_private_key = Some(new_key);
                new_key
            }
        };

        let profile_key = get_profile_key(&private_key)?;

        let passport_key = passport.get_passport_key()?;

        let result = get_document_status(&passport_key, &profile_key, config).await?;

        Ok(result)
    }

    fn get_register_proof(&mut self, passport: &RarimePassport) -> Result<Vec<u8>, RarimeError> {
        let private_key: [u8; 32] = match self.config.user_configuration.user_private_key.clone() {
            Some(key) => key,
            None => {
                let new_key = RarimeUtils::generate_bjj_private_key()?;
                self.config.user_configuration.user_private_key = Some(new_key);
                new_key
            }
        };

        let profile_key = get_profile_key(&private_key)?;

        let result = passport.prove_dg1(&profile_key)?;

        Ok(result)
    }

    pub async fn verify_sod(
        &mut self,
        passport: &RarimePassport,
    ) -> Result<VerifySodResponse, RarimeError> {
        let api_provider = ApiProvider::new(&self.config.api_configuration.rarime_api_url)?;

        let verify_sod_request = VerifySodRequest {
            data: Data {
                id: "".to_string(),
                type_name: "register".to_string(),
                attributes: Attributes {
                    document_sod: DocumentSod {
                        hash_algorithm: passport.get_dg_hash_algorithm()?.to_string(),
                        signature_algorithm: passport.get_signature_algorithm()?.to_string(),
                        signed_attributes: hex::encode(to_der(
                            &passport.extract_signed_attributes()?,
                        )?),
                        encapsulated_content: hex::encode(to_der(
                            &passport.extract_encapsulated_content()?,
                        )?),
                        signature: hex::encode(&passport.extract_signature()?),
                        aa_signature: match &passport.aa_signature {
                            Some(value) => hex::encode(value),
                            None => "".to_string(),
                        },
                        pem_file: passport.get_certificate_pem()?,
                        dg15: match &passport.data_group15 {
                            Some(value) => hex::encode(value),
                            None => "".to_string(),
                        },
                        sod: hex::encode(&passport.sod),
                    },
                    zk_proof: ZkProof {
                        proof: self.get_register_proof(passport)?,
                    },
                },
            },
        };

        let verify_sod_responce = api_provider.verify_sod(&verify_sod_request).await?;

        return Ok(verify_sod_responce);
    }
}

pub struct RarimeUtils {}

impl RarimeUtils {
    pub fn generate_bjj_private_key() -> Result<[u8; 32], RarimeError> {
        return rarime_utils::generate_bjj_private_key();
    }
}

pub use crate::document::DocumentStatus;
use crate::document::get_document_status;
use crate::utils::get_profile_key;
use ::base64::DecodeError;
use api::ApiProvider;
use api::errors::ApiError;
use api::types::verify_sod::{
    Attributes, Data, DocumentSod, VerifySodRequest, VerifySodResponse, ZkProof,
};
use contracts::{ContractsError, ContractsProviderConfig};
pub use document::RarimePassport;
use proofs::ProofError;
use simple_asn1::to_der;
use thiserror::Error;
pub use utils::rarime_utils;

#[derive(Error, Debug)]
pub enum RarimeError {
    #[error("failed to parse asn1 data")]
    ASN1ParseError(#[from] asn1::ParseError),
    #[error("failed to write asn1 data")]
    ASN1WriteError(#[from] asn1::WriteError),
    #[error("failed to perform RSA operation")]
    RSAError(#[from] rsa::errors::Error),
    #[error("unsupported signature algorithm")]
    UnsupportedSignatureAlgorithm,
    #[error("X509 error: {0}")]
    X509Error(String),
    #[error("PEM error: {0}")]
    PemError(String),
    #[error("No certificates found")]
    NoCertificatesFound,
    #[error("UTF-8 error: {0}")]
    UTF8Error(#[from] std::str::Utf8Error),
    #[error("Decoding error: {0}")]
    DecodeError(#[from] DecodeError),
    #[error("Der error: {0}")]
    DerError(String),
    #[error("Unsupported type of public key")]
    UnsupportedPassportKey,
    #[error("Parsing DG15 error: {0}")]
    ParseDg15Error(String),
    #[error("Get passport key error: {0}")]
    GetPassportKeyError(String),
    #[error("Generate private key error")]
    GeneratePrivateKeyError,
    #[error("Poseidon error: {0}")]
    PoseidonHashError(String),
    #[error("Contract error: {0}")]
    ContractCallError(#[from] ContractsError),
    #[error("ASN1 routing error: {0}")]
    ASN1RouteError(String),
    #[error("Empty DER data: expected at least one block")]
    EmptyDer,
    #[error("Decoding ASN1 error: {0}")]
    ASN1DecodeError(#[from] simple_asn1::ASN1DecodeErr),
    #[error("Encoding ASN1 error: {0}")]
    ASN1EncodeError(#[from] simple_asn1::ASN1EncodeErr),
    #[error(transparent)]
    ContractError(ContractsError),
    #[error("OID operation error: {0}")]
    OIDError(const_oid::Error),
    #[error("Generate proof error: {0}")]
    ProveError(#[from] ProofError),
    #[error("Api call error: {0}")]
    ApiError(#[from] ApiError),
}
