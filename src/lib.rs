pub use crate::document::DocumentStatus;
use crate::document::get_document_status;
use ::base64::engine::general_purpose::STANDARD;
use ::base64::{DecodeError, Engine};
use api::ApiProvider;
use api::errors::ApiError;
use api::types::relayer_light_register::{
    LiteRegisterData, LiteRegisterRequest, LiteRegisterResponse,
};
use api::types::verify_sod::{Attributes, Data, DocumentSod, VerifySodRequest};
use contracts::RegistrationSimple::{Passport, registerSimpleViaNoirCall};
use contracts::call_data_builder::CallDataBuilder;
use contracts::utils::convert_to_u256;
use contracts::{ContractsError, ContractsProviderConfig};
pub use document::RarimePassport;
use hex::FromHexError;
use proofs::ProofError;
use simple_asn1::to_der;
use thiserror::Error;

pub use utils::rarime_utils;
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
    pub register_contract_address: String,
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

        let profile_key = rarime_utils::get_profile_key(&private_key)?;

        let passport_key = passport.get_passport_key()?;

        let result = get_document_status(&passport_key, &profile_key, config).await?;

        Ok(result)
    }

    pub async fn light_registration(
        &mut self,
        passport: &RarimePassport,
    ) -> Result<LiteRegisterResponse, RarimeError> {
        let private_key: [u8; 32] = match self.config.user_configuration.user_private_key.clone() {
            Some(key) => key,
            None => {
                let new_key = RarimeUtils::generate_bjj_private_key()?;
                self.config.user_configuration.user_private_key = Some(new_key);
                new_key
            }
        };
        let api_provider = ApiProvider::new(&self.config.api_configuration.rarime_api_url)?;
        let proof = passport.prove_dg1(&private_key)?;
        let verify_sod_request = VerifySodRequest {
            data: Data {
                id: "".to_string(),
                type_field: "register".to_string(),
                attributes: Attributes {
                    document_sod: DocumentSod {
                        hash_algorithm: passport.get_dg_hash_algorithm()?.to_string(),
                        signature_algorithm: passport.get_signature_algorithm()?.to_string(),
                        signed_attributes: format!(
                            "0x{}",
                            hex::encode(to_der(&passport.extract_signed_attributes()?)?)
                                .to_uppercase()
                        ),
                        encapsulated_content: format!(
                            "0x{}",
                            &hex::encode(to_der(&passport.extract_encapsulated_content()?)?)
                                .to_uppercase()[8..]
                        ),
                        signature: format!(
                            "0x{}",
                            hex::encode(&passport.extract_signature()?).to_uppercase()
                        ),
                        pem_file: passport.get_certificate_pem()?,
                        dg15: match &passport.data_group15 {
                            Some(value) => format!("0x{}", hex::encode(value).to_uppercase()),
                            None => "".to_string(),
                        },
                        aa_signature: match &passport.aa_signature {
                            Some(value) => format!("0x{}", hex::encode(value).to_uppercase()),
                            None => "".to_string(),
                        },
                        sod: format!("0x{}", hex::encode(&passport.sod).to_uppercase()),
                    },
                    zk_proof: STANDARD.encode(&proof),
                },
            },
        };

        let verify_sod_response = api_provider.verify_sod(&verify_sod_request).await?;
        dbg!(&verify_sod_response);
        dbg!(hex::encode(&proof[0..32]).to_uppercase());
        dbg!(hex::encode(&proof[32..64]).to_uppercase());
        dbg!(hex::encode(&proof[64..96]).to_uppercase());
        dbg!(hex::encode(&passport.extract_dg1_commitment(&private_key)?).to_uppercase());
        let call_data_builder = CallDataBuilder::new();
        let inputs = registerSimpleViaNoirCall {
            identityKey_: convert_to_u256(&RarimeUtils::get_profile_key(&private_key)?)?,
            passport_: Passport {
                dgCommit: convert_to_u256(&proof[..32].try_into().unwrap())?,
                //convert_to_u256(&passport.extract_dg1_commitment(&private_key)?)?,
                dg1Hash: convert_to_u256(&proof[32..64].try_into().unwrap())?.into(),
                // passport
                //     .get_dg_hash_algorithm()?
                //     .get_hash_fixed32(&passport.data_group1)
                //     .into(),
                publicKey: //hex::decode(verify_sod_response.data.attributes.public_key.chars()[2..34]).into(),
                // [0u8; 32].into(),
                passport.get_passport_key()?.into(),
                passportHash: passport.get_passport_hash()?.into(),
                verifier: hex::decode(
                    verify_sod_response
                        .data
                        .attributes
                        .verifier
                        .chars()
                        .skip(2)
                        .collect::<String>(),
                )?
                    .as_slice()
                    .try_into()
                    .expect("Expected a 20-byte slice as verifier address"),
            },
            signature_: hex::decode(&verify_sod_response.data.attributes.signature[2..])?.into(),
            zkPoints_: proof[96..].to_vec().into(),
        };
        dbg!(&inputs);
        let call_data = call_data_builder.build_noir_lite_register_call_data(inputs)?;
        let lite_register_request = LiteRegisterRequest {
            data: LiteRegisterData {
                tx_data: format!("0x{}", hex::encode(&call_data)),
                no_send: false,
                destination: self
                    .config
                    .contracts_configuration
                    .register_contract_address
                    .clone(),
            },
        };
        let lite_register_response = api_provider
            .relayer_light_register(&lite_register_request)
            .await?;

        return Ok(lite_register_response);
    }
}

pub struct RarimeUtils {}

impl RarimeUtils {
    pub fn generate_bjj_private_key() -> Result<[u8; 32], RarimeError> {
        return rarime_utils::generate_bjj_private_key();
    }

    pub fn get_profile_key(private_key: &[u8; 32]) -> Result<[u8; 32], RarimeError> {
        return rarime_utils::get_profile_key(&private_key);
    }
}

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
    #[error("Decode hex error: {0}")]
    DecodeHexError(#[from] FromHexError),
}
