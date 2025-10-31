pub use crate::document::DocumentStatus;
use crate::document::get_document_status;
pub use crate::errors::RarimeError;
use crate::utils::vec_u8_to_u8_32;
use ::base64::Engine;
use ::base64::engine::general_purpose::STANDARD;
use api::ApiProvider;
pub use api::types::relayer_light_register::{
    LiteRegisterData, LiteRegisterRequest, LiteRegisterResponse, LiteRegisterResponseBody,
    RegisterResponseAttributes,
};
use api::types::verify_sod::{Attributes, Data, DocumentSod, VerifySodRequest, VerifySodResponse};
use contracts::ContractsProviderConfig;
use contracts::RegistrationSimple::{Passport, registerSimpleViaNoirCall};
use contracts::call_data_builder::CallDataBuilder;
use contracts::utils::convert_to_u256;
pub use document::RarimePassport;
use simple_asn1::to_der;
pub use utils::rarime_utils;

pub mod masters_certificate_pool;
pub mod passport;
pub mod rfc;

mod base64;
mod document;
mod errors;
mod hash_algorithm;
mod owned_cert;
mod signature_algorithm;
mod treap_tree;
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

#[derive(Debug, Clone)]
pub struct RarimeUserConfiguration {
    pub user_private_key: Vec<u8>,
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
    pub poseidon_smt_address: String,
}

#[derive(Debug, Clone)]
pub struct RarimeConfiguration {
    pub contracts_configuration: RarimeContractsConfiguration,
    pub api_configuration: RarimeAPIConfiguration,
    pub user_configuration: RarimeUserConfiguration,
}

#[derive(Debug, Clone)]
pub struct Rarime {
    config: RarimeConfiguration,
}

impl Rarime {
    pub fn new(config: RarimeConfiguration) -> Result<Self, RarimeError> {
        if config.user_configuration.user_private_key.len() != 32 {
            return Err(RarimeError::SetupSDKError(
                "User private key length must be 32".to_string(),
            ));
        }
        return Ok(Self { config });
    }

    pub async fn get_document_status(
        &self,
        passport: RarimePassport,
    ) -> Result<DocumentStatus, RarimeError> {
        let config = ContractsProviderConfig {
            rpc_url: self.config.api_configuration.json_rpc_evm_url.clone(),
            state_keeper_contract_address: self
                .config
                .contracts_configuration
                .state_keeper_contract_address
                .clone(),

            poseidon_smt_address: self
                .config
                .contracts_configuration
                .poseidon_smt_address
                .clone(),
        };

        let profile_key = rarime_utils::get_profile_key(&vec_u8_to_u8_32(
            &self.config.user_configuration.user_private_key,
        )?)?;

        let passport_key = passport.get_passport_key()?;

        let result = get_document_status(&passport_key, &profile_key, config).await?;

        Ok(result)
    }

    pub async fn verify_sod(
        &self,
        passport: &RarimePassport,
        proof: &[u8],
    ) -> Result<VerifySodResponse, RarimeError> {
        let api_provider = ApiProvider::new(&self.config.api_configuration.rarime_api_url)?;
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
        return Ok(verify_sod_response);
    }

    pub(crate) fn build_call_data(
        &self,
        verify_sod_response: &VerifySodResponse,
        passport: &RarimePassport,
        proof: &[u8],
    ) -> Result<Vec<u8>, RarimeError> {
        let public_key: [u8; 32] =
            hex::decode(&verify_sod_response.data.attributes.public_key[2..])
                .expect("Invalid hex string")[..32]
                .try_into()
                .expect("slice with incorrect length");

        let call_data_builder = CallDataBuilder::new();
        let inputs = registerSimpleViaNoirCall {
            identityKey_: convert_to_u256(&vec_u8_to_u8_32(
                &RarimeUtils
                    .get_profile_key(self.config.user_configuration.user_private_key.clone())?,
            )?)?,
            passport_: Passport {
                dgCommit: convert_to_u256(
                    &proof[..32]
                        .try_into()
                        .expect("proof with incorrect length (length < 32)"),
                )?,
                dg1Hash: convert_to_u256(
                    &proof[32..64]
                        .try_into()
                        .expect("proof with incorrect length (length < 64)"),
                )?
                .into(),
                publicKey: public_key.into(),
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
            // Remove public signals from the proof
            zkPoints_: proof[96..].to_vec().into(),
        };

        let call_data = call_data_builder.build_noir_lite_register_call_data(inputs)?;
        return Ok(call_data);
    }

    pub async fn light_registration(
        &self,
        passport: RarimePassport,
    ) -> Result<String, RarimeError> {
        let private_key_validate =
            vec_u8_to_u8_32(&self.config.user_configuration.user_private_key)?;

        let proof = passport.prove_dg1(&private_key_validate)?;
        let verify_sod_response = self.verify_sod(&passport, &proof).await?;

        let api_provider = ApiProvider::new(&self.config.api_configuration.rarime_api_url)?;

        let call_data = self.build_call_data(&verify_sod_response, &passport, &proof)?;

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

        let tx_hash = lite_register_response.data.attributes.tx_hash;

        return Ok(tx_hash);
    }

    pub async fn generate_query_proof(
        &self,
        passport: RarimePassport,
        query_params: QueryProofParams,
    ) -> Result<Vec<u8>, RarimeError> {
        let config = ContractsProviderConfig {
            rpc_url: self.config.api_configuration.json_rpc_evm_url.clone(),
            state_keeper_contract_address: self
                .config
                .contracts_configuration
                .state_keeper_contract_address
                .clone(),

            poseidon_smt_address: self
                .config
                .contracts_configuration
                .poseidon_smt_address
                .clone(),
        };

        let passport_key = passport.get_passport_key()?;

        let pk_u8_32: [u8; 32] = vec_u8_to_u8_32(&self.config.user_configuration.user_private_key)?;

        let proof = passport
            .generate_document_query_proof(query_params, &passport_key, &pk_u8_32, config)
            .await?;

        return Ok(proof);
    }
}

pub struct RarimeUtils;

impl RarimeUtils {
    pub fn new() -> Self {
        RarimeUtils {}
    }
    pub fn generate_bjj_private_key(&self) -> Result<Vec<u8>, RarimeError> {
        return Ok(rarime_utils::generate_bjj_private_key()?.to_vec());
    }

    pub fn get_profile_key(&self, private_key: Vec<u8>) -> Result<Vec<u8>, RarimeError> {
        let private_key_validate = vec_u8_to_u8_32(&private_key)?;
        return Ok(rarime_utils::get_profile_key(&private_key_validate)?.to_vec());
    }
}
